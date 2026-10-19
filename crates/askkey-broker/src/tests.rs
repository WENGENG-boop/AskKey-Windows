use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use askkey_protocol::{
    read_frame, write_frame, BrokerPayload, BrokerRequest, BrokerResponse, CatalogItem, ErrorCode,
    RequestState, RunRequest, RunResult,
};
use zeroize::Zeroizing;

use crate::*;

struct FakeCredential {
    resolved: ResolvedCredential,
    values: Vec<(String, String)>,
    hidden: bool,
}

#[derive(Default)]
struct FakeProvider {
    credentials: Mutex<Vec<FakeCredential>>,
    paused: AtomicBool,
    events: Mutex<Vec<AccessEvent>>,
    /// Makes delivery slow, to hold a launch inside its final boundary.
    deliver_delay: Mutex<Option<Duration>>,
    delivering: AtomicBool,
    delivered: AtomicBool,
}

impl FakeProvider {
    fn add(&self, name: &str, access: Access, variable: &str, value: &str) {
        self.credentials.lock().unwrap().push(FakeCredential {
            resolved: ResolvedCredential {
                id: format!("id-{name}"),
                name: name.into(),
                access,
                expired: false,
                revision: "1".into(),
                environment_variables: vec![variable.into()],
            },
            values: vec![(variable.into(), value.into())],
            hidden: false,
        });
    }

    fn set_access(&self, name: &str, access: Access) {
        for credential in self.credentials.lock().unwrap().iter_mut() {
            if credential.resolved.name == name {
                credential.resolved.access = access;
            }
        }
    }

    /// An edit in the App: new value, new revision.
    fn edit(&self, name: &str, value: &str) {
        for credential in self.credentials.lock().unwrap().iter_mut() {
            if credential.resolved.name == name {
                credential.values[0].1 = value.into();
                credential.resolved.revision.push('+');
            }
        }
    }

    fn remove(&self, name: &str) {
        self.credentials
            .lock()
            .unwrap()
            .retain(|credential| credential.resolved.name != name);
    }

    fn hide(&self, name: &str) {
        for credential in self.credentials.lock().unwrap().iter_mut() {
            if credential.resolved.name == name {
                credential.hidden = true;
            }
        }
    }
}

impl CredentialProvider for FakeProvider {
    fn agent_access_paused(&self) -> bool {
        self.paused.load(Ordering::SeqCst)
    }

    fn catalog(&self) -> Result<(Vec<CatalogItem>, Vec<String>), ErrorCode> {
        Ok((Vec::new(), Vec::new()))
    }

    fn resolve(&self, name: &str) -> Result<Option<ResolvedCredential>, ErrorCode> {
        Ok(self
            .credentials
            .lock()
            .unwrap()
            .iter()
            .find(|credential| {
                !credential.hidden && credential.resolved.name.eq_ignore_ascii_case(name)
            })
            .map(|credential| credential.resolved.clone()))
    }

    fn deliver(
        &self,
        credential_id: &str,
        revision: &str,
    ) -> Result<Vec<(String, Zeroizing<String>)>, ErrorCode> {
        self.delivering.store(true, Ordering::SeqCst);
        if let Some(delay) = *self.deliver_delay.lock().unwrap() {
            std::thread::sleep(delay);
        }
        self.delivered.store(true, Ordering::SeqCst);
        let credentials = self.credentials.lock().unwrap();
        let credential = credentials
            .iter()
            .find(|c| c.resolved.id == credential_id && c.resolved.revision == revision)
            .ok_or(ErrorCode::RequestRejected)?;
        Ok(credential
            .values
            .iter()
            .map(|(name, value)| (name.clone(), Zeroizing::new(value.clone())))
            .collect())
    }

    fn record(&self, event: AccessEvent) {
        self.events.lock().unwrap().push(event);
    }
}

#[derive(Default)]
struct CountingPresenter(AtomicUsize, Mutex<Vec<usize>>);

impl ApprovalPresenter for CountingPresenter {
    fn pending_changed(&self, pending: usize) {
        self.0.fetch_add(1, Ordering::SeqCst);
        self.1.lock().unwrap().push(pending);
    }
}

fn system_root() -> String {
    std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into())
}

/// `cmd.exe /d /c exit %VARIABLE%`: the exit code proves what the target saw.
fn exit_with(variable: &str, operation: &str, credentials: &[&str]) -> RunRequest {
    let root = system_root();
    RunRequest {
        operation_id: operation.into(),
        command: vec![
            "cmd.exe".into(),
            "/d".into(),
            "/c".into(),
            format!("exit %{variable}%"),
        ],
        credential_names: credentials.iter().map(|name| name.to_string()).collect(),
        working_directory: Some(root.clone()),
        inherited_environment: BTreeMap::from([
            ("PATH".into(), format!(r"{root}\System32")),
            ("SystemRoot".into(), root),
            ("SECRET_FROM_AGENT_SHELL".into(), "9".into()),
        ]),
        caller_name: Some("Synthetic agent".into()),
        caller_purpose: Some("Test".into()),
        streams: None,
    }
}

fn setup() -> (Arc<Broker>, Arc<FakeProvider>, Arc<CountingPresenter>) {
    let provider = Arc::new(FakeProvider::default());
    let presenter = Arc::new(CountingPresenter::default());
    (
        Broker::new(provider.clone(), presenter.clone()),
        provider,
        presenter,
    )
}

async fn run(broker: &Arc<Broker>, request: RunRequest) -> BrokerResponse {
    broker
        .run(request, std::process::id(), std::future::pending())
        .await
}

fn exited(code: i32) -> BrokerResponse {
    BrokerResponse::Ok(BrokerPayload::Run(RunResult::Exited(code)))
}

#[tokio::test]
async fn allow_delivers_without_approval() {
    let (broker, provider, _) = setup();
    provider.add("Code", Access::Allow, "SYNTH_CODE", "42");
    assert_eq!(
        run(&broker, exit_with("SYNTH_CODE", "op-allow", &["Code"])).await,
        exited(42)
    );
    let events = provider.events.lock().unwrap();
    assert_eq!(events[0].outcome, AccessOutcome::Allowed);
    assert_eq!(events[0].executable, "cmd.exe");
}

#[tokio::test]
async fn non_allowlisted_inherited_variables_are_dropped() {
    let (broker, provider, _) = setup();
    provider.add("Code", Access::Allow, "SYNTH_CODE", "42");
    // cmd leaves an undefined %VAR% as literal text, and `exit` of a
    // non-number exits with 0.
    assert_eq!(
        run(
            &broker,
            exit_with("SECRET_FROM_AGENT_SHELL", "op-env", &["Code"])
        )
        .await,
        exited(0)
    );
}

#[tokio::test]
async fn ask_requires_one_approval_and_replays_status() {
    let (broker, provider, presenter) = setup();
    provider.add("Code", Access::Ask, "SYNTH_CODE", "17");
    let request = exit_with("SYNTH_CODE", "op-ask", &["Code"]);

    let BrokerResponse::Ok(BrokerPayload::Run(RunResult::ApprovalRequired { tickets, .. })) =
        run(&broker, request.clone()).await
    else {
        panic!("expected approvalRequired");
    };
    assert_eq!(presenter.0.load(Ordering::SeqCst), 1);
    let pending = broker.pending_approvals();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].environment_variables, vec!["SYNTH_CODE"]);
    assert!(pending[0].command_line.contains("exit %SYNTH_CODE%"));

    // Retrying before approval does not run anything.
    assert!(matches!(
        run(&broker, request.clone()).await,
        BrokerResponse::Ok(BrokerPayload::Run(RunResult::ApprovalRequired { .. }))
    ));

    broker.decide(&tickets[0].request_id, true).unwrap();
    assert_eq!(run(&broker, request.clone()).await, exited(17));
    // A completed operation returns its status without running again.
    assert_eq!(run(&broker, request.clone()).await, exited(17));
    let status = broker.handle_simple(&BrokerRequest::ticket(
        "request.status",
        &tickets[0].request_id,
        &tickets[0].capability,
    ));
    assert_eq!(
        status,
        BrokerResponse::Ok(BrokerPayload::RequestStatus {
            state: RequestState::Completed
        })
    );
    assert_eq!(provider.events.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn changed_retry_is_rejected() {
    let (broker, provider, _) = setup();
    provider.add("Code", Access::Ask, "SYNTH_CODE", "1");
    let request = exit_with("SYNTH_CODE", "op-change", &["Code"]);
    let _ = run(&broker, request.clone()).await;
    let id = broker.pending_approvals()[0].request_id.clone();
    broker.decide(&id, true).unwrap();
    let mut changed = request;
    changed.command.push("extra".into());
    assert_eq!(
        run(&broker, changed).await,
        BrokerResponse::Error(ErrorCode::RequestRejected)
    );
}

fn approval_required(response: &BrokerResponse) -> bool {
    matches!(
        response,
        BrokerResponse::Ok(BrokerPayload::Run(RunResult::ApprovalRequired { .. }))
    )
}

#[tokio::test]
async fn edit_after_approval_needs_a_new_approval() {
    let (broker, provider, _) = setup();
    provider.add("Code", Access::Ask, "SYNTH_CODE", "11");
    let request = exit_with("SYNTH_CODE", "op-edit", &["Code"]);
    let _ = run(&broker, request.clone()).await;
    let id = broker.pending_approvals()[0].request_id.clone();
    broker.decide(&id, true).unwrap();
    provider.edit("Code", "12");
    assert_eq!(
        run(&broker, request.clone()).await,
        BrokerResponse::Error(ErrorCode::RequestRejected)
    );
    // Nothing ran, and the retry asks again for the edited credential.
    assert!(provider.events.lock().unwrap().is_empty());
    assert!(approval_required(&run(&broker, request.clone()).await));
    let id = broker.pending_approvals()[0].request_id.clone();
    broker.decide(&id, true).unwrap();
    assert_eq!(run(&broker, request).await, exited(12));
}

#[tokio::test]
async fn recreated_credential_needs_a_new_approval() {
    let (broker, provider, _) = setup();
    provider.add("Code", Access::Ask, "SYNTH_CODE", "11");
    let request = exit_with("SYNTH_CODE", "op-recreate", &["Code"]);
    let _ = run(&broker, request.clone()).await;
    let id = broker.pending_approvals()[0].request_id.clone();
    broker.decide(&id, true).unwrap();
    provider.remove("Code");
    provider.add("Code", Access::Ask, "SYNTH_CODE", "13");
    provider.credentials.lock().unwrap()[0].resolved.id = "id-Code-2".into();
    assert_eq!(
        run(&broker, request).await,
        BrokerResponse::Error(ErrorCode::RequestRejected)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pause_waits_for_a_launch_inside_the_boundary() {
    let (broker, provider, _) = setup();
    provider.add("Code", Access::Allow, "SYNTH_CODE", "8");
    *provider.deliver_delay.lock().unwrap() = Some(Duration::from_millis(300));
    let launching = {
        let broker = broker.clone();
        tokio::spawn(
            async move { run(&broker, exit_with("SYNTH_CODE", "op-race", &["Code"])).await },
        )
    };
    while !provider.delivering.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // The pause cannot slip in between the final check and process creation.
    let pause = {
        let (broker, provider) = (broker.clone(), provider.clone());
        tokio::task::spawn_blocking(move || {
            broker.exclusive(|| {
                provider.paused.store(true, Ordering::SeqCst);
                provider.delivered.load(Ordering::SeqCst)
            })
        })
    };
    assert!(pause.await.unwrap(), "pause ran inside the launch boundary");
    assert_eq!(launching.await.unwrap(), exited(8));
    // After the pause won, nothing launches.
    assert_eq!(
        run(&broker, exit_with("SYNTH_CODE", "op-after", &["Code"])).await,
        BrokerResponse::Error(ErrorCode::AgentAccessPaused)
    );
}

#[tokio::test]
async fn expiry_is_reported_before_the_next_approval() {
    let (broker, provider, presenter) = setup();
    provider.add("Code", Access::Ask, "SYNTH_CODE", "1");
    let _ = run(&broker, exit_with("SYNTH_CODE", "op-old", &["Code"])).await;
    broker.approvals.expire_all_for_test();
    let _ = run(&broker, exit_with("SYNTH_CODE", "op-new", &["Code"])).await;
    // 1 pending, then 0 after the expiry, then 1 again: the window is raised.
    assert_eq!(*presenter.1.lock().unwrap(), vec![1, 0, 1]);
}

#[tokio::test]
async fn denial_is_final_and_recorded() {
    let (broker, provider, _) = setup();
    provider.add("Code", Access::Ask, "SYNTH_CODE", "1");
    let request = exit_with("SYNTH_CODE", "op-deny", &["Code"]);
    let _ = run(&broker, request.clone()).await;
    let id = broker.pending_approvals()[0].request_id.clone();
    broker.decide(&id, false).unwrap();
    assert_eq!(
        run(&broker, request).await,
        BrokerResponse::Error(ErrorCode::RequestRejected)
    );
    assert_eq!(
        provider.events.lock().unwrap()[0].outcome,
        AccessOutcome::Denied
    );
}

#[tokio::test]
async fn hidden_and_missing_look_the_same() {
    let (broker, provider, _) = setup();
    provider.add("Secret", Access::Allow, "SYNTH_CODE", "1");
    provider.hide("Secret");
    let hidden = run(&broker, exit_with("SYNTH_CODE", "op-hidden", &["Secret"])).await;
    let missing = run(&broker, exit_with("SYNTH_CODE", "op-missing", &["Nothing"])).await;
    assert_eq!(hidden, BrokerResponse::Error(ErrorCode::RequestNotFound));
    assert_eq!(hidden, missing);
}

#[tokio::test]
async fn revocation_before_launch_wins() {
    let (broker, provider, _) = setup();
    provider.add("Code", Access::Ask, "SYNTH_CODE", "5");
    let request = exit_with("SYNTH_CODE", "op-revoke", &["Code"]);
    let _ = run(&broker, request.clone()).await;
    let id = broker.pending_approvals()[0].request_id.clone();
    broker.decide(&id, true).unwrap();
    provider.hide("Code");
    assert_eq!(
        run(&broker, request).await,
        BrokerResponse::Error(ErrorCode::RequestNotFound)
    );
}

#[tokio::test]
async fn allow_downgraded_to_ask_needs_approval() {
    let (broker, provider, _) = setup();
    provider.add("Code", Access::Allow, "SYNTH_CODE", "3");
    provider.set_access("Code", Access::Ask);
    assert!(matches!(
        run(&broker, exit_with("SYNTH_CODE", "op-downgrade", &["Code"])).await,
        BrokerResponse::Ok(BrokerPayload::Run(RunResult::ApprovalRequired { .. }))
    ));
}

#[tokio::test]
async fn pause_blocks_and_cancels() {
    let (broker, provider, _) = setup();
    provider.add("Code", Access::Ask, "SYNTH_CODE", "3");
    let _ = run(&broker, exit_with("SYNTH_CODE", "op-pause", &["Code"])).await;
    provider.paused.store(true, Ordering::SeqCst);
    broker.cancel_pending();
    assert!(broker.pending_approvals().is_empty());
    assert_eq!(
        run(&broker, exit_with("SYNTH_CODE", "op-paused", &["Code"])).await,
        BrokerResponse::Error(ErrorCode::AgentAccessPaused)
    );
    assert_eq!(
        broker.handle_simple(&BrokerRequest::simple("catalog")),
        BrokerResponse::Error(ErrorCode::AgentAccessPaused)
    );
}

#[tokio::test]
async fn batch_files_are_refused() {
    let (broker, provider, _) = setup();
    provider.add("Code", Access::Allow, "SYNTH_CODE", "3");
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("deploy.cmd"), b"@exit 0").unwrap();
    let mut request = exit_with("SYNTH_CODE", "op-batch", &["Code"]);
    request.command = vec![r".\deploy.cmd".into()];
    request.working_directory = Some(directory.path().to_string_lossy().into_owned());
    assert_eq!(
        run(&broker, request).await,
        BrokerResponse::Error(ErrorCode::TargetRejected)
    );
}

#[tokio::test]
async fn disconnect_terminates_the_target() {
    let (broker, provider, _) = setup();
    provider.add("Code", Access::Allow, "SYNTH_CODE", "3");
    let root = system_root();
    let mut request = exit_with("SYNTH_CODE", "op-disconnect", &["Code"]);
    request.command = vec![
        "ping.exe".into(),
        "-n".into(),
        "60".into(),
        "127.0.0.1".into(),
    ];
    request.working_directory = Some(root);
    let started = std::time::Instant::now();
    let disconnected = tokio::time::sleep(std::time::Duration::from_millis(300));
    let response = broker.run(request, std::process::id(), disconnected).await;
    assert_eq!(response, exited(1));
    assert!(started.elapsed() < std::time::Duration::from_secs(20));
}

#[tokio::test]
async fn rejects_invalid_requests() {
    let (broker, provider, _) = setup();
    provider.add("Code", Access::Allow, "SYNTH_CODE", "3");
    let mut relative = exit_with("SYNTH_CODE", "op-relative", &["Code"]);
    relative.working_directory = Some("relative".into());
    assert_eq!(
        run(&broker, relative).await,
        BrokerResponse::Error(ErrorCode::InvalidRequest)
    );
    let none = exit_with("SYNTH_CODE", "op-none", &[]);
    assert_eq!(
        run(&broker, none).await,
        BrokerResponse::Error(ErrorCode::InvalidRequest)
    );
    assert_eq!(
        broker.handle_simple(&BrokerRequest::simple("vault.dump")),
        BrokerResponse::Error(ErrorCode::MethodNotAllowed)
    );
    let mut old = BrokerRequest::simple("health");
    old.version = 0;
    assert_eq!(
        broker.handle_simple(&old),
        BrokerResponse::Error(ErrorCode::UnsupportedVersion)
    );
}

#[tokio::test]
async fn serves_over_a_private_pipe() {
    let (broker, provider, _) = setup();
    provider.add("Code", Access::Allow, "SYNTH_CODE", "23");
    let name = format!(r"\\.\pipe\askkey-broker-test-{}", std::process::id());
    let server = tokio::spawn(serve(broker, name.clone()));
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    // A second server on the same name must fail: the first instance owns it.
    let (second, _, _) = setup();
    assert!(serve(second, name.clone()).await.is_err());

    let response = tokio::task::spawn_blocking(move || {
        let mut pipe = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&name)
            .unwrap();
        write_frame(&mut pipe, &BrokerRequest::simple("health")).unwrap();
        let health: BrokerResponse = read_frame(&mut pipe).unwrap();
        write_frame(
            &mut pipe,
            &BrokerRequest::run(exit_with("SYNTH_CODE", "op-pipe", &["Code"])),
        )
        .unwrap();
        let run: BrokerResponse = read_frame(&mut pipe).unwrap();
        (health, run)
    })
    .await
    .unwrap();
    assert!(matches!(
        response.0,
        BrokerResponse::Ok(BrokerPayload::Health { .. })
    ));
    assert_eq!(response.1, exited(23));
    server.abort();
}
