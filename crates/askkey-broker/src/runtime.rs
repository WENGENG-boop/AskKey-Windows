//! `runtime.run`: authorize an explicit credential selection, then launch the
//! target with approved values in its environment.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use askkey_protocol::{
    inherited_variable_allowed, BrokerPayload, BrokerResponse, ErrorCode, RunRequest, RunResult,
};
use askkey_system::{
    build_command_line, duplicate_stream_handles, null_handle, resolve_executable, spawn_in_job,
    JobChild, SpawnSpec,
};

use crate::approvals::{executable_name, ApprovalSummary, Begin, Binding};
use crate::environment::lookup;
use crate::{Access, AccessEvent, AccessOutcome, Broker, ResolvedCredential};

struct Resolved {
    credentials: Vec<ResolvedCredential>,
    executable: PathBuf,
}

impl Resolved {
    fn binding(&self) -> Binding {
        self.credentials
            .iter()
            .map(|credential| (credential.id.clone(), credential.revision.clone()))
            .collect()
    }
}

fn ok(result: RunResult) -> BrokerResponse {
    BrokerResponse::Ok(BrokerPayload::Run(result))
}

/// Control characters would let a crafted argument disguise the prompt.
fn displayable(text: &str) -> String {
    text.chars()
        .flat_map(|c| {
            if c.is_control() {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}

fn working_directory(request: &RunRequest) -> Result<PathBuf, ErrorCode> {
    let directory = request
        .working_directory
        .as_deref()
        .map(PathBuf::from)
        .ok_or(ErrorCode::InvalidRequest)?;
    if !directory.is_absolute() || !directory.is_dir() {
        return Err(ErrorCode::InvalidRequest);
    }
    Ok(directory)
}

fn resolve_target(request: &RunRequest, directory: &Path) -> Result<PathBuf, ErrorCode> {
    let environment = &request.inherited_environment;
    resolve_executable(
        &request.command[0],
        directory,
        lookup(environment, "PATH"),
        lookup(environment, "PATHEXT"),
    )
    .map_err(|_| ErrorCode::TargetRejected)
}

impl Broker {
    fn resolve_credentials(
        &self,
        request: &RunRequest,
    ) -> Result<Vec<ResolvedCredential>, ErrorCode> {
        let mut credentials: Vec<ResolvedCredential> = Vec::new();
        for name in &request.credential_names {
            let credential = self
                .provider
                .resolve(name)?
                .ok_or(ErrorCode::RequestNotFound)?;
            if credential.expired {
                return Err(ErrorCode::RequestRejected);
            }
            if !credentials
                .iter()
                .any(|existing| existing.id == credential.id)
            {
                credentials.push(credential);
            }
        }
        let mut variables: Vec<String> = Vec::new();
        for variable in credentials
            .iter()
            .flat_map(|credential| &credential.environment_variables)
        {
            let key = variable.to_ascii_uppercase();
            if variables.contains(&key) {
                return Err(ErrorCode::InvalidRequest);
            }
            variables.push(key);
        }
        Ok(credentials)
    }

    fn resolve(&self, request: &RunRequest, directory: &Path) -> Result<Resolved, ErrorCode> {
        Ok(Resolved {
            credentials: self.resolve_credentials(request)?,
            executable: resolve_target(request, directory)?,
        })
    }

    fn summary(
        &self,
        request: &RunRequest,
        directory: &Path,
        resolved: &Resolved,
    ) -> ApprovalSummary {
        ApprovalSummary {
            request_id: String::new(),
            command_line: displayable(&build_command_line(&request.command)),
            executable: resolved.executable.to_string_lossy().into_owned(),
            working_directory: displayable(&directory.to_string_lossy()),
            credential_names: resolved
                .credentials
                .iter()
                .map(|credential| credential.name.clone())
                .collect(),
            environment_variables: resolved
                .credentials
                .iter()
                .flat_map(|credential| credential.environment_variables.clone())
                .collect(),
            caller_name: request.caller_name.as_deref().map(displayable),
            caller_purpose: request.caller_purpose.as_deref().map(displayable),
            created_at: 0,
            expires_at: 0,
        }
    }

    fn record(&self, request: &RunRequest, outcome: AccessOutcome) {
        self.provider.record(AccessEvent {
            credential_names: request.credential_names.clone(),
            executable: executable_name(&request.command[0]),
            caller_name: request.caller_name.clone(),
            outcome,
        });
    }

    pub(crate) async fn run<D: Future<Output = ()>>(
        self: &Arc<Self>,
        request: RunRequest,
        client_pid: u32,
        disconnected: D,
    ) -> BrokerResponse {
        if !request.is_bounded() || request.credential_names.is_empty() {
            return BrokerResponse::Error(ErrorCode::InvalidRequest);
        }
        if self.provider.agent_access_paused() {
            return BrokerResponse::Error(ErrorCode::AgentAccessPaused);
        }
        let directory = match working_directory(&request) {
            Ok(directory) => directory,
            Err(code) => return BrokerResponse::Error(code),
        };
        let operation = request.operation_id.clone();
        let begin = self.approvals.begin(&operation, &request.digest());
        if self.approvals.take_expired() {
            self.notify();
        }
        let begin = match begin {
            Ok(begin) => begin,
            Err(code) => return BrokerResponse::Error(code),
        };
        let approved = match begin {
            Begin::Pending(ticket) => {
                return ok(RunResult::ApprovalRequired {
                    operation_id: operation,
                    tickets: vec![ticket],
                })
            }
            Begin::Completed(code) => return ok(RunResult::Exited(code)),
            Begin::OutcomeUnknown => return ok(RunResult::OutcomeUnknown),
            Begin::Approved(binding) => Some(binding),
            Begin::New => {
                let resolved = match self.resolve(&request, &directory) {
                    Ok(resolved) => resolved,
                    Err(code) => {
                        self.approvals.abandon(&operation);
                        if code == ErrorCode::RequestNotFound {
                            self.record(&request, AccessOutcome::Unavailable);
                        }
                        return BrokerResponse::Error(code);
                    }
                };
                if resolved
                    .credentials
                    .iter()
                    .any(|credential| credential.access == Access::Ask)
                {
                    let summary = self.summary(&request, &directory, &resolved);
                    let binding = resolved.binding();
                    return match self
                        .approvals
                        .request_approval(&operation, summary, binding)
                    {
                        Ok(ticket) => {
                            self.notify();
                            ok(RunResult::ApprovalRequired {
                                operation_id: operation,
                                tickets: vec![ticket],
                            })
                        }
                        Err(code) => BrokerResponse::Error(code),
                    };
                }
                self.approvals.start(&operation);
                None
            }
        };
        match self
            .launch(
                &request,
                &directory,
                approved.as_ref(),
                client_pid,
                disconnected,
            )
            .await
        {
            Ok(response) => response,
            Err(code) => {
                // Nothing started: the operation can be retried from scratch.
                self.approvals.abandon(&operation);
                BrokerResponse::Error(code)
            }
        }
    }

    /// The final launch boundary: re-check everything the authorization
    /// depended on, then decrypt, deliver and create the process, all while
    /// holding the gate that pause and credential changes wait on.
    fn authorize_and_spawn(
        &self,
        request: &RunRequest,
        directory: &Path,
        approved: Option<&Binding>,
        client_pid: u32,
    ) -> Result<JobChild, ErrorCode> {
        let _gate = self
            .gate
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.provider.agent_access_paused() {
            return Err(ErrorCode::AgentAccessPaused);
        }
        let resolved = self.resolve(request, directory)?;
        match approved {
            // The approval covers exactly the credential revisions it showed;
            // an edit, permission change or re-creation needs a new one.
            Some(binding) => {
                if &resolved.binding() != binding {
                    return Err(ErrorCode::RequestRejected);
                }
            }
            None => {
                if resolved
                    .credentials
                    .iter()
                    .any(|credential| credential.access != Access::Allow)
                {
                    return Err(ErrorCode::RequestRejected);
                }
            }
        }

        let mut environment: Vec<(String, String)> = request
            .inherited_environment
            .iter()
            .filter(|(name, _)| inherited_variable_allowed(name))
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        let mut delivered = Vec::new();
        for credential in &resolved.credentials {
            delivered.extend(
                self.provider
                    .deliver(&credential.id, &credential.revision)?,
            );
        }
        // Delivered values replace inherited variables of the same name.
        environment.extend(
            delivered
                .iter()
                .map(|(name, value)| (name.clone(), value.to_string())),
        );
        drop(delivered);

        let streams = match request.streams {
            Some(streams) => duplicate_stream_handles(
                client_pid,
                &[streams.stdin, streams.stdout, streams.stderr],
            )
            .map_err(|_| ErrorCode::InvalidRequest)?,
            None => {
                let null = || null_handle().map_err(|_| ErrorCode::InternalError);
                vec![null()?, null()?, null()?]
            }
        };
        let child = spawn_in_job(&SpawnSpec {
            executable: &resolved.executable,
            arguments: &request.command,
            working_directory: directory,
            environment: &environment,
            stdin: &streams[0],
            stdout: &streams[1],
            stderr: &streams[2],
        });
        // Our copies of the values and streams are no longer needed.
        for (_, value) in environment.iter_mut() {
            zeroize::Zeroize::zeroize(value);
        }
        drop(streams);
        child.map_err(|_| ErrorCode::InternalError)
    }

    async fn launch<D: Future<Output = ()>>(
        self: &Arc<Self>,
        request: &RunRequest,
        directory: &Path,
        approved: Option<&Binding>,
        client_pid: u32,
        disconnected: D,
    ) -> Result<BrokerResponse, ErrorCode> {
        let child = Arc::new(self.authorize_and_spawn(request, directory, approved, client_pid)?);
        self.record(
            request,
            if approved.is_some() {
                AccessOutcome::Approved
            } else {
                AccessOutcome::Allowed
            },
        );

        let waiter = {
            let child = child.clone();
            tokio::task::spawn_blocking(move || child.wait())
        };
        tokio::pin!(waiter);
        let exit = tokio::select! {
            exit = &mut waiter => exit,
            () = disconnected => {
                // The helper went away (cancelled or killed): stop the target.
                child.terminate();
                waiter.await
            }
        };
        let operation = &request.operation_id;
        Ok(match exit {
            Ok(Ok(code)) => {
                self.approvals.complete(operation, code);
                ok(RunResult::Exited(code))
            }
            _ => {
                self.approvals.mark_unknown(operation);
                ok(RunResult::OutcomeUnknown)
            }
        })
    }
}
