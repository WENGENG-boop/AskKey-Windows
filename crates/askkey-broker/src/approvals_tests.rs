use super::*;

fn summary() -> ApprovalSummary {
    ApprovalSummary {
        request_id: String::new(),
        command_line: "git.exe push".into(),
        executable: r"C:\Program Files\Git\cmd\git.exe".into(),
        working_directory: r"C:\work".into(),
        credential_names: vec!["GitHub".into()],
        environment_variables: vec!["GH_TOKEN".into()],
        caller_name: None,
        caller_purpose: None,
        created_at: 0,
        expires_at: 0,
    }
}

fn binding() -> Binding {
    vec![("id-1".into(), "rev-1".into())]
}

fn pending(approvals: &Approvals, operation: &str) -> ApprovalTicket {
    assert_eq!(approvals.begin(operation, "digest").unwrap(), Begin::New);
    approvals
        .request_approval(operation, summary(), binding())
        .unwrap()
}

#[test]
fn approval_is_consumed_once() {
    let approvals = Approvals::default();
    let ticket = pending(&approvals, "op");
    assert_eq!(
        approvals.begin("op", "digest").unwrap(),
        Begin::Pending(ticket.clone())
    );
    approvals.decide(&ticket.request_id, true).unwrap();
    assert_eq!(
        approvals
            .status(&ticket.request_id, &ticket.capability)
            .unwrap(),
        RequestState::Approved
    );
    assert_eq!(
        approvals.begin("op", "digest").unwrap(),
        Begin::Approved(binding())
    );
    // A concurrent identical retry cannot consume it again.
    assert_eq!(
        approvals.begin("op", "digest"),
        Err(ErrorCode::RequestRejected)
    );
    approvals.complete("op", 7);
    assert_eq!(
        approvals.begin("op", "digest").unwrap(),
        Begin::Completed(7)
    );
}

#[test]
fn changed_payload_is_rejected() {
    let approvals = Approvals::default();
    let ticket = pending(&approvals, "op");
    approvals.decide(&ticket.request_id, true).unwrap();
    assert_eq!(
        approvals.begin("op", "other-digest"),
        Err(ErrorCode::RequestRejected)
    );
}

#[test]
fn denial_and_cancellation_stop_the_operation() {
    let approvals = Approvals::default();
    let denied = pending(&approvals, "denied");
    approvals.decide(&denied.request_id, false).unwrap();
    assert_eq!(
        approvals.begin("denied", "digest"),
        Err(ErrorCode::RequestRejected)
    );
    assert_eq!(
        approvals
            .status(&denied.request_id, &denied.capability)
            .unwrap(),
        RequestState::Denied
    );

    let cancelled = pending(&approvals, "cancelled");
    assert_eq!(
        approvals
            .cancel(&cancelled.request_id, &cancelled.capability)
            .unwrap(),
        RequestState::Cancelled
    );
    assert!(approvals.decide(&cancelled.request_id, true).is_err());
}

#[test]
fn wrong_capability_looks_unknown() {
    let approvals = Approvals::default();
    let ticket = pending(&approvals, "op");
    assert_eq!(
        approvals.status(&ticket.request_id, "guess"),
        Err(ErrorCode::RequestNotFound)
    );
    assert_eq!(
        approvals.cancel(&ticket.request_id, "guess"),
        Err(ErrorCode::RequestNotFound)
    );
}

#[test]
fn expiry_of_a_pending_approval_is_reported_once() {
    let approvals = Approvals::default();
    pending(&approvals, "op");
    assert!(!approvals.take_expired());
    approvals.expire_all_for_test();
    assert!(approvals.take_expired());
    assert!(!approvals.take_expired());
}

#[test]
fn approvals_expire() {
    let approvals = Approvals::default();
    let ticket = pending(&approvals, "op");
    approvals.decide(&ticket.request_id, true).unwrap();
    approvals.expire_all_for_test();
    assert_eq!(
        approvals
            .status(&ticket.request_id, &ticket.capability)
            .unwrap(),
        RequestState::Expired
    );
    assert_eq!(
        approvals.begin("op", "digest"),
        Err(ErrorCode::RequestRejected)
    );
    assert!(approvals.pending().is_empty());
}

#[test]
fn abandoned_operations_can_start_over() {
    let approvals = Approvals::default();
    assert_eq!(approvals.begin("op", "digest").unwrap(), Begin::New);
    assert_eq!(
        approvals.begin("op", "digest"),
        Err(ErrorCode::RequestRejected)
    );
    approvals.abandon("op");
    assert_eq!(approvals.begin("op", "digest").unwrap(), Begin::New);
}

#[test]
fn pause_cancels_pending() {
    let approvals = Approvals::default();
    let ticket = pending(&approvals, "op");
    assert_eq!(approvals.cancel_all_pending(), 1);
    assert_eq!(
        approvals
            .status(&ticket.request_id, &ticket.capability)
            .unwrap(),
        RequestState::Cancelled
    );
}

#[test]
fn retention_keeps_active_operations() {
    let approvals = Approvals::default();
    for index in 0..Limits::MAX_RETAINED_OPERATIONS {
        let id = format!("op-{index}");
        assert_eq!(approvals.begin(&id, "d").unwrap(), Begin::New);
        approvals.start(&id);
        approvals.complete(&id, 0);
    }
    assert_eq!(approvals.begin("fresh", "d").unwrap(), Begin::New);
    // The oldest completed operation was evicted.
    assert_eq!(approvals.begin("op-0", "d").unwrap(), Begin::New);
}
