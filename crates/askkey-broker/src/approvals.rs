//! Operation and approval bookkeeping.
//!
//! Each run operation is identified by the caller's operation ID and bound to
//! the digest of its whole request. An approval belongs to exactly one
//! operation, can be consumed once, and expires after five minutes. Only an
//! identical retry continues an operation; changed content is rejected.

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use askkey_protocol::{ApprovalTicket, ErrorCode, Limits, RequestState};
use rand::RngCore;
use serde::Serialize;

/// What the App shows the person. Derived inside the Broker from the same
/// request the approval binds; values are never part of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalSummary {
    #[serde(rename = "requestID")]
    pub request_id: String,
    pub command_line: String,
    pub executable: String,
    pub working_directory: String,
    pub credential_names: Vec<String>,
    pub environment_variables: Vec<String>,
    /// Self-declared and unverified.
    pub caller_name: Option<String>,
    /// Self-declared and unverified.
    pub caller_purpose: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
}

impl ApprovalSummary {
    /// File name of the executable, the only part kept in access records.
    pub fn executable_name(&self) -> String {
        executable_name(&self.executable)
    }
}

pub(crate) fn executable_name(command: &str) -> String {
    command
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(command)
        .to_owned()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    /// Credentials are being resolved; retries wait for the outcome.
    Resolving,
    AwaitingApproval,
    Approved,
    Running,
    Completed(i32),
    Refused(RequestState),
    Unknown,
}

impl Status {
    fn is_active(self) -> bool {
        matches!(
            self,
            Self::Resolving | Self::AwaitingApproval | Self::Approved | Self::Running
        )
    }

    fn request_state(self) -> RequestState {
        match self {
            Self::Resolving | Self::AwaitingApproval => RequestState::Pending,
            Self::Approved => RequestState::Approved,
            Self::Running => RequestState::Consumed,
            Self::Completed(_) => RequestState::Completed,
            Self::Refused(state) => state,
            Self::Unknown => RequestState::OutcomeUnknown,
        }
    }
}

struct Ticket {
    request_id: String,
    capability: String,
    deadline: Instant,
    summary: ApprovalSummary,
}

/// The credential IDs and revisions an approval showed, in request order.
pub(crate) type Binding = Vec<(String, String)>;

struct Operation {
    digest: String,
    status: Status,
    ticket: Option<Ticket>,
    binding: Binding,
}

#[derive(Default)]
struct State {
    operations: HashMap<String, Operation>,
    order: VecDeque<String>,
    /// A pending approval expired since the presenter last heard about it.
    expired_unreported: bool,
}

#[derive(Default)]
pub struct Approvals {
    state: Mutex<State>,
}

/// Where an operation stands when a run request arrives.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Begin {
    /// A new operation, now reserved; resolve credentials and then call
    /// [`Approvals::start`], [`Approvals::request_approval`] or
    /// [`Approvals::abandon`].
    New,
    /// The approval was consumed by this call; launch now, but only with the
    /// credential revisions it was bound to.
    Approved(Binding),
    /// Still waiting for the person.
    Pending(ApprovalTicket),
    /// Already finished during this App runtime; return its status without
    /// running again or replaying output.
    Completed(i32),
    OutcomeUnknown,
}

fn random_hex(bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut buffer);
    hex::encode(buffer)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

impl State {
    fn sweep(&mut self, now: Instant) {
        for operation in self.operations.values_mut() {
            let expired = operation
                .ticket
                .as_ref()
                .is_some_and(|ticket| ticket.deadline <= now);
            if expired
                && matches!(
                    operation.status,
                    Status::AwaitingApproval | Status::Approved
                )
            {
                if operation.status == Status::AwaitingApproval {
                    self.expired_unreported = true;
                }
                operation.status = Status::Refused(RequestState::Expired);
            }
        }
    }

    fn reserve(&mut self, operation_id: &str, digest: &str) -> Result<(), ErrorCode> {
        while self.operations.len() >= Limits::MAX_RETAINED_OPERATIONS {
            let position = self
                .order
                .iter()
                .position(|id| {
                    self.operations
                        .get(id)
                        .is_none_or(|operation| !operation.status.is_active())
                })
                .ok_or(ErrorCode::ResourceExhausted)?;
            let evicted = self.order.remove(position).expect("position is in range");
            self.operations.remove(&evicted);
        }
        self.operations.insert(
            operation_id.to_owned(),
            Operation {
                digest: digest.to_owned(),
                status: Status::Resolving,
                ticket: None,
                binding: Vec::new(),
            },
        );
        self.order.push_back(operation_id.to_owned());
        Ok(())
    }

    fn by_ticket(
        &mut self,
        request_id: &str,
        capability: &str,
    ) -> Result<&mut Operation, ErrorCode> {
        self.operations
            .values_mut()
            .find(|operation| {
                operation.ticket.as_ref().is_some_and(|ticket| {
                    ticket.request_id == request_id
                        && constant_time_eq(&ticket.capability, capability)
                })
            })
            // A wrong capability looks exactly like an unknown request.
            .ok_or(ErrorCode::RequestNotFound)
    }

    fn set(&mut self, operation_id: &str, status: Status) {
        if let Some(operation) = self.operations.get_mut(operation_id) {
            operation.status = status;
        }
    }
}

impl Approvals {
    fn lock(&self) -> MutexGuard<'_, State> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.sweep(Instant::now());
        state
    }

    pub(crate) fn begin(&self, operation_id: &str, digest: &str) -> Result<Begin, ErrorCode> {
        let mut state = self.lock();
        let Some(operation) = state.operations.get_mut(operation_id) else {
            state.reserve(operation_id, digest)?;
            return Ok(Begin::New);
        };
        if operation.digest != digest {
            return Err(ErrorCode::RequestRejected);
        }
        match operation.status {
            Status::Approved => {
                operation.status = Status::Running;
                Ok(Begin::Approved(operation.binding.clone()))
            }
            Status::AwaitingApproval => {
                let ticket = operation
                    .ticket
                    .as_ref()
                    .expect("awaiting operations have a ticket");
                Ok(Begin::Pending(ApprovalTicket {
                    request_id: ticket.request_id.clone(),
                    capability: ticket.capability.clone(),
                }))
            }
            Status::Completed(code) => Ok(Begin::Completed(code)),
            Status::Unknown => Ok(Begin::OutcomeUnknown),
            Status::Resolving | Status::Running | Status::Refused(_) => {
                Err(ErrorCode::RequestRejected)
            }
        }
    }

    /// The reserved operation needs no approval and starts now.
    pub(crate) fn start(&self, operation_id: &str) {
        self.lock().set(operation_id, Status::Running);
    }

    /// Creates the approval ticket for a reserved operation.
    pub(crate) fn request_approval(
        &self,
        operation_id: &str,
        mut summary: ApprovalSummary,
        binding: Binding,
    ) -> Result<ApprovalTicket, ErrorCode> {
        let mut state = self.lock();
        let pending = state
            .operations
            .values()
            .filter(|operation| operation.status == Status::AwaitingApproval)
            .count();
        if pending >= Limits::MAX_PENDING_APPROVALS {
            state.operations.remove(operation_id);
            state.order.retain(|id| id != operation_id);
            return Err(ErrorCode::ResourceExhausted);
        }
        let ticket = ApprovalTicket {
            request_id: random_hex(16),
            capability: random_hex(32),
        };
        let lifetime: Duration = Limits::APPROVAL_LIFETIME;
        summary.request_id = ticket.request_id.clone();
        summary.created_at = unix_now();
        summary.expires_at = summary.created_at + lifetime.as_secs();
        let operation = state
            .operations
            .get_mut(operation_id)
            .ok_or(ErrorCode::InternalError)?;
        operation.status = Status::AwaitingApproval;
        operation.binding = binding;
        operation.ticket = Some(Ticket {
            request_id: ticket.request_id.clone(),
            capability: ticket.capability.clone(),
            deadline: Instant::now() + lifetime,
            summary,
        });
        Ok(ticket)
    }

    /// The operation never started; a retry with the same ID starts over.
    pub(crate) fn abandon(&self, operation_id: &str) {
        let mut state = self.lock();
        state.operations.remove(operation_id);
        state.order.retain(|id| id != operation_id);
    }

    pub(crate) fn complete(&self, operation_id: &str, code: i32) {
        self.lock().set(operation_id, Status::Completed(code));
    }

    pub(crate) fn mark_unknown(&self, operation_id: &str) {
        self.lock().set(operation_id, Status::Unknown);
    }

    pub(crate) fn status(
        &self,
        request_id: &str,
        capability: &str,
    ) -> Result<RequestState, ErrorCode> {
        Ok(self
            .lock()
            .by_ticket(request_id, capability)?
            .status
            .request_state())
    }

    pub(crate) fn cancel(
        &self,
        request_id: &str,
        capability: &str,
    ) -> Result<RequestState, ErrorCode> {
        let mut state = self.lock();
        let operation = state.by_ticket(request_id, capability)?;
        if matches!(
            operation.status,
            Status::AwaitingApproval | Status::Approved
        ) {
            operation.status = Status::Refused(RequestState::Cancelled);
        }
        Ok(operation.status.request_state())
    }

    pub(crate) fn decide(
        &self,
        request_id: &str,
        approve: bool,
    ) -> Result<ApprovalSummary, ErrorCode> {
        let mut state = self.lock();
        let operation = state
            .operations
            .values_mut()
            .find(|operation| {
                operation
                    .ticket
                    .as_ref()
                    .is_some_and(|ticket| ticket.request_id == request_id)
            })
            .ok_or(ErrorCode::RequestNotFound)?;
        if operation.status != Status::AwaitingApproval {
            return Err(ErrorCode::RequestRejected);
        }
        operation.status = if approve {
            Status::Approved
        } else {
            Status::Refused(RequestState::Denied)
        };
        Ok(operation
            .ticket
            .as_ref()
            .expect("awaiting operations have a ticket")
            .summary
            .clone())
    }

    pub(crate) fn pending(&self) -> Vec<ApprovalSummary> {
        let state = self.lock();
        let mut summaries: Vec<ApprovalSummary> = state
            .operations
            .values()
            .filter(|operation| operation.status == Status::AwaitingApproval)
            .filter_map(|operation| {
                operation
                    .ticket
                    .as_ref()
                    .map(|ticket| ticket.summary.clone())
            })
            .collect();
        summaries.sort_by_key(|summary| std::cmp::Reverse(summary.created_at));
        summaries
    }

    /// Whether a pending approval expired since the last call.
    pub(crate) fn take_expired(&self) -> bool {
        std::mem::take(&mut self.lock().expired_unreported)
    }

    pub(crate) fn cancel_all_pending(&self) -> usize {
        let mut state = self.lock();
        let mut cancelled = 0;
        for operation in state.operations.values_mut() {
            if matches!(
                operation.status,
                Status::AwaitingApproval | Status::Approved
            ) {
                operation.status = Status::Refused(RequestState::Cancelled);
                cancelled += 1;
            }
        }
        cancelled
    }

    #[cfg(test)]
    pub(crate) fn expire_all_for_test(&self) {
        let mut state = self.state.lock().unwrap();
        for operation in state.operations.values_mut() {
            if let Some(ticket) = operation.ticket.as_mut() {
                ticket.deadline = Instant::now() - Duration::from_secs(1);
            }
        }
    }
}

#[cfg(test)]
#[path = "approvals_tests.rs"]
mod tests;
