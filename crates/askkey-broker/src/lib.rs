//! The Ask Key Broker.
//!
//! The Broker answers the helper over a private named pipe. It never returns
//! stored values: approved values go only into a target's environment. The
//! App supplies credentials through [`CredentialProvider`] and presents
//! approvals through [`ApprovalPresenter`]; this crate does not depend on the
//! vault.

mod approvals;
mod environment;
mod runtime;
mod server;

use std::sync::{Arc, RwLock};

pub use approvals::{ApprovalSummary, Approvals};
pub use askkey_protocol as protocol;
pub use server::{bind, serve, Listener};

use askkey_protocol::{CatalogItem, ErrorCode};
use zeroize::Zeroizing;

/// Agent access of a credential the agent can see.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Allow,
    Ask,
}

/// A visible credential matched by name. Hidden or missing credentials are
/// never returned, so they look the same to an agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedCredential {
    pub id: String,
    pub name: String,
    pub access: Access,
    pub expired: bool,
    /// Changes whenever the stored credential changes. An approval is bound
    /// to the revisions it showed.
    pub revision: String,
    /// Variables its delivered components are injected as.
    pub environment_variables: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessOutcome {
    Allowed,
    Approved,
    Denied,
    Cancelled,
    Expired,
    Unavailable,
    Failed,
}

/// One access event for the App's access records.
#[derive(Debug, Clone)]
pub struct AccessEvent {
    pub credential_names: Vec<String>,
    /// File name of the executable only.
    pub executable: String,
    pub caller_name: Option<String>,
    pub outcome: AccessOutcome,
}

pub trait CredentialProvider: Send + Sync + 'static {
    fn agent_access_paused(&self) -> bool;
    /// Metadata for every visible credential, and the visible group names.
    fn catalog(&self) -> Result<(Vec<CatalogItem>, Vec<String>), ErrorCode>;
    fn resolve(&self, name: &str) -> Result<Option<ResolvedCredential>, ErrorCode>;
    /// `(variable, value)` pairs of the delivered components of exactly this
    /// revision. Called only at the final launch boundary, after
    /// authorization.
    fn deliver(
        &self,
        credential_id: &str,
        revision: &str,
    ) -> Result<Vec<(String, Zeroizing<String>)>, ErrorCode>;
    fn record(&self, event: AccessEvent);
}

pub trait ApprovalPresenter: Send + Sync + 'static {
    /// Called when the set of pending approvals changes, with how many are
    /// now pending.
    fn pending_changed(&self, pending: usize);
}

/// Shared Broker state. Clone the `Arc` into the server and the App.
pub struct Broker {
    provider: Arc<dyn CredentialProvider>,
    presenter: Arc<dyn ApprovalPresenter>,
    approvals: Approvals,
    /// The final launch boundary holds this for reading from its last check
    /// through process creation. Pause, revocation and mutation hold it for
    /// writing, so one that wins the boundary prevents launch.
    gate: RwLock<()>,
}

impl Broker {
    pub fn new(
        provider: Arc<dyn CredentialProvider>,
        presenter: Arc<dyn ApprovalPresenter>,
    ) -> Arc<Self> {
        Arc::new(Self {
            provider,
            presenter,
            approvals: Approvals::default(),
            gate: RwLock::new(()),
        })
    }

    /// Runs a change that a launch must not interleave with: pausing agent
    /// access, or creating, editing, deleting or re-permissioning a
    /// credential. Waits for a launch in progress to create its process.
    pub fn exclusive<R>(&self, change: impl FnOnce() -> R) -> R {
        let _gate = self
            .gate
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        change()
    }

    /// Requests waiting for the person, newest first.
    pub fn pending_approvals(&self) -> Vec<ApprovalSummary> {
        self.approvals.pending()
    }

    /// Records the person's decision. The App authenticates the person before
    /// calling this with `approve = true`.
    pub fn decide(&self, request_id: &str, approve: bool) -> Result<(), ErrorCode> {
        let summary = self.approvals.decide(request_id, approve)?;
        if !approve {
            self.provider.record(AccessEvent {
                credential_names: summary.credential_names.clone(),
                executable: summary.executable_name(),
                caller_name: summary.caller_name.clone(),
                outcome: AccessOutcome::Denied,
            });
        }
        self.notify();
        Ok(())
    }

    /// Cancels every pending approval, for example when agent access pauses.
    pub fn cancel_pending(&self) {
        if self.approvals.cancel_all_pending() > 0 {
            self.notify();
        }
    }

    pub(crate) fn notify(&self) {
        self.presenter
            .pending_changed(self.approvals.pending().len());
    }
}

#[cfg(test)]
mod tests;
