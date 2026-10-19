//! Connects the Broker to the vault.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use askkey_broker::{Access, AccessEvent, AccessOutcome, CredentialProvider, ResolvedCredential};
use askkey_protocol::{CatalogComponent, CatalogItem, Delivery, ErrorCode};
use askkey_vault::{AccessDecision, AccessRecord, Credential, Permission, Vault};
use zeroize::Zeroizing;

pub const PAUSED_SETTING: &str = "agent_access_paused";

pub struct VaultProvider {
    pub vault: Arc<Vault>,
    pub paused: AtomicBool,
}

impl VaultProvider {
    pub fn new(vault: Arc<Vault>) -> Self {
        let paused = vault.setting(PAUSED_SETTING).ok().flatten().as_deref() == Some("true");
        Self {
            vault,
            paused: AtomicBool::new(paused),
        }
    }

    pub fn set_paused(&self, paused: bool) -> askkey_vault::Result<()> {
        self.vault
            .set_setting(PAUSED_SETTING, if paused { "true" } else { "false" })?;
        self.paused.store(paused, Ordering::SeqCst);
        Ok(())
    }
}

fn catalog_item(credential: &Credential, now: i64) -> CatalogItem {
    CatalogItem {
        credential_id: credential.id.clone(),
        name: credential.name.clone(),
        usage_instructions: credential.usage_instructions.clone(),
        group: credential.group.clone(),
        components: credential
            .components
            .iter()
            .map(|component| CatalogComponent {
                name: component.name.clone(),
                delivery: match &component.environment_variable {
                    Some(variable) => Delivery::Environment {
                        environment_variable: variable.clone(),
                    },
                    None => Delivery::None,
                },
            })
            .collect(),
        expired: credential.is_expired(now),
    }
}

/// Storage problems surface as internal errors, never as details.
fn internal<E>(_: E) -> ErrorCode {
    ErrorCode::InternalError
}

impl CredentialProvider for VaultProvider {
    fn agent_access_paused(&self) -> bool {
        self.paused.load(Ordering::SeqCst)
    }

    fn catalog(&self) -> Result<(Vec<CatalogItem>, Vec<String>), ErrorCode> {
        let now = askkey_vault::now();
        let visible: Vec<Credential> = self
            .vault
            .list()
            .map_err(internal)?
            .into_iter()
            .filter(|credential| credential.permission != Permission::Hidden)
            .collect();
        let groups: BTreeSet<String> = visible
            .iter()
            .filter_map(|credential| credential.group.clone())
            .collect();
        Ok((
            visible
                .iter()
                .map(|credential| catalog_item(credential, now))
                .collect(),
            groups.into_iter().collect(),
        ))
    }

    fn resolve(&self, name: &str) -> Result<Option<ResolvedCredential>, ErrorCode> {
        let Ok(found) = self.vault.find_by_name(name) else {
            // An invalid name cannot match anything.
            return Ok(None);
        };
        Ok(found.and_then(|credential| {
            let access = match credential.permission {
                Permission::Allow => Access::Allow,
                Permission::Ask => Access::Ask,
                Permission::Hidden => return None,
            };
            Some(ResolvedCredential {
                id: credential.id.clone(),
                name: credential.name.clone(),
                access,
                expired: credential.is_expired(askkey_vault::now()),
                revision: credential.revision.clone(),
                environment_variables: credential
                    .components
                    .iter()
                    .filter_map(|component| component.environment_variable.clone())
                    .collect(),
            })
        }))
    }

    fn deliver(
        &self,
        credential_id: &str,
        revision: &str,
    ) -> Result<Vec<(String, Zeroizing<String>)>, ErrorCode> {
        let credential = self.vault.get(credential_id).map_err(internal)?;
        if credential.revision != revision {
            return Err(ErrorCode::RequestRejected);
        }
        let values = self.vault.values(credential_id).map_err(internal)?;
        Ok(credential
            .components
            .iter()
            .zip(values)
            .filter_map(|(component, value)| {
                component
                    .environment_variable
                    .clone()
                    .map(|variable| (variable, value))
            })
            .collect())
    }

    fn record(&self, event: AccessEvent) {
        let decision = match event.outcome {
            AccessOutcome::Allowed => AccessDecision::Allowed,
            AccessOutcome::Approved => AccessDecision::Approved,
            AccessOutcome::Denied => AccessDecision::Denied,
            AccessOutcome::Cancelled => AccessDecision::Cancelled,
            AccessOutcome::Expired => AccessDecision::Expired,
            AccessOutcome::Unavailable => AccessDecision::Unavailable,
            AccessOutcome::Failed => AccessDecision::Failed,
        };
        let _ = self.vault.record_access(AccessRecord {
            at: 0,
            credential_names: event.credential_names,
            executable: event.executable,
            caller_name: event.caller_name,
            decision,
        });
    }
}
