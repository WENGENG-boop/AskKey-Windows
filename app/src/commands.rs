//! Commands the management window calls. Errors are short codes the UI
//! translates; they never contain stored values.

use std::time::{Duration, Instant};

use askkey_broker::ApprovalSummary;
use askkey_vault::{
    AccessRecord, Credential, CredentialUpdate, NewCredential, Permission, VaultError,
};
use serde::Serialize;
use tauri::{Emitter, State, WebviewWindow};
use zeroize::Zeroizing;

use crate::{auth, AppState, DEVELOPMENT};

/// Management locks after five idle minutes.
const SESSION_IDLE: Duration = Duration::from_secs(5 * 60);
const APPROVAL_AUTH_SETTING: &str = "approval_requires_auth";

type CommandResult<T> = Result<T, String>;

fn vault_error(error: VaultError) -> String {
    match error {
        VaultError::Invalid(message) => format!("invalid:{message}"),
        VaultError::NameTaken => "name_taken".into(),
        VaultError::NotFound => "not_found".into(),
        VaultError::Authentication => "integrity_failure".into(),
        _ => "storage_failure".into(),
    }
}

fn window_handle(window: &WebviewWindow) -> isize {
    window.hwnd().map(|handle| handle.0 as isize).unwrap_or(0)
}

/// Asks Windows Hello on a worker thread.
async fn authenticate(window: &WebviewWindow, message: &str) -> CommandResult<()> {
    let handle = window_handle(window);
    let message = message.to_owned();
    tauri::async_runtime::spawn_blocking(move || auth::verify(handle, &message))
        .await
        .map_err(|_| "authentication_failed".to_string())?
        .map_err(|error| error.to_string())
}

fn require_session(state: &AppState) -> CommandResult<()> {
    let mut session = state.session.lock().unwrap();
    match *session {
        Some(until) if until > Instant::now() => {
            *session = Some(Instant::now() + SESSION_IDLE);
            Ok(())
        }
        _ => {
            *session = None;
            Err("locked".into())
        }
    }
}

pub fn require_unlocked(state: &AppState) -> CommandResult<()> {
    require_session(state)
}

fn approval_requires_auth(state: &AppState) -> bool {
    state
        .vault
        .setting(APPROVAL_AUTH_SETTING)
        .ok()
        .flatten()
        .as_deref()
        != Some("false")
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfo {
    version: &'static str,
    development: bool,
    helper_path: String,
    pipe_name: String,
    data_directory: String,
    agent_access_paused: bool,
    approval_requires_auth: bool,
}

#[tauri::command]
pub fn app_info(state: State<'_, AppState>) -> AppInfo {
    AppInfo {
        version: env!("CARGO_PKG_VERSION"),
        development: DEVELOPMENT,
        helper_path: crate::clients::helper_path().to_string_lossy().into_owned(),
        pipe_name: state.pipe_name.clone(),
        data_directory: state.vault.directory().to_string_lossy().into_owned(),
        agent_access_paused: state
            .provider
            .paused
            .load(std::sync::atomic::Ordering::SeqCst),
        approval_requires_auth: approval_requires_auth(&state),
    }
}

#[tauri::command]
pub fn session_status(state: State<'_, AppState>) -> bool {
    require_session(&state).is_ok()
}

#[tauri::command]
pub async fn unlock(window: WebviewWindow, state: State<'_, AppState>) -> CommandResult<()> {
    authenticate(&window, "Unlock Ask Key to manage credentials").await?;
    *state.session.lock().unwrap() = Some(Instant::now() + SESSION_IDLE);
    Ok(())
}

#[tauri::command]
pub fn lock(state: State<'_, AppState>) {
    *state.session.lock().unwrap() = None;
}

#[tauri::command]
pub fn list_credentials(state: State<'_, AppState>) -> CommandResult<Vec<Credential>> {
    require_session(&state)?;
    state.vault.list().map_err(vault_error)
}

/// Allow lets agents use a credential without asking, so setting it needs
/// proof that the person is present, also on creation.
async fn confirm_allow(window: &WebviewWindow, name: &str) -> CommandResult<()> {
    authenticate(window, &format!("Let agents use \"{name}\" without asking")).await
}

#[tauri::command]
pub async fn create_credential(
    window: WebviewWindow,
    state: State<'_, AppState>,
    input: NewCredential,
) -> CommandResult<Credential> {
    require_session(&state)?;
    if input.permission == Permission::Allow {
        confirm_allow(&window, input.name.trim()).await?;
    }
    state
        .broker
        .exclusive(|| state.vault.create(input))
        .map_err(vault_error)
}

#[tauri::command]
pub fn update_credential(
    state: State<'_, AppState>,
    id: String,
    input: CredentialUpdate,
) -> CommandResult<Credential> {
    require_session(&state)?;
    state
        .broker
        .exclusive(|| state.vault.update(&id, input))
        .map_err(vault_error)
}

#[tauri::command]
pub async fn delete_credential(
    window: WebviewWindow,
    state: State<'_, AppState>,
    id: String,
) -> CommandResult<()> {
    require_session(&state)?;
    let name = state.vault.get(&id).map_err(vault_error)?.name;
    authenticate(&window, &format!("Delete \"{name}\" from Ask Key")).await?;
    state
        .broker
        .exclusive(|| state.vault.delete(&id))
        .map_err(vault_error)
}

#[tauri::command]
pub async fn set_permission(
    window: WebviewWindow,
    state: State<'_, AppState>,
    id: String,
    permission: Permission,
) -> CommandResult<Credential> {
    require_session(&state)?;
    if permission == Permission::Allow {
        let name = state.vault.get(&id).map_err(vault_error)?.name;
        confirm_allow(&window, &name).await?;
    }
    state
        .broker
        .exclusive(|| state.vault.set_permission(&id, permission))
        .map_err(vault_error)
}

#[tauri::command]
pub async fn reveal_values(
    window: WebviewWindow,
    state: State<'_, AppState>,
    id: String,
) -> CommandResult<Vec<String>> {
    require_session(&state)?;
    let name = state.vault.get(&id).map_err(vault_error)?.name;
    authenticate(&window, &format!("Show the values of \"{name}\"")).await?;
    let values: Vec<Zeroizing<String>> = state.vault.values(&id).map_err(vault_error)?;
    Ok(values.iter().map(|value| value.to_string()).collect())
}

/// Pending approvals are shown without unlocking management.
#[tauri::command]
pub fn pending_approvals(state: State<'_, AppState>) -> Vec<ApprovalSummary> {
    state.broker.pending_approvals()
}

#[tauri::command]
pub async fn decide(
    window: WebviewWindow,
    state: State<'_, AppState>,
    request_id: String,
    approve: bool,
) -> CommandResult<()> {
    if approve && approval_requires_auth(&state) {
        let summary = state
            .broker
            .pending_approvals()
            .into_iter()
            .find(|summary| summary.request_id == request_id)
            .ok_or("not_found")?;
        authenticate(
            &window,
            &format!(
                "Approve {} using {}",
                summary.executable_name(),
                summary.credential_names.join(", ")
            ),
        )
        .await?;
    }
    state
        .broker
        .decide(&request_id, approve)
        .map_err(|code| format!("{code:?}"))
}

#[tauri::command]
pub async fn set_agent_access_paused(
    window: WebviewWindow,
    state: State<'_, AppState>,
    paused: bool,
) -> CommandResult<()> {
    if !paused {
        authenticate(&window, "Resume agent access to Ask Key").await?;
    }
    state
        .broker
        .exclusive(|| state.provider.set_paused(paused))
        .map_err(vault_error)?;
    if paused {
        state.broker.cancel_pending();
    }
    let _ = window.emit("settings-changed", ());
    Ok(())
}

#[tauri::command]
pub async fn set_approval_requires_auth(
    window: WebviewWindow,
    state: State<'_, AppState>,
    required: bool,
) -> CommandResult<()> {
    require_session(&state)?;
    if !required {
        authenticate(&window, "Approve agent requests without Windows Hello").await?;
    }
    state
        .vault
        .set_setting(
            APPROVAL_AUTH_SETTING,
            if required { "true" } else { "false" },
        )
        .map_err(vault_error)
}

#[tauri::command]
pub fn access_records(state: State<'_, AppState>) -> CommandResult<Vec<AccessRecord>> {
    require_session(&state)?;
    state.vault.access_records(200).map_err(vault_error)
}
