// No console window for the release App.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod auth;
mod clients;
mod commands;
mod provider;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use askkey_broker::{ApprovalPresenter, Broker};
use askkey_vault::Vault;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Emitter, Manager, UserAttentionType, WindowEvent};

use provider::VaultProvider;

pub const DEVELOPMENT: bool = cfg!(debug_assertions);

pub struct AppState {
    pub vault: Arc<Vault>,
    pub provider: Arc<VaultProvider>,
    pub broker: Arc<Broker>,
    /// Management is unlocked until this instant.
    pub session: Mutex<Option<std::time::Instant>>,
    pub pipe_name: String,
}

/// Brings the App forward when an agent asks for approval.
struct WindowPresenter {
    app: AppHandle,
    previous: AtomicUsize,
}

impl ApprovalPresenter for WindowPresenter {
    fn pending_changed(&self, pending: usize) {
        let _ = self.app.emit("approvals-changed", pending);
        let previous = self.previous.swap(pending, Ordering::SeqCst);
        if pending > previous {
            if let Some(window) = self.app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.unminimize();
                let _ = window.set_focus();
                let _ = window.request_user_attention(Some(UserAttentionType::Critical));
            }
        }
    }
}

fn fatal(message: &str) -> ! {
    use windows::core::HSTRING;
    use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK};
    unsafe {
        MessageBoxW(
            None,
            &HSTRING::from(message),
            &HSTRING::from("Ask Key"),
            MB_OK | MB_ICONERROR,
        );
    }
    std::process::exit(1);
}

fn show_main(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

fn main() {
    let directory = askkey_vault::default_directory(DEVELOPMENT);
    let vault = match Vault::open(&directory, askkey_vault::key_namespace(DEVELOPMENT)) {
        Ok(vault) => Arc::new(vault),
        // Fail closed: never replace a library that cannot be opened.
        Err(error) => fatal(&format!(
            "Ask Key cannot open its library in {}.\n\n{error}",
            directory.display()
        )),
    };
    let sid = askkey_system::current_user_sid().unwrap_or_else(|error| fatal(&error.to_string()));
    let pipe_name = askkey_protocol::pipe_name(&sid, DEVELOPMENT);

    tauri::Builder::default()
        .setup(move |app| {
            let provider = Arc::new(VaultProvider::new(vault.clone()));
            let presenter = Arc::new(WindowPresenter {
                app: app.handle().clone(),
                previous: AtomicUsize::new(0),
            });
            let broker = Broker::new(provider.clone(), presenter);
            let listener = tauri::async_runtime::block_on(async {
                askkey_broker::bind(&pipe_name)
            })
            .unwrap_or_else(|_| {
                fatal("Ask Key is already running. Look for its icon in the notification area.")
            });
            let serving = broker.clone();
            tauri::async_runtime::spawn(async move {
                if let Err(error) = listener.serve(serving).await {
                    eprintln!("Ask Key Broker stopped: {error}");
                }
            });
            app.manage(AppState {
                vault,
                provider,
                broker,
                session: Mutex::new(None),
                pipe_name,
            });

            let open = MenuItem::with_id(app, "open", "Open Ask Key", true, None::<&str>)?;
            let pause = MenuItem::with_id(app, "pause", "Pause agent access", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit Ask Key", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&open, &pause, &quit])?;
            TrayIconBuilder::with_id("askkey")
                .icon(app.default_window_icon().cloned().expect("bundled icon"))
                .tooltip("Ask Key")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id().as_ref() {
                    "open" => show_main(app),
                    "pause" => {
                        let state = app.state::<AppState>();
                        let paused = state.broker.exclusive(|| state.provider.set_paused(true));
                        if paused.is_ok() {
                            state.broker.cancel_pending();
                            let _ = app.emit("settings-changed", ());
                        }
                    }
                    "quit" => app.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let tauri::tray::TrayIconEvent::Click {
                        button: tauri::tray::MouseButton::Left,
                        ..
                    } = event
                    {
                        show_main(tray.app_handle());
                    }
                })
                .build(app)?;
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the window keeps the Broker running in the tray.
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
                if let Some(state) = window.try_state::<AppState>() {
                    *state.session.lock().unwrap() = None;
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::app_info,
            commands::session_status,
            commands::unlock,
            commands::lock,
            commands::list_credentials,
            commands::create_credential,
            commands::update_credential,
            commands::delete_credential,
            commands::set_permission,
            commands::reveal_values,
            commands::pending_approvals,
            commands::decide,
            commands::set_agent_access_paused,
            commands::set_approval_requires_auth,
            commands::access_records,
            clients::client_status,
            clients::connect_client,
        ])
        .run(tauri::generate_context!())
        .unwrap_or_else(|error| fatal(&format!("Ask Key failed to start: {error}")));
}
