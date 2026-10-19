# ADR 0001: Windows edition

## Status

Accepted for v0.1.

## Context

[AskKey](https://github.com/sudoHG/AskKey) is a macOS App. Its security model depends on macOS facilities with no direct Windows equivalent: a keychain item whose ACL admits only the App binary, LocalAuthentication, a Unix-domain socket with descriptor passing, POSIX process groups, and code-signature checks on the App bundle. Swift on Windows cannot reuse those modules, and its UI and SQLite support is weak, so this edition is a reimplementation in Rust with Tauri 2.

The product rules do not change by platform. AskKey's ADR 0001 (domain and storage), 0002 (Broker and bound approvals), 0003 (explicit delivery), 0008 (approvals show what will run) and 0010 (agent metadata writes) bind this edition. This ADR records how they are realised on Windows and where Windows forces a weaker or different guarantee.

## Decision

### Shape

- Six crates mirror AskKey's module boundaries (see `AGENTS.md`). All Win32 `unsafe` lives in `askkey-system`. The helper depends only on `askkey-protocol` and `askkey-system`, so it cannot open the vault.
- Broker protocol version 1, its method names (`health`, `version`, `catalog`, `request.status`, `request.cancel`, `runtime.run`), error codes and limits are kept. One error code is added: `target_rejected`. The JSON envelope is Rust's (`{"ok": …}` / `{"error": "…"}`), not Swift's synthesized enum encoding; the helper and App ship together, so wire compatibility with the macOS helper is not a goal.
- The storage schema is this edition's own (`askkey-windows-0001-baseline`). Libraries are not moved between platforms.

### Platform mapping

| macOS | Windows |
| --- | --- |
| `/Applications/Ask Key.app`, `Contents/Helpers/askkey` | `Ask Key.exe` and `askkey.exe` in the same directory, installed per machine under `%ProgramFiles%\Ask Key` so standard users cannot replace the helper |
| `~/Library/Application Support/AskKey` (`0700`/`0600`) | `%LOCALAPPDATA%\AskKey` (non-roaming); `dev` subdirectory for development. Protected DACL granting only the current user |
| Keychain item `com.sudohg.askkey.vault` with App-only ACL | 32-byte vault key wrapped with DPAPI (current user), entropy `com.sudohg.askkey.vault` (`.dev` for development) |
| LocalAuthentication (Touch ID or password) | Windows Hello `UserConsentVerifier` (face, fingerprint or PIN) over the App window |
| Unix socket | Named pipe `\\.\pipe\askkey-broker-<SID>` (`askkey-broker-dev-<SID>`), DACL current user only, `PIPE_REJECT_REMOTE_CLIENTS`, `FILE_FLAG_FIRST_PIPE_INSTANCE` |
| Descriptor passing | The helper creates anonymous pipes and sends their handle values; the Broker duplicates them from the helper's process (PID from `GetNamedPipeClientProcessId`) and accepts only file, pipe and character handles |
| Process group, signals | Job object with kill-on-close; the target starts suspended, joins the job, then resumes. Disconnecting the helper terminates the job |
| Code signature check of the bundle | The helper requires the pipe server's image to be `Ask Key.exe` (or the development `askkey-app.exe`) in the helper's own directory. Authenticode verification is added once releases are signed |

### Key protection

DPAPI can be unwrapped by any process running as the same user. macOS's App-only keychain ACL has no equivalent for an unpackaged desktop App. Therefore at-rest protection against same-user malware is weaker than on macOS. This is stated in the App's Settings and in `SECURITY.md`. The approval model still limits what agents receive. A stronger mode that requires Windows Hello to unwrap the key at App start is future work.

### Runtime delivery

- Targets must resolve to an `.exe` or `.com`. `.bat` and `.cmd` targets are refused (`target_rejected`), because `cmd.exe` parsing defeats argument quoting (the CVE-2024-24576 class). A user can still name `cmd.exe` explicitly. Bare names are searched only on the caller's `PATH`, never in the working directory.
- Arguments are quoted for `CommandLineToArgvW`. The target gets no console window (`CREATE_NO_WINDOW`), and inherits only its three stream handles (`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`).
- Environment names are case-insensitive. The inherited-environment allowlist (PATH, PATHEXT, SystemRoot, profile and temp directories, locale variables and a few others) is applied in the helper and again in the Broker. Delivered variables replace inherited ones, and two delivered variables that differ only in case are rejected.
- On the CLI route the helper copies the target's output bytes to its own standard streams without inspecting them. That differs from macOS, where the target writes to the helper's descriptors directly, but the bytes are the same. MCP runs discard output.
- v0.1 delivers text components through environment variables only. File components and agent writes (create, modify, delete, organize) are not implemented yet.

### Approvals

As in AskKey's ADR 0002: one ticket per operation, bound to the SHA-256 digest of the whole run request (operation ID, command, credentials, working directory, inherited environment, caller declarations), and to the IDs and revisions of the credentials it showed: editing, re-permissioning, or deleting and re-creating a credential under the same name invalidates it. The final launch check, decryption and process creation run under one gate that pausing and credential changes also take, so a pause or change that wins that boundary prevents launch. The ticket is consumed at most once, expires after five minutes, and is queried and cancelled only with its capability. Caller name and purpose are shown as unverified. By default, approving needs Windows Hello; turning that off needs Windows Hello and an unlocked management session. Allow permission also needs Windows Hello to set, including on a new credential. Pausing agent access cancels pending tickets, and resuming needs Windows Hello.

### Distribution

An MSI built by the Tauri bundler, with the helper as an external binary. Builds are unsigned until a signing source is chosen. SmartScreen will warn about unsigned builds, and the helper's server check relies on the install path alone.

## Consequences

Windows users get the same permission and approval model. The edition cannot claim macOS's App-bound key protection, cannot run batch files directly, cannot stop targets gracefully, and relays CLI output through the helper. Each limitation is documented rather than worked around. Protocol or rule changes in AskKey need a matching change here.
