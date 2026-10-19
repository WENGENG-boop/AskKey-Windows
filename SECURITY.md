# Security policy

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository (Security tab, then Report a vulnerability). Never include real credentials or library files; use synthetic values.

## Security boundaries

- Credentials are encrypted locally with AES-256-GCM. Every record, including its permission, is authenticated with HMAC-SHA256. The vault key is wrapped with DPAPI for your Windows account.
- **DPAPI does not protect against programs running as you.** Any process in your account can unwrap the key and decrypt the library. Ask Key controls what agents receive through the Broker; it is not a defence against malware already running in your account. The macOS edition binds its key to the signed App; Windows offers no equivalent for a desktop App.
- Agents reach Ask Key only through `askkey.exe` and a named pipe whose DACL admits your account only. The Broker never returns stored values. Approved values are placed in the environment of the target it launches, and that target can print or forward them.
- Caller names and purposes are what the agent says about itself. They are shown as unverified and grant nothing.
- An approval is bound to one exact request and to the credential revisions it showed, used at most once, and expires after five minutes. Hidden, missing, revoked, edited and expired credentials are checked again at the final launch boundary, which pausing agent access and credential changes wait on.
- Batch files are refused as targets because `cmd.exe` argument parsing defeats quoting.
