# Reproducible testing

Run from the repository root in PowerShell. Native compilation needs a Rust MSVC toolchain and Windows SDK. The \`npm run tauri\` wrapper can use the repository-local Rust toolchain when it is present.

~~~powershell
npm ci
node --test src/i18n.test.mjs
npm run build
npm run tauri -- build --bundles nsis
~~~

The localization suite checks all six catalogs, placeholder consistency, saved-language fallback, number formatting, and translation of selected native engine warnings. The Vite build validates the React bundle. Building the NSIS installer does **not** install it or register the optional service.

With Cargo available in PATH, run the native suites:

~~~powershell
cargo test --manifest-path src-tauri/Cargo.toml --release --locked --no-default-features --features yara
cargo test --manifest-path service-daemon/Cargo.toml --release --locked
cargo build --manifest-path service-daemon/Cargo.toml --release --locked
~~~

The engine tests exercise harmless hash/PE/entropy/YARA fixtures, malformed files, vault encryption and restoration, Windows alternate streams, and an actual filesystem watcher event. The service tests cover configuration, security checks, bounded queues, and logs. None of these tests installs or starts a driver or service.

For a manual desktop check without an installer, run \`npm run tauri -- dev\`. Confirm the language menu switches every view and persists after restarting. Run Quick Scan, a small Custom Scan, pause/resume/stop, and inspect the error and incomplete-analysis counters. In the browser-only preview, native file actions are intentionally disabled.

Test quarantine and restore only on a **disposable file** and compare SHA-256 before and after with \`Get-FileHash\`. Other installed antivirus products may intercept the EICAR test string; do not disable them or run live malware merely to validate the UI.

Install the unsigned NSIS package in a clean, disposable Windows VM with a standard account and a snapshot. Check setup-only UAC, non-elevated application launch, WebView2 bootstrap, tray behavior, Explorer actions, Unicode/spaced paths, upgrade, and uninstall with vault preservation. Repeat on Windows 10 and 11. Measure idle and scan CPU/RAM; a 45 MB WebView2 footprint has **not** been demonstrated. The shipped definitions are for integration testing, not primary antivirus protection.
