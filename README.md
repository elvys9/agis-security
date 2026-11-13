# Aegis Security

**Aegis Security is an experimental Windows desktop security application, not a certified antivirus.** It combines a React/Tauri interface with a Rust static file scanner, a user-mode folder watcher, an encrypted quarantine vault, and a separately buildable Windows service. The current signature database contains only integration-test indicators. Do not rely on this prerelease as your primary endpoint protection.

## Download and try it

The [latest experimental release](https://github.com/elvys9/agis-security/releases) includes a Windows 10/11 x64 NSIS installer. The installer is **unsigned**. Test it in a disposable VM with a snapshot first.

1. Download the installer from the release's **Assets** section.
2. Run setup; UAC is required for installation and removal. WebView2 may be downloaded if it is not already installed.
3. Open Aegis Security from the Start menu as a standard user. Do not run the application itself as Administrator.
4. Try **Quick Scan** or choose a small, harmless folder under **Select folder**. Review the error and incomplete-analysis counters after a scan.
5. If you test quarantine and restore, use a disposable test file and compare its SHA-256 before and after restoration. Closing the window leaves the app in the system tray; choose **Exit** there to stop monitoring.

The interface starts in English. Use the **Language** menu in the header to choose English, Italian, French, German, Simplified Chinese, or Russian. The choice is saved locally. File paths, hashes, rule identifiers, and some low-level operating-system errors are intentionally left in their original form.

## What works today

| Area | Current behavior |
|---|---|
| Manual scans | Quick scan covers selected high-risk user folders and accessible on-disk images of active processes. Full scan traverses the main drive. Custom scan accepts files and folders through the picker or drag and drop. |
| Static analysis | SHA-256 and legacy MD5 are calculated in a 64 KiB streaming pass. The engine computes global entropy, parses PE sections conservatively, flags writable-and-executable sections and high-entropy executable sections, and applies bundled YARA-X rules within a 16 MiB inspection budget. |
| User-mode monitoring | Watches Downloads, Desktop, and TEMP for selected executable/script extensions while the app runs. It reports findings and native notifications but does not prevent execution. |
| Quarantine | On Windows, stores authenticated, chunked AES-256-GCM containers under a per-user ProgramData vault. The master key is DPAPI-protected. Restoration refuses to overwrite an existing file. Quarantine is always an explicit user action. |
| Definition updates | HTTPS download, Ed25519 verification, version checks, and atomic activation are implemented. The endpoint and public key are deliberately blank, so remote updates are currently disabled. |
| Optional service | A separately built, manually installed LocalSystem service can run scheduled scans and write a protected log. It is not bundled by the desktop installer and has no GUI command channel. |
| Read-only hardening audit | Evaluates five original, Microsoft-sourced registry-policy rules through a native Rust probe. The separate Hardening audit page shows observed values, inconclusive states, and source URLs. No setting is changed and no PowerShell process is launched. |
| Local explanations (0.1.2 source) | The Hardening page can run an included GGUF model on demand to explain an audit in plain language. A deterministic report remains available if inference fails; generated prose never changes the audit. The published 0.1.1 installer predates this feature. |

Heuristic flags are evidence for review, not proof of malware. The bundled database includes only the EICAR test hash and a harmless YARA integration fixture; it is **not** a production threat-intelligence feed. Errors and incomplete analyses are shown rather than interpreted as clean results.

The hardening audit and local explanation are available in the current source code. The published 0.1.1 installer predates them; build the desktop app from source to try them. The build downloads and verifies an approximately 1.12 GB model plus a Windows x64 CPU runtime, then includes both in the new installer. The installed app does not download a model to explain results.

## Important limitations

- There is no minifilter, WFP driver, kernel anti-tampering, pre-execution blocking, ONNX model, process-memory scan, ransomware rollback, or persistence-remediation engine.
- The hardening page currently covers only five registry-policy rules. It does not assess all Windows security settings, prove effective protection, or apply changes. Local AI text can be inaccurate and does not accelerate antivirus scanning.
- The user-mode watcher can miss events and cannot scan locked or inaccessible files. A successful scan does not guarantee the device is safe.
- The installer and application are not code-signed. They have not completed clean-machine Windows 10/11 installation, upgrade, uninstall, performance, independent security, or antivirus-efficacy validation.
- The Windows vault is designed for reversible containment; physical secure erasure on SSDs cannot be guaranteed. On macOS/Linux the current vault conservatively retains the original file and must not be treated as isolation.
- The service and GUI are independent. Installing the service requires a separate administrator-reviewed process described in [its README](service-daemon/README.md).

Keep an established antivirus enabled while evaluating Aegis Security.

## Build from source

Prerequisites: Node.js/npm, a stable Rust MSVC toolchain, Windows SDK, and WebView2. In PowerShell at the repository root:

~~~powershell
npm ci
npm run tauri -- dev
~~~

The debug build stores data under %LOCALAPPDATA%\AegisSecurity-Dev. To build the supported NSIS package:

~~~powershell
npm run tauri -- build --bundles nsis
~~~

The installer is written to src-tauri/target/release/bundle/nsis. Install it before launching the Release executable directly: setup prepares the protected ProgramData parent directories. Building does not install or start a SYSTEM service or driver.

Run the localization checks with `node --test src/i18n.test.mjs`. The [testing guide](docs/testing.md) lists the native Rust suites and VM validation steps.

## Project layout

~~~text
src/                 React interface and six-language message catalog
src-tauri/           Tauri desktop backend, scanner, watcher, vault, updater
catalog/             Original Microsoft-sourced hardening rules
service-daemon/      Optional, separately installed Windows SCM scanner
signatures/          Integration-test definitions and YARA fixture
installer/           NSIS hooks and protected-vault setup
docs/                Architecture, testing, distribution, workspace audit
~~~

Dependencies are locked in package-lock.json and the two Cargo.lock files. Generated output, local toolchains, and the archived C++/WPF prototype are excluded from Git.

Read the [architecture](docs/architecture.md), [hardening audit guide](docs/hardening-audit.md), [local model guide](docs/local-llm.md), [primary-antivirus engineering guide](docs/primary-antivirus-and-hardening-plan.md), [distribution notes](docs/distribution.md), and [workspace audit](docs/workspace-audit.md) for component boundaries and release gates. This repository has no open-source license at present; public visibility does not grant general reuse rights.
