# Native read-only hardening audit

This document describes the **feature/hardening** branch. The published 0.1.1 installer predates this branch and does not contain the audit. Aegis remains an experimental scanner, not a primary antivirus.

## Scope and architecture

- [catalog/rules.json](../catalog/rules.json) contains five original rules written for Aegis. Every rule has a Microsoft Learn source URL. No HardeningKitty, CIS, or third-party finding list is copied into the product.
- [hardening.rs](../src-tauri/src/hardening.rs) parses a bounded catalog, evaluates rules through a `Probe` trait, and implements a Windows registry reader behind `cfg(windows)`. The reader uses `KEY_READ | KEY_WOW64_64KEY`; it never writes registry values or launches a process.
- [app.rs](../src-tauri/src/app.rs) exposes `audit_hardening` through a blocking worker so the WebView remains responsive. [HardeningView.jsx](../src/components/HardeningView.jsx) displays the report separately from antivirus scanning and has no remediation action.
- No new crate or npm dependency was introduced. The existing `windows-sys` dependency gained its Registry API feature.

The catalog covers three UAC registry policies and two checks requiring further verification (LLMNR and legacy NTLM policy). The latter have `"verify": true` and return `UnknownEffectiveState` when present, even if a stored value matches. A matching UAC value means **the configured registry value matches this rule**; it is not proof that a pending reboot has occurred or that every protection is effective.

## Results

| State | Meaning |
|---|---|
| `Compliant` | A trusted, correctly typed configured value matches a verified rule. |
| `NonCompliant` | A trusted configured value differs from a verified rule. |
| `MissingKey` / `MissingValue` | The item is absent; no insecure default is inferred. |
| `AccessDenied` | The standard-user process cannot read it. |
| `NotApplicable` | The documented build constraint excludes the rule. |
| `ManagedExternally` | Reserved for a probe with evidence of another policy owner; the current Windows registry probe does not infer this from a path alone. |
| `UnknownEffectiveState` | Type/encoding is malformed, OS build cannot be established, or the rule is marked for verification. |

Raw registry values are limited to 64 KiB. `REG_DWORD` must be exactly four bytes; `REG_SZ` and `REG_MULTI_SZ` must be valid, properly terminated UTF-16. The report truncates untrusted strings to 128 Unicode characters and does not evaluate arbitrary commands embedded in rule data. Each catalog URL is validated as HTTPS on `learn.microsoft.com`; it is displayed as provenance, never fetched during an audit.

## How to verify

On Windows, build the desktop app and open **Hardening audit → Run audit** as a normal signed-in user. The browser preview intentionally disables this button. Review each observed value, expected value, source, and inconclusive reason; do not interpret the summary as a whole-device score.

~~~powershell
cargo test --manifest-path src-tauri/Cargo.toml --test hardening --no-default-features --locked
cargo test --manifest-path src-tauri/Cargo.toml --lib --no-default-features --locked registry_decode_tests
npm run test:i18n
npm run build
~~~

The tests use a simulated `Probe` for matching, missing values, access denied, management and applicability, plus a read-only native registry smoke check on Windows. They do not write system settings. Review `git diff --name-only main...feature/hardening` to confirm scanner, quarantine, watcher, updater and service-daemon source files remain unchanged.

This audit does **not** make antivirus file scans faster. It runs on demand, independently of the scanner. A future local LLM may explain the structured result, but it must not turn uncertain results into confident security claims or gain permission to change system settings.
