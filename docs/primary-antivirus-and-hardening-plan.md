# Aegis: primary-antivirus and native hardening engineering guide

**Status: architecture and verification plan, not an implemented protection claim.** Scope: Windows 10/11 x64. No step in this guide authorizes disabling Microsoft Defender, deploying an unsigned driver, applying all hardening rules at once, or registering false health with Windows Security. The six modules below have independent acceptance gates; "primary antivirus" is the final outcome after those gates, not an installer option.

## Repository baseline, audited 2026-11-11

| Capability | Evidence in this repository | Current conclusion |
|---|---|---|
| Local definitions and YARA | [definitions.rs](../src-tauri/src/definitions.rs), [scanner.rs](../src-tauri/src/scanner.rs), [initial.mbdb](../signatures/initial.mbdb), [baseline.yar](../signatures/baseline.yar) | One EICAR test hash, no allowlist entries, one harmless YARA integration rule. No efficacy corpus. |
| Signed updates | [updater.rs](../src-tauri/src/updater.rs) verifies Ed25519 before parsing, then checks expiry and version. [update-config.json](../signatures/update-config.json) has empty endpoint and key. | Crypto verifier and tests exist; operational threat feed is **disabled**. |
| Continuous protection | [watcher.rs](../src-tauri/src/watcher.rs) and [app.rs](../src-tauri/src/app.rs) use notify/user-mode callbacks. The optional [service runtime](../service-daemon/src/runtime.rs) also uses notify. | Monitoring is post-event and limited; no pre-execution block. No project-owned .sys or FltRegisterFilter. |
| Privileged service | [service-daemon](../service-daemon/README.md) has manual SCM installation and protected logs. The [desktop installer](../installer/hooks.nsh) does not install it. | Not connected to the GUI; not ELAM/PPL. |
| Vault | [quarantine.rs](../src-tauri/src/quarantine.rs) uses chunked AES-256-GCM and Windows DPAPI/ACL support in [platform.rs](../src-tauri/src/platform.rs). | Reversible encrypted containment exists on Windows, without a transaction/WAL for multi-object remediation. |
| Native hardening, WSC, signing | No native rule engine, WSC registration path, or signed retail driver package. The [NSIS hook](../installer/hooks.nsh) currently invokes PowerShell for vault ACL provisioning; the local 0.1.1 installer reports NotSigned under Get-AuthenticodeSignature. | Hardening is not implemented. The project as a whole is not yet script-free. WSC product status and Defender mode must not be inferred from a GUI badge. |

No security-sensitive runtime probes were executed on the developer's host for this document. Commands below are **read-only operator checks** unless clearly labeled as future implementation. Test drivers and hardening remediation belong in disposable, snapshotted VMs.

## 1. Reliable detection and threat-intelligence feed

**Architecture.** Separate a small trusted updater from untrusted feed parsing and scan workers. Obtain licensed, versioned intelligence with documented provenance and revocation. Fetch over HTTPS; sign a canonical manifest that binds payload hash, schema version, feed sequence, expiry, minimum engine version, and key identifier. Verify the Ed25519 signature against a pinned, offline-controlled trust root **before** parsing rules or replacing in-memory definitions. TLS already encrypts transport; encrypt the feed payload at rest only if confidentiality is required, with a separate AEAD key lifecycle. Keep the previous verified generation and a monotonic anti-rollback floor, rotate/revoke signing keys, stage rollouts, and define an emergency rollback signed with an authorized recovery key. Hash matches, YARA, and heuristics must return evidence and confidence, not one undifferentiated "malware" bit.

**Audit and verification.** Search [updater.rs](../src-tauri/src/updater.rs) for `verify_strict`, size limits, expiry, monotonic version, and the point where verified data enters [definitions.rs](../src-tauri/src/definitions.rs). Check [update-config.json](../signatures/update-config.json) for a real HTTPS endpoint and key; empty fields mean no live updates. Confirm a genuine externally curated feed, signing service, key-rotation procedure, offline/expired-feed behavior, and reproducible tests on versioned benign and malicious corpora. Measure `TPR=TP/(TP+FN)` and `FPR=FP/(FP+TN)`; report sample sizes and confidence intervals by family, age, file type, OS, and update age. The existing unit tests prove verifier behavior, **not** detection efficacy.

**Critical risks.** A poisoned or replayed feed can cause mass false positives; a stale cache can leave devices unprotected. YARA rule complexity can exhaust memory or time, so run it with bounded file size, timeout, and worker isolation. Low FPR is essential when automatic blocking is contemplated: even a small rate can affect many ordinary files. Never promote a heuristic directly to irreversible deletion without independent validation.

**Recommended data contract.**

~~~json
{
  "schema": 2,
  "sequence": 42,
  "issued_at": "2026-11-11T00:00:00Z",
  "expires_at": "2026-11-18T00:00:00Z",
  "min_engine": "0.2.0",
  "key_id": "definitions-2026-q4",
  "payload_sha256": "<64 lowercase hex characters>",
  "payload_bytes": 1048576
}
~~~

Sign the exact canonical bytes of this manifest plus the payload digest; reject unknown fields and oversized inputs. The signature, key ID, and full verified generation should be recorded in the audit log without recording private keys.

## 2. Pre-execution protection: minifilter versus watcher

**Architecture.** Keep the existing watcher as best-effort telemetry. A separate WDK minifilter should use `FltRegisterFilter`/`FltStartFiltering`, an allocated altitude, and narrow callbacks for `IRP_MJ_CREATE`, write/rename invalidation, and only carefully justified section-synchronization cases. Pre-create cannot reliably inspect file content because the target object is not yet established; plan a safe post-create/section path and a verdict cache keyed to volume/file identity, content generation and policy version, not a pathname alone. Communicate with a small SYSTEM broker through an ACL-restricted FltMgr port: kernel `FltCreateCommunicationPort`/`FltSendMessage`, user `FilterConnectCommunicationPort`/`FilterGetMessage`/`FilterReplyMessage`. Define strict framing, bounded queues, cancellation, driver/broker version negotiation, timeouts, and a documented fail-open/fail-closed policy per operation. No PE/YARA/ML parsing and no unbounded service wait inside Ring 0. Microsoft documents both the [port model](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/communication-between-user-mode-and-kernel-mode) and [pending/completion rules](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/processing-i-o-operations).

`IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION` is **not** a generic "deny all executables" hook: the documented failure behavior depends on `SyncType`; `SyncTypeOther` cannot be failed, and the documentation describes limited failure for `SyncTypeCreateSection`. Design an enforcement path only after validating the exact WDK contract and filesystem cases. "Zero latency" is not a credible requirement for synchronous inspection. [Microsoft parameter notes](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/flt-parameters-for-irp-mj-acquire-for-section-synchronization)

**Audit and verification.** Search the tracked source and installer for `*.sys`, `*.inf`, `*.cat`, `FltRegisterFilter`, `FltCreateCommunicationPort`, `FilterConnectCommunicationPort`, and `FltSendMessage`. Today none of the driver artifacts or calls are present. On a dedicated test VM after installation, compare `fltmc filters` and `fltmc instances` with the expected service name, altitude and volumes; inspect SCM/INF state and verify that disabling the user-mode watcher does not falsely imply kernel enforcement. A callback registered in source is not evidence that the driver loads, attaches, or blocks correctly.

**Critical risks.** Recursive opens by the broker, paging I/O, network filesystems, reparse points, oplocks, teardown, timeout races, and lock-order inversion can hang a device or cause a BSOD. `FltSendMessage` with no timeout can wait indefinitely; `STATUS_TIMEOUT` must be treated as a distinct outcome even though its NTSTATUS success classification is unusual. Use Driver Verifier/Filter Verifier and boot/unload/resume stress in VMs before enforcement. [FltSendMessage semantics](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltsendmessage), [Filter Verifier](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/development-and-testing-tools)

**Recommended IPC record.**

~~~cpp
struct ScanRequestV1 {
    uint32_t size;
    uint16_t version;
    uint16_t operation;       // create, write-invalidate, section-observe
    uint64_t correlation_id;
    uint64_t volume_id;
    uint64_t file_id;
    uint64_t content_generation;
    uint64_t policy_generation;
    uint32_t timeout_ms;
};
enum class Verdict : uint8_t { Allow, Block, Unknown, TimedOut };
~~~

The broker must revalidate message length, version, caller identity and file identity; a path string is optional display metadata, never sufficient identity.

## 3. Resilience, privilege boundaries, PPL and ELAM

**Architecture.** Split into a signed standard-user GUI, a minimal SYSTEM broker with explicit command authorization, isolated scan workers, and a separate service-maintenance path. Windows antimalware-light PPL is not obtained by setting a process flag: Microsoft requires an appropriately signed ELAM driver with service-signing certificate information, registration, and signed non-Windows DLLs. Design this only after the ordinary service and minifilter are stable. ELAM protects early boot-driver decisions; it does not make Aegis invulnerable to a compromised kernel, firmware, or offline disk attack. [Microsoft protected-service requirements](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-), [ELAM overview](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/early-launch-antimalware)

Retain AES-256-GCM and DPAPI-backed vault keys; **do not use XOR as encryption**. Add a protected transactional metadata store (SQLite WAL or a documented append-only journal) for decisions and multi-object remediation. A durable `PREPARED` record must capture identity, source location, expected hash, original permissions and policy generation before mutation; subsequent `APPLIED`, `VERIFIED`, and `COMMITTED` states allow idempotent recovery. Vault restore must preserve no-clobber semantics and make false-positive reversal visible. Do not infer that SQLite WAL alone makes filesystem moves and registry changes atomic.

**Audit and verification.** In [quarantine.rs](../src-tauri/src/quarantine.rs), verify authentication, source readback, no-clobber restoration, key protection and the exact point source deletion occurs. Search for SQLite/WAL or a remediation journal: none exists. In [service-daemon](../service-daemon/README.md), verify manual installation, SCM identity and whether the desktop installer includes it (it does not). On test VMs, inspect the service protection level with Process Explorer or documented process/service query APIs; a LocalSystem token alone is not PPL. Corrupt/truncate a disposable .quar and power-cycle at each journal transition to verify recovery, without using real user data.

**Critical risks.** Incorrect handle filtering can break security tools or Windows servicing. PPL limits injected DLLs and debugging, complicating updates and incident response. Power loss between encrypted copy, deletion and metadata commit can leave duplicates or orphans; SSD overwrite is not guaranteed physical erasure. Avoid any automatic "clean all" persistence removal until reversible, independently tested remediation exists.

**Recommended journal state.**

~~~text
transaction_id | object_identity | original_path | original_acl_hash
content_sha256  | requested_action | policy_generation | phase
PREPARED -> APPLIED -> VERIFIED -> COMMITTED
                 \-> ROLLBACK_PENDING -> ROLLED_BACK / MANUAL_RECOVERY
~~~

## 4. Native system hardening and configuration assessment

**Release 0.1.1 does not include hardening.** The current source code includes a limited, read-only Rust registry audit with five original rules and a desktop view; it has no remediation or local LLM. See the [native audit guide](./hardening-audit.md). The C++ function below remains a standalone reference example and is not compiled into Aegis.

**Architecture.** Add a small native C++20 audit engine and a separately authorized remediation helper. No product runtime may spawn `powershell.exe`; PowerShell commands in this guide are operator-only checks. Rules should be signed, versioned JSON with explicit Windows build/edition/domain applicability, probe kind, registry view, value type, operator, missing-value semantics, policy owner, and rollback strategy. Support `REG_DWORD`, `REG_SZ`, `REG_MULTI_SZ`; equality, greater-or-equal, bitmask and absent-key predicates. Open the 64-bit view with `KEY_READ | KEY_WOW64_64KEY` (or C# `RegistryView.Registry64`); never hard-code `Wow6432Node`. Microsoft requires consistent alternate-view flags for child operations. [Registry view documentation](https://learn.microsoft.com/en-us/windows/win32/winprog64/accessing-an-alternate-registry-view)

Report separate states: `Compliant`, `NonCompliant`, `MissingKey`, `MissingValue`, `AccessDenied`, `NotApplicable`, `ManagedExternally`, and `UnknownEffectiveState`. A missing registry value is **not automatically insecure**: map it to the documented default for that exact OS/build/edition and check effective Group Policy/MDM state. A local registry write can be overwritten by domain/MDM policy; do not fight the policy manager. Prefer purpose-specific probes over registry guesses:

| Area | Probe and safety note |
|---|---|
| UAC; NTLMv1; LLMNR | Versioned registry/policy probes plus effective-policy check; changing UAC/authentication can require reboot or break legacy logons. |
| SMBv1 | Optional-feature and SMB client/server state, not one registry bit; disabling can break old shares. |
| NetBIOS | Per-adapter configuration through native WMI/COM; DNS/WINS dependencies must be assessed. |
| Credential Guard | VBS/Device Guard runtime status and hardware eligibility; a configured registry value alone is insufficient. |
| ASR | Defender policy/provider status; rules may be unavailable when Defender is not active. Never silently disable them while changing AV providers. |
| Audit policy | `AuditQuerySystemPolicy` per subcategory; the caller may need `SeSecurityPrivilege` or audit-query access. [API](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-auditquerysystempolicy) |
| DEP/ASLR | Use system/process mitigation APIs and effective state, not only registry values; legacy applications may fail under forced mitigations. |

Start with **read-only audit**. For remediation, show an exact before/after diff and request an administrator-approved change per rule. Before each write, save the original existence, type and raw bytes to a restricted, checksummed journal; flush the journal, re-read the target to detect concurrent GPO/MDM changes, apply one allowlisted change, verify the effective setting, and keep a timed rollback plan. Snapshot a relevant subtree with `RegSaveKeyExW` only where appropriate privileges and restore semantics are understood. Registry snapshots, WAL and journal files do not make multi-setting OS changes globally atomic. For networking, logon and boot settings require a VM canary, local recovery account, reboot/remote-access plan, and an explicit maintenance window; default to audit-only. [Registry backup/restore behavior](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-files)

**Audit and verification.** Search the repository for `RegOpenKeyExW`, `RegQueryValueExW`, `KEY_WOW64_64KEY`, `AuditQuerySystemPolicy`, signed hardening rules, a rollback journal, and any product-side `powershell.exe` invocation. No native hardening engine exists today. Validate read-only tests under standard user, admin, 32-bit/64-bit views, missing keys, malformed strings, access denied, domain/MDM-managed devices, and Windows 10/11 images. Every rule must be tested against an independently observed effective setting and documented default; never classify `ERROR_FILE_NOT_FOUND` as `NonCompliant` by itself. Microsoft's [Security Compliance Toolkit](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10) is a baseline reference, not an API contract.

The current [NSIS hook](../installer/hooks.nsh) calls powershell.exe for vault ACL setup. A future native hardening engine must not depend on that script; if the requirement is that the **entire product** be script-free, this installer step must also be replaced with a reviewed native custom action. Exclude this guide itself when searching source for API names, because its reference code intentionally contains them.

**Critical risks.** Blind UAC, NTLM, SMB, NetBIOS or Credential Guard changes can lock out users, sever management, break apps or prevent boot. `RegQueryValueExW` can return malformed non-terminated strings; check type, size and terminators before parsing. A rule list copied from another tool can be stale for a Windows build. HardeningKitty's core repository is [MIT licensed](https://github.com/scipag/HardeningKitty/blob/master/LICENSE), but rule-list provenance must be checked separately; CIS terms restrict product integration and commercial use without suitable rights. Do not bundle CIS Benchmarks or claim CIS compliance merely because rules resemble them. [CIS vendor licensing](https://www.cisecurity.org/cis-securesuite/pricing-and-categories/product-vendor)

**Recommended typed rule.**

~~~json
{
  "id": "UAC-ENABLE-LUA",
  "profile": "windows-client-versioned",
  "probe": {
    "kind": "registry",
    "hive": "HKLM",
    "view": "64",
    "key": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
    "value": "EnableLUA"
  },
  "expected": { "type": "REG_DWORD", "operator": "eq", "value": 1 },
  "missing": "resolve-documented-default-for-os-build",
  "managed_policy": "report-do-not-overwrite",
  "remediation": "administrator-approval-and-reboot-plan"
}
~~~

**Read-only C++20 registry probe (reference).** It deliberately returns raw bytes; a separate, typed evaluator must validate DWORD length, UTF-16 alignment/termination and `REG_MULTI_SZ` double termination before comparing. [Microsoft documents those string hazards](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types).

~~~cpp
#include <windows.h>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

enum class ReadState { Present, MissingKey, MissingValue, AccessDenied, Invalid, Error };
struct RegistryRead {
    ReadState state;
    DWORD type = REG_NONE;
    std::vector<BYTE> bytes;
    LSTATUS error = ERROR_SUCCESS;
};

RegistryRead ReadRegistry64(HKEY hive, const std::wstring& subkey,
                            const std::wstring& value) {
    HKEY opened = nullptr;
    LSTATUS rc = RegOpenKeyExW(hive, subkey.c_str(), 0,
                              KEY_READ | KEY_WOW64_64KEY, &opened);
    if (rc == ERROR_FILE_NOT_FOUND) return {ReadState::MissingKey};
    if (rc == ERROR_ACCESS_DENIED) return {ReadState::AccessDenied};
    if (rc != ERROR_SUCCESS) return {ReadState::Error, REG_NONE, {}, rc};
    struct Closer { HKEY key; ~Closer() { RegCloseKey(key); } } closer{opened};
    const wchar_t* name = value.empty() ? nullptr : value.c_str();
    for (int attempt = 0; attempt != 3; ++attempt) {
        DWORD type = REG_NONE, size = 0;
        rc = RegQueryValueExW(opened, name, nullptr, &type, nullptr, &size);
        if (rc == ERROR_FILE_NOT_FOUND) return {ReadState::MissingValue};
        if (rc == ERROR_ACCESS_DENIED) return {ReadState::AccessDenied};
        if (rc != ERROR_SUCCESS && rc != ERROR_MORE_DATA)
            return {ReadState::Error, type, {}, rc};
        if (size > 65536) return {ReadState::Invalid, type, {}, ERROR_MORE_DATA};
        std::vector<BYTE> data(size);
        DWORD actual = size;
        rc = RegQueryValueExW(opened, name, nullptr, &type, data.data(), &actual);
        if (rc == ERROR_MORE_DATA) continue;  // Concurrent change: retry, bounded.
        if (rc == ERROR_FILE_NOT_FOUND) return {ReadState::MissingValue};
        if (rc == ERROR_ACCESS_DENIED) return {ReadState::AccessDenied};
        if (rc != ERROR_SUCCESS) return {ReadState::Error, type, {}, rc};
        data.resize(actual);
        if (type == REG_DWORD && actual != sizeof(DWORD))
            return {ReadState::Invalid, type, {}, ERROR_INVALID_DATA};
        if ((type == REG_SZ || type == REG_MULTI_SZ) &&
            (actual % sizeof(wchar_t) != 0 || actual < sizeof(wchar_t)))
            return {ReadState::Invalid, type, {}, ERROR_INVALID_DATA};
        return {ReadState::Present, type, std::move(data)};
    }
    return {ReadState::Error, REG_NONE, {}, ERROR_RETRY};
}
~~~

## 5. Signing, certification and Windows compatibility

**Architecture.** Sign and timestamp user-mode EXE/DLL/installer in a controlled build pipeline with protected keys and reproducible provenance. For kernel packages, establish the Microsoft Hardware Developer account and its EV-associated identity, submit INF/CAT/SYS with the appropriate HLK/WHCP evidence for the target Windows versions, and validate Secure Boot/HVCI. An EV certificate alone does **not** make a kernel driver loadable or certified. Current Microsoft guidance treats attestation as a testing path, not retail Windows Update certification; ELAM needs extra PE signature attributes that ordinary attestation does not provide. [Driver signing requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-reqs), [signing options](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/driver-signing-offerings), [HLK](https://learn.microsoft.com/en-us/windows-hardware/test/hlk/)

**Audit and verification.** Examine CI provenance, signed artifacts, certificate chain, timestamp, catalog binding, INF altitude, HLK results, and version-specific driver package. Current local NSIS installer is `NotSigned`, and no .sys/.cat/.inf exists in tracked source. On a disposable VM, use `Get-AuthenticodeSignature .\aegis-security.exe` and `Get-AuthenticodeSignature .\setup.exe`; for a catalog-signed driver, also validate the CAT/SYS package with SignTool's kernel-policy verification rather than assuming a standalone .sys signature is sufficient. Check `bcdedit /enum` for `testsigning` and confirm retail tests run with Secure Boot/HVCI as intended. Do not toggle testsigning on user machines.

**Critical risks.** Invalid signatures prevent loading, while a valid signature does not prove the driver is safe. Bad minifilter boot ordering, incompatibility with another EPP, memory corruption, or flawed installer rollback can cause boot loops and BSODs. Never place signing keys or EV credentials in this repository or a CI log. Use staged rollout and a recovery package.

**Recommended release evidence record.**

~~~json
{
  "artifact_sha256": "<sha256>",
  "source_commit": "<git-sha>",
  "toolchain": "<pinned-id>",
  "signer_subject": "<organization>",
  "timestamp_verified": true,
  "driver_catalog_microsoft_signed": true,
  "hlk_package_id": "<submission-id>",
  "tested_os_builds": ["<Windows 10 build>", "<Windows 11 build>"]
}
~~~

Do not set any field to `true` until evidence exists.

## 6. Validation, AMTSO and Windows Security Center

**Architecture.** Treat WSC reporting as a vendor integration gate after real, continuously running protection is measured. Microsoft's Windows Security documentation says compliant third-party real-time products register/report through **private APIs**; public `IWSCProductList`/`WscGetSecurityProviderHealth` interfaces are for observing provider state, not a supported self-registration shortcut. Do not write `root\SecurityCenter2` WMI instances or registry keys to impersonate a provider. Coordinate the supported vendor path with Microsoft, then report truthful engine, real-time and definition health. [Windows Security developer note](https://learn.microsoft.com/en-us/windows/win32/devnotes/windows-security-center)

Do **not** assume registration always puts Defender into a mode labeled "Passive." Microsoft documents different client, Defender for Endpoint and coexistence states; the outcome depends on onboarding, WSC service health and configuration. Never disable `WinDefend`, `wscsvc` or Tamper Protection to force a transition. [Defender compatibility](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-compatibility), [Windows Security/Defender modes](https://learn.microsoft.com/windows/security/threat-protection/windows-defender-antivirus/windows-defender-antivirus-in-windows-10)

**Audit and verification.** First prove installer, continuous protection, signed updates and self-recovery on clean Windows 10/11 VMs. Use Windows Security > Virus & threat protection > Manage providers, a read-only `IWSCProductList` query, and operator checks:

~~~powershell
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct
Get-MpComputerStatus | Select-Object AMRunningMode, AntivirusEnabled, RealTimeProtectionEnabled
~~~

These PowerShell commands are **manual verification only**; the native Aegis product must not depend on PowerShell. WMI enumeration and a dashboard badge are observations, not proof of compliant registration or protection. Confirm Defender mode and protection after install, crash, service stop, update failure, uninstall and reboot. A missing/unhealthy Aegis provider must leave Windows with a recoverable protection state.

For efficacy, follow a published, independently reviewed test plan with sample provenance, clean-software sets, time-to-protection, detection rate, false-positive rate, remediation success, rollback success and user-workload performance (p50/p95/p99 file-open latency, CPU, RAM, boot time). Distinguish offline from cloud-assisted results and disclose exclusions. Seek independent labs using the [AMTSO Testing Protocol Standard](https://www.amtso.org/standards/); AMTSO is a test protocol, **not** a magic certification of Aegis.

**Critical risks.** Premature WSC reporting could cause users or Windows to rely on a product with only test signatures. Misrepresenting an unhealthy service as active can leave a device unprotected. Coexisting file filters can magnify latency and deadlocks; untested uninstall can strand a stale WSC entry or disable protection. A single EICAR pass, a green UI badge, or one fast VM scan is not an antivirus efficacy result.

**Recommended health contract.**

~~~cpp
struct AvHealth {
    uint64_t definition_sequence;
    bool signature_verified;
    bool broker_running;
    bool minifilter_attached;
    bool real_time_enforcement_healthy;
    bool last_update_within_policy;
    uint64_t dropped_events;
    uint64_t incomplete_analyses;
};
// WSC reporting is permitted only after the supported vendor integration
// exists and all required health predicates reflect observed OS state.
~~~

## Release gate

Keep Defender or another established antivirus active until all six modules have production evidence. The gate is crossed only when: a licensed signed feed and independent efficacy/FPR results exist; pre-execution enforcement survives kernel stress and coexists with other filters; signed services/driver and recovery paths pass clean-machine testing; hardening remains read-only by default with tested rollback; retail signatures/HLK/WHCP evidence are valid; and WSC reports truthful state through Microsoft's supported vendor path. None of those conditions can be inferred from building the current Tauri installer.
