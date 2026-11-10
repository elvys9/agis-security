# Current architecture and EPP/EDR roadmap

Aegis Security is currently a **standard-user Tauri application**. Its modular structure is inspired by endpoint security products, but it does not contain proprietary Malwarebytes components or a certified kernel driver. The optional SCM service is independent of the GUI and does not process GUI commands.

~~~text
Standard user
┌───────────────────────────────────────────────────────────┐
│ React/WebView2 UI ── Tauri commands/events ── Rust app.rs  │
│ Six-language controls, scan progress, findings, vault     │
└──────────────────────────────┬────────────────────────────┘
                               │ validated commands
             ┌─────────────────┴───────────────────────────┐
             │ scan coordinator + bounded pool (1–4 workers)│
             │ WalkDir → SHA-256/MD5 → PE/entropy → YARA-X   │
             │ findings, read errors, incomplete coverage    │
             └──────────────┬───────────────────┬────────────┘
                            │                   │
                notify: Downloads,         AES-256-GCM vault
                Desktop, TEMP              DPAPI + per-user ACL
                            └─────────┬─────────┘
                             in-memory definitions
                             HTTPS + Ed25519 (unconfigured)

Separate administrator boundary
┌───────────────────────────────────────────────────────────┐
│ Optional LocalSystem SCM service: scheduled scans,        │
│ user-mode watcher, protected log. No GUI command channel. │
└───────────────────────────────────────────────────────────┘

Ring 0: no driver is implemented or installed by this release.
~~~

| Component | Privilege | Main APIs/libraries | Performance and failure handling |
|---|---|---|---|
| Tauri/React GUI | Standard user | Tauri invoke/events, dialog, tray, WebView2 | Async commands; progress emission at most every 50 ms. WebView2 idle RAM is not yet benchmarked. |
| Static scanner | Standard user | WalkDir, streaming SHA-256/MD5, PE parser, YARA-X | 1–4 workers, bounded queue, 64 KiB stream buffer per file. Read failures and incomplete coverage are counted. |
| Folder watcher | Standard user | notify / ReadDirectoryChangesW | Single worker, bounded debounce. Lost or incomplete events appear as warnings. |
| Quarantine | Standard user | AES-256-GCM, DPAPI, NTFS ACLs and Windows handles | 1 MiB chunks, authenticated readback, fail-closed restore with no overwrite. |
| Updater | Standard user | HTTPS/rustls, Ed25519, atomic definition swap | Download size and version/expiry limits; disabled until feed trust material is configured. |
| Optional service | LocalSystem | SCM, notify, shared scanner | 1–4 workers, bounded queue/log, strict owner/DACL checks; manually installed. |
| Minifilter/WFP | Kernel, future | FltMgr and WFP | Not implemented; no kernel enforcement claim. |

## Detection sequence

1. Traverse ordinary files without following symlinks or reparse points; skip special OS files and the vault.
2. Read in blocks, calculate hashes and global entropy, and compare SHA-256 with bundled definitions.
3. Parse PE sections, calculate section entropy, and flag W^X and high-entropy executable sections.
4. Run local YARA-X rules when the file fits the inspection budget.
5. Show evidence for user review. Quarantine requires an explicit action; there is no automatic file removal.

The current engine does **not** verify Authenticode, use a Bloom filter or ONNX model, correlate runtime behavior, remove persistence, or block execution. Quick Scan checks accessible on-disk process images, not process memory. An unreadable or changing file is reported as an error or incomplete analysis.

> [Self-Check] The renderer has no privileged filesystem scanner. Parsing remains outside the kernel. Scan workers and queues are bounded, and expensive Tauri commands run off the UI thread. The vault authenticates a durable container before attempting source removal on Windows. This does not prove safety against every filesystem race or a hostile administrator.

## Four-phase development path

| Phase | Status and exit gate |
|---|---|
| 1. Static scanner | Implemented in Rust with hash, PE, entropy, YARA, error, and harmless fixture tests. Expand fuzzing/corpus and benchmark before release. |
| 2. Standard-user desktop | Tauri, tray, watcher, six-language UI, and NSIS bundle implemented. Clean Windows 10/11 VM tests, accessibility review, performance measurements, upgrade/uninstall tests, and code signing remain. |
| 3. Service and remediation | Optional SCM service exists, but is not integrated into setup or GUI. Requires authenticated IPC, authorization, isolated workers, a remediation journal, and rollback tests. |
| 4. Certified kernel protection | Design an observe-only minifilter/WFP sensor before enforcement. Requires WDK/HLK, Driver Verifier, HVCI, Microsoft signing, compatibility testing, pilot rollout, and recovery. No Ring 0 artifact ships today. |

A public production claim requires a real signed threat-intelligence feed, independent security review, supported-hardware validation, and signed release artifacts. EV/attestation/WHQL are not produced by a source build.
