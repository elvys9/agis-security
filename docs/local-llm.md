# Bundled local explanation model

The Windows x64 **0.1.2 source build** includes a local model for the read-only Hardening audit. The published 0.1.1 installer does not include this feature. The model produces short, optional explanations; the Rust audit engine remains the only source of statuses and counts. ThreatLens is still an experimental scanner, not a primary antivirus.

## Assets and licenses

The build script [prepare-llm.ps1](../installer/prepare-llm.ps1) downloads fixed upstream artifacts into the ignored local build cache, checks exact byte counts and SHA-256 values, and stages only the model, server executable, required DLLs, and license files in `src-tauri/llm-assets/`. Tauri includes that directory as `llm/` resources in the NSIS installer. Nothing is fetched on the installed PC when explaining an audit.

| Asset | Pinned source | Size | SHA-256 | License |
|---|---|---:|---|---|
| Qwen2.5-1.5B-Instruct Q4_K_M GGUF | [Qwen revision 91cad511](https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF/tree/91cad51170dc346986eccefdc2dd33a9da36ead9) | 1,117,320,736 bytes | `6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e` | Apache-2.0 |
| llama.cpp Windows x64 CPU archive | [b12244 release](https://github.com/ggml-org/llama.cpp/releases/tag/b12244) | 24,930,349 bytes | `318f11fadcbc3a86541ec55d9930cc76646c6b8d2ff18798c8477e9ff0dc452a` | MIT; bundled LLVM OpenMP notice |

The GGUF is about 1.12 GB before installer compression. Build and installation need substantially more free disk space than version 0.1.1, and inference uses additional RAM/CPU. The model card documents support for Italian, English, French, German, Chinese and Russian, but output quality must still be tested in all six languages. The model and runtime are not committed to Git. Their license texts are included in the installer.

## Trust boundary

- The user runs the audit first. The `explain_hardening` Tauri command re-runs the read-only audit and returns the exact snapshot being explained. The WebView cannot submit its own report, model path, prompt, URL or executable arguments.
- Only bundled rule IDs, titles, descriptions, expected values, states and Microsoft URLs enter the model prompt. Raw registry values, file paths and malware findings do not. The local server binds only `127.0.0.1` with a random per-request API key; the WebView never talks to it directly.
- The runtime starts on demand as the standard user, uses a bounded CPU thread count, and is killed after the request. A Windows Job Object with kill-on-close also covers an abrupt app exit. No web UI or built-in agent tools are enabled.
- Rust verifies the installed model and server hashes before starting, bounds startup/request duration and HTTP response size, and validates the JSON shape, advice IDs and text lengths. Invalid or unavailable model output becomes a deterministic simple report. AI prose is labeled and must be checked against the original audit and Microsoft sources; no generated instruction is executed.
- The deterministic report groups `NonCompliant` separately from `MissingKey`, `MissingValue`, `AccessDenied`, `ManagedExternally`, `NotApplicable` and `UnknownEffectiveState`. No missing value is called insecure without evidence.

This is an explanation feature for a small hardening catalog, not a general security chatbot. It does not alter antivirus scans, quarantined files, registry settings or the optional Windows service. A locally generated explanation can still be inaccurate; it is not a security verdict or certification.

## Build and verify

On Windows x64, from the repository root:

~~~powershell
npm ci
npm run tauri -- build --bundles nsis
node --test installer/prepare-llm.test.mjs
~~~

The Tauri wrapper calls the preparation script before `dev` or `build`; it fails rather than packaging mismatched assets. To verify a prepared asset folder directly:

~~~powershell
powershell -NoProfile -File installer/prepare-llm.ps1 -VerifyOnly
~~~

The generated NSIS package should contain the GGUF, runtime DLLs and licenses. Test on a disposable Windows 10/11 x64 VM with a snapshot and no network after WebView2 has been installed. Run **Hardening audit → Run audit → Explain results locally** as a standard user. Confirm the explanatory text is separate from audit states, then test missing or damaged model files and check that the simple report remains available. Inspect that `llama-server.exe` exits after the request and that no localhost service stays open. The installer is unsigned until the project's signing and release checks are completed.
