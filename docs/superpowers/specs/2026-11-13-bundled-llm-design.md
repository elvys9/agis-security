# Bundled local explanation model design

## Intent

Give a non-expert a short explanation of ThreatLens's read-only hardening audit and practical, cautious next checks. The model ships inside the Windows x64 installer and runs offline on demand. ThreatLens remains an experimental scanner; the model never classifies malware, changes audit verdicts, alters Windows settings, or acts on files.

## Chosen approach and alternatives

The user chose a bundled model over optional Ollama. Bundle the official Apache-2.0 Qwen2.5-1.5B-Instruct Q4_K_M GGUF (1,117,320,736 bytes) and a pinned Windows x64 CPU `llama.cpp` runtime. The build fetches each from a fixed revision/release, verifies SHA-256, and copies licenses into Tauri resources. No model download occurs on an installed machine. An optional Ollama service would make the installer smaller but require separate user setup. An embedded inference crate would avoid a sidecar but require substantially more native build and runtime integration.

## Runtime boundary

Only the Rust desktop backend controls the sidecar. It starts lazily as the logged-in standard user, bound to `127.0.0.1` on a transient port with a per-run bearer token, no web UI or tools, bounded CPU threads and context. The frontend receives only Tauri command results and cannot choose a binary path, model path, endpoint, command-line arguments, or prompt. The child process is terminated when ThreatLens exits; Windows job-object ownership also terminates it after a crash. Never use a cloud model or a remote URL.

The model receives only bounded, product-authored rule IDs, titles, descriptions, expected values, states and Microsoft source URLs from an audit snapshot. Raw registry strings, file paths, hashes, and arbitrary user text stay out of prompts. A fixed system instruction says to explain evidence, preserve missing/unknown states, and avoid definitive security claims or automatic remedies. Output uses a small JSON schema; Rust validates size, known rule IDs, length and shape before display. No generated text becomes an executable command or a scan verdict.

## User experience

The existing Hardening audit view gains **Explain results** after an audit, a visible busy state, and a plain-language report with what was checked, what differed, what remains unknown, and the original Microsoft sources. Model-generated prose is explicitly marked as an AI explanation. A deterministic plain-language report is always available; it is used when the model is absent, fails integrity checks, times out, or returns invalid output. The current six UI languages are supported; the prompt requests the selected language. Long waits do not block the WebView.

## Distribution and checks

`npm run tauri -- build --bundles nsis` prepares the pinned assets before Tauri packaging and fails if verification fails. The installer must physically contain the runtime, GGUF, and license files; a source-only commit is not a bundled release. Never commit the 1.1 GB model to Git. Verify a clean VM install, offline explanation, timeout/fallback, standard-user execution, model process cleanup, and installer size. The existing published 0.1.1 installer remains unchanged until a new tested release is created.
