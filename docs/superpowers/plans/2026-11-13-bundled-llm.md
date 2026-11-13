# Bundled Local LLM Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a Windows x64 installer containing a local model that explains the read-only hardening audit and produces a simple report.

**Architecture:** A deterministic Rust report is the source of truth. A lazily started, bundled llama.cpp CPU sidecar paraphrases a bounded audit snapshot through a loopback API; Rust validates its response and falls back to deterministic prose. React displays the result without running inference or accessing the registry itself.

**Tech Stack:** Rust, Tauri v2, React, Windows NSIS, llama.cpp b12244, Qwen2.5-1.5B-Instruct Q4_K_M GGUF.

**Spec:** [bundled local explanation model design](../specs/2026-11-13-bundled-llm-design.md)

## Global Constraints

- Windows x64 only; Aegis stays a standard-user process.
- No remote inference, runtime model download, registry write, automatic remediation, or changes to scanner/quarantine/watcher/updater/service.
- Package pinned assets only after SHA-256 and size verification; never commit the GGUF to Git.
- Preserve all eight hardening states, especially Missing/AccessDenied/Unknown, as inconclusive where appropriate.
- Keep LLM-generated content separate and visibly labeled; use deterministic text on failure.

## Review Focus

- Missing, truncated, or altered model/runtime yields a deterministic report instead of an app crash.
- A busy/wrong local port cannot redirect audit data to an unrelated service; authenticate the sidecar.
- Malformed, oversized, duplicate-ID, or invented-ID model output is rejected.
- A language change or second audit does not display stale model prose as if it belonged to the new report.
- Closing or crashing Aegis does not leave a persistent inference service.

---

### Task 1: Deterministic explanation contract

**Files:** Create `src-tauri/src/explanation.rs`; modify `src-tauri/src/lib.rs`; create `src-tauri/tests/explanation.rs`.

**Interfaces:** `plain_report(&hardening::Report, language: &str) -> PlainReport`; `model_input(&hardening::Report) -> ModelInput`; `validate_model_output(&str, &hardening::Report) -> Result<ModelOutput>`.

- [ ] Write failing tests for all eight states, source preservation, unknowns staying inconclusive, input omitting observed values, and malformed/invented-ID response rejection.
- [ ] Run focused tests to see the expected missing-module failure.
- [ ] Implement bounded typed serialization, deterministic text, and strict output validation.
- [ ] Run focused and full Rust tests; commit.

### Task 2: Bundled inference runtime

**Files:** Create `src-tauri/src/local_llm.rs`; modify `src-tauri/src/app.rs`, `src-tauri/src/lib.rs`, `src-tauri/Cargo.toml` only if existing Windows API features need extension; create focused runtime tests.

**Interfaces:** `explain(report: hardening::Report, language: &str, resource_dir: &Path) -> ExplanationResponse`; Tauri command `explain_hardening(language: String)` recomputes and returns its audit snapshot plus explanation.

- [ ] Write failing tests for missing assets, invalid hash, no server, timeout and response validation with a local fake HTTP server.
- [ ] Run focused tests to confirm failure.
- [ ] Implement lazy child startup, loopback-only authenticated HTTP, bounded timeouts/response size, Windows process cleanup, and fallback.
- [ ] Run focused and full Rust tests and desktop compile; commit.

### Task 3: User-facing report

**Files:** Modify `src/components/HardeningView.jsx`, `src/i18n.js`, `src/i18n.test.mjs`, `src/styles.css`.

**Interfaces:** The view invokes `explain_hardening` only after an audit; it shows deterministic counts and AI text as separate sections.

- [ ] Extend translation tests first for all six locales and report states; watch them fail.
- [ ] Add explain control, progress/error/fallback, simple report, and safe text-only rendering.
- [ ] Run localization tests and Vite build; review desktop and browser-preview views; commit.

### Task 4: Installer assets and distribution proof

**Files:** Create `installer/prepare-llm.ps1`, `docs/local-llm.md`; modify `installer/tauri-cli.mjs`, `src-tauri/tauri.conf.json`, `.gitignore`, `README.md`, distribution notes and package version files if required.

**Interfaces:** `npm run tauri -- build --bundles nsis` prepares pinned assets and embeds `llama-server`, all required DLLs, Q4_K_M GGUF, and licenses; a failed hash aborts the build.

- [ ] Write a packaging preflight test that rejects absent/mismatched assets and checks resource mapping.
- [ ] Run it to see the expected failure.
- [ ] Implement pinned download/verify/extract and Tauri resource configuration; document size, sources, licenses and runtime behavior.
- [ ] Build NSIS installer; inspect its contents, install in a disposable Windows VM if available, exercise offline explanation, verify process cleanup; commit.
