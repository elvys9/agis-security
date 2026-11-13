//! Local, presentation-only explanation of a fresh hardening audit.
use crate::{explanation::{model_input, plain_report, validate_model_output, ModelOutput, PlainReport}, hardening::Report};
use anyhow::{bail, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{fs::File, io::Read, path::Path};

const MODEL_SIZE: u64 = 1_117_320_736;
const MODEL_SHA256: &str = "6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e";
const SERVER_SIZE: u64 = 9_728;
const SERVER_SHA256: &str = "dfd23267c514f055ec7a0357175d47d79af79bfced21be0e969e08e8de24d1f6";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BackendError { MissingAssets, Integrity, Startup, Timeout, Transport }

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum ModelState { Generated, MissingAssets, IntegrityFailed, Unavailable, TimedOut, InvalidResponse }

pub trait LlmBackend {
    fn generate(&self, prompt: &str) -> std::result::Result<String, BackendError>;
}

#[derive(Debug, Serialize)]
pub struct ExplanationResponse {
    pub report: Report,
    pub plain: PlainReport,
    pub ai: Option<ModelOutput>,
    pub model_state: ModelState,
}

fn language_name(language: &str) -> &'static str {
    match language {
        "it" => "Italian", "fr" => "French", "de" => "German",
        "zh-CN" => "Simplified Chinese", "ru" => "Russian", _ => "English",
    }
}

pub fn explain_with<B: LlmBackend>(report: Report, language: &str, backend: &B) -> ExplanationResponse {
    let plain = plain_report(&report);
    let prompt = format!(
        "Explain the following read-only Windows policy audit in {}. Return a short JSON object with summary and advice (each advice has rule_id and text). Only refer to the supplied rule IDs and statuses. A missing, denied, or unknown setting does not prove insecurity. Never change a verdict, claim the device is safe, recommend disabling protection, or invent a source. Suggest only reviewing the linked Microsoft documentation. Do not provide commands. Data: {}",
        language_name(language), model_input(&report)
    );
    let (model_state, ai) = match backend.generate(&prompt) {
        Ok(raw) => match validate_model_output(&raw, &report) {
            Ok(output) => (ModelState::Generated, Some(output)),
            Err(_) => (ModelState::InvalidResponse, None),
        },
        Err(BackendError::MissingAssets) => (ModelState::MissingAssets, None),
        Err(BackendError::Integrity) => (ModelState::IntegrityFailed, None),
        Err(BackendError::Timeout) => (ModelState::TimedOut, None),
        Err(BackendError::Startup | BackendError::Transport) => (ModelState::Unavailable, None),
    };
    ExplanationResponse { report, plain, ai, model_state }
}

pub fn verify_file(path: &Path, expected_size: u64, expected_sha256: &str) -> Result<()> {
    let mut file = File::open(path)?;
    if file.metadata()?.len() != expected_size { bail!("Bundled asset size differs"); }
    let mut hasher = Sha256::new();
    let mut block = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut block)?;
        if read == 0 { break; }
        hasher.update(&block[..read]);
    }
    if hex::encode(hasher.finalize()) != expected_sha256.to_ascii_lowercase() {
        bail!("Bundled asset checksum differs");
    }
    Ok(())
}

pub fn parse_chat_response(bytes: &[u8]) -> Result<String> {
    if bytes.len() > 32 * 1024 { bail!("Local model response is too large"); }
    let response: serde_json::Value = serde_json::from_slice(bytes)?;
    let content = response.pointer("/choices/0/message/content")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("Local model response contains no text"))?;
    if content.is_empty() || content.len() > 8 * 1024 {
        bail!("Local model text is empty or too large");
    }
    Ok(content.to_owned())
}

pub fn explain_bundled(report: Report, language: &str, resource_dir: &Path) -> ExplanationResponse {
    explain_with(report, language, &BundledBackend { resource_dir })
}

struct BundledBackend<'a> { resource_dir: &'a Path }

impl LlmBackend for BundledBackend<'_> {
    fn generate(&self, prompt: &str) -> std::result::Result<String, BackendError> {
        let root = self.resource_dir.join("llm");
        let model = root.join("model.gguf");
        let runtime = root.join("runtime");
        let server = runtime.join("llama-server.exe");
        if !model.is_file() || !server.is_file() {
            return Err(BackendError::MissingAssets);
        }
        verify_file(&model, MODEL_SIZE, MODEL_SHA256).map_err(|_| BackendError::Integrity)?;
        verify_file(&server, SERVER_SIZE, SERVER_SHA256).map_err(|_| BackendError::Integrity)?;
        #[cfg(windows)]
        { windows::generate(&runtime, &server, &model, prompt) }
        #[cfg(not(windows))]
        { let _ = (runtime, prompt); Err(BackendError::Startup) }
    }
}

#[cfg(windows)]
mod windows {
    use super::{parse_chat_response, BackendError};
    use rand::RngCore;
    use std::{
        io::Read,
        net::TcpListener,
        os::windows::{io::{AsRawHandle, FromRawHandle, OwnedHandle}, process::CommandExt},
        path::Path,
        process::{Child, Command, Stdio},
        thread,
        time::{Duration, Instant},
    };
    use windows_sys::Win32::{
        Foundation::HANDLE,
        System::{
            JobObjects::{AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
                SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE},
            Threading::{BELOW_NORMAL_PRIORITY_CLASS, CREATE_NO_WINDOW},
        },
    };

    struct ServerProcess { child: Child, _job: OwnedHandle }

    impl ServerProcess {
        fn start(runtime: &Path, executable: &Path, model: &Path, port: u16, key: &str) -> Result<Self, BackendError> {
            let threads = thread::available_parallelism().map(|n| n.get().saturating_sub(1).clamp(1, 4)).unwrap_or(1);
            let mut child = Command::new(executable)
                .current_dir(runtime)
                .args(["--model", model.to_str().ok_or(BackendError::Startup)?, "--alias", "aegis-local",
                    "--host", "127.0.0.1", "--port", &port.to_string(), "--no-webui", "--no-agent",
                    "--no-slots", "--cors-origins", "localhost", "--parallel", "1",
                    "--ctx-size", "4096", "--threads", &threads.to_string()])
                .env("LLAMA_API_KEY", key)
                .stdout(Stdio::null()).stderr(Stdio::null())
                .creation_flags(CREATE_NO_WINDOW | BELOW_NORMAL_PRIORITY_CLASS)
                .spawn().map_err(|_| BackendError::Startup)?;
            let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if job.is_null() {
                let _ = child.kill(); let _ = child.wait();
                return Err(BackendError::Startup);
            }
            let job = unsafe { OwnedHandle::from_raw_handle(job) };
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let set = unsafe { SetInformationJobObject(
                job.as_raw_handle() as HANDLE, JobObjectExtendedLimitInformation,
                &limits as *const _ as *const _, std::mem::size_of_val(&limits) as u32,
            ) };
            let assigned = set != 0 && unsafe { AssignProcessToJobObject(job.as_raw_handle() as HANDLE,
                child.as_raw_handle() as HANDLE) } != 0;
            if !assigned {
                let _ = child.kill(); let _ = child.wait();
                return Err(BackendError::Startup);
            }
            Ok(Self { child, _job: job })
        }
    }

    impl Drop for ServerProcess {
        fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); }
    }

    fn transport(error: reqwest::Error) -> BackendError {
        if error.is_timeout() { BackendError::Timeout } else { BackendError::Transport }
    }

    pub(super) fn generate(runtime: &Path, executable: &Path, model: &Path, prompt: &str)
        -> Result<String, BackendError> {
        let reservation = TcpListener::bind("127.0.0.1:0").map_err(|_| BackendError::Startup)?;
        let port = reservation.local_addr().map_err(|_| BackendError::Startup)?.port();
        drop(reservation);
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        let key = hex::encode(secret);
        let mut server = ServerProcess::start(runtime, executable, model, port, &key)?;
        let client = reqwest::blocking::Client::builder()
            .no_proxy().redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(2)).timeout(Duration::from_secs(75))
            .build().map_err(transport)?;
        let base = format!("http://127.0.0.1:{port}");
        let started = Instant::now();
        loop {
            if server.child.try_wait().map_err(|_| BackendError::Startup)?.is_some() {
                return Err(BackendError::Startup);
            }
            if let Ok(response) = client.get(format!("{base}/health"))
                .timeout(Duration::from_secs(1)).send() {
                if response.status().is_success() { break; }
            }
            if started.elapsed() >= Duration::from_secs(90) { return Err(BackendError::Timeout); }
            thread::sleep(Duration::from_millis(250));
        }
        let request = serde_json::json!({
            "model": "aegis-local", "stream": false, "temperature": 0.2, "max_tokens": 380,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": "You explain a read-only security audit. Return a JSON object with summary and advice. Do not invent rule IDs, changes, commands or protection claims."},
                {"role": "user", "content": prompt}
            ]
        });
        let body = serde_json::to_vec(&request).map_err(|_| BackendError::Transport)?;
        let response = client.post(format!("{base}/v1/chat/completions"))
            .bearer_auth(&key).header("Content-Type", "application/json")
            .body(body).send().map_err(transport)?;
        if !response.status().is_success() { return Err(BackendError::Transport); }
        let mut bytes = Vec::new();
        response.take(32 * 1024 + 1).read_to_end(&mut bytes).map_err(|_| BackendError::Transport)?;
        parse_chat_response(&bytes).map_err(|_| BackendError::Transport)
    }
}
