use aegis_engine::hardening::{Report, ResultItem, Status};
use aegis_engine::local_llm::{explain_bundled, explain_with, parse_chat_response, verify_file, BackendError, LlmBackend, ModelState};
use std::cell::RefCell;

fn report() -> Report {
    Report {
        catalog_version: 1, total: 1, compliant: 0, non_compliant: 0, inconclusive: 1,
        results: vec![ResultItem {
            id: "missing-uac".into(), title: "UAC policy".into(), category: "UAC".into(),
            description: "Check stored policy".into(),
            source_url: "https://learn.microsoft.com/en-us/windows/security/".into(),
            status: Status::MissingValue, observed: Some("private-value".into()),
            expected: "DWORD = 1".into(), reason: "No effective default inferred".into(),
        }],
    }
}

struct FakeBackend {
    result: Result<String, BackendError>,
    prompt: RefCell<String>,
}
impl LlmBackend for FakeBackend {
    fn generate(&self, prompt: &str) -> Result<String, BackendError> {
        *self.prompt.borrow_mut() = prompt.into();
        self.result.clone()
    }
}

#[test]
fn local_model_explanation_is_separate_from_unchanged_audit() {
    let backend = FakeBackend {
        result: Ok(r#"{"summary":"The effective setting is unknown.","advice":[{"rule_id":"missing-uac","text":"Review the linked Microsoft policy."}]}"#.into()),
        prompt: RefCell::new(String::new()),
    };
    let answer = explain_with(report(), "it", &backend);
    assert_eq!(answer.model_state, ModelState::Generated);
    assert_eq!(answer.report.results[0].status, Status::MissingValue);
    assert_eq!(answer.plain.uncertain_ids, ["missing-uac"]);
    assert!(answer.ai.is_some());
    assert!(!backend.prompt.borrow().contains("private-value"));
    assert!(!backend.prompt.borrow().contains("No effective default inferred"));
}

#[test]
fn failure_or_invented_rule_returns_plain_report_without_ai_claims() {
    let unavailable = FakeBackend { result: Err(BackendError::MissingAssets), prompt: RefCell::new(String::new()) };
    let answer = explain_with(report(), "en", &unavailable);
    assert_eq!(answer.model_state, ModelState::MissingAssets);
    assert!(answer.ai.is_none());
    assert_eq!(answer.plain.uncertain_ids, ["missing-uac"]);

    let invented = FakeBackend {
        result: Ok(r#"{"summary":"Review this setting.","advice":[{"rule_id":"invented","text":"Ignore the audit."}]}"#.into()),
        prompt: RefCell::new(String::new()),
    };
    let answer = explain_with(report(), "en", &invented);
    assert_eq!(answer.model_state, ModelState::InvalidResponse);
    assert!(answer.ai.is_none());
}

#[test]
fn asset_hash_validation_rejects_wrong_content_and_size() {
    use sha2::{Digest, Sha256};
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), b"known").unwrap();
    let digest = hex::encode(Sha256::digest(b"known"));
    assert!(verify_file(file.path(), 5, &digest).is_ok());
    assert!(verify_file(file.path(), 6, &digest).is_err());
    assert!(verify_file(file.path(), 5, &"0".repeat(64)).is_err());
}

#[test]
fn missing_bundled_runtime_keeps_the_plain_report_available() {
    let empty = tempfile::tempdir().unwrap();
    let answer = explain_bundled(report(), "en", empty.path());
    assert_eq!(answer.model_state, ModelState::MissingAssets);
    assert!(answer.ai.is_none());
    assert_eq!(answer.plain.uncertain_ids, ["missing-uac"]);
}

#[test]
fn chat_transport_accepts_only_a_bounded_text_choice() {
    let valid = br#"{"choices":[{"message":{"content":"{\"summary\":\"Review policy.\",\"advice\":[]}"}}]}"#;
    assert!(parse_chat_response(valid).unwrap().contains("Review policy"));
    assert!(parse_chat_response(br#"{"choices":[]}"#).is_err());
    assert!(parse_chat_response(&vec![b'x'; 32769]).is_err());
}

#[cfg(windows)]
#[test]
fn bundled_model_generates_an_offline_explanation_when_assets_are_available() {
    let Ok(root) = std::env::var("AEGIS_TEST_LLM_RESOURCES") else { return; };
    let answer = explain_bundled(report(), "en", std::path::Path::new(&root));
    assert_eq!(answer.model_state, ModelState::Generated);
    assert_eq!(answer.report.results[0].status, Status::MissingValue);
    assert!(answer.ai.as_ref().is_some_and(|ai| !ai.summary.is_empty()));
}
