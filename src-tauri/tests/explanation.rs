use aegis_engine::explanation::{model_input, plain_report, validate_model_output};
use aegis_engine::hardening::{Report, ResultItem, Status};

fn item(id: &str, status: Status, observed: Option<&str>) -> ResultItem {
    ResultItem {
        id: id.into(), title: format!("Rule {id}"), category: "Policy".into(),
        description: "Bundled rule description".into(),
        source_url: "https://learn.microsoft.com/en-us/windows/security/".into(),
        status, observed: observed.map(str::to_owned), expected: "DWORD = 1".into(),
        reason: "Stored policy only".into(),
    }
}

fn report() -> Report {
    Report {
        catalog_version: 1, total: 4, compliant: 1, non_compliant: 1, inconclusive: 2,
        results: vec![
            item("good", Status::Compliant, None),
            item("different", Status::NonCompliant, Some("0")),
            item("missing", Status::MissingValue, None),
            item("unknown", Status::UnknownEffectiveState, Some("private-registry-value")),
        ],
    }
}

#[test]
fn plain_report_keeps_missing_and_unknown_out_of_differing_list() {
    let plain = plain_report(&report());
    assert_eq!(plain.differing_ids, ["different"]);
    assert_eq!(plain.uncertain_ids, ["missing", "unknown"]);
    assert_eq!(plain.matching_count, 1);
}

#[test]
fn model_input_does_not_disclose_raw_registry_values() {
    let input = model_input(&report());
    let encoded = serde_json::to_string(&input).unwrap();
    assert!(!encoded.contains("private-registry-value"));
    assert!(!encoded.contains("Stored policy only"));
    assert!(encoded.contains("UnknownEffectiveState"));
    assert!(encoded.contains("learn.microsoft.com"));
}

#[test]
fn output_rejects_invented_ids_duplicates_and_long_text() {
    let valid = r#"{"summary":"One policy differs and two require review.","advice":[{"rule_id":"different","text":"Review the documented policy."}]}"#;
    assert_eq!(validate_model_output(valid, &report()).unwrap().advice.len(), 1);
    assert!(validate_model_output(&valid.replace("different\",\"text", "invented\",\"text"), &report()).is_err());
    assert!(validate_model_output(r#"{"summary":"Review results.","advice":[{"rule_id":"different","text":"Check policy."},{"rule_id":"different","text":"Check again."}]}"#, &report()).is_err());
    let oversized = format!(r#"{{"summary":"{}","advice":[]}}"#, "x".repeat(700));
    assert!(validate_model_output(&oversized, &report()).is_err());
}
