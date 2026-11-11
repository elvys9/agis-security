use aegis_engine::hardening::{evaluate, Catalog, Probe, ProbeValue, Rule, Status};
use std::collections::HashMap;

struct FakeProbe {
    values: HashMap<String, ProbeValue>,
    build: Option<u32>,
}
impl Probe for FakeProbe {
    fn read(&self, rule: &Rule) -> ProbeValue {
        self.values.get(&rule.id).cloned().unwrap_or(ProbeValue::MissingValue)
    }
    fn os_build(&self) -> Option<u32> { self.build }
}
fn fake(values: &[(&str, ProbeValue)], build: Option<u32>) -> FakeProbe {
    FakeProbe {
        values: values.iter().map(|(id, value)| (id.to_string(), value.clone())).collect(),
        build,
    }
}
const RULES: &str = r#"{
  "version": 1,
  "rules": [
    {
      "id": "uac", "title": "UAC enabled", "category": "UAC",
      "description": "Registry configuration only",
      "source_url": "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/958053ae-5397-4f96-977f-b7700ee461ec",
      "verify": false,
      "probe": {"kind":"registry","hive":"HKLM","key":"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System","value":"EnableLUA"},
      "expected": {"kind":"dword_eq","value":1}
    },
    {
      "id": "uac-secure-desktop", "title": "Secure desktop", "category": "UAC",
      "description": "Registry configuration only",
      "source_url": "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/9ad50fd3-4d8d-4870-9f5b-978ce292b9d8",
      "verify": false,
      "probe": {"kind":"registry","hive":"HKLM","key":"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System","value":"PromptOnSecureDesktop"},
      "expected": {"kind":"dword_eq","value":1}
    },
    {
      "id": "llmnr", "title": "LLMNR", "category": "Networking",
      "description": "Requires an effective-policy check",
      "source_url": "https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-dnsclient",
      "verify": true,
      "min_build": 22000,
      "probe": {"kind":"registry","hive":"HKLM","key":"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient","value":"EnableMulticast"},
      "expected": {"kind":"dword_eq","value":0}
    }
  ]
}"#;

#[test]
fn matches_typed_dword_without_elevating_privileges() {
    let catalog = Catalog::parse(RULES).unwrap();
    let report = evaluate(&catalog, &fake(&[
        ("uac", ProbeValue::Dword(1)),
        ("uac-secure-desktop", ProbeValue::Dword(0)),
        ("llmnr", ProbeValue::Dword(0)),
    ], Some(22631)));
    assert_eq!(report.results[0].status, Status::Compliant);
    assert_eq!(report.results[1].status, Status::NonCompliant);
    assert_eq!(report.results[2].status, Status::UnknownEffectiveState);
}

#[test]
fn missing_and_denied_are_not_reported_as_insecure() {
    let catalog = Catalog::parse(RULES).unwrap();
    let report = evaluate(&catalog, &fake(&[
        ("uac", ProbeValue::MissingKey),
        ("uac-secure-desktop", ProbeValue::AccessDenied),
        ("llmnr", ProbeValue::MissingValue),
    ], Some(22631)));
    assert_eq!(report.results[0].status, Status::MissingKey);
    assert_eq!(report.results[1].status, Status::AccessDenied);
    assert_eq!(report.results[2].status, Status::MissingValue);
    assert_eq!(report.non_compliant, 0);
}

#[test]
fn applicability_and_external_management_remain_distinct() {
    let catalog = Catalog::parse(RULES).unwrap();
    let report = evaluate(&catalog, &fake(&[
        ("uac", ProbeValue::ManagedExternally),
        ("uac-secure-desktop", ProbeValue::Dword(1)),
        ("llmnr", ProbeValue::Dword(0)),
    ], Some(19045)));
    assert_eq!(report.results[0].status, Status::ManagedExternally);
    assert_eq!(report.results[2].status, Status::NotApplicable);
}

#[test]
fn string_multi_string_bitmask_and_type_mismatch_are_checked() {
    let catalog = Catalog::parse(r#"{"version":1,"rules":[
      {"id":"str","title":"String","category":"Test","description":"Test","source_url":"https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types","verify":false,"probe":{"kind":"registry","hive":"HKCU","key":"Software\\Aegis","value":"Text"},"expected":{"kind":"sz_eq","value":"safe"}},
      {"id":"multi","title":"Multi","category":"Test","description":"Test","source_url":"https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types","verify":false,"probe":{"kind":"registry","hive":"HKCU","key":"Software\\Aegis","value":"Names"},"expected":{"kind":"multi_contains","value":"alpha"}},
      {"id":"mask","title":"Mask","category":"Test","description":"Test","source_url":"https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types","verify":false,"probe":{"kind":"registry","hive":"HKCU","key":"Software\\Aegis","value":"Flags"},"expected":{"kind":"dword_bitmask_all","mask":3}}
    ]}"#).unwrap();
    let report = evaluate(&catalog, &fake(&[
        ("str", ProbeValue::Sz("safe".into())),
        ("multi", ProbeValue::MultiSz(vec!["alpha".into(), "beta".into()])),
        ("mask", ProbeValue::Dword(7)),
    ], None));
    assert!(report.results.iter().all(|result| result.status == Status::Compliant));
    let mismatch = evaluate(&catalog, &fake(&[("str", ProbeValue::Dword(1))], None));
    assert_eq!(mismatch.results[0].status, Status::UnknownEffectiveState);
}

#[test]
fn catalog_rejects_untrusted_sources_and_duplicate_rules() {
    assert!(Catalog::parse(&RULES.replace("https://learn.microsoft.com/", "http://example.com/")).is_err());
    assert!(Catalog::parse(&RULES.replace("\"uac-secure-desktop\"", "\"uac\"")).is_err());
}

#[test]
fn bundled_rules_are_original_sourced_and_explicit_about_uncertainty() {
    let catalog = Catalog::parse(include_str!("../../catalog/rules.json")).unwrap();
    assert_eq!(catalog.rules.len(), 5);
    assert!(catalog.rules.iter().all(|rule| rule.source_url.starts_with("https://learn.microsoft.com/")));
    assert_eq!(catalog.rules.iter().filter(|rule| rule.verify).count(), 2);
}
