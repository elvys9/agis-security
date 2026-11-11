//! Read-only configuration assessment. No remediation or process execution.
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

const MAX_CATALOG_BYTES: usize = 128 * 1024;
const MAX_RULES: usize = 128;
const MAX_DISPLAY_CHARS: usize = 128;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    pub version: u32,
    pub rules: Vec<Rule>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub title: String,
    pub category: String,
    pub description: String,
    pub source_url: String,
    pub verify: bool,
    #[serde(default)]
    pub min_build: Option<u32>,
    pub probe: ProbeSpec,
    pub expected: Expected,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProbeSpec {
    Registry { hive: Hive, key: String, value: String },
}

#[derive(Clone, Copy, Debug, Deserialize)]
pub enum Hive {
    #[serde(rename = "HKLM")]
    LocalMachine,
    #[serde(rename = "HKCU")]
    CurrentUser,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Expected {
    DwordEq { value: u32 },
    DwordMin { value: u32 },
    DwordBitmaskAll { mask: u32 },
    SzEq { value: String },
    MultiContains { value: String },
    KeyAbsent,
}

#[derive(Clone, Debug)]
pub enum ProbeValue {
    Dword(u32),
    Sz(String),
    MultiSz(Vec<String>),
    KeyPresent,
    MissingKey,
    MissingValue,
    AccessDenied,
    NotApplicable,
    ManagedExternally,
    Unknown(String),
}

pub trait Probe {
    fn read(&self, rule: &Rule) -> ProbeValue;
    fn os_build(&self) -> Option<u32> { None }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum Status {
    Compliant,
    NonCompliant,
    MissingKey,
    MissingValue,
    AccessDenied,
    NotApplicable,
    ManagedExternally,
    UnknownEffectiveState,
}

#[derive(Clone, Debug, Serialize)]
pub struct ResultItem {
    pub id: String,
    pub title: String,
    pub category: String,
    pub description: String,
    pub source_url: String,
    pub status: Status,
    pub observed: Option<String>,
    pub expected: String,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub catalog_version: u32,
    pub total: usize,
    pub compliant: usize,
    pub non_compliant: usize,
    pub inconclusive: usize,
    pub results: Vec<ResultItem>,
}

impl Catalog {
    pub fn parse(text: &str) -> Result<Self> {
        if text.len() > MAX_CATALOG_BYTES { bail!("Rule catalog is too large"); }
        let catalog: Self = serde_json::from_str(text)?;
        if catalog.version != 1 || catalog.rules.is_empty() || catalog.rules.len() > MAX_RULES {
            bail!("Unsupported catalog version or rule count");
        }
        let mut ids = HashSet::new();
        for rule in &catalog.rules {
            if rule.id.is_empty() || rule.id.len() > 64
                || !rule.id.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                || !ids.insert(rule.id.as_str()) {
                bail!("Invalid or duplicate rule identifier");
            }
            if rule.title.is_empty() || rule.title.len() > 160 || rule.category.is_empty()
                || rule.category.len() > 80 || rule.description.len() > 512 {
                bail!("Invalid rule text");
            }
            let url = reqwest::Url::parse(&rule.source_url)?;
            if url.scheme() != "https" || url.host_str() != Some("learn.microsoft.com")
                || !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
                bail!("A rule source must be a Microsoft Learn HTTPS URL");
            }
            match &rule.probe {
                ProbeSpec::Registry { key, value, .. } => {
                    if key.is_empty() || key.len() > 512 || value.len() > 160
                        || key.contains('\0') || value.contains('\0')
                        || key.split('\\').any(|part| part.is_empty() || part == "..") {
                        bail!("Invalid registry probe");
                    }
                }
            }
            match &rule.expected {
                Expected::SzEq { value } | Expected::MultiContains { value }
                    if value.is_empty() || value.len() > 256 || value.contains('\0') => {
                    bail!("Invalid expected string");
                }
                _ => {}
            }
        }
        Ok(catalog)
    }
}

fn display(text: &str) -> String {
    text.chars().take(MAX_DISPLAY_CHARS).map(|ch| {
        if ch.is_control() { '�' } else { ch }
    }).collect()
}

fn observed(value: &ProbeValue) -> Option<String> {
    match value {
        ProbeValue::Dword(number) => Some(number.to_string()),
        ProbeValue::Sz(text) => Some(display(text)),
        ProbeValue::MultiSz(items) => Some(display(&items.join("; "))),
        ProbeValue::KeyPresent => Some("Key exists".into()),
        _ => None,
    }
}

fn expected_text(expected: &Expected) -> String {
    match expected {
        Expected::DwordEq { value } => format!("DWORD = {value}"),
        Expected::DwordMin { value } => format!("DWORD >= {value}"),
        Expected::DwordBitmaskAll { mask } => format!("DWORD contains bits 0x{mask:08x}"),
        Expected::SzEq { value } => format!("REG_SZ = {}", display(value)),
        Expected::MultiContains { value } => format!("REG_MULTI_SZ contains {}", display(value)),
        Expected::KeyAbsent => "Key absent".into(),
    }
}

fn assess(rule: &Rule, value: &ProbeValue) -> (Status, &'static str) {
    match value {
        ProbeValue::NotApplicable => return (Status::NotApplicable, "Rule is not applicable"),
        ProbeValue::ManagedExternally => return (Status::ManagedExternally, "Managed by another policy source"),
        ProbeValue::AccessDenied => return (Status::AccessDenied, "Current user cannot read this setting"),
        ProbeValue::Unknown(_) => return (Status::UnknownEffectiveState, "Probe could not establish a trustworthy value"),
        ProbeValue::MissingKey => {
            if matches!(rule.expected, Expected::KeyAbsent) && !rule.verify {
                return (Status::Compliant, "Documented key-absence condition observed");
            }
            return (Status::MissingKey, "Key is absent; effective default is not inferred");
        }
        ProbeValue::MissingValue => return (Status::MissingValue, "Value is absent; effective default is not inferred"),
        _ => {}
    }
    if rule.verify {
        return (Status::UnknownEffectiveState, "Rule requires verification for this OS configuration");
    }
    let matches = match (&rule.expected, value) {
        (Expected::DwordEq { value: want }, ProbeValue::Dword(got)) => *got == *want,
        (Expected::DwordMin { value: want }, ProbeValue::Dword(got)) => *got >= *want,
        (Expected::DwordBitmaskAll { mask }, ProbeValue::Dword(got)) => *got & *mask == *mask,
        (Expected::SzEq { value: want }, ProbeValue::Sz(got)) => got.eq_ignore_ascii_case(want),
        (Expected::MultiContains { value: want }, ProbeValue::MultiSz(got)) =>
            got.iter().any(|item| item.eq_ignore_ascii_case(want)),
        (Expected::KeyAbsent, ProbeValue::KeyPresent) => false,
        _ => return (Status::UnknownEffectiveState, "Registry value type does not match the rule"),
    };
    if matches {
        (Status::Compliant, "Observed configuration matches the rule")
    } else {
        (Status::NonCompliant, "Observed configuration differs from the rule")
    }
}

pub fn evaluate<P: Probe>(catalog: &Catalog, probe: &P) -> Report {
    let results: Vec<_> = catalog.rules.iter().map(|rule| {
        let value = if let Some(min_build) = rule.min_build {
            match probe.os_build() {
                Some(build) if build < min_build => ProbeValue::NotApplicable,
                None => ProbeValue::Unknown("Windows build is unavailable".into()),
                _ => probe.read(rule),
            }
        } else {
            probe.read(rule)
        };
        let (status, reason) = assess(rule, &value);
        ResultItem {
            id: rule.id.clone(),
            title: rule.title.clone(),
            category: rule.category.clone(),
            description: rule.description.clone(),
            source_url: rule.source_url.clone(),
            status,
            observed: observed(&value),
            expected: expected_text(&rule.expected),
            reason: match value {
                ProbeValue::Unknown(ref details) => format!("{reason}: {}", display(details)),
                _ => reason.into(),
            },
        }
    }).collect();
    let compliant = results.iter().filter(|result| result.status == Status::Compliant).count();
    let non_compliant = results.iter().filter(|result| result.status == Status::NonCompliant).count();
    Report {
        catalog_version: catalog.version,
        total: results.len(),
        compliant,
        non_compliant,
        inconclusive: results.len() - compliant - non_compliant,
        results,
    }
}
