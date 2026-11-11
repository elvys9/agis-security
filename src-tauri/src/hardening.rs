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

fn decode_registry_value(kind: u32, bytes: &[u8]) -> ProbeValue {
    if bytes.len() > 64 * 1024 { return ProbeValue::Unknown("Registry value exceeds 64 KiB".into()); }
    if kind == 4 {
        return if bytes.len() == 4 {
            ProbeValue::Dword(u32::from_le_bytes(bytes.try_into().expect("length checked")))
        } else {
            ProbeValue::Unknown("Malformed REG_DWORD length".into())
        };
    }
    if kind != 1 && kind != 7 {
        return ProbeValue::Unknown(format!("Unsupported registry type {kind}"));
    }
    if bytes.len() < if kind == 7 { 4 } else { 2 } || bytes.len() % 2 != 0 {
        return ProbeValue::Unknown("Malformed UTF-16 registry length".into());
    }
    let units: Vec<u16> = bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
    if kind == 1 {
        if units.last() != Some(&0) || units[..units.len() - 1].contains(&0) {
            return ProbeValue::Unknown("Malformed REG_SZ terminator".into());
        }
        return match String::from_utf16(&units[..units.len() - 1]) {
            Ok(value) => ProbeValue::Sz(value),
            Err(_) => ProbeValue::Unknown("Invalid REG_SZ UTF-16".into()),
        };
    }
    if !units.ends_with(&[0, 0]) {
        return ProbeValue::Unknown("Malformed REG_MULTI_SZ terminators".into());
    }
    if units == [0, 0] { return ProbeValue::MultiSz(Vec::new()); }
    let mut values = Vec::new();
    let mut start = 0usize;
    for (index, &unit) in units.iter().enumerate() {
        if unit != 0 { continue; }
        if index == start {
            if index != units.len() - 1 {
                return ProbeValue::Unknown("Empty REG_MULTI_SZ element".into());
            }
            break;
        }
        match String::from_utf16(&units[start..index]) {
            Ok(value) => values.push(value),
            Err(_) => return ProbeValue::Unknown("Invalid REG_MULTI_SZ UTF-16".into()),
        }
        start = index + 1;
    }
    ProbeValue::MultiSz(values)
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

pub fn audit_system() -> Result<Report> {
    let catalog = Catalog::parse(include_str!("../../catalog/rules.json"))?;
    #[cfg(windows)]
    { Ok(evaluate(&catalog, &WindowsRegistryProbe)) }
    #[cfg(not(windows))]
    { Ok(evaluate(&catalog, &OtherPlatformProbe)) }
}

#[cfg(not(windows))]
struct OtherPlatformProbe;
#[cfg(not(windows))]
impl Probe for OtherPlatformProbe {
    fn read(&self, _: &Rule) -> ProbeValue { ProbeValue::NotApplicable }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use windows_sys::Win32::{
        Foundation::{ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_SUCCESS},
        System::Registry::{
            RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_CURRENT_USER,
            HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY,
        },
    };

    const MAX_REGISTRY_BYTES: u32 = 64 * 1024;
    struct OpenKey(HKEY);
    impl Drop for OpenKey {
        fn drop(&mut self) { unsafe { RegCloseKey(self.0); } }
    }

    #[repr(C)]
    struct OsVersion {
        size: u32, major: u32, minor: u32, build: u32, platform: u32, service_pack: [u16; 128],
    }
    #[link(name = "ntdll")]
    extern "system" { fn RtlGetVersion(info: *mut OsVersion) -> i32; }

    pub struct WindowsRegistryProbe;
    impl Probe for WindowsRegistryProbe {
        fn os_build(&self) -> Option<u32> {
            let mut version = OsVersion {
                size: std::mem::size_of::<OsVersion>() as u32,
                major: 0, minor: 0, build: 0, platform: 0, service_pack: [0; 128],
            };
            if unsafe { RtlGetVersion(&mut version) } == 0 { Some(version.build) } else { None }
        }
        fn read(&self, rule: &Rule) -> ProbeValue {
            let ProbeSpec::Registry { hive, key, value } = &rule.probe;
            let root = match hive {
                Hive::LocalMachine => HKEY_LOCAL_MACHINE,
                Hive::CurrentUser => HKEY_CURRENT_USER,
            };
            let wide_key: Vec<u16> = key.encode_utf16().chain(Some(0)).collect();
            let wide_value: Vec<u16> = value.encode_utf16().chain(Some(0)).collect();
            let mut handle = std::ptr::null_mut();
            let open = unsafe {
                RegOpenKeyExW(root, wide_key.as_ptr(), 0, KEY_READ | KEY_WOW64_64KEY, &mut handle)
            };
            match open {
                ERROR_FILE_NOT_FOUND => return ProbeValue::MissingKey,
                ERROR_ACCESS_DENIED => return ProbeValue::AccessDenied,
                ERROR_SUCCESS => {},
                code => return ProbeValue::Unknown(format!("RegOpenKeyExW error {code}")),
            }
            let _key = OpenKey(handle);
            if matches!(rule.expected, Expected::KeyAbsent) {
                return ProbeValue::KeyPresent;
            }
            for _ in 0..3 {
                let mut kind = 0;
                let mut size = 0;
                let query = unsafe {
                    RegQueryValueExW(handle, wide_value.as_ptr(), std::ptr::null(), &mut kind,
                        std::ptr::null_mut(), &mut size)
                };
                match query {
                    ERROR_FILE_NOT_FOUND => return ProbeValue::MissingValue,
                    ERROR_ACCESS_DENIED => return ProbeValue::AccessDenied,
                    ERROR_SUCCESS | ERROR_MORE_DATA => {},
                    code => return ProbeValue::Unknown(format!("RegQueryValueExW error {code}")),
                }
                if size > MAX_REGISTRY_BYTES {
                    return ProbeValue::Unknown("Registry value exceeds 64 KiB".into());
                }
                let mut bytes = vec![0u8; size as usize];
                let mut actual = size;
                let data = if bytes.is_empty() { std::ptr::null_mut() } else { bytes.as_mut_ptr() };
                let read = unsafe {
                    RegQueryValueExW(handle, wide_value.as_ptr(), std::ptr::null(), &mut kind,
                        data, &mut actual)
                };
                match read {
                    ERROR_MORE_DATA => continue,
                    ERROR_FILE_NOT_FOUND => return ProbeValue::MissingValue,
                    ERROR_ACCESS_DENIED => return ProbeValue::AccessDenied,
                    ERROR_SUCCESS => {
                        if actual > size {
                            return ProbeValue::Unknown("Registry size changed during read".into());
                        }
                        bytes.truncate(actual as usize);
                        return decode_registry_value(kind, &bytes);
                    }
                    code => return ProbeValue::Unknown(format!("RegQueryValueExW error {code}")),
                }
            }
            ProbeValue::Unknown("Registry value changed repeatedly during read".into())
        }
    }
}
#[cfg(windows)]
pub use windows::WindowsRegistryProbe;

#[cfg(test)]
mod registry_decode_tests {
    use super::{decode_registry_value, ProbeValue};

    fn wide(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn decodes_only_well_formed_registry_values() {
        assert!(matches!(decode_registry_value(4, &[1, 0, 0, 0]), ProbeValue::Dword(1)));
        assert!(matches!(decode_registry_value(4, &[1, 0]), ProbeValue::Unknown(_)));
        assert!(matches!(decode_registry_value(1, &wide("safe\0")), ProbeValue::Sz(value) if value == "safe"));
        assert!(matches!(decode_registry_value(1, &wide("unterminated")), ProbeValue::Unknown(_)));
        assert!(matches!(decode_registry_value(7, &wide("alpha\0beta\0\0")), ProbeValue::MultiSz(values) if values == ["alpha", "beta"]));
        assert!(matches!(decode_registry_value(7, &wide("\0\0")), ProbeValue::MultiSz(values) if values.is_empty()));
        assert!(matches!(decode_registry_value(7, &wide("alpha\0beta\0")), ProbeValue::Unknown(_)));
        assert!(matches!(decode_registry_value(3, &[1, 2, 3]), ProbeValue::Unknown(_)));
    }
}
