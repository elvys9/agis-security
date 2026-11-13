//! Presentation-only audit summaries. Model text never changes a hardening verdict.
use crate::hardening::{Report, Status};
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Serialize)]
pub struct PlainReport {
    pub matching_count: usize,
    pub differing_ids: Vec<String>,
    pub uncertain_ids: Vec<String>,
}

pub fn plain_report(report: &Report) -> PlainReport {
    let mut plain = PlainReport {
        matching_count: 0,
        differing_ids: Vec::new(),
        uncertain_ids: Vec::new(),
    };
    for result in &report.results {
        match result.status {
            Status::Compliant => plain.matching_count += 1,
            Status::NonCompliant => plain.differing_ids.push(result.id.clone()),
            _ => plain.uncertain_ids.push(result.id.clone()),
        }
    }
    plain
}

/// Only bundled rule text and categorical states cross into the model process.
pub fn model_input(report: &Report) -> serde_json::Value {
    serde_json::json!({
        "catalog_version": report.catalog_version,
        "rules": report.results.iter().map(|item| serde_json::json!({
            "id": item.id,
            "title": item.title,
            "description": item.description,
            "expected": item.expected,
            "status": item.status,
            "source_url": item.source_url,
        })).collect::<Vec<_>>()
    })
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelAdvice {
    pub rule_id: String,
    pub text: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelOutput {
    pub summary: String,
    pub advice: Vec<ModelAdvice>,
}

fn acceptable(text: &str, max_chars: usize) -> bool {
    let length = text.chars().count();
    length > 0 && length <= max_chars && !text.chars().any(|ch| ch.is_control())
}

pub fn validate_model_output(text: &str, report: &Report) -> Result<ModelOutput> {
    if text.len() > 8 * 1024 { bail!("Model output is too large"); }
    let output: ModelOutput = serde_json::from_str(text)?;
    if !acceptable(&output.summary, 600) || output.advice.len() > report.results.len().min(8) {
        bail!("Invalid model summary or advice count");
    }
    let known: HashSet<_> = report.results.iter().map(|item| item.id.as_str()).collect();
    let mut seen = HashSet::new();
    for advice in &output.advice {
        if !known.contains(advice.rule_id.as_str()) || !seen.insert(advice.rule_id.as_str())
            || !acceptable(&advice.text, 400) {
            bail!("Invalid or duplicate model advice");
        }
    }
    Ok(output)
}
