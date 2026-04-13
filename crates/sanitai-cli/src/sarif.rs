//! SARIF 2.1.0 output serializer.
//!
//! Produces valid SARIF 2.1.0 JSON for consumption by GitHub Code Scanning,
//! Visual Studio, and other SAST integration points.
//!
//! Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
//!
//! Design notes:
//! - Hand-rolled structs so we never pull an unvetted SARIF crate into the
//!   build. The schema surface we care about is small.
//! - `matched_raw` is never surfaced. SARIF consumers get detector id,
//!   byte offsets, confidence level, and transform chain only.
//! - Rules are deduplicated by `detector_id` so the driver.rules array
//!   matches the universe of rules that actually produced a result.

use std::collections::HashSet;

use sanitai_core::finding::{Confidence, Finding, Transform};
use serde::Serialize;

#[derive(Serialize)]
pub struct SarifLog {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
pub struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
pub struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
pub struct SarifDriver {
    name: &'static str,
    version: String,
    #[serde(rename = "informationUri")]
    information_uri: &'static str,
    rules: Vec<SarifRule>,
}

#[derive(Serialize)]
pub struct SarifRule {
    id: String,
    name: String,
    #[serde(rename = "shortDescription")]
    short_description: SarifMessage,
    #[serde(rename = "defaultConfiguration")]
    default_configuration: SarifConfig,
}

#[derive(Serialize)]
pub struct SarifConfig {
    level: &'static str,
}

#[derive(Serialize)]
pub struct SarifMessage {
    text: String,
}

#[derive(Serialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: &'static str,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
    properties: SarifProperties,
}

#[derive(Serialize)]
pub struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
pub struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation,
    region: SarifRegion,
}

#[derive(Serialize)]
pub struct SarifArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
pub struct SarifRegion {
    #[serde(rename = "byteOffset")]
    byte_offset: usize,
    #[serde(rename = "byteLength")]
    byte_length: usize,
}

#[derive(Serialize)]
pub struct SarifProperties {
    turn: usize,
    confidence: &'static str,
    transforms: Vec<&'static str>,
    synthetic: bool,
    // These fields land with Phase 0. Until then they carry sensible
    // defaults so consumers see a stable shape.
    #[serde(rename = "contextClass")]
    context_class: &'static str,
    category: &'static str,
}

fn confidence_str(c: &Confidence) -> &'static str {
    match c {
        Confidence::High => "high",
        Confidence::Medium => "medium",
        Confidence::Low => "low",
    }
}

fn confidence_level(c: &Confidence) -> &'static str {
    match c {
        Confidence::High => "error",
        Confidence::Medium => "warning",
        Confidence::Low => "note",
    }
}

fn transform_str(t: &Transform) -> &'static str {
    match t {
        Transform::Base64 => "base64",
        Transform::Hex => "hex",
        Transform::UrlEncoded => "url",
        Transform::Gzip => "gzip",
        Transform::HtmlEntity => "html",
    }
}

pub fn findings_to_sarif(findings: &[Finding], tool_version: &str) -> SarifLog {
    let mut seen_rules: HashSet<&str> = HashSet::new();
    let rules: Vec<SarifRule> = findings
        .iter()
        .filter_map(|f| {
            if seen_rules.insert(f.detector_id) {
                Some(SarifRule {
                    id: f.detector_id.to_string(),
                    name: f.detector_id.to_string(),
                    short_description: SarifMessage {
                        text: format!("Detected potential secret: {}", f.detector_id),
                    },
                    default_configuration: SarifConfig { level: "error" },
                })
            } else {
                None
            }
        })
        .collect();

    let results: Vec<SarifResult> = findings
        .iter()
        .map(|f| SarifResult {
            rule_id: f.detector_id.to_string(),
            level: confidence_level(&f.confidence),
            message: SarifMessage {
                text: format!(
                    "{} detected at bytes {}..{}",
                    f.detector_id, f.byte_range.start, f.byte_range.end
                ),
            },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: f.turn_id.0.to_string_lossy().into_owned(),
                    },
                    region: SarifRegion {
                        byte_offset: f.byte_range.start,
                        byte_length: f.byte_range.end.saturating_sub(f.byte_range.start),
                    },
                },
            }],
            properties: SarifProperties {
                turn: f.turn_id.1,
                confidence: confidence_str(&f.confidence),
                transforms: f.transform.0.iter().map(transform_str).collect(),
                synthetic: f.synthetic,
                context_class: "unclassified",
                category: "credential",
            },
        })
        .collect();

    SarifLog {
        schema: "https://json.schemastore.org/sarif-2.1.0.json",
        version: "2.1.0",
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "sanitai",
                    version: tool_version.to_string(),
                    information_uri: "https://github.com/sanitai/sanitai",
                    rules,
                },
            },
            results,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sanitai_core::finding::{SpanKind, TransformChain};
    use std::path::PathBuf;
    use std::sync::Arc;

    fn mk_finding(detector: &'static str, confidence: Confidence) -> Finding {
        Finding {
            turn_id: (Arc::new(PathBuf::from("/tmp/test.jsonl")), 7),
            detector_id: detector,
            byte_range: 10..25,
            matched_raw: "REDACTED".to_string(),
            transform: TransformChain::default(),
            confidence,
            span_kind: SpanKind::Single,
            synthetic: false,
        }
    }

    #[test]
    fn sarif_output_has_schema_and_version() {
        let findings = vec![mk_finding("aws_access_key", Confidence::High)];
        let log = findings_to_sarif(&findings, "0.1.2");
        let json = serde_json::to_string(&log).expect("ser");
        assert!(json.contains("2.1.0"));
        assert!(json.contains("sarif"));
        assert!(json.contains("sanitai"));
        assert!(json.contains("aws_access_key"));
    }

    #[test]
    fn sarif_output_for_empty_findings() {
        let log = findings_to_sarif(&[], "0.1.2");
        let json = serde_json::to_string(&log).expect("ser");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(parsed["version"], "2.1.0");
        assert_eq!(
            parsed["runs"][0]["results"]
                .as_array()
                .map(|a| a.len())
                .unwrap_or(99),
            0
        );
        assert_eq!(
            parsed["runs"][0]["tool"]["driver"]["rules"]
                .as_array()
                .map(|a| a.len())
                .unwrap_or(99),
            0
        );
    }

    #[test]
    fn sarif_dedupes_rules_per_detector() {
        let findings = vec![
            mk_finding("aws_access_key", Confidence::High),
            mk_finding("aws_access_key", Confidence::Medium),
            mk_finding("github_pat", Confidence::Low),
        ];
        let log = findings_to_sarif(&findings, "0.1.2");
        let json = serde_json::to_value(&log).expect("ser");
        let rules = json["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .expect("rules array");
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn never_leaks_matched_raw() {
        let mut f = mk_finding("aws_access_key", Confidence::High);
        f.matched_raw = "AKIATOPSECRETVALUE12".to_string();
        let log = findings_to_sarif(&[f], "0.1.2");
        let json = serde_json::to_string(&log).expect("ser");
        assert!(!json.contains("AKIATOPSECRETVALUE12"));
    }
}
