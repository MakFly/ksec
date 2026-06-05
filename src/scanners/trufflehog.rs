use crate::scanner::{Category, Finding, Scanner, Severity};
use serde::Deserialize;
use std::path::Path;
use std::process::Output;
use tokio::process::Command;

pub struct TruffleHog;

#[derive(Deserialize)]
struct TruffleHogMatch {
    #[serde(rename = "DetectorName")]
    detector_name: Option<String>,
    #[serde(rename = "Verified")]
    verified: Option<bool>,
    #[serde(rename = "SourceMetadata")]
    source_metadata: Option<serde_json::Value>,
}

impl Scanner for TruffleHog {
    fn name(&self) -> &str {
        "trufflehog"
    }
    fn binary(&self) -> &str {
        "trufflehog"
    }
    fn category(&self) -> Category {
        Category::Secrets
    }
    fn install_hint(&self) -> &str {
        "brew install trufflehog | go install github.com/trufflesecurity/trufflehog/v3@latest"
    }
    fn build_command(&self, target: &Path) -> Command {
        let mut cmd = Command::new("trufflehog");
        cmd.args(["filesystem", &target.to_string_lossy(), "--json", "--no-update"]);
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        cmd
    }
    fn parse_output(&self, output: &Output) -> Vec<Finding> {
        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout
            .lines()
            .filter_map(|line| serde_json::from_str::<TruffleHogMatch>(line).ok())
            .map(|m| {
                let verified = m.verified.unwrap_or(false);
                let severity = if verified {
                    Severity::Critical
                } else {
                    Severity::High
                };
                let file = m
                    .source_metadata
                    .as_ref()
                    .and_then(|sm| sm.get("Data"))
                    .and_then(|d| d.get("Filesystem"))
                    .and_then(|fs| fs.get("file"))
                    .and_then(|f| f.as_str())
                    .map(String::from);
                let verified_label = if verified { " [VERIFIED ACTIVE]" } else { "" };
                Finding {
                    severity,
                    category: Category::Secrets,
                    scanner: "trufflehog".into(),
                    title: format!(
                        "{}{}",
                        m.detector_name.unwrap_or_else(|| "secret".into()),
                        verified_label
                    ),
                    file,
                    line: None,
                    detail: None,
                }
            })
            .collect()
    }
}
