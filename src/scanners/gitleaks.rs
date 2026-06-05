use crate::scanner::{Category, Finding, Scanner, Severity};
use serde::Deserialize;
use std::path::Path;
use std::process::Output;
use tokio::process::Command;

pub struct Gitleaks;

#[derive(Deserialize)]
struct GitleaksMatch {
    #[serde(rename = "RuleID")]
    rule_id: Option<String>,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[serde(rename = "File")]
    file: Option<String>,
    #[serde(rename = "StartLine")]
    start_line: Option<u32>,
}

impl Scanner for Gitleaks {
    fn name(&self) -> &str {
        "gitleaks"
    }
    fn binary(&self) -> &str {
        "gitleaks"
    }
    fn category(&self) -> Category {
        Category::Secrets
    }
    fn install_hint(&self) -> &str {
        "brew install gitleaks | go install github.com/gitleaks/gitleaks/v8@latest"
    }
    fn build_command(&self, target: &Path) -> Command {
        let mut cmd = Command::new("gitleaks");
        cmd.args(["detect", "--source", &target.to_string_lossy(), "--report-format", "json", "--report-path", "/dev/stdout", "--no-banner"]);
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        cmd
    }
    fn parse_output(&self, output: &Output) -> Vec<Finding> {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let matches: Vec<GitleaksMatch> = serde_json::from_str(&stdout).unwrap_or_default();
        matches
            .into_iter()
            .map(|m| Finding {
                severity: Severity::High,
                category: Category::Secrets,
                scanner: "gitleaks".into(),
                title: m
                    .description
                    .or(m.rule_id)
                    .unwrap_or_else(|| "secret detected".into()),
                file: m.file,
                line: m.start_line,
                detail: None,
            })
            .collect()
    }
}
