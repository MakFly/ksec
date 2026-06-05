use crate::scanner::{Category, Finding, Scanner, Severity};
use serde::Deserialize;
use std::path::Path;
use std::process::Output;
use tokio::process::Command;

pub struct Trivy;

#[derive(Deserialize)]
struct TrivyOutput {
    #[serde(rename = "Results")]
    results: Option<Vec<TrivyResult>>,
}

#[derive(Deserialize)]
struct TrivyResult {
    #[serde(rename = "Target")]
    target: Option<String>,
    #[serde(rename = "Vulnerabilities")]
    vulnerabilities: Option<Vec<TrivyVuln>>,
}

#[derive(Deserialize)]
struct TrivyVuln {
    #[serde(rename = "VulnerabilityID")]
    vulnerability_id: Option<String>,
    #[serde(rename = "PkgName")]
    pkg_name: Option<String>,
    #[serde(rename = "InstalledVersion")]
    installed_version: Option<String>,
    #[serde(rename = "FixedVersion")]
    fixed_version: Option<String>,
    #[serde(rename = "Severity")]
    severity: Option<String>,
    #[serde(rename = "Title")]
    title: Option<String>,
}

fn map_severity(s: &str) -> Severity {
    match s.to_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MEDIUM" => Severity::Medium,
        "LOW" => Severity::Low,
        _ => Severity::Info,
    }
}

impl Scanner for Trivy {
    fn name(&self) -> &str {
        "trivy"
    }
    fn binary(&self) -> &str {
        "trivy"
    }
    fn category(&self) -> Category {
        Category::Deps
    }
    fn install_hint(&self) -> &str {
        "brew install trivy | curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh"
    }
    fn build_command(&self, target: &Path) -> Command {
        let mut cmd = Command::new("trivy");
        cmd.args(["fs", "--format", "json", "--scanners", "vuln", &target.to_string_lossy()]);
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        cmd
    }
    fn parse_output(&self, output: &Output) -> Vec<Finding> {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let parsed: TrivyOutput = serde_json::from_str(&stdout).unwrap_or(TrivyOutput { results: None });
        let mut findings = Vec::new();
        for result in parsed.results.unwrap_or_default() {
            let target_file = result.target.unwrap_or_default();
            for vuln in result.vulnerabilities.unwrap_or_default() {
                let sev = vuln
                    .severity
                    .as_deref()
                    .map(map_severity)
                    .unwrap_or(Severity::Medium);
                let pkg = vuln.pkg_name.unwrap_or_default();
                let version = vuln.installed_version.unwrap_or_default();
                let fixed = vuln
                    .fixed_version
                    .map(|v| format!(" (fix: {v})"))
                    .unwrap_or_default();
                let vid = vuln.vulnerability_id.unwrap_or_default();
                findings.push(Finding {
                    severity: sev,
                    category: Category::Deps,
                    scanner: "trivy".into(),
                    title: format!("{vid} {pkg}@{version}{fixed}"),
                    file: Some(target_file.clone()),
                    line: None,
                    detail: vuln.title,
                });
            }
        }
        findings
    }
}
