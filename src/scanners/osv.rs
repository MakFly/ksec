use crate::scanner::{Category, Finding, Scanner, Severity};
use serde::Deserialize;
use std::path::Path;
use std::process::Output;
use tokio::process::Command;

pub struct OsvScanner;

#[derive(Deserialize)]
struct OsvOutput {
    results: Option<Vec<OsvResult>>,
}

#[derive(Deserialize)]
struct OsvResult {
    source: Option<OsvSource>,
    packages: Option<Vec<OsvPackage>>,
}

#[derive(Deserialize)]
struct OsvSource {
    path: Option<String>,
}

#[derive(Deserialize)]
struct OsvPackage {
    package: Option<OsvPkgInfo>,
    vulnerabilities: Option<Vec<OsvVuln>>,
}

#[derive(Deserialize)]
struct OsvPkgInfo {
    name: Option<String>,
    version: Option<String>,
}

#[derive(Deserialize)]
struct OsvVuln {
    id: Option<String>,
    summary: Option<String>,
    database_specific: Option<OsvDbSpecific>,
}

#[derive(Deserialize)]
struct OsvDbSpecific {
    severity: Option<String>,
}

impl Scanner for OsvScanner {
    fn name(&self) -> &str {
        "osv-scanner"
    }
    fn binary(&self) -> &str {
        "osv-scanner"
    }
    fn category(&self) -> Category {
        Category::Deps
    }
    fn install_hint(&self) -> &str {
        "go install github.com/google/osv-scanner/cmd/osv-scanner@latest"
    }
    fn build_command(&self, target: &Path) -> Command {
        let mut cmd = Command::new("osv-scanner");
        cmd.args(["scan", "--format", "json", "--recursive", &target.to_string_lossy()]);
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        cmd
    }
    fn parse_output(&self, output: &Output) -> Vec<Finding> {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let parsed: OsvOutput = serde_json::from_str(&stdout).unwrap_or(OsvOutput { results: None });
        let mut findings = Vec::new();
        for result in parsed.results.unwrap_or_default() {
            let source_path = result
                .source
                .and_then(|s| s.path)
                .unwrap_or_default();
            for pkg in result.packages.unwrap_or_default() {
                let pkg_name = pkg
                    .package
                    .as_ref()
                    .and_then(|p| p.name.clone())
                    .unwrap_or_default();
                let pkg_version = pkg
                    .package
                    .as_ref()
                    .and_then(|p| p.version.clone())
                    .unwrap_or_default();
                for vuln in pkg.vulnerabilities.unwrap_or_default() {
                    let sev_str = vuln
                        .database_specific
                        .and_then(|d| d.severity)
                        .unwrap_or_default();
                    let severity = match sev_str.to_uppercase().as_str() {
                        "CRITICAL" => Severity::Critical,
                        "HIGH" => Severity::High,
                        "MODERATE" | "MEDIUM" => Severity::Medium,
                        "LOW" => Severity::Low,
                        _ => Severity::Medium,
                    };
                    let vid = vuln.id.unwrap_or_default();
                    findings.push(Finding {
                        severity,
                        category: Category::Deps,
                        scanner: "osv-scanner".into(),
                        title: format!("{vid} {pkg_name}@{pkg_version}"),
                        file: Some(source_path.clone()),
                        line: None,
                        detail: vuln.summary,
                    });
                }
            }
        }
        findings
    }
}
