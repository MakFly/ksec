use crate::scanner::{Category, Finding, Scanner, Severity};
use serde::Deserialize;
use std::path::Path;
use std::process::Output;
use tokio::process::Command;

pub struct OpenGrep;

#[derive(Deserialize)]
struct SemgrepOutput {
    results: Option<Vec<SemgrepResult>>,
}

#[derive(Deserialize)]
struct SemgrepResult {
    check_id: Option<String>,
    path: Option<String>,
    start: Option<SemgrepPos>,
    extra: Option<SemgrepExtra>,
}

#[derive(Deserialize)]
struct SemgrepPos {
    line: Option<u32>,
}

#[derive(Deserialize)]
struct SemgrepExtra {
    message: Option<String>,
    severity: Option<String>,
}

fn map_severity(s: &str) -> Severity {
    match s.to_uppercase().as_str() {
        "ERROR" => Severity::High,
        "WARNING" => Severity::Medium,
        "INFO" => Severity::Low,
        _ => Severity::Medium,
    }
}

impl Scanner for OpenGrep {
    fn name(&self) -> &str {
        "opengrep"
    }
    fn binary(&self) -> &str {
        "opengrep"
    }
    fn is_available(&self) -> bool {
        which::which("opengrep").is_ok() || which::which("semgrep").is_ok()
    }
    fn category(&self) -> Category {
        Category::Sast
    }
    fn install_hint(&self) -> &str {
        "pip install opengrep | pip install semgrep"
    }
    fn build_command(&self, target: &Path) -> Command {
        let bin = if which::which("opengrep").is_ok() {
            "opengrep"
        } else {
            "semgrep"
        };
        let mut cmd = Command::new(bin);
        cmd.args([
            "scan",
            "--config",
            "auto",
            "--json",
            "--quiet",
            &target.to_string_lossy(),
        ]);
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        cmd
    }
    fn parse_output(&self, output: &Output) -> Vec<Finding> {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let parsed: SemgrepOutput =
            serde_json::from_str(&stdout).unwrap_or(SemgrepOutput { results: None });
        parsed
            .results
            .unwrap_or_default()
            .into_iter()
            .map(|r| {
                let sev = r
                    .extra
                    .as_ref()
                    .and_then(|e| e.severity.as_deref())
                    .map(map_severity)
                    .unwrap_or(Severity::Medium);
                Finding {
                    severity: sev,
                    category: Category::Sast,
                    scanner: "opengrep".into(),
                    title: r.check_id.unwrap_or_else(|| "finding".into()),
                    file: r.path,
                    line: r.start.and_then(|s| s.line),
                    detail: r.extra.and_then(|e| e.message),
                }
            })
            .collect()
    }
}
