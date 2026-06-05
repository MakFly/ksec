use crate::scanner::{Category, Finding, Scanner, Severity};
use serde::Deserialize;
use std::path::Path;
use std::process::Output;
use tokio::process::Command;

pub struct BunAudit;

#[derive(Deserialize)]
struct NpmAuditOutput {
    vulnerabilities: Option<std::collections::HashMap<String, NpmVuln>>,
}

#[derive(Deserialize)]
struct NpmVuln {
    name: Option<String>,
    severity: Option<String>,
    range: Option<String>,
}

fn map_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "moderate" | "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

impl Scanner for BunAudit {
    fn name(&self) -> &str {
        "bun-audit"
    }
    fn binary(&self) -> &str {
        "bun"
    }
    fn is_available(&self) -> bool {
        which::which("bun").is_ok()
    }
    fn category(&self) -> Category {
        Category::Deps
    }
    fn install_hint(&self) -> &str {
        "curl -fsSL https://bun.sh/install | bash"
    }
    fn build_command(&self, target: &Path) -> Command {
        let mut cmd = Command::new("bun");
        cmd.args(["audit", "--json"]);
        cmd.current_dir(target);
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        cmd
    }
    fn parse_output(&self, output: &Output) -> Vec<Finding> {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let parsed: NpmAuditOutput =
            serde_json::from_str(&stdout).unwrap_or(NpmAuditOutput { vulnerabilities: None });
        parsed
            .vulnerabilities
            .unwrap_or_default()
            .into_values()
            .map(|v| {
                let sev = v
                    .severity
                    .as_deref()
                    .map(map_severity)
                    .unwrap_or(Severity::Medium);
                let name = v.name.unwrap_or_else(|| "unknown".into());
                let range = v
                    .range
                    .map(|r| format!(" ({r})"))
                    .unwrap_or_default();
                Finding {
                    severity: sev,
                    category: Category::Deps,
                    scanner: "bun-audit".into(),
                    title: format!("{name}{range}"),
                    file: Some("package.json".into()),
                    line: None,
                    detail: None,
                }
            })
            .collect()
    }
}
