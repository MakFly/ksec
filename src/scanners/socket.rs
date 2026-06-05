use crate::scanner::{Category, Finding, Scanner, Severity};
use serde::Deserialize;
use std::path::Path;
use std::process::Output;
use tokio::process::Command;

pub struct SocketCli;

#[derive(Deserialize)]
struct SocketAlert {
    severity: Option<String>,
    #[serde(rename = "type")]
    alert_type: Option<String>,
    package: Option<String>,
    description: Option<String>,
}

impl Scanner for SocketCli {
    fn name(&self) -> &str {
        "socket"
    }
    fn binary(&self) -> &str {
        "socket"
    }
    fn category(&self) -> Category {
        Category::SupplyChain
    }
    fn install_hint(&self) -> &str {
        "bun install -g @socketsecurity/cli"
    }
    fn build_command(&self, target: &Path) -> Command {
        let mut cmd = Command::new("socket");
        cmd.args(["scan", "--json", &target.to_string_lossy()]);
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        cmd
    }
    fn parse_output(&self, output: &Output) -> Vec<Finding> {
        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout
            .lines()
            .filter_map(|line| serde_json::from_str::<SocketAlert>(line).ok())
            .map(|a| {
                let severity = match a.severity.as_deref().unwrap_or("medium").to_lowercase().as_str() {
                    "critical" => Severity::Critical,
                    "high" => Severity::High,
                    "medium" | "moderate" => Severity::Medium,
                    "low" => Severity::Low,
                    _ => Severity::Medium,
                };
                Finding {
                    severity,
                    category: Category::SupplyChain,
                    scanner: "socket".into(),
                    title: format!(
                        "{} — {}",
                        a.alert_type.unwrap_or_else(|| "alert".into()),
                        a.package.unwrap_or_default()
                    ),
                    file: None,
                    line: None,
                    detail: a.description,
                }
            })
            .collect()
    }
}
