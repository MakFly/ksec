use crate::lockfile;
use crate::scanner::{Category, Finding, Scanner, Severity};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct DepsScanner;

#[derive(Serialize)]
struct OsvBatchRequest {
    queries: Vec<OsvQuery>,
}

#[derive(Serialize)]
struct OsvQuery {
    package: OsvPackage,
    version: String,
}

#[derive(Serialize)]
struct OsvPackage {
    name: String,
    ecosystem: String,
}

#[derive(Deserialize)]
struct OsvBatchResponse {
    results: Option<Vec<OsvQueryResult>>,
}

#[derive(Deserialize)]
struct OsvQueryResult {
    vulns: Option<Vec<OsvVuln>>,
}

#[derive(Deserialize)]
struct OsvVuln {
    id: Option<String>,
    summary: Option<String>,
    severity: Option<Vec<OsvSeverity>>,
    database_specific: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct OsvSeverity {
    score: Option<f64>,
}

fn score_to_severity(vuln: &OsvVuln) -> Severity {
    if let Some(sevs) = &vuln.severity {
        if let Some(s) = sevs.first().and_then(|s| s.score) {
            return match s {
                s if s >= 9.0 => Severity::Critical,
                s if s >= 7.0 => Severity::High,
                s if s >= 4.0 => Severity::Medium,
                _ => Severity::Low,
            };
        }
    }

    if let Some(db) = &vuln.database_specific {
        if let Some(sev_str) = db.get("severity").and_then(|s| s.as_str()) {
            return match sev_str.to_uppercase().as_str() {
                "CRITICAL" => Severity::Critical,
                "HIGH" => Severity::High,
                "MODERATE" | "MEDIUM" => Severity::Medium,
                "LOW" => Severity::Low,
                _ => Severity::Medium,
            };
        }
    }

    Severity::Medium
}

const BATCH_SIZE: usize = 1000;

impl Scanner for DepsScanner {
    fn name(&self) -> &str {
        "deps"
    }
    fn category(&self) -> Category {
        Category::Deps
    }
    fn scan(&self, target: &Path) -> Vec<Finding> {
        let deps = lockfile::detect_and_parse(target);
        if deps.is_empty() {
            return vec![Finding {
                severity: Severity::Info,
                category: Category::Deps,
                scanner: "deps".into(),
                title: "no lockfile found".into(),
                file: None,
                line: None,
                detail: Some("supported: package-lock.json, bun.lock, yarn.lock, Cargo.lock, composer.lock, requirements.txt, poetry.lock, go.sum".into()),
            }];
        }

        let mut findings = Vec::new();

        for chunk in deps.chunks(BATCH_SIZE) {
            let queries: Vec<OsvQuery> = chunk
                .iter()
                .map(|d| OsvQuery {
                    version: d.version.clone(),
                    package: OsvPackage {
                        name: d.name.clone(),
                        ecosystem: d.ecosystem.clone(),
                    },
                })
                .collect();

            let request = OsvBatchRequest { queries };
            let body = match serde_json::to_string(&request) {
                Ok(b) => b,
                Err(_) => continue,
            };

            let response = ureq::post("https://api.osv.dev/v1/querybatch")
                .header("Content-Type", "application/json")
                .send(&body);

            let response = match response {
                Ok(r) => r,
                Err(e) => {
                    findings.push(Finding {
                        severity: Severity::Info,
                        category: Category::Deps,
                        scanner: "deps".into(),
                        title: "OSV API unreachable".into(),
                        file: None,
                        line: None,
                        detail: Some(format!("could not reach api.osv.dev: {e}")),
                    });
                    continue;
                }
            };

            let body_str = match response.into_body().read_to_string() {
                Ok(s) => s,
                Err(_) => continue,
            };

            let batch: OsvBatchResponse = match serde_json::from_str(&body_str) {
                Ok(b) => b,
                Err(_) => continue,
            };

            if let Some(results) = batch.results {
                for (i, result) in results.iter().enumerate() {
                    if let Some(vulns) = &result.vulns {
                        let dep = &chunk[i];
                        for vuln in vulns {
                            let vid = vuln.id.as_deref().unwrap_or("unknown");
                            let severity = score_to_severity(vuln);
                            findings.push(Finding {
                                severity,
                                category: Category::Deps,
                                scanner: "deps".into(),
                                title: format!(
                                    "{} — {}@{}",
                                    vid, dep.name, dep.version
                                ),
                                file: None,
                                line: None,
                                detail: vuln.summary.clone(),
                            });
                        }
                    }
                }
            }
        }

        findings
    }
}
