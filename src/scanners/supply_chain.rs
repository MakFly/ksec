use crate::rules::supply_chain::supply_chain_patterns;
use crate::scanner::{Category, Finding, Scanner, Severity};
use crate::walk;
use std::fs;
use std::path::Path;

pub struct SupplyChainScanner;

const JS_EXTENSIONS: &[&str] = &["js", "cjs", "mjs", "ts", "tsx", "jsx"];

fn scan_known_malware_files(target: &Path, findings: &mut Vec<Finding>) {
    const PAYLOAD_FILES: &[&str] = &["Math_Symbol.js", "math_init.js"];
    const DROPPER_FILES: &[&str] = &["setup.mjs"];
    let files = walk::walk_files(target);

    for file_path in &files {
        let name = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if PAYLOAD_FILES.contains(&name) || DROPPER_FILES.contains(&name) {
            let relative = file_path
                .strip_prefix(target)
                .unwrap_or(file_path)
                .to_string_lossy()
                .to_string();

            let mut flagged = PAYLOAD_FILES.contains(&name);
            if DROPPER_FILES.contains(&name)
                && let Ok(content) = fs::read_to_string(file_path)
            {
                flagged = content.contains("execFileSync")
                    || content.contains("oven-sh/bun")
                    || content.contains("releases/download");
            }

            if flagged {
                findings.push(Finding {
                    severity: Severity::Critical,
                    category: Category::SupplyChain,
                    scanner: "supply-chain".into(),
                    title: format!("known Shai-Hulud dropper/payload file: {name}"),
                    file: Some(relative),
                    line: None,
                    detail: Some(
                        "Indicator matches the keyv & friends supply-chain worm (Aug 2026)".into(),
                    ),
                });
            }
        }
    }
}

fn scan_package_jsons(target: &Path, findings: &mut Vec<Finding>) {
    let patterns = supply_chain_patterns();
    let install_patterns: Vec<_> = patterns
        .iter()
        .filter(|p| p.id.contains("install") || p.id.contains("postinstall"))
        .collect();

    let files = walk::walk_files(target);
    for file_path in &files {
        if file_path.file_name().and_then(|n| n.to_str()) != Some("package.json") {
            continue;
        }

        let content = match fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let relative = file_path
            .strip_prefix(target)
            .unwrap_or(file_path)
            .to_string_lossy()
            .to_string();

        let parsed: serde_json::Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(_) => continue,
        };

        if let Some(scripts) = parsed.get("scripts").and_then(|s| s.as_object()) {
            for (key, val) in scripts {
                let script_val = val.as_str().unwrap_or("");
                let is_lifecycle = matches!(
                    key.as_str(),
                    "preinstall" | "install" | "postinstall" | "preuninstall" | "postuninstall"
                );

                if is_lifecycle && !script_val.is_empty() {
                    for pat in &install_patterns {
                        if pat.regex.is_match(script_val) || pat.regex.is_match(&content) {
                            findings.push(Finding {
                                severity: Severity::High,
                                category: Category::SupplyChain,
                                scanner: "supply-chain".into(),
                                title: format!(
                                    "{} in {} script ({})",
                                    pat.description, key, pat.id
                                ),
                                file: Some(relative.clone()),
                                line: None,
                                detail: Some(format!("{key}: {script_val}")),
                            });
                        }
                    }

                    if script_val.contains("curl ")
                        || script_val.contains("wget ")
                        || script_val.contains("http://")
                        || script_val.contains("https://")
                    {
                        findings.push(Finding {
                            severity: Severity::High,
                            category: Category::SupplyChain,
                            scanner: "supply-chain".into(),
                            title: format!("network access in {key} script"),
                            file: Some(relative.clone()),
                            line: None,
                            detail: Some(format!("{key}: {script_val}")),
                        });
                    }
                }
            }
        }
    }
}

impl Scanner for SupplyChainScanner {
    fn name(&self) -> &str {
        "supply-chain"
    }
    fn category(&self) -> Category {
        Category::SupplyChain
    }
    fn scan(&self, target: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = supply_chain_patterns();

        scan_package_jsons(target, &mut findings);
        scan_known_malware_files(target, &mut findings);

        let files = walk::walk_files_with_extensions(target, JS_EXTENSIONS);

        for file_path in &files {
            let content = match fs::read_to_string(file_path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let relative = file_path
                .strip_prefix(target)
                .unwrap_or(file_path)
                .to_string_lossy()
                .to_string();

            if relative.starts_with("node_modules/")
                || relative.contains("/test/")
                || relative.contains("/tests/")
                || relative.contains("/__tests__/")
                || relative.contains("/fixtures/")
                || relative.contains("/examples/")
                || relative.ends_with(".test.js")
                || relative.ends_with(".test.ts")
                || relative.ends_with(".spec.js")
                || relative.ends_with(".spec.ts")
                || relative.ends_with(".min.js")
                || relative.ends_with(".d.ts")
            {
                continue;
            }

            for (line_num, line) in content.lines().enumerate() {
                if line.len() > 5000 {
                    continue;
                }
                let trimmed = line.trim();
                if trimmed.starts_with("//")
                    || trimmed.starts_with("/*")
                    || trimmed.starts_with('*')
                    || trimmed.contains("assert")
                    || trimmed.contains("expect(")
                    || trimmed.contains("describe(")
                {
                    continue;
                }
                for pat in &patterns {
                    if pat.regex.is_match(line) {
                        findings.push(Finding {
                            severity: Severity::Medium,
                            category: Category::SupplyChain,
                            scanner: "supply-chain".into(),
                            title: format!("{} ({})", pat.description, pat.id),
                            file: Some(relative.clone()),
                            line: Some((line_num + 1) as u32),
                            detail: None,
                        });
                        break;
                    }
                }
            }
        }

        findings
    }
}
