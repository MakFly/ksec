use crate::rules::sast::sast_rules;
use crate::scanner::{Category, Finding, Scanner};
use crate::walk;
use std::fs;
use std::path::Path;

pub struct SastScanner;

impl Scanner for SastScanner {
    fn name(&self) -> &str {
        "sast"
    }
    fn category(&self) -> Category {
        Category::Sast
    }
    fn scan(&self, target: &Path) -> Vec<Finding> {
        let rules = sast_rules();
        let files = walk::walk_files(target);
        let mut findings = Vec::new();

        for file_path in &files {
            let ext = file_path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("");

            let applicable_rules: Vec<_> = rules
                .iter()
                .filter(|r| r.extensions.contains(&ext))
                .collect();

            if applicable_rules.is_empty() {
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

            for (line_num, line) in content.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.starts_with("//")
                    || trimmed.starts_with('#')
                    || trimmed.starts_with("/*")
                    || trimmed.starts_with('*')
                    || trimmed.contains("r#\"")
                    || trimmed.contains("Regex::new")
                {
                    continue;
                }

                for rule in &applicable_rules {
                    if rule.regex.is_match(line) {
                        findings.push(Finding {
                            severity: rule.severity,
                            category: Category::Sast,
                            scanner: "sast".into(),
                            title: format!("{} ({})", rule.description, rule.id),
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
