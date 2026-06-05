use crate::rules::secrets::secret_rules;
use crate::scanner::{Category, Finding, Scanner};
use crate::walk;
use std::fs;
use std::path::Path;

pub struct SecretsScanner;

const ALLOWLIST_PATTERNS: &[&str] = &[
    "EXAMPLE",
    "example",
    "PLACEHOLDER",
    "placeholder",
    "your-",
    "YOUR_",
    "xxx",
    "XXX",
    "000000",
    "CHANGE_ME",
    "change_me",
    "TODO",
    "FIXME",
    "<your",
    "${",
    "{{",
    "process.env",
    "os.environ",
    "env(",
];

fn is_allowlisted(line: &str) -> bool {
    if line.trim_start().starts_with("//")
        || line.trim_start().starts_with('#')
        || line.trim_start().starts_with("/*")
        || line.trim_start().starts_with('*')
    {
        return true;
    }
    if line.contains("r#\"") || line.contains("r\"") || line.contains("Regex::new") {
        return true;
    }
    ALLOWLIST_PATTERNS.iter().any(|p| line.contains(p))
}

const SKIP_FILES: &[&str] = &[
    "package-lock.json",
    "bun.lock",
    "yarn.lock",
    "pnpm-lock.yaml",
    "Cargo.lock",
    "composer.lock",
    "poetry.lock",
    "go.sum",
];

impl Scanner for SecretsScanner {
    fn name(&self) -> &str {
        "secrets"
    }
    fn category(&self) -> Category {
        Category::Secrets
    }
    fn scan(&self, target: &Path) -> Vec<Finding> {
        let rules = secret_rules();
        let files = walk::walk_files(target);
        let mut findings = Vec::new();

        for file_path in &files {
            let file_name = file_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");

            if SKIP_FILES.contains(&file_name) {
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
                if line.len() > 2000 {
                    continue;
                }
                if is_allowlisted(line) {
                    continue;
                }

                for rule in &rules {
                    if rule.regex.is_match(line) {
                        findings.push(Finding {
                            severity: rule.severity,
                            category: Category::Secrets,
                            scanner: "secrets".into(),
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
