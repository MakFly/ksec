use crate::rules::sast::sast_rules;
use crate::scanner::{Category, Finding, Scanner};
use crate::walk;
use std::fs;
use std::path::Path;

pub struct SastScanner;

const SKIP_PATH_SEGMENTS: &[&str] = &[
    "test", "tests", "spec", "specs",
    "__tests__", "__mocks__", "__fixtures__",
    "fixtures", "testdata", "test-data",
    "examples", "example", "demo",
    "docs", "migrations",
];

fn should_skip_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    SKIP_PATH_SEGMENTS
        .iter()
        .any(|seg| lower.contains(&format!("/{seg}/")) || lower.starts_with(&format!("{seg}/")))
        || lower.ends_with(".test.ts")
        || lower.ends_with(".test.js")
        || lower.ends_with(".spec.ts")
        || lower.ends_with(".spec.js")
        || lower.ends_with("_test.go")
        || lower.ends_with("_test.py")
        || lower.contains(".min.")
        || lower.ends_with(".d.ts")
        || lower.ends_with(".map")
}

fn should_skip_line(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.starts_with("//")
        || trimmed.starts_with('#')
        || trimmed.starts_with("/*")
        || trimmed.starts_with('*')
        || trimmed.starts_with("<!--")
        || trimmed.contains("r#\"")
        || trimmed.contains("Regex::new")
        || trimmed.contains("re.compile")
        || trimmed.contains("preg_match")
        || trimmed.contains("Pattern.compile")
        || trimmed.contains("assert")
        || trimmed.contains("expect(")
        || trimmed.contains("it(\"")
        || trimmed.contains("it('")
        || trimmed.contains("describe(")
        || trimmed.contains("test(\"")
        || trimmed.contains("test('")
        || trimmed.is_empty()
}

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

            let relative = file_path
                .strip_prefix(target)
                .unwrap_or(file_path)
                .to_string_lossy()
                .to_string();

            if should_skip_path(&relative) {
                continue;
            }

            let content = match fs::read_to_string(file_path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            for (line_num, line) in content.lines().enumerate() {
                if should_skip_line(line) {
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
