use crate::scanner::{Category, Finding, Scanner, Severity};
use crate::walk;
use regex::Regex;
use std::fs;
use std::path::Path;

pub struct ObfuscationScanner;

const CONFIG_PATTERNS: &[&str] = &[
    "*.config.js",
    "*.config.mjs",
    "*.config.cjs",
    "*.config.ts",
    ".eslintrc.js",
    ".prettierrc.js",
    "rollup.config.*",
    "vite.config.*",
    "webpack.config.*",
    "next.config.*",
    "nuxt.config.*",
    "tailwind.config.*",
    "postcss.config.*",
    "jest.config.*",
];

fn is_config_file(filename: &str) -> bool {
    CONFIG_PATTERNS.iter().any(|pat| {
        let pat_clean = pat.replace("*", "");
        if pat.starts_with('*') && pat.ends_with('*') {
            filename.contains(pat_clean.trim_matches('.'))
        } else if pat.starts_with('*') {
            filename.ends_with(&pat_clean)
        } else if pat.ends_with('*') {
            filename.starts_with(&pat_clean)
        } else {
            filename == pat_clean || filename == *pat
        }
    })
}

impl Scanner for ObfuscationScanner {
    fn name(&self) -> &str {
        "obfuscation"
    }
    fn category(&self) -> Category {
        Category::Obfuscation
    }
    fn scan(&self, target: &Path) -> Vec<Finding> {
        let files = walk::walk_files(target);
        let global_re = Regex::new(r#"global\[|_\$_[0-9a-f]"#).unwrap();
        let hex_heavy_re = Regex::new(r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){20,}").unwrap();
        let mut findings = Vec::new();

        for file_path in &files {
            let filename = file_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");

            if !is_config_file(filename) {
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
                let line_no = (line_num + 1) as u32;

                if line.len() > 500 {
                    let trimmed = line.trim();
                    let looks_like_data = trimmed.starts_with('{')
                        || trimmed.starts_with('[')
                        || trimmed.starts_with("//")
                        || trimmed.contains("sourceMap")
                        || trimmed.contains("webpack");
                    let severity = if looks_like_data || line.len() < 1000 {
                        Severity::Medium
                    } else {
                        Severity::High
                    };
                    findings.push(Finding {
                        severity,
                        category: Category::Obfuscation,
                        scanner: "obfuscation".into(),
                        title: format!("line >500 chars ({} chars) in config file", line.len()),
                        file: Some(relative.clone()),
                        line: Some(line_no),
                        detail: None,
                    });
                }

                if global_re.is_match(line) {
                    findings.push(Finding {
                        severity: Severity::High,
                        category: Category::Obfuscation,
                        scanner: "obfuscation".into(),
                        title: "suspicious global[] or _$_ pattern".into(),
                        file: Some(relative.clone()),
                        line: Some(line_no),
                        detail: None,
                    });
                }

                if hex_heavy_re.is_match(line) {
                    findings.push(Finding {
                        severity: Severity::High,
                        category: Category::Obfuscation,
                        scanner: "obfuscation".into(),
                        title: "heavy hex-encoded content in config".into(),
                        file: Some(relative.clone()),
                        line: Some(line_no),
                        detail: None,
                    });
                }
            }
        }

        findings
    }
}
