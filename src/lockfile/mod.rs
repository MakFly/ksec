pub mod cargo_lock;
pub mod composer;
pub mod go_sum;
pub mod npm;
pub mod pip;

#[derive(Debug, Clone)]
pub struct Dependency {
    pub name: String,
    pub version: String,
    pub ecosystem: String,
}

use std::path::Path;

pub fn detect_and_parse(target: &Path) -> Vec<Dependency> {
    let mut deps = Vec::new();

    type Parser = fn(&str) -> Vec<Dependency>;
    let candidates: Vec<(&str, Parser)> = vec![
        ("package-lock.json", npm::parse_package_lock),
        ("bun.lock", npm::parse_bun_lock),
        ("yarn.lock", npm::parse_yarn_lock),
        ("Cargo.lock", cargo_lock::parse),
        ("composer.lock", composer::parse),
        ("go.sum", go_sum::parse),
        ("requirements.txt", pip::parse_requirements),
        ("poetry.lock", pip::parse_poetry_lock),
    ];

    for (filename, parser) in candidates {
        let path = target.join(filename);
        if path.exists() && let Ok(content) = std::fs::read_to_string(&path) {
            deps.extend(parser(&content));
        }
    }

    deps
}
