use super::Dependency;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Deserialize)]
struct PackageLock {
    packages: Option<HashMap<String, PackageLockEntry>>,
    dependencies: Option<HashMap<String, PackageLockDep>>,
}

#[derive(Deserialize)]
struct PackageLockEntry {
    version: Option<String>,
}

#[derive(Deserialize)]
struct PackageLockDep {
    version: Option<String>,
}

pub fn parse_package_lock(content: &str) -> Vec<Dependency> {
    let parsed: PackageLock = match serde_json::from_str(content) {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };

    let mut deps = Vec::new();

    if let Some(packages) = parsed.packages {
        for (key, entry) in packages {
            if key.is_empty() {
                continue;
            }
            let name = key
                .strip_prefix("node_modules/")
                .unwrap_or(&key)
                .to_string();
            if let Some(version) = entry.version {
                deps.push(Dependency {
                    name,
                    version,
                    ecosystem: "npm".into(),
                });
            }
        }
    } else if let Some(dependencies) = parsed.dependencies {
        for (name, dep) in dependencies {
            if let Some(version) = dep.version {
                deps.push(Dependency {
                    name,
                    version,
                    ecosystem: "npm".into(),
                });
            }
        }
    }

    deps
}

pub fn parse_bun_lock(content: &str) -> Vec<Dependency> {
    let parsed: serde_json::Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => return parse_bun_lock_text(content),
    };

    let mut deps = Vec::new();

    if let Some(packages) = parsed.get("packages").and_then(|p| p.as_object()) {
        for (key, val) in packages {
            let name = key
                .strip_prefix("node_modules/")
                .unwrap_or(key)
                .to_string();
            let version = val
                .as_array()
                .and_then(|arr| arr.first())
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !version.is_empty() {
                deps.push(Dependency {
                    name,
                    version: version.to_string(),
                    ecosystem: "npm".into(),
                });
            }
        }
    }

    deps
}

fn parse_bun_lock_text(content: &str) -> Vec<Dependency> {
    let mut deps = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with('"') {
            continue;
        }
        // "package@version": [...]
        if let Some((name, version)) = trimmed
            .strip_prefix('"')
            .and_then(|s| s.split('"').next())
            .and_then(|pkg| pkg.rsplit_once('@'))
        {
            if !name.is_empty() && !version.is_empty() {
                deps.push(Dependency {
                    name: name.to_string(),
                    version: version.to_string(),
                    ecosystem: "npm".into(),
                });
            }
        }
    }
    deps
}

pub fn parse_yarn_lock(content: &str) -> Vec<Dependency> {
    let mut deps = Vec::new();
    let mut current_name = String::new();

    for line in content.lines() {
        let trimmed = line.trim();

        if !trimmed.starts_with('#') && !trimmed.is_empty() && !line.starts_with(' ') {
            let clean = trimmed.trim_matches('"').trim_end_matches(':');
            if let Some((name, _)) = clean.rsplit_once('@') {
                current_name = name.trim_matches('"').to_string();
            }
        }

        if trimmed.starts_with("version ") {
            let version = trimmed
                .strip_prefix("version ")
                .unwrap_or("")
                .trim_matches('"');
            if !current_name.is_empty() && !version.is_empty() {
                deps.push(Dependency {
                    name: current_name.clone(),
                    version: version.to_string(),
                    ecosystem: "npm".into(),
                });
            }
        }
    }

    deps
}
