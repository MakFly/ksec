use super::Dependency;

pub fn parse_requirements(content: &str) -> Vec<Dependency> {
    let mut deps = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('-') {
            continue;
        }

        let spec = trimmed.split('#').next().unwrap_or("").trim();

        if let Some((name, rest)) = spec.split_once("==") {
            let version = rest.split([';', ' ', ',']).next().unwrap_or("").trim();
            if !version.is_empty() {
                deps.push(Dependency {
                    name: name.trim().to_lowercase(),
                    version: version.to_string(),
                    ecosystem: "PyPI".into(),
                });
            }
        }
    }

    deps
}

pub fn parse_poetry_lock(content: &str) -> Vec<Dependency> {
    let mut deps = Vec::new();
    let mut name = String::new();
    let mut version = String::new();

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed == "[[package]]" {
            if !name.is_empty() && !version.is_empty() {
                deps.push(Dependency {
                    name: name.clone(),
                    version: version.clone(),
                    ecosystem: "PyPI".into(),
                });
            }
            name.clear();
            version.clear();
            continue;
        }

        if let Some(val) = trimmed.strip_prefix("name = ") {
            name = val.trim_matches('"').to_lowercase();
        } else if let Some(val) = trimmed.strip_prefix("version = ") {
            version = val.trim_matches('"').to_string();
        }
    }

    if !name.is_empty() && !version.is_empty() {
        deps.push(Dependency {
            name,
            version,
            ecosystem: "PyPI".into(),
        });
    }

    deps
}
