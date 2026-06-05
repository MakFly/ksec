use super::Dependency;

pub fn parse(content: &str) -> Vec<Dependency> {
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
                    ecosystem: "crates.io".into(),
                });
            }
            name.clear();
            version.clear();
            continue;
        }

        if let Some(val) = trimmed.strip_prefix("name = ") {
            name = val.trim_matches('"').to_string();
        } else if let Some(val) = trimmed.strip_prefix("version = ") {
            version = val.trim_matches('"').to_string();
        }
    }

    if !name.is_empty() && !version.is_empty() {
        deps.push(Dependency {
            name,
            version,
            ecosystem: "crates.io".into(),
        });
    }

    deps
}
