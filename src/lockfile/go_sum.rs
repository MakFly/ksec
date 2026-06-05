use super::Dependency;

pub fn parse(content: &str) -> Vec<Dependency> {
    let mut deps = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        let module = parts[0];
        let version = parts[1].split('/').next().unwrap_or("");
        let clean_version = version.strip_prefix('v').unwrap_or(version);
        let key = format!("{module}@{clean_version}");

        if !seen.contains(&key) && !clean_version.is_empty() {
            seen.insert(key);
            deps.push(Dependency {
                name: module.to_string(),
                version: clean_version.to_string(),
                ecosystem: "Go".into(),
            });
        }
    }

    deps
}
