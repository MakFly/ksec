use super::Dependency;
use serde::Deserialize;

#[derive(Deserialize)]
struct ComposerLock {
    packages: Option<Vec<ComposerPackage>>,
    #[serde(rename = "packages-dev")]
    packages_dev: Option<Vec<ComposerPackage>>,
}

#[derive(Deserialize)]
struct ComposerPackage {
    name: Option<String>,
    version: Option<String>,
}

pub fn parse(content: &str) -> Vec<Dependency> {
    let parsed: ComposerLock = match serde_json::from_str(content) {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };

    let mut deps = Vec::new();

    for pkg in parsed
        .packages
        .unwrap_or_default()
        .into_iter()
        .chain(parsed.packages_dev.unwrap_or_default())
    {
        if let (Some(name), Some(version)) = (pkg.name, pkg.version) {
            let clean_version = version.strip_prefix('v').unwrap_or(&version).to_string();
            deps.push(Dependency {
                name,
                version: clean_version,
                ecosystem: "Packagist".into(),
            });
        }
    }

    deps
}
