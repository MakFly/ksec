use ignore::WalkBuilder;
use ignore::overrides::OverrideBuilder;
use std::fs;
use std::path::{Path, PathBuf};

const SKIP_DIRS: &[&str] = &[
    // package managers
    "node_modules",
    "vendor",
    ".venv",
    "venv",
    ".tox",
    // build outputs
    "dist",
    "build",
    ".next",
    ".nuxt",
    ".output",
    "target",
    "__pycache__",
    "coverage",
    ".nyc_output",
    // VCS
    ".git",
    // IDE / editor runtimes
    ".cursor-server",
    ".vscode-server",
    ".vscode",
    ".cursor",
    ".idea",
    // tool caches (pure noise, no user code)
    ".cache",
    ".local",
    ".npm",
    ".bun",
    ".cargo",
    ".rustup",
    "snap",
    ".oh-my-zsh",
    ".codex",
    ".nvm",
    ".pyenv",
    ".gradle",
    ".m2",
    ".docker",
    // Go module cache (library code, not user code)
    "pkg",
    // browser internals
    "google-chrome",
    "chromium",
    "firefox",
    "BraveSoftware",
    // Claude Code internals (history, plugins, sessions)
    "file-history",
    "plugins",
    "worktrees",
    // auto-generated docs
    ".next-docs",
];

const BINARY_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "webp", "ico", "svg", "bmp", "tiff", "mp3", "mp4", "avi", "mov",
    "mkv", "flac", "wav", "ogg", "zip", "tar", "gz", "bz2", "xz", "7z", "rar", "woff", "woff2",
    "ttf", "eot", "otf", "pdf", "doc", "docx", "xls", "xlsx", "exe", "dll", "so", "dylib", "o",
    "a", "wasm", "pyc", "pyo", "class", "sqlite", "db",
];

fn load_ksecignore(target: &Path) -> Option<ignore::overrides::Override> {
    let ignore_path = target.join(".ksecignore");
    let content = fs::read_to_string(&ignore_path).ok()?;
    let mut builder = OverrideBuilder::new(target);
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // .ksecignore uses gitignore syntax but means "exclude"
        // override builder uses "!" to negate (include), so we invert:
        // a pattern "foo" in .ksecignore means exclude foo → override "!foo"
        let pattern = if trimmed.starts_with('!') {
            // negation in .ksecignore = re-include → no prefix in override
            trimmed.strip_prefix('!').unwrap_or(trimmed).to_string()
        } else {
            format!("!{trimmed}")
        };
        builder.add(&pattern).ok();
    }
    builder.build().ok()
}

pub fn walk_files(target: &Path) -> Vec<PathBuf> {
    let overrides = load_ksecignore(target);

    let mut files = Vec::new();
    let mut builder = WalkBuilder::new(target);
    builder
        .hidden(false)
        .git_ignore(true)
        .git_global(false)
        .git_exclude(true)
        .filter_entry(|entry| {
            if let Some(name) = entry.file_name().to_str()
                && entry.file_type().is_some_and(|ft| ft.is_dir())
            {
                return !SKIP_DIRS.contains(&name);
            }
            true
        });

    if let Some(ref ov) = overrides {
        builder.overrides(ov.clone());
    }

    let walker = builder.build();

    for entry in walker.flatten() {
        if !entry.file_type().is_some_and(|ft| ft.is_file()) {
            continue;
        }
        let path = entry.path();
        if path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|ext| BINARY_EXTENSIONS.contains(&ext.to_lowercase().as_str()))
        {
            continue;
        }
        files.push(path.to_path_buf());
    }
    files
}

pub fn walk_files_with_extensions(target: &Path, extensions: &[&str]) -> Vec<PathBuf> {
    walk_files(target)
        .into_iter()
        .filter(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .is_some_and(|ext| extensions.contains(&ext.to_lowercase().as_str()))
        })
        .collect()
}
