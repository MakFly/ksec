use ignore::WalkBuilder;
use std::path::{Path, PathBuf};

const SKIP_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    "vendor",
    "dist",
    "build",
    ".next",
    "__pycache__",
    "target",
    ".venv",
    "venv",
    ".tox",
    "coverage",
    ".nyc_output",
    ".cursor-server",
    ".vscode-server",
    ".vscode",
    ".cursor",
    ".idea",
    ".cache",
    ".local",
    ".npm",
    ".bun",
    ".cargo",
    ".rustup",
    "snap",
];

const BINARY_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "webp", "ico", "svg", "bmp", "tiff",
    "mp3", "mp4", "avi", "mov", "mkv", "flac", "wav", "ogg",
    "zip", "tar", "gz", "bz2", "xz", "7z", "rar",
    "woff", "woff2", "ttf", "eot", "otf",
    "pdf", "doc", "docx", "xls", "xlsx",
    "exe", "dll", "so", "dylib", "o", "a",
    "wasm", "pyc", "pyo", "class",
    "sqlite", "db",
];

pub fn walk_files(target: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let walker = WalkBuilder::new(target)
        .hidden(false)
        .git_ignore(true)
        .git_global(false)
        .git_exclude(true)
        .filter_entry(|entry| {
            if let Some(name) = entry.file_name().to_str() {
                if entry.file_type().is_some_and(|ft| ft.is_dir()) {
                    return !SKIP_DIRS.contains(&name);
                }
            }
            true
        })
        .build();

    for entry in walker.flatten() {
        if !entry.file_type().is_some_and(|ft| ft.is_file()) {
            continue;
        }
        let path = entry.path();
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if BINARY_EXTENSIONS.contains(&ext.to_lowercase().as_str()) {
                continue;
            }
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
