use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Category {
    Secrets,
    Deps,
    SupplyChain,
    Sast,
    Obfuscation,
}

impl std::fmt::Display for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Category::Secrets => write!(f, "secrets"),
            Category::Deps => write!(f, "deps"),
            Category::SupplyChain => write!(f, "supply-chain"),
            Category::Sast => write!(f, "sast"),
            Category::Obfuscation => write!(f, "obfuscation"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub category: Category,
    pub scanner: String,
    pub title: String,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub detail: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub scanner: String,
    pub category: Category,
    pub findings: Vec<Finding>,
    pub duration_ms: u128,
}

pub trait Scanner: Send + Sync {
    fn name(&self) -> &str;
    fn category(&self) -> Category;
    fn scan(&self, target: &Path) -> Vec<Finding>;
}
