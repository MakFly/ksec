use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "ksec", version, about = "Unified security scanner CLI")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Target directory to scan (defaults to current directory)
    #[arg(global = true, default_value = ".")]
    pub path: PathBuf,

    /// Output as JSON
    #[arg(long, global = true)]
    pub json: bool,

    /// Only show findings at or above this severity
    #[arg(long, global = true, default_value = "low")]
    pub min_severity: String,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run all scanners
    Scan {
        /// Target directory
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Scan for leaked secrets (gitleaks + trufflehog)
    Secrets {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Scan dependencies for vulnerabilities (trivy + osv-scanner + bun audit)
    Deps {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Static analysis for security (opengrep)
    Sast {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Supply chain analysis (socket)
    SupplyChain {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Check installed scanners and install missing ones
    Doctor,
    /// Generate lefthook.yml for pre-commit hooks
    Init {
        /// Overwrite existing lefthook.yml
        #[arg(long)]
        force: bool,
    },
}
