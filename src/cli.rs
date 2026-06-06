use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "ksec",
    version,
    about = "Self-contained security scanner — secrets, deps, supply chain, SAST, obfuscation"
)]
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
    /// Run all scanners (secrets + deps + supply-chain + sast + obfuscation)
    Scan {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Detect leaked secrets (150+ regex rules — API keys, tokens, private keys, DB URIs)
    Secrets {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Check dependencies for known vulnerabilities (parses lockfiles, queries OSV API)
    Deps {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Static analysis — OWASP Top 10 (SQLi, XSS, command injection, SSRF, etc.)
    Sast {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Detect suspicious patterns in packages (eval, network exfil, obfuscation, malicious scripts)
    SupplyChain {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Detect obfuscated code in config files (long lines, global[], hex payloads)
    Obfuscation {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Generate lefthook.yml for pre-commit hooks
    Init {
        /// Overwrite existing lefthook.yml
        #[arg(long)]
        force: bool,
    },
}
