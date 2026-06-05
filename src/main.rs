mod cli;
mod init;
mod lockfile;
mod report;
mod rules;
mod runner;
mod scanner;
mod scanners;
mod walk;

use clap::{CommandFactory, Parser};
use cli::{Cli, Commands};
use std::path::PathBuf;

fn resolve_path(path: &PathBuf) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.clone())
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Init { force }) => {
            init::run_init(*force);
        }
        Some(Commands::Scan { path }) => {
            run_scan(scanners::all_scanners(), &resolve_path(path), &cli).await;
        }
        Some(Commands::Secrets { path }) => {
            run_scan(scanners::secrets_scanners(), &resolve_path(path), &cli).await;
        }
        Some(Commands::Deps { path }) => {
            run_scan(scanners::deps_scanners(), &resolve_path(path), &cli).await;
        }
        Some(Commands::Sast { path }) => {
            run_scan(scanners::sast_scanners(), &resolve_path(path), &cli).await;
        }
        Some(Commands::SupplyChain { path }) => {
            run_scan(scanners::supply_chain_scanners(), &resolve_path(path), &cli).await;
        }
        Some(Commands::Obfuscation { path }) => {
            run_scan(scanners::obfuscation_scanners(), &resolve_path(path), &cli).await;
        }
        None => {
            Cli::command().print_help().ok();
            println!();
        }
    }
}

async fn run_scan(
    scan_list: Vec<std::sync::Arc<dyn scanner::Scanner>>,
    target: &std::path::Path,
    cli: &Cli,
) {
    let results = runner::run_scanners(scan_list, target).await;

    if cli.json {
        report::print_json(&results);
    } else {
        report::print_report(&results, &cli.min_severity);
    }

    std::process::exit(report::exit_code(&results));
}
