use crate::scanners;
use colored::Colorize;

pub fn run_doctor() {
    println!();
    println!("{}", "ksec doctor".bold());
    println!("{}", "checking installed scanners...".dimmed());
    println!();

    let all = scanners::all_scanners();
    let mut installed = 0;
    let mut missing = 0;

    for scanner in &all {
        if scanner.is_available() {
            println!("  {} {} {}", "✓".green(), scanner.name().bold(), scanner.category().to_string().dimmed());
            installed += 1;
        } else {
            println!(
                "  {} {} {}",
                "✗".red(),
                scanner.name().bold(),
                "not found".red()
            );
            println!("       {}", scanner.install_hint().dimmed());
            missing += 1;
        }
    }

    println!();
    println!(
        "  {}/{} scanners installed",
        installed.to_string().green().bold(),
        all.len()
    );

    if missing > 0 {
        println!();
        println!("{}", "  quick install (all):".bold());
        println!();
        println!("    # secrets");
        println!("    go install github.com/gitleaks/gitleaks/v8@latest");
        println!("    go install github.com/trufflesecurity/trufflehog/v3@latest");
        println!();
        println!("    # deps & supply chain");
        println!("    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b ~/.local/bin");
        println!("    go install github.com/google/osv-scanner/cmd/osv-scanner@latest");
        println!("    bun install -g @socketsecurity/cli");
        println!();
        println!("    # sast");
        println!("    pip install opengrep");
        println!();
        println!("    # pre-commit hooks");
        println!("    go install github.com/evilmartians/lefthook@latest");
    } else {
        println!("  {}", "all scanners ready!".green());
    }

    println!();
}
