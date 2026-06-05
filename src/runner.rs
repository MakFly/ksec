use crate::scanner::{ScanResult, Scanner};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

pub async fn run_scanners(scanners: Vec<Arc<dyn Scanner>>, target: &Path) -> Vec<ScanResult> {
    let mp = MultiProgress::new();
    let style = ProgressStyle::with_template("  {spinner:.cyan} {msg}")
        .unwrap()
        .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", "✓"]);

    let mut handles = Vec::new();
    let target = target.to_path_buf();

    for scanner in scanners {
        let pb = mp.add(ProgressBar::new_spinner());
        pb.set_style(style.clone());
        pb.set_message(format!("{} — running", scanner.name()));
        pb.enable_steady_tick(std::time::Duration::from_millis(80));

        let target = target.clone();
        let handle = tokio::spawn(async move {
            let start = Instant::now();

            if !scanner.is_available() {
                pb.finish_with_message(format!("{} — skipped (not installed)", scanner.name()));
                return ScanResult {
                    scanner: scanner.name().to_string(),
                    category: scanner.category(),
                    success: false,
                    findings: vec![],
                    error: Some(format!("not installed — {}", scanner.install_hint())),
                    duration_ms: start.elapsed().as_millis(),
                };
            }

            let mut cmd = scanner.build_command(&target);
            let result = cmd.output().await;

            let duration_ms = start.elapsed().as_millis();

            match result {
                Ok(output) => {
                    let findings = scanner.parse_output(&output);
                    let count = findings.len();
                    let label = if count == 0 { "clean" } else { "findings" };
                    pb.finish_with_message(format!(
                        "{} — {} {} ({}ms)",
                        scanner.name(),
                        count,
                        label,
                        duration_ms
                    ));
                    ScanResult {
                        scanner: scanner.name().to_string(),
                        category: scanner.category(),
                        success: true,
                        findings,
                        error: None,
                        duration_ms,
                    }
                }
                Err(e) => {
                    pb.finish_with_message(format!("{} — error", scanner.name()));
                    ScanResult {
                        scanner: scanner.name().to_string(),
                        category: scanner.category(),
                        success: false,
                        findings: vec![],
                        error: Some(e.to_string()),
                        duration_ms,
                    }
                }
            }
        });

        handles.push(handle);
    }

    let mut results = Vec::new();
    for handle in handles {
        if let Ok(result) = handle.await {
            results.push(result);
        }
    }

    results
}
