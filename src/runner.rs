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
        pb.set_message(format!("{} — scanning", scanner.name()));
        pb.enable_steady_tick(std::time::Duration::from_millis(80));

        let target = target.clone();
        let handle = tokio::task::spawn_blocking(move || {
            let start = Instant::now();
            let findings = scanner.scan(&target);
            let duration_ms = start.elapsed().as_millis();
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
                findings,
                duration_ms,
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
