pub mod bun_audit;
pub mod gitleaks;
pub mod opengrep;
pub mod osv;
pub mod socket;
pub mod trivy;
pub mod trufflehog;

use crate::scanner::Scanner;
use std::sync::Arc;

pub fn all_scanners() -> Vec<Arc<dyn Scanner>> {
    vec![
        Arc::new(gitleaks::Gitleaks),
        Arc::new(trufflehog::TruffleHog),
        Arc::new(trivy::Trivy),
        Arc::new(osv::OsvScanner),
        Arc::new(bun_audit::BunAudit),
        Arc::new(opengrep::OpenGrep),
        Arc::new(socket::SocketCli),
    ]
}

pub fn secrets_scanners() -> Vec<Arc<dyn Scanner>> {
    vec![
        Arc::new(gitleaks::Gitleaks),
        Arc::new(trufflehog::TruffleHog),
    ]
}

pub fn deps_scanners() -> Vec<Arc<dyn Scanner>> {
    vec![
        Arc::new(trivy::Trivy),
        Arc::new(osv::OsvScanner),
        Arc::new(bun_audit::BunAudit),
    ]
}

pub fn sast_scanners() -> Vec<Arc<dyn Scanner>> {
    vec![Arc::new(opengrep::OpenGrep)]
}

pub fn supply_chain_scanners() -> Vec<Arc<dyn Scanner>> {
    vec![Arc::new(socket::SocketCli)]
}
