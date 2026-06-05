use regex::Regex;

pub struct SupplyChainPattern {
    pub id: &'static str,
    pub description: &'static str,
    pub regex: Regex,
}

macro_rules! pattern {
    ($id:expr, $desc:expr, $pat:expr) => {
        SupplyChainPattern {
            id: $id,
            description: $desc,
            regex: Regex::new($pat).unwrap(),
        }
    };
}

pub fn supply_chain_patterns() -> Vec<SupplyChainPattern> {
    vec![
        // ── Dynamic code execution ──
        pattern!("eval-usage", "eval() call — dynamic code execution", r"\beval\s*\("),
        pattern!("function-constructor", "Function constructor — dynamic code generation", r"\bnew\s+Function\s*\("),
        pattern!("vm-run", "vm.runInNewContext / vm.runInThisContext", r"\bvm\.(runInNewContext|runInThisContext|createScript)\s*\("),

        // ── Network exfiltration ──
        pattern!("http-request", "HTTP request in package code", r"\b(?:https?\.(?:get|request|createServer)|fetch\s*\(|XMLHttpRequest|axios\.|got\(|node-fetch)"),
        pattern!("dns-lookup", "DNS lookup — potential exfiltration", r"\bdns\.(?:lookup|resolve|reverse)\s*\("),
        pattern!("child-process-net", "Child process with network command", r#"\b(?:exec|execSync|spawn|spawnSync)\s*\(\s*['"](?:curl|wget|nc|ncat)"#),
        pattern!("websocket", "WebSocket connection", r"\bnew\s+WebSocket\s*\("),

        // ── Filesystem access to sensitive paths ──
        pattern!("read-ssh-keys", "Access to SSH keys", r#"(?:\.ssh|id_rsa|id_ed25519|authorized_keys)"#),
        pattern!("read-env-file", "Reading .env file", r#"(?:readFile|readFileSync)\s*\([^)]*\.env"#),
        pattern!("read-etc-passwd", "Access to /etc/passwd", r"/etc/(?:passwd|shadow|hosts)"),
        pattern!("home-dir-access", "Access to home directory files", r#"(?:homedir|HOME|USERPROFILE)[^)]*\+[^)]*(?:\.bashrc|\.zshrc|\.profile|\.aws|\.npmrc|\.gitconfig)"#),

        // ── Obfuscation techniques ──
        pattern!("hex-encoded-strings", "Hex-encoded string — possible obfuscation", r#"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){10,}"#),
        pattern!("base64-decode-exec", "Base64 decode + execute pattern", r"(?:atob|Buffer\.from)\s*\([^)]+(?:base64|b64)[^)]*\)"),
        pattern!("char-code-assembly", "String.fromCharCode assembly", r"String\.fromCharCode\s*\([^)]{20,}\)"),
        pattern!("global-bracket", "global[] accessor — typical obfuscation", r#"global\[['"][^'"]+['"]\]"#),

        // ── Suspicious install scripts ──
        pattern!("postinstall-exec", "Shell exec in install script", r#"(?:preinstall|postinstall|install)\s*"?\s*:\s*"[^"]*(?:sh |bash |node |curl |wget )"#),

        // ── Environment variable harvesting ──
        pattern!("env-dump", "Environment variable dump", r#"\bprocess\.env\b[^.\[\]]*(?:JSON\.stringify|Object\.keys|Object\.entries|Object\.values)"#),
        pattern!("env-exfiltration", "Send environment variables over network", r#"(?:fetch|https?\.(?:get|request)|axios)\s*\([^)]*process\.env"#),

        // ── Typosquatting indicators ──
        pattern!("install-script-download", "Download binary in install script", r#"(?:preinstall|postinstall)\s*"?\s*:\s*"[^"]*(?:curl|wget|https?://)[^"]*""#),
    ]
}
