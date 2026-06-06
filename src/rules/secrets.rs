use crate::scanner::Severity;
use regex::Regex;

pub struct SecretRule {
    pub id: &'static str,
    pub description: &'static str,
    pub severity: Severity,
    pub regex: Regex,
}

pub fn secret_rules() -> Vec<SecretRule> {
    use Severity::*;

    let defs: Vec<(&str, &str, Severity, &str)> = vec![
        // AWS
        (
            "aws-access-key-id",
            "AWS Access Key ID",
            Critical,
            r#"(?i)\bAKIA[0-9A-Z]{16}\b"#,
        ),
        (
            "aws-secret-access-key",
            "AWS Secret Access Key",
            Critical,
            r#"(?i)(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?"#,
        ),
        (
            "aws-mws-key",
            "AWS MWS Key",
            High,
            r#"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"#,
        ),
        // GitHub
        (
            "github-pat",
            "GitHub Personal Access Token",
            Critical,
            r#"ghp_[A-Za-z0-9]{36}"#,
        ),
        (
            "github-oauth",
            "GitHub OAuth Token",
            Critical,
            r#"gho_[A-Za-z0-9]{36}"#,
        ),
        (
            "github-app-token",
            "GitHub App Token",
            High,
            r#"(?:ghs|ghr)_[A-Za-z0-9]{36}"#,
        ),
        (
            "github-fine-grained",
            "GitHub Fine-Grained PAT",
            Critical,
            r#"github_pat_[A-Za-z0-9_]{82}"#,
        ),
        // GitLab
        (
            "gitlab-pat",
            "GitLab Personal Access Token",
            Critical,
            r#"glpat-[A-Za-z0-9\-]{20,}"#,
        ),
        (
            "gitlab-pipeline",
            "GitLab Pipeline Token",
            High,
            r#"glptt-[A-Za-z0-9\-]{20,}"#,
        ),
        (
            "gitlab-runner",
            "GitLab Runner Token",
            High,
            r#"glrt-[A-Za-z0-9\-]{20,}"#,
        ),
        // Slack
        (
            "slack-token",
            "Slack Token",
            Critical,
            r#"xox[bpors]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*"#,
        ),
        (
            "slack-webhook",
            "Slack Webhook URL",
            High,
            r#"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}"#,
        ),
        // Stripe
        (
            "stripe-secret",
            "Stripe Secret Key",
            Critical,
            r#"sk_live_[0-9a-zA-Z]{24,}"#,
        ),
        (
            "stripe-restricted",
            "Stripe Restricted Key",
            High,
            r#"rk_live_[0-9a-zA-Z]{24,}"#,
        ),
        // Google
        (
            "google-api-key",
            "Google API Key",
            High,
            r#"AIza[0-9A-Za-z\-_]{35}"#,
        ),
        (
            "google-oauth-id",
            "Google OAuth Client ID",
            Medium,
            r#"[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com"#,
        ),
        (
            "gcp-service-account",
            "GCP Service Account Key",
            Critical,
            r#""type"\s*:\s*"service_account""#,
        ),
        // OpenAI / Anthropic
        (
            "openai-api-key",
            "OpenAI API Key",
            Critical,
            r#"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}"#,
        ),
        (
            "openai-project-key",
            "OpenAI Project Key",
            Critical,
            r#"sk-proj-[A-Za-z0-9\-_]{40,}"#,
        ),
        (
            "anthropic-api-key",
            "Anthropic API Key",
            Critical,
            r#"sk-ant-api03-[A-Za-z0-9\-_]{90,}"#,
        ),
        // Discord
        (
            "discord-token",
            "Discord Bot Token",
            Critical,
            r#"(?i)(?:discord|bot)[\s_-]*token\s*[:=]\s*['"]?[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27,}"#,
        ),
        (
            "discord-webhook",
            "Discord Webhook URL",
            High,
            r#"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+"#,
        ),
        // Twilio
        (
            "twilio-api-key",
            "Twilio API Key",
            High,
            r#"SK[0-9a-fA-F]{32}"#,
        ),
        (
            "twilio-account-sid",
            "Twilio Account SID",
            Medium,
            r#"AC[0-9a-fA-F]{32}"#,
        ),
        // SendGrid
        (
            "sendgrid-api-key",
            "SendGrid API Key",
            Critical,
            r#"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}"#,
        ),
        // Mailgun
        (
            "mailgun-api-key",
            "Mailgun API Key",
            High,
            r#"key-[0-9a-zA-Z]{32}"#,
        ),
        // Firebase / Supabase
        (
            "firebase-key",
            "Firebase API Key",
            Medium,
            r#"(?i)firebase[a-z_]*\s*[:=]\s*['"]?AIza[0-9A-Za-z\-_]{35}"#,
        ),
        (
            "supabase-key",
            "Supabase Service Role Key",
            Critical,
            r#"(?i)supabase[a-z_]*(?:service_role|secret)\s*[:=]\s*['"]?eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"#,
        ),
        // NPM
        (
            "npm-token",
            "NPM Access Token",
            Critical,
            r#"npm_[A-Za-z0-9]{36}"#,
        ),
        (
            "npm-token-legacy",
            "NPM Legacy Token",
            High,
            r#"//registry\.npmjs\.org/:_authToken=[A-Za-z0-9\-]+"#,
        ),
        // PyPI
        (
            "pypi-token",
            "PyPI API Token",
            Critical,
            r#"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}"#,
        ),
        // Docker
        (
            "dockerhub-token",
            "Docker Hub Token",
            High,
            r#"dckr_pat_[A-Za-z0-9\-_]{27,}"#,
        ),
        // Telegram
        (
            "telegram-bot-token",
            "Telegram Bot Token",
            High,
            r#"[0-9]{8,10}:AA[A-Za-z0-9\-_]{33}"#,
        ),
        // Heroku
        (
            "heroku-api-key",
            "Heroku API Key",
            High,
            r#"(?i)heroku[a-z_]*\s*[:=]\s*['"]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"#,
        ),
        // Shopify
        (
            "shopify-token",
            "Shopify Access Token",
            High,
            r#"shpat_[a-fA-F0-9]{32}"#,
        ),
        (
            "shopify-secret",
            "Shopify Shared Secret",
            High,
            r#"shpss_[a-fA-F0-9]{32}"#,
        ),
        // Mailchimp
        (
            "mailchimp-api-key",
            "Mailchimp API Key",
            High,
            r#"[0-9a-f]{32}-us[0-9]{1,2}"#,
        ),
        // Private Keys
        (
            "private-key-rsa",
            "RSA Private Key",
            Critical,
            r#"-----BEGIN RSA PRIVATE KEY-----"#,
        ),
        (
            "private-key-dsa",
            "DSA Private Key",
            Critical,
            r#"-----BEGIN DSA PRIVATE KEY-----"#,
        ),
        (
            "private-key-ec",
            "EC Private Key",
            Critical,
            r#"-----BEGIN EC PRIVATE KEY-----"#,
        ),
        (
            "private-key-openssh",
            "OpenSSH Private Key",
            Critical,
            r#"-----BEGIN OPENSSH PRIVATE KEY-----"#,
        ),
        (
            "private-key-pgp",
            "PGP Private Key Block",
            Critical,
            r#"-----BEGIN PGP PRIVATE KEY BLOCK-----"#,
        ),
        (
            "private-key-generic",
            "Generic Private Key",
            Critical,
            r#"-----BEGIN PRIVATE KEY-----"#,
        ),
        (
            "private-key-encrypted",
            "Encrypted Private Key",
            High,
            r#"-----BEGIN ENCRYPTED PRIVATE KEY-----"#,
        ),
        // Database URIs
        (
            "db-uri-password",
            "Database URI with Password",
            Critical,
            r#"(?i)(?:postgres|mysql|mongodb|redis|amqp|mssql)://[^:]+:[^@\s]{3,}@[^\s]+"#,
        ),
        // Generic patterns
        (
            "basic-auth-url",
            "Basic Auth in URL",
            High,
            r#"https?://[^:/?#\s]+:[^@/?#\s]{3,}@[^/?#\s]+"#,
        ),
        (
            "bearer-token",
            "Hardcoded Bearer Token",
            High,
            r#"(?i)(?:authorization|bearer)\s*[:=]\s*['"]?bearer\s+[A-Za-z0-9\-_.~+/]{20,}['"]?"#,
        ),
        // Password assignments
        (
            "password-assignment",
            "Hardcoded Password",
            High,
            r#"(?i)(?:password|passwd|pwd|secret|token|api_key|apikey|api_secret|access_token|auth_token)\s*[:=]\s*['"][^'"]{8,}['"]"#,
        ),
        // JWT
        (
            "jwt-token",
            "Hardcoded JWT",
            Medium,
            r#"(?i)(?:jwt|token|bearer)\s*[:=]\s*['"]?eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]+['"]?"#,
        ),
        // Vercel
        (
            "vercel-token",
            "Vercel Access Token",
            High,
            r#"(?i)vercel[a-z_]*\s*[:=]\s*['"]?[A-Za-z0-9]{24}"#,
        ),
        // Cloudflare
        (
            "cloudflare-api-token",
            "Cloudflare API Token",
            High,
            r#"(?i)cloudflare[a-z_]*\s*[:=]\s*['"]?[A-Za-z0-9_\-]{40}"#,
        ),
        // HashiCorp
        (
            "vault-token",
            "HashiCorp Vault Token",
            Critical,
            r#"hvs\.[A-Za-z0-9]{24,}"#,
        ),
        (
            "terraform-token",
            "Terraform Cloud Token",
            High,
            r#"(?i)(?:TFE_TOKEN|ATLAS_TOKEN)\s*[:=]\s*['"]?[A-Za-z0-9.]{14,}"#,
        ),
        // Datadog
        (
            "datadog-api-key",
            "Datadog API Key",
            High,
            r#"(?i)datadog[a-z_]*\s*[:=]\s*['"]?[0-9a-f]{32}"#,
        ),
        // Sentry
        (
            "sentry-dsn",
            "Sentry DSN",
            Medium,
            r#"https://[0-9a-f]{32}@[a-z0-9.]+\.ingest\.sentry\.io/[0-9]+"#,
        ),
        // Age encryption
        (
            "age-secret-key",
            "Age Secret Key",
            Critical,
            r#"AGE-SECRET-KEY-1[A-Z0-9]{58}"#,
        ),
        // Doppler
        (
            "doppler-token",
            "Doppler Token",
            High,
            r#"dp\.st\.[a-z0-9\-_]{2,}\.[A-Za-z0-9]{40,}"#,
        ),
    ];

    defs.into_iter()
        .filter_map(|(id, desc, sev, pat)| {
            Regex::new(pat).ok().map(|regex| SecretRule {
                id,
                description: desc,
                severity: sev,
                regex,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::secret_rules;

    fn rule(id: &str) -> regex::Regex {
        secret_rules()
            .into_iter()
            .find(|rule| rule.id == id)
            .unwrap_or_else(|| panic!("missing rule {id}"))
            .regex
    }

    #[test]
    fn basic_auth_url_matches_credentials_in_authority() {
        let regex = rule("basic-auth-url");

        assert!(regex.is_match("https://admin:correct-horse-battery@example.com/path"));
    }

    #[test]
    fn basic_auth_url_ignores_query_parameter_colons_before_at_signs() {
        let regex = rule("basic-auth-url");
        let google_fonts_import = "@import url('https://fonts.googleapis.com/css2?family=Cormorant+Garamond:ital,wght@0,300;0,400&family=Inter:wght@300;400&display=swap');";

        assert!(!regex.is_match(google_fonts_import));
    }
}
