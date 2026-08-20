//! Vault templates — shared by CLI (`vaultly template`) and TUI.
//! Mirrors src/templates.ts exactly.

pub struct VaultTemplate {
    pub keys: &'static [&'static str],
    pub description: &'static str,
}

pub const TEMPLATES: &[(&str, VaultTemplate)] = &[
    (
        "cloudflare",
        VaultTemplate {
            description: "Cloudflare account (API token or global key + account ID)",
            keys: &["CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID"],
        },
    ),
    (
        "github",
        VaultTemplate {
            description: "GitHub (personal access token)",
            keys: &["GITHUB_TOKEN", "GITHUB_USERNAME"],
        },
    ),
    (
        "aws",
        VaultTemplate {
            description: "AWS credentials",
            keys: &["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION"],
        },
    ),
    (
        "gcp",
        VaultTemplate {
            description: "Google Cloud Platform",
            keys: &["GOOGLE_APPLICATION_CREDENTIALS", "GCP_PROJECT_ID"],
        },
    ),
    (
        "vercel",
        VaultTemplate {
            description: "Vercel deployment",
            keys: &["VERCEL_TOKEN", "VERCEL_ORG_ID", "VERCEL_PROJECT_ID"],
        },
    ),
    (
        "database",
        VaultTemplate {
            description: "Database connection",
            keys: &["DATABASE_URL", "DATABASE_PASSWORD"],
        },
    ),
    (
        "stripe",
        VaultTemplate {
            description: "Stripe payments",
            keys: &["STRIPE_SECRET_KEY", "STRIPE_WEBHOOK_SECRET", "STRIPE_PUBLISHABLE_KEY"],
        },
    ),
    (
        "openai",
        VaultTemplate {
            description: "OpenAI / AI APIs",
            keys: &["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_AI_KEY"],
        },
    ),
    (
        "smtp",
        VaultTemplate {
            description: "Email sending",
            keys: &["SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASSWORD"],
        },
    ),
    (
        "docker",
        VaultTemplate {
            description: "Docker registry",
            keys: &["DOCKER_USERNAME", "DOCKER_PASSWORD", "DOCKER_REGISTRY"],
        },
    ),
    (
        "npm",
        VaultTemplate {
            description: "npm publishing",
            keys: &["NPM_TOKEN"],
        },
    ),
    (
        "ssh",
        VaultTemplate {
            description: "Server access",
            keys: &["SERVER_HOST", "SERVER_USER", "SERVER_PASSWORD", "SERVER_SSH_KEY"],
        },
    ),
    (
        "social-media",
        VaultTemplate {
            description: "Social media APIs",
            keys: &["META_ACCESS_TOKEN", "TWITTER_BEARER_TOKEN", "LINKEDIN_ACCESS_TOKEN"],
        },
    ),
    (
        "custom",
        VaultTemplate {
            description: "Custom vault (define your own keys)",
            keys: &[],
        },
    ),
];

pub fn get_template(name: &str) -> Option<&'static VaultTemplate> {
    TEMPLATES.iter().find(|(n, _)| *n == name).map(|(_, t)| t)
}

pub fn template_names() -> Vec<&'static str> {
    TEMPLATES.iter().map(|(n, _)| *n).collect()
}
