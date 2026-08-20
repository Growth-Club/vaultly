/**
 * Vault templates — shared by CLI (`vaultly template`) and TUI.
 */

export interface VaultTemplate {
  keys: string[];
  description: string;
}

export const TEMPLATES: Record<string, VaultTemplate> = {
  cloudflare: {
    description: "Cloudflare account (API token or global key + account ID)",
    keys: ["CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID"],
  },
  github: {
    description: "GitHub (personal access token)",
    keys: ["GITHUB_TOKEN", "GITHUB_USERNAME"],
  },
  aws: {
    description: "AWS credentials",
    keys: ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION"],
  },
  gcp: {
    description: "Google Cloud Platform",
    keys: ["GOOGLE_APPLICATION_CREDENTIALS", "GCP_PROJECT_ID"],
  },
  vercel: {
    description: "Vercel deployment",
    keys: ["VERCEL_TOKEN", "VERCEL_ORG_ID", "VERCEL_PROJECT_ID"],
  },
  database: {
    description: "Database connection",
    keys: ["DATABASE_URL", "DATABASE_PASSWORD"],
  },
  stripe: {
    description: "Stripe payments",
    keys: ["STRIPE_SECRET_KEY", "STRIPE_WEBHOOK_SECRET", "STRIPE_PUBLISHABLE_KEY"],
  },
  openai: {
    description: "OpenAI / AI APIs",
    keys: ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_AI_KEY"],
  },
  smtp: {
    description: "Email sending",
    keys: ["SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASSWORD"],
  },
  docker: {
    description: "Docker registry",
    keys: ["DOCKER_USERNAME", "DOCKER_PASSWORD", "DOCKER_REGISTRY"],
  },
  npm: {
    description: "npm publishing",
    keys: ["NPM_TOKEN"],
  },
  ssh: {
    description: "Server access",
    keys: ["SERVER_HOST", "SERVER_USER", "SERVER_PASSWORD", "SERVER_SSH_KEY"],
  },
  "social-media": {
    description: "Social media APIs",
    keys: ["META_ACCESS_TOKEN", "TWITTER_BEARER_TOKEN", "LINKEDIN_ACCESS_TOKEN"],
  },
  custom: {
    description: "Custom vault (define your own keys)",
    keys: [],
  },
};