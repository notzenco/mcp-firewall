//! Credential patterns.
//!
//! A match on any of these means a credential is present in the text. Matches
//! are redacted rather than reported verbatim, so neither the audit log nor a
//! forwarded tool result becomes a place where credentials accumulate.

/// A named credential pattern.
pub struct SecretPattern {
    /// The name reported when the pattern matches.
    pub name: &'static str,
    /// The regular expression to match.
    pub regex: &'static str,
    /// An extra check on the matched text; a match that fails it is ignored.
    pub validate: Option<fn(&str) -> bool>,
}

/// True when a generic assignment looks like a real credential rather than a
/// placeholder such as `password = "changeme"`.
pub fn looks_like_a_credential(value: &str) -> bool {
    let trimmed = value.trim_matches(|c: char| c == '"' || c == '\'');
    if trimmed.len() < 8 {
        return false;
    }
    let has_letter = trimmed.chars().any(|c| c.is_ascii_alphabetic());
    let has_other = trimmed.chars().any(|c| !c.is_ascii_alphabetic());
    if !has_letter || !has_other {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    const PLACEHOLDERS: &[&str] = &[
        "changeme",
        "change_me",
        "placeholder",
        "example",
        "yourkeyhere",
        "your_key_here",
        "redacted",
        "xxxxxxxx",
        "password",
        "secretkey",
        "none",
        "null",
        "undefined",
        "todo",
    ];
    !PLACEHOLDERS.iter().any(|p| lower.contains(p))
}

/// The built-in credential patterns.
pub const PATTERNS: &[SecretPattern] = &[
    SecretPattern {
        name: "aws_access_key_id",
        regex: r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b",
        validate: None,
    },
    SecretPattern {
        name: "github_token",
        regex: r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b",
        validate: None,
    },
    SecretPattern {
        name: "gitlab_token",
        regex: r"\bglpat-[A-Za-z0-9_-]{20,}\b",
        validate: None,
    },
    SecretPattern {
        name: "slack_token",
        regex: r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b",
        validate: None,
    },
    SecretPattern {
        name: "anthropic_api_key",
        regex: r"\bsk-ant-[A-Za-z0-9_-]{20,}\b",
        validate: None,
    },
    SecretPattern {
        name: "openai_api_key",
        regex: r"\b(?:sk-proj-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{32,})\b",
        validate: None,
    },
    SecretPattern {
        name: "google_api_key",
        regex: r"\bAIza[0-9A-Za-z_-]{35}\b",
        validate: None,
    },
    SecretPattern {
        name: "stripe_secret_key",
        regex: r"\b[rs]k_live_[0-9A-Za-z]{16,}\b",
        validate: None,
    },
    SecretPattern {
        name: "npm_token",
        regex: r"\bnpm_[A-Za-z0-9]{36}\b",
        validate: None,
    },
    SecretPattern {
        name: "sendgrid_api_key",
        regex: r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b",
        validate: None,
    },
    SecretPattern {
        name: "twilio_api_key",
        regex: r"\bSK[0-9a-fA-F]{32}\b",
        validate: None,
    },
    SecretPattern {
        name: "hugging_face_token",
        regex: r"\bhf_[A-Za-z0-9]{34,}\b",
        validate: None,
    },
    SecretPattern {
        name: "jwt",
        regex: r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
        validate: None,
    },
    SecretPattern {
        name: "private_key",
        regex: r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----",
        validate: None,
    },
    SecretPattern {
        name: "credential_in_url",
        regex: r"(?i)\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|rediss|amqp|amqps|ftp|sftp)://[^\s:@/]+:[^\s@/]+@",
        validate: None,
    },
    SecretPattern {
        name: "assigned_credential",
        regex: r#"(?i)\b(?:api[_-]?key|apikey|access[_-]?key|access[_-]?token|secret[_-]?key|secret[_-]?token|client[_-]?secret|private[_-]?key|auth[_-]?token|password|passwd|pwd)\b\s*[:=]\s*["']?([A-Za-z0-9+/=_-]{8,})"#,
        validate: Some(looks_like_a_credential),
    },
];
