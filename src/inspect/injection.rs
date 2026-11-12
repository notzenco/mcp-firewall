//! Prompt injection patterns.
//!
//! These match the shapes of instructions that a server can smuggle into a
//! tool description or a tool result in order to steer the agent. The set is
//! a starting point, not a complete one: it catches the well known payloads,
//! and a policy can add its own.

/// A named pattern and the severity of a match.
pub struct InjectionPattern {
    /// The name reported when the pattern matches.
    pub name: &'static str,
    /// The regular expression, matched case-insensitively.
    pub regex: &'static str,
    /// Whether a match is an error or only a warning.
    pub critical: bool,
}

/// The built-in injection patterns.
pub const PATTERNS: &[InjectionPattern] = &[
    InjectionPattern {
        name: "ignore_previous_instructions",
        regex: r"(?i)\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(previous|prior|above|earlier|preceding|all|any)\b[^.\n]{0,40}\b(instruction|prompt|direction|rule|message|guideline)s?\b",
        critical: false,
    },
    InjectionPattern {
        name: "new_instructions",
        regex: r"(?i)\b(new|updated|revised|additional|real|actual)\s+(instruction|prompt|direction)s?\b\s*[:\-]",
        critical: false,
    },
    InjectionPattern {
        name: "role_override",
        regex: r"(?i)\byou are (now|about to be|no longer)\b|\bact as (an?|the)\b[^.\n]{0,30}\b(without|ignoring|free of)\b",
        critical: false,
    },
    InjectionPattern {
        name: "hidden_from_user",
        regex: r"(?i)\b(do not|don'?t|never|avoid)\b[^.\n]{0,30}\b(tell|telling|inform|informing|mention|mentioning|show|showing|reveal|revealing|notify|notifying|alert|alerting)\b[^.\n]{0,40}\b(user|human|operator|owner)\b",
        critical: false,
    },
    InjectionPattern {
        name: "system_prompt_exfil",
        regex: r"(?i)\b(reveal|print|output|show|repeat|dump|disclose)\b[^.\n]{0,40}\b(system prompt|initial instructions|your instructions|hidden prompt|your prompt)\b",
        critical: true,
    },
    InjectionPattern {
        name: "critical_marker",
        regex: r"(?i)<\s*/?\s*important\s*>|\[\[\s*important\s*\]\]|critical instruction|urgent instruction|###\s*system\b",
        critical: false,
    },
    InjectionPattern {
        name: "fake_chat_tokens",
        regex: r"(?i)<\|\s*(im_start|im_end|system|assistant|user|endoftext)\s*\|?>|\[/?INST\]|<<SYS>>",
        critical: false,
    },
    InjectionPattern {
        name: "exfiltration",
        regex: r"(?i)\b(exfiltrate|steal|siphon)\b[^.\n]{0,40}\b(file|files|credential|credentials|secret|secrets|key|keys|token|tokens|data|contents|conversation|history)\b|\b(send|post|upload|transmit|forward)\b[^.\n]{0,40}\b(to|at)\b[^.\n]{0,20}\b(https?://|www\.)",
        critical: true,
    },
    InjectionPattern {
        name: "remote_code_execution",
        regex: r"(?i)\b(curl|wget)\b[^\n]{0,120}\|\s*(ba|z|k)?sh\b|\bbase64\s+(-d|--decode)\b[^\n]{0,60}\|\s*(ba|z|k)?sh\b",
        critical: true,
    },
    InjectionPattern {
        name: "credential_request",
        regex: r"(?i)\b(send|post|upload|include|attach|append|copy)\b[^.\n]{0,40}\b(api[ _-]?key|access[ _-]?key|secret[ _-]?key|private key|credential|password|passwd|token|session cookie|\.env)\b",
        critical: true,
    },
    InjectionPattern {
        name: "tool_output_is_instructions",
        regex: r"(?i)\b(this (tool|document|file|content|response) (contains|includes|holds) (instructions|commands|directives))\b|\bbefore (using|calling|answering)\b[^.\n]{0,30}\b(read|run|execute|send|upload)\b",
        critical: false,
    },
];
