//! Policy files: parsing, compilation and evaluation.
//!
//! A policy is a TOML file. It is parsed and compiled once, at start-up; any
//! problem is a start-up failure, because a firewall that cannot read its own
//! rules must not start unprotected.

use serde::Deserialize;
use serde_json::Value;

use crate::glob::{self, Glob};

/// The policy schema version this build understands.
pub const POLICY_VERSION: u32 = 1;

/// Something that stopped a policy from being loaded.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("cannot read policy `{path}`: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot parse policy: {source}")]
    Parse {
        #[source]
        source: toml::de::Error,
    },
    #[error("invalid policy: {0}")]
    Invalid(String),
}

/// What the policy does with a tool call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    /// Permit the call. Argument violations are refused.
    Allow,
    /// Permit the call only after a human approves it.
    Ask,
    /// Refuse the call.
    Deny,
    /// Permit the call but report argument violations instead of enforcing them.
    LogOnly,
}

impl Mode {
    /// The name used in the audit log and in error messages.
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Allow => "allow",
            Mode::Ask => "ask",
            Mode::Deny => "deny",
            Mode::LogOnly => "log-only",
        }
    }
}

/// The result of evaluating one tool call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The call may go through.
    Allow,
    /// The call needs a human decision.
    Ask,
    /// The call is refused.
    Deny,
}

/// The outcome of a policy evaluation, with the reasons behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluation {
    /// The mode that applied to the tool.
    pub mode: Mode,
    /// What to do with the call.
    pub outcome: Outcome,
    /// A stable, machine readable reason code.
    pub code: &'static str,
    /// Why, in a form suitable for an error message.
    pub reason: String,
    /// The argument rules that were broken.
    pub violations: Vec<Violation>,
}

/// One broken argument rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// Which check failed: `allow`, `deny`, `regex`, `deny_regex`, `max_bytes`
    /// or `max_total_bytes`.
    pub rule: String,
    /// The argument the check applied to.
    pub argument: String,
    /// A human readable explanation.
    pub detail: String,
}

// --- The TOML shapes -------------------------------------------------------

/// The whole file, which holds a single `policy` table.
///
/// The policy lives inside one table so that the order of the sections in
/// the file never matters: a top level key written after a table header is a
/// classic TOML trap, and a policy file should not be able to fail because
/// of where somebody put a line.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDocument {
    /// The policy itself.
    pub policy: Policy,
}

/// A policy file, as written.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// The schema version. Only `1` is understood.
    pub version: u32,
    #[serde(default)]
    pub defaults: Defaults,
    /// Which tools are permitted or refused outright.
    #[serde(default)]
    pub filters: Filters,
    /// Per-tool rules. The first matching rule wins.
    #[serde(default)]
    pub tools: Vec<ToolRule>,
    #[serde(default)]
    pub redact: Redact,
    #[serde(default)]
    pub pin: Pin,
}

/// Filters that apply before the per-tool rules.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Filters {
    /// Tool name globs that are always refused.
    #[serde(default)]
    pub deny_tools: Vec<String>,
    /// When non-empty, tool name globs that are the only ones permitted.
    #[serde(default)]
    pub allow_tools: Vec<String>,
}

/// Defaults that apply when nothing more specific matches.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    #[serde(default = "default_mode")]
    pub mode: Mode,
}

fn default_mode() -> Mode {
    Mode::LogOnly
}

impl Default for Defaults {
    fn default() -> Self {
        Self {
            mode: default_mode(),
        }
    }
}

/// A rule for one tool.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolRule {
    /// The tool name, or a glob over tool names.
    pub name: String,
    /// What to do with calls to this tool. Falls back to `defaults.mode`.
    #[serde(default)]
    pub mode: Option<Mode>,
    /// A note for whoever reads the policy.
    #[serde(default)]
    pub description: Option<String>,
    /// Rules for the tool's arguments.
    #[serde(default)]
    pub args: Vec<ArgumentRule>,
    /// The largest the serialised `arguments` object may be.
    #[serde(default)]
    pub max_total_bytes: Option<usize>,
}

/// A rule for the arguments of a tool.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArgumentRule {
    /// The argument name, or a glob over argument names and paths.
    pub name: String,
    /// Globs the value must match at least one of.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Globs the value must match none of.
    #[serde(default)]
    pub deny: Vec<String>,
    /// A regular expression the value must match.
    #[serde(default)]
    pub regex: Option<String>,
    /// A regular expression the value must not match.
    #[serde(default)]
    pub deny_regex: Option<String>,
    /// The largest a matched value may be, in bytes.
    #[serde(default)]
    pub max_bytes: Option<usize>,
}

/// Secret redaction settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Redact {
    /// Use the built-in credential patterns.
    #[serde(default = "default_true")]
    pub builtin: bool,
    /// Also strip credentials from tool results before the agent sees them.
    #[serde(default)]
    pub forward_results: bool,
    /// Extra patterns, matched alongside the built-in ones.
    #[serde(default)]
    pub patterns: Vec<Pattern>,
}

/// A user supplied pattern.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pattern {
    /// A short name, used when reporting a match.
    pub name: String,
    /// The regular expression to match.
    pub regex: String,
}

fn default_true() -> bool {
    true
}

impl Default for Redact {
    fn default() -> Self {
        Self {
            builtin: true,
            forward_results: false,
            patterns: Vec::new(),
        }
    }
}

/// Tool definition pinning.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pin {
    /// The expected hash of the canonical tool list.
    #[serde(default)]
    pub expected_sha256: Option<String>,
    /// Refuse a tool list whose hash differs from `expected_sha256`.
    #[serde(default)]
    pub enforce: bool,
}

// --- The compiled policy ---------------------------------------------------

/// A pattern that is ready to be matched.
#[derive(Debug, Clone)]
pub struct CompiledPattern {
    pub name: String,
    pub regex: regex::Regex,
}

/// Redaction settings, compiled.
#[derive(Debug, Clone)]
pub struct RedactConfig {
    /// Use the built-in credential patterns.
    pub builtin: bool,
    /// Strip credentials from tool results before the agent sees them.
    pub forward_results: bool,
    /// Extra patterns, compiled.
    pub patterns: Vec<CompiledPattern>,
}

/// A tool rule, compiled.
#[derive(Debug, Clone)]
pub struct CompiledToolRule {
    pub name: Glob,
    pub mode: Option<Mode>,
    pub description: Option<String>,
    pub args: Vec<CompiledArgumentRule>,
    pub max_total_bytes: Option<usize>,
}

/// An argument rule, compiled.
#[derive(Debug, Clone)]
pub struct CompiledArgumentRule {
    pub name: Glob,
    pub allow: Vec<Glob>,
    pub deny: Vec<Glob>,
    pub regex: Option<regex::Regex>,
    pub deny_regex: Option<regex::Regex>,
    pub max_bytes: Option<usize>,
}

/// A policy that is parsed, validated and ready to evaluate.
#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    pub version: u32,
    pub defaults: Defaults,
    deny_tools: Vec<Glob>,
    allow_tools: Vec<Glob>,
    tools: Vec<CompiledToolRule>,
    pub redact: RedactConfig,
    pub pin: Pin,
}

impl CompiledPolicy {
    /// Parses a policy from TOML text and compiles it.
    pub fn parse(text: &str) -> Result<Self, PolicyError> {
        let document: PolicyDocument =
            toml::from_str(text).map_err(|source| PolicyError::Parse { source })?;
        Self::from_policy(document.policy)
    }

    /// Reads a policy file and compiles it.
    pub fn load(path: &std::path::Path) -> Result<Self, PolicyError> {
        let text = std::fs::read_to_string(path).map_err(|source| PolicyError::Read {
            path: path.display().to_string(),
            source,
        })?;
        Self::parse(&text)
    }

    /// Compiles an already parsed policy.
    pub fn from_policy(policy: Policy) -> Result<Self, PolicyError> {
        if policy.version != POLICY_VERSION {
            return Err(PolicyError::Invalid(format!(
                "unsupported policy version {} (this build understands version {})",
                policy.version, POLICY_VERSION
            )));
        }

        let deny_tools = compile_globs(&policy.filters.deny_tools, "deny_tools")?;
        let allow_tools = compile_globs(&policy.filters.allow_tools, "allow_tools")?;

        let mut tools = Vec::with_capacity(policy.tools.len());
        for rule in &policy.tools {
            tools.push(CompiledToolRule {
                name: Glob::new(&rule.name)
                    .map_err(|e| PolicyError::Invalid(format!("tool rule `{}`: {e}", rule.name)))?,
                mode: rule.mode,
                description: rule.description.clone(),
                args: rule
                    .args
                    .iter()
                    .map(compile_argument_rule)
                    .collect::<Result<_, _>>()?,
                max_total_bytes: rule.max_total_bytes,
            });
        }

        let mut patterns = Vec::with_capacity(policy.redact.patterns.len());
        for pattern in &policy.redact.patterns {
            let regex = regex::Regex::new(&pattern.regex).map_err(|source| {
                PolicyError::Invalid(format!(
                    "redact pattern `{}` has an invalid regex: {source}",
                    pattern.name
                ))
            })?;
            patterns.push(CompiledPattern {
                name: pattern.name.clone(),
                regex,
            });
        }

        // An empty digest means "not pinned", so a policy file can carry the
        // key without having to be edited before it is used.
        let expected_sha256 = match policy.pin.expected_sha256.as_deref() {
            None | Some("") => None,
            Some(expected) => {
                if !is_sha256_hex(expected) {
                    return Err(PolicyError::Invalid(format!(
                        "pin.expected_sha256 is not a 64 character hex digest: `{expected}`"
                    )));
                }
                Some(expected.to_string())
            }
        };

        Ok(Self {
            version: policy.version,
            defaults: policy.defaults,
            deny_tools,
            allow_tools,
            tools,
            redact: RedactConfig {
                builtin: policy.redact.builtin,
                forward_results: policy.redact.forward_results,
                patterns,
            },
            pin: Pin {
                expected_sha256,
                enforce: policy.pin.enforce,
            },
        })
    }

    /// The mode that applies to `tool`, ignoring argument rules.
    pub fn mode_for(&self, tool: &str) -> Mode {
        if glob::any_match(&self.deny_tools, tool) {
            return Mode::Deny;
        }
        if !self.allow_tools.is_empty() && !glob::any_match(&self.allow_tools, tool) {
            return Mode::Deny;
        }
        self.rule_for(tool)
            .and_then(|rule| rule.mode)
            .unwrap_or(self.defaults.mode)
    }

    /// The first rule whose name matches `tool`.
    fn rule_for(&self, tool: &str) -> Option<&CompiledToolRule> {
        self.tools.iter().find(|rule| rule.name.matches(tool))
    }

    /// Evaluates a tool call against the policy.
    pub fn evaluate(&self, tool: &str, arguments: &Value) -> Evaluation {
        if glob::any_match(&self.deny_tools, tool) {
            return Evaluation {
                mode: Mode::Deny,
                outcome: Outcome::Deny,
                code: "deny_list",
                reason: format!("tool `{tool}` is on the deny list"),
                violations: Vec::new(),
            };
        }

        if !self.allow_tools.is_empty() && !glob::any_match(&self.allow_tools, tool) {
            return Evaluation {
                mode: Mode::Deny,
                outcome: Outcome::Deny,
                code: "not_in_allow_list",
                reason: format!("tool `{tool}` is not on the allow list"),
                violations: Vec::new(),
            };
        }

        let rule = self.rule_for(tool);
        let mode = rule.and_then(|r| r.mode).unwrap_or(self.defaults.mode);
        let violations = rule
            .map(|r| self.violations_for(r, arguments))
            .unwrap_or_default();

        match mode {
            Mode::Deny => Evaluation {
                mode,
                outcome: Outcome::Deny,
                code: "policy_deny",
                reason: format!("tool `{tool}` is denied by policy"),
                violations,
            },
            Mode::Allow if !violations.is_empty() => Evaluation {
                mode,
                outcome: Outcome::Deny,
                code: "argument_violation",
                reason: format!(
                    "tool `{tool}` violates {} argument rule(s)",
                    violations.len()
                ),
                violations,
            },
            Mode::Ask => Evaluation {
                mode,
                outcome: Outcome::Ask,
                code: "needs_approval",
                reason: format!("tool `{tool}` needs approval"),
                violations,
            },
            Mode::Allow | Mode::LogOnly => Evaluation {
                mode,
                outcome: Outcome::Allow,
                code: "allowed",
                reason: format!("tool `{tool}` is permitted"),
                violations,
            },
        }
    }

    /// Evaluates the argument rules of `rule` against `arguments`.
    fn violations_for(&self, rule: &CompiledToolRule, arguments: &Value) -> Vec<Violation> {
        let mut violations = Vec::new();

        if let Some(max) = rule.max_total_bytes {
            let size = serde_json::to_vec(arguments).map(|v| v.len()).unwrap_or(0);
            if size > max {
                violations.push(Violation {
                    rule: "max_total_bytes".to_string(),
                    argument: "arguments".to_string(),
                    detail: format!("arguments are {size} bytes, the limit is {max}"),
                });
            }
        }

        let leaves = collect_strings(arguments);
        for arg_rule in &rule.args {
            for leaf in &leaves {
                if !arg_rule.name.matches(&leaf.key) && !arg_rule.name.matches(&leaf.path) {
                    continue;
                }
                violations.extend(check_rule(arg_rule, leaf));
            }
        }

        violations
    }
}

/// A string inside the arguments, with the key it was found under.
#[derive(Debug, Clone)]
struct StringLeaf {
    /// The property name the value was found under.
    key: String,
    /// The full path inside `arguments`, for example `files[0].path`.
    path: String,
    value: String,
}

/// Applies one argument rule to one string leaf.
fn check_rule(rule: &CompiledArgumentRule, leaf: &StringLeaf) -> Vec<Violation> {
    let mut violations = Vec::new();
    let value = &leaf.value;

    if !rule.allow.is_empty() && !glob::any_match(&rule.allow, &expand_home(value)) {
        violations.push(Violation {
            rule: "allow".to_string(),
            argument: leaf.path.clone(),
            detail: format!("value does not match any allowed pattern: {value}"),
        });
    }

    if glob::any_match(&rule.deny, &expand_home(value)) {
        violations.push(Violation {
            rule: "deny".to_string(),
            argument: leaf.path.clone(),
            detail: format!("value matches a denied pattern: {value}"),
        });
    }

    if let Some(regex) = &rule.regex
        && !regex.is_match(value)
    {
        violations.push(Violation {
            rule: "regex".to_string(),
            argument: leaf.path.clone(),
            detail: format!("value does not match the required pattern: {value}"),
        });
    }

    if let Some(regex) = &rule.deny_regex
        && regex.is_match(value)
    {
        violations.push(Violation {
            rule: "deny_regex".to_string(),
            argument: leaf.path.clone(),
            detail: format!("value matches a forbidden pattern: {value}"),
        });
    }

    if let Some(max) = rule.max_bytes
        && value.len() > max
    {
        violations.push(Violation {
            rule: "max_bytes".to_string(),
            argument: leaf.path.clone(),
            detail: format!("value is {} bytes, the limit is {max}", value.len()),
        });
    }

    violations
}

/// Collects every string in a JSON value, with the key and path it sits at.
fn collect_strings(value: &Value) -> Vec<StringLeaf> {
    let mut out = Vec::new();
    walk(value, "", "", &mut out);
    out
}

fn walk(value: &Value, key: &str, path: &str, out: &mut Vec<StringLeaf>) {
    match value {
        Value::String(s) => out.push(StringLeaf {
            key: key.to_string(),
            path: path.to_string(),
            value: s.clone(),
        }),
        Value::Object(map) => {
            for (k, v) in map {
                let child_path = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                walk(v, k, &child_path, out);
            }
        }
        Value::Array(items) => {
            for (i, v) in items.iter().enumerate() {
                let child_path = format!("{path}[{i}]");
                walk(v, key, &child_path, out);
            }
        }
        _ => {}
    }
}

/// Expands a leading `~` to the home directory.
fn expand_home(value: &str) -> String {
    if value == "~" {
        return home_dir().unwrap_or_else(|| value.to_string());
    }
    if let Some(rest) = value.strip_prefix("~/")
        && let Some(home) = home_dir()
    {
        return format!("{home}/{rest}");
    }
    value.to_string()
}

/// The home directory, if the environment names one.
fn home_dir() -> Option<String> {
    std::env::var("HOME").ok().filter(|h| !h.is_empty())
}

/// Compiles a list of globs, naming the field in any error.
fn compile_globs(patterns: &[String], field: &str) -> Result<Vec<Glob>, PolicyError> {
    glob::compile_all(patterns).map_err(|e| PolicyError::Invalid(format!("{field}: {e}")))
}

/// Compiles one argument rule.
fn compile_argument_rule(rule: &ArgumentRule) -> Result<CompiledArgumentRule, PolicyError> {
    Ok(CompiledArgumentRule {
        name: Glob::new(&rule.name)
            .map_err(|e| PolicyError::Invalid(format!("argument rule `{}`: {e}", rule.name)))?,
        allow: compile_globs(&rule.allow, "argument allow")?,
        deny: compile_globs(&rule.deny, "argument deny")?,
        regex: match &rule.regex {
            Some(source) => Some(regex::Regex::new(source).map_err(|e| {
                PolicyError::Invalid(format!("argument rule `{}` regex: {e}", rule.name))
            })?),
            None => None,
        },
        deny_regex: match &rule.deny_regex {
            Some(source) => Some(regex::Regex::new(source).map_err(|e| {
                PolicyError::Invalid(format!("argument rule `{}` deny_regex: {e}", rule.name))
            })?),
            None => None,
        },
        max_bytes: rule.max_bytes,
    })
}

/// True when `value` looks like a hex sha256 digest.
fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn policy(text: &str) -> CompiledPolicy {
        CompiledPolicy::parse(text).expect("policy compiles")
    }

    #[test]
    fn a_minimal_policy_defaults_to_log_only() {
        let p = policy("[policy]\nversion = 1\n");
        assert_eq!(p.mode_for("anything"), Mode::LogOnly);
        let evaluation = p.evaluate("anything", &json!({}));
        assert_eq!(evaluation.outcome, Outcome::Allow);
    }

    #[test]
    fn an_unknown_version_is_refused() {
        let err = CompiledPolicy::parse("[policy]\nversion = 2\n").unwrap_err();
        assert!(matches!(err, PolicyError::Invalid(_)));
    }

    #[test]
    fn an_unknown_key_is_refused() {
        let err = CompiledPolicy::parse("[policy]\nversion = 1\nmdoe = \"allow\"\n").unwrap_err();
        assert!(matches!(err, PolicyError::Parse { .. }));
    }

    #[test]
    fn the_order_of_the_sections_does_not_matter() {
        let text = "[policy]\nversion = 1\n\n[policy.pin]\nenforce = true\n\n[policy.defaults]\nmode = \"deny\"\n";
        let policy = policy(text);
        assert_eq!(policy.mode_for("anything"), Mode::Deny);
        assert!(policy.pin.enforce);
    }

    #[test]
    fn an_invalid_regex_is_refused() {
        let text = "[policy]\nversion = 1\n[policy.redact]\n[[policy.redact.patterns]]\nname = \"x\"\nregex = \"(\"\n";
        let err = CompiledPolicy::parse(text).unwrap_err();
        assert!(matches!(err, PolicyError::Invalid(_)));
    }

    #[test]
    fn the_deny_list_wins_over_everything() {
        let p = policy(
            r#"
[policy]
version = 1

[policy.filters]
deny_tools = ["shell_*"]

[[policy.tools]]
name = "shell_exec"
mode = "allow"
"#,
        );
        let evaluation = p.evaluate("shell_exec", &json!({}));
        assert_eq!(evaluation.outcome, Outcome::Deny);
        assert!(evaluation.reason.contains("deny list"));
    }

    #[test]
    fn a_non_empty_allow_list_denies_everything_else() {
        let p = policy(
            r#"
[policy]
version = 1

[policy.filters]
allow_tools = ["read_*"]
"#,
        );
        assert_eq!(p.evaluate("read_file", &json!({})).outcome, Outcome::Allow);
        assert_eq!(p.evaluate("write_file", &json!({})).outcome, Outcome::Deny);
    }

    #[test]
    fn the_first_matching_rule_wins() {
        let p = policy(
            r#"
[policy]
version = 1
[[policy.tools]]
name = "read_*"
mode = "allow"

[[policy.tools]]
name = "read_file"
mode = "deny"
"#,
        );
        assert_eq!(p.mode_for("read_file"), Mode::Allow);
    }

    #[test]
    fn a_path_rule_blocks_values_outside_the_allowed_tree() {
        let p = policy(
            r#"
[policy]
version = 1
[[policy.tools]]
name = "read_file"
mode = "allow"

[[policy.tools.args]]
name = "path"
allow = ["/srv/project/**"]
"#,
        );
        let good = p.evaluate("read_file", &json!({"path": "/srv/project/a.txt"}));
        assert_eq!(good.outcome, Outcome::Allow);

        let bad = p.evaluate("read_file", &json!({"path": "/etc/passwd"}));
        assert_eq!(bad.outcome, Outcome::Deny);
        assert_eq!(bad.violations.len(), 1);
        assert_eq!(bad.violations[0].rule, "allow");
    }

    #[test]
    fn a_deny_rule_blocks_a_matching_value() {
        let p = policy(
            r#"
[policy]
version = 1
[[policy.tools]]
name = "read_file"
mode = "allow"

[[policy.tools.args]]
name = "path"
deny = ["/srv/project/.env"]
"#,
        );
        let evaluation = p.evaluate("read_file", &json!({"path": "/srv/project/.env"}));
        assert_eq!(evaluation.outcome, Outcome::Deny);
        assert_eq!(evaluation.violations[0].rule, "deny");
    }

    #[test]
    fn a_regex_rule_requires_a_match() {
        let p = policy(
            r#"
[policy]
version = 1
[[policy.tools]]
name = "query"
mode = "allow"

[[policy.tools.args]]
name = "sql"
regex = "^SELECT "
"#,
        );
        assert_eq!(
            p.evaluate("query", &json!({"sql": "SELECT 1"})).outcome,
            Outcome::Allow
        );
        let bad = p.evaluate("query", &json!({"sql": "DROP TABLE users"}));
        assert_eq!(bad.outcome, Outcome::Deny);
        assert_eq!(bad.violations[0].rule, "regex");
    }

    #[test]
    fn a_size_limit_is_enforced() {
        let p = policy(
            r#"
[policy]
version = 1
[[policy.tools]]
name = "write"
mode = "allow"

[[policy.tools.args]]
name = "content"
max_bytes = 4
"#,
        );
        assert_eq!(
            p.evaluate("write", &json!({"content": "abcd"})).outcome,
            Outcome::Allow
        );
        let bad = p.evaluate("write", &json!({"content": "abcde"}));
        assert_eq!(bad.outcome, Outcome::Deny);
        assert_eq!(bad.violations[0].rule, "max_bytes");
    }

    #[test]
    fn a_total_size_limit_is_enforced() {
        let p = policy(
            r#"
[policy]
version = 1
[[policy.tools]]
name = "write"
mode = "allow"
max_total_bytes = 10
"#,
        );
        let bad = p.evaluate("write", &json!({"content": "0123456789"}));
        assert_eq!(bad.outcome, Outcome::Deny);
        assert_eq!(bad.violations[0].rule, "max_total_bytes");
    }

    #[test]
    fn nested_arguments_are_reached_by_key_and_by_path() {
        let p = policy(
            r#"
[policy]
version = 1
[[policy.tools]]
name = "copy"
mode = "allow"

[[policy.tools.args]]
name = "path"
deny = ["/etc/**"]
"#,
        );
        let evaluation = p.evaluate("copy", &json!({"files": [{"path": "/etc/passwd"}]}));
        assert_eq!(evaluation.outcome, Outcome::Deny);
        assert_eq!(evaluation.violations[0].argument, "files[0].path");
    }

    #[test]
    fn log_only_records_violations_without_blocking() {
        let p = policy(
            r#"
[policy]
version = 1
[[policy.tools]]
name = "read_file"
mode = "log-only"

[[policy.tools.args]]
name = "path"
allow = ["/srv/**"]
"#,
        );
        let evaluation = p.evaluate("read_file", &json!({"path": "/etc/passwd"}));
        assert_eq!(evaluation.outcome, Outcome::Allow);
        assert_eq!(evaluation.violations.len(), 1);
    }

    #[test]
    fn ask_asks() {
        let p = policy(
            r#"
[policy]
version = 1
[[policy.tools]]
name = "write_file"
mode = "ask"
"#,
        );
        assert_eq!(p.evaluate("write_file", &json!({})).outcome, Outcome::Ask);
    }

    #[test]
    fn deny_refuses() {
        let p = policy(
            r#"
[policy]
version = 1
[[policy.tools]]
name = "write_file"
mode = "deny"
"#,
        );
        let evaluation = p.evaluate("write_file", &json!({}));
        assert_eq!(evaluation.outcome, Outcome::Deny);
        assert_eq!(evaluation.mode, Mode::Deny);
    }

    #[test]
    fn a_bad_pin_digest_is_refused() {
        let text = "[policy]\nversion = 1\n[policy.pin]\nexpected_sha256 = \"nope\"\n";
        assert!(matches!(
            CompiledPolicy::parse(text).unwrap_err(),
            PolicyError::Invalid(_)
        ));
    }

    #[test]
    fn an_empty_pin_digest_means_not_pinned() {
        let text = "[policy]\nversion = 1\n[policy.pin]\nexpected_sha256 = \"\"\n";
        let policy = policy(text);
        assert!(policy.pin.expected_sha256.is_none());
    }
}
