//! Hashing of tool definitions.
//!
//! The hash is what makes a rug pull visible: the same server, with a
//! different tool list, produces a different digest. The canonical form is
//! built here rather than taken from `serde_json`, because key order in the
//! digest must not depend on the feature flags another crate happens to
//! enable.

use serde_json::Value;
use sha2::{Digest, Sha256};

/// The fields of a tool definition that are hashed.
///
/// Icons and other presentation metadata are left out on purpose: they change
/// without changing what a tool does, and a digest that churns on every
/// render is a digest nobody trusts.
const HASHED_FIELDS: &[&str] = &[
    "name",
    "title",
    "description",
    "inputSchema",
    "outputSchema",
    "annotations",
];

/// The fingerprint of one tool.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ToolFingerprint {
    /// The tool's name.
    pub name: String,
    /// The hash of the tool's canonical form.
    pub hash: String,
}

/// The canonical JSON form of a value: object keys sorted, no insignificant
/// whitespace.
pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => {
            out.push('"');
            out.push_str(&serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string()));
            out.push('"');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key).unwrap_or_else(|_| "\"\"".to_string()));
                out.push(':');
                write_canonical(&map[*key], out);
            }
            out.push('}');
        }
    }
}

/// The canonical form of one tool definition.
pub fn canonical_tool(tool: &Value) -> String {
    let mut parts = String::from("{");
    let mut fields: Vec<&str> = HASHED_FIELDS.to_vec();
    fields.sort_unstable();

    let mut first = true;
    for field in fields {
        let Some(value) = tool.get(field) else {
            continue;
        };
        if !first {
            parts.push(',');
        }
        first = false;
        parts.push_str(&format!("\"{field}\":{}", canonical_json(value)));
    }
    parts.push('}');
    parts
}

/// The fingerprint of one tool definition.
pub fn fingerprint(tool: &Value) -> ToolFingerprint {
    let name = tool
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let hash = sha256_hex(canonical_tool(tool).as_bytes());
    ToolFingerprint { name, hash }
}

/// The fingerprints of a tool list, in the order the server gave them.
pub fn fingerprints(tools: &[Value]) -> Vec<ToolFingerprint> {
    tools.iter().map(fingerprint).collect()
}

/// The hash of a whole tool list.
///
/// It is the hash of the fingerprints, so a change to any tool changes it,
/// and adding or removing a tool changes it too.
pub fn tools_hash(tools: &[Value]) -> String {
    let prints = fingerprints(tools);
    let mut canonical = String::from("[");
    for (i, print) in prints.iter().enumerate() {
        if i > 0 {
            canonical.push(',');
        }
        canonical.push_str(&format!(
            "{{\"name\":{},\"hash\":{}}}",
            serde_json::to_string(&print.name).unwrap_or_else(|_| "\"\"".to_string()),
            serde_json::to_string(&print.hash).unwrap_or_else(|_| "\"\"".to_string())
        ));
    }
    canonical.push(']');
    sha256_hex(canonical.as_bytes())
}

/// The hex sha256 digest of some bytes.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::new().chain_update(bytes).finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// What changed between two tool lists.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolDiff {
    /// Tools that are new.
    pub added: Vec<String>,
    /// Tools that are gone.
    pub removed: Vec<String>,
    /// Tools that are still there but hash differently.
    pub changed: Vec<String>,
}

impl ToolDiff {
    /// True when nothing changed.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }

    /// A one line description.
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if !self.added.is_empty() {
            parts.push(format!("added: {}", self.added.join(", ")));
        }
        if !self.removed.is_empty() {
            parts.push(format!("removed: {}", self.removed.join(", ")));
        }
        if !self.changed.is_empty() {
            parts.push(format!("changed: {}", self.changed.join(", ")));
        }
        if parts.is_empty() {
            "no change".to_string()
        } else {
            parts.join("; ")
        }
    }
}

/// Compares two sets of fingerprints.
pub fn diff(previous: &[ToolFingerprint], current: &[ToolFingerprint]) -> ToolDiff {
    let mut result = ToolDiff::default();

    for print in current {
        match previous.iter().find(|p| p.name == print.name) {
            Some(old) if old.hash == print.hash => {}
            Some(_) => result.changed.push(print.name.clone()),
            None => result.added.push(print.name.clone()),
        }
    }
    for print in previous {
        if !current.iter().any(|p| p.name == print.name) {
            result.removed.push(print.name.clone());
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tool(name: &str, description: &str) -> Value {
        json!({
            "name": name,
            "description": description,
            "inputSchema": {"type": "object"}
        })
    }

    #[test]
    fn canonical_json_sorts_object_keys() {
        let value = json!({"b": 1, "a": {"d": 2, "c": 3}});
        assert_eq!(canonical_json(&value), r#"{"a":{"c":3,"d":2},"b":1}"#);
    }

    #[test]
    fn the_hash_is_stable_for_the_same_list() {
        let tools = vec![tool("read_file", "reads"), tool("write_file", "writes")];
        assert_eq!(tools_hash(&tools), tools_hash(&tools));
    }

    #[test]
    fn the_hash_changes_when_a_description_changes() {
        let before = vec![tool("read_file", "reads")];
        let after = vec![tool("read_file", "reads and writes")];
        assert_ne!(tools_hash(&before), tools_hash(&after));
    }

    #[test]
    fn the_hash_changes_when_a_schema_changes() {
        let before = vec![json!({"name": "t", "inputSchema": {"type": "object"}})];
        let after =
            vec![json!({"name": "t", "inputSchema": {"type": "object", "required": ["a"]}})];
        assert_ne!(tools_hash(&before), tools_hash(&after));
    }

    #[test]
    fn the_hash_ignores_icon_churn() {
        let before = vec![json!({"name": "t", "icons": []})];
        let after = vec![json!({"name": "t", "icons": [{"src": "https://example.com/i.png"}]})];
        assert_eq!(tools_hash(&before), tools_hash(&after));
    }

    #[test]
    fn the_hash_changes_when_a_tool_is_added() {
        let before = vec![tool("read_file", "reads")];
        let after = vec![tool("read_file", "reads"), tool("write_file", "writes")];
        assert_ne!(tools_hash(&before), tools_hash(&after));
    }

    #[test]
    fn a_diff_reports_added_removed_and_changed_tools() {
        let previous = fingerprints(&[tool("read_file", "reads"), tool("old_tool", "old")]);
        let current = fingerprints(&[
            tool("read_file", "reads differently"),
            tool("new_tool", "new"),
        ]);
        let diff = diff(&previous, &current);
        assert_eq!(diff.changed, vec!["read_file"]);
        assert_eq!(diff.added, vec!["new_tool"]);
        assert_eq!(diff.removed, vec!["old_tool"]);
        assert!(diff.describe().contains("changed: read_file"));
    }

    #[test]
    fn an_unchanged_list_has_an_empty_diff() {
        let tools = vec![tool("read_file", "reads")];
        let diff = diff(&fingerprints(&tools), &fingerprints(&tools));
        assert!(diff.is_empty());
    }
}
