//! The pinned tool list state.
//!
//! The state file remembers the tool list the firewall last saw, so a change
//! is noticed even across restarts. It is written next to the audit log by
//! default.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::hash::ToolFingerprint;

/// The state file's schema version.
pub const STATE_VERSION: u32 = 1;

/// The remembered tool list.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PinState {
    /// The schema version.
    #[serde(default)]
    pub version: u32,
    /// The hash of the tool list as it was last seen.
    #[serde(default)]
    pub tools_sha256: Option<String>,
    /// The hash of the tool list as it was first seen.
    #[serde(default)]
    pub first_seen_sha256: Option<String>,
    /// When the tool list was first seen.
    #[serde(default)]
    pub first_seen: Option<String>,
    /// The fingerprints of the tools as they were last seen.
    #[serde(default)]
    pub tools: Vec<ToolFingerprint>,
}

/// Something that stopped the state file from being used.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("cannot read state file `{path}`: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot write state file `{path}`: {source}")]
    Write {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot parse state file `{path}`: {source}")]
    Parse {
        path: String,
        #[source]
        source: serde_json::Error,
    },
}

impl PinState {
    /// Reads the state file, returning an empty state when it does not exist.
    pub fn load(path: &Path) -> Result<Self, StateError> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(PinState {
                    version: STATE_VERSION,
                    ..PinState::default()
                });
            }
            Err(source) => {
                return Err(StateError::Read {
                    path: path.display().to_string(),
                    source,
                });
            }
        };

        let mut state: PinState =
            serde_json::from_str(&text).map_err(|source| StateError::Parse {
                path: path.display().to_string(),
                source,
            })?;
        state.version = STATE_VERSION;
        Ok(state)
    }

    /// Writes the state file.
    pub fn save(&self, path: &Path) -> Result<(), StateError> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            let _ = std::fs::create_dir_all(parent);
        }
        let text = serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string());
        std::fs::write(path, text).map_err(|source| StateError::Write {
            path: path.display().to_string(),
            source,
        })
    }

    /// The default state path for an audit log.
    pub fn default_path_for(audit_path: &Path) -> PathBuf {
        let directory = audit_path.parent().filter(|p| !p.as_os_str().is_empty());
        match directory {
            Some(dir) => dir.join("state.json"),
            None => PathBuf::from("state.json"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("mcp-firewall-state-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_missing_state_file_is_an_empty_state() {
        let path = temp_dir("missing").join("state.json");
        let _ = std::fs::remove_file(&path);
        let state = PinState::load(&path).unwrap();
        assert!(state.tools_sha256.is_none());
    }

    #[test]
    fn a_state_file_round_trips() {
        let path = temp_dir("roundtrip").join("state.json");
        let state = PinState {
            version: STATE_VERSION,
            tools_sha256: Some("abc".to_string()),
            first_seen_sha256: Some("abc".to_string()),
            first_seen: Some("2026-01-01T00:00:00.000Z".to_string()),
            tools: vec![ToolFingerprint {
                name: "read_file".to_string(),
                hash: "def".to_string(),
            }],
        };
        state.save(&path).unwrap();
        let loaded = PinState::load(&path).unwrap();
        assert_eq!(loaded.tools_sha256, Some("abc".to_string()));
        assert_eq!(loaded.tools.len(), 1);
        assert_eq!(loaded.tools[0].name, "read_file");
    }

    #[test]
    fn a_corrupt_state_file_is_an_error() {
        let path = temp_dir("corrupt").join("state.json");
        std::fs::write(&path, "not json").unwrap();
        assert!(matches!(
            PinState::load(&path).unwrap_err(),
            StateError::Parse { .. }
        ));
    }

    #[test]
    fn the_default_state_path_sits_beside_the_audit_log() {
        let path = PinState::default_path_for(Path::new("/tmp/logs/audit.jsonl"));
        assert_eq!(path, PathBuf::from("/tmp/logs/state.json"));

        let path = PinState::default_path_for(Path::new("audit.jsonl"));
        assert_eq!(path, PathBuf::from("state.json"));
    }
}
