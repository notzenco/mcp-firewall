//! The JSONL audit log.
//!
//! One JSON object per line, append-only. Every line is a self-contained
//! event, so the log can be tailed, grepped and summarised without any
//! index. Credentials are redacted before they reach the log.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::{Map, Value};

use crate::inspect::Severity;
use crate::time::now_rfc3339;

/// Something that stopped the audit log from being written.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("cannot open audit log `{path}`: {source}")]
    Open {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot write to audit log `{path}`: {source}")]
    Write {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot read audit log `{path}`: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("audit log `{path}` has a malformed line {line}: {source}")]
    Malformed {
        path: String,
        line: usize,
        #[source]
        source: serde_json::Error,
    },
}

/// An event in the audit log.
#[derive(Debug, Clone, Serialize)]
pub struct Event {
    /// When the event happened, in RFC 3339.
    pub ts: String,
    /// What kind of event it is.
    pub event: String,
    /// How serious it is.
    pub severity: Severity,
    /// The event's own fields.
    #[serde(flatten)]
    pub fields: Map<String, Value>,
}

impl Event {
    /// Starts an event with the current time.
    pub fn new(event: &str, severity: Severity) -> Self {
        Event {
            ts: now_rfc3339(),
            event: event.to_string(),
            severity,
            fields: Map::new(),
        }
    }

    /// Adds a field.
    pub fn with(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.fields.insert(key.to_string(), value.into());
        self
    }
}

/// An append-only writer for the audit log.
pub struct AuditLog {
    path: PathBuf,
    writer: BufWriter<File>,
}

impl AuditLog {
    /// Opens the log for appending, creating it if needed.
    pub fn open(path: &Path) -> Result<Self, AuditError> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|source| AuditError::Open {
                path: path.display().to_string(),
                source,
            })?;
        Ok(Self {
            path: path.to_path_buf(),
            writer: BufWriter::new(file),
        })
    }

    /// The path of the log.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Writes an event and flushes it.
    ///
    /// The flush matters: if the proxy is killed, the last thing it did must
    /// still be in the log.
    pub fn write(&mut self, event: &Event) -> Result<(), AuditError> {
        let mut line = serde_json::to_vec(event).map_err(|source| AuditError::Write {
            path: self.path.display().to_string(),
            source: std::io::Error::other(source),
        })?;
        line.push(b'\n');
        self.writer
            .write_all(&line)
            .map_err(|source| AuditError::Write {
                path: self.path.display().to_string(),
                source,
            })?;
        self.writer.flush().map_err(|source| AuditError::Write {
            path: self.path.display().to_string(),
            source,
        })
    }
}

/// A count of something in the log.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Counts {
    /// How many of each key.
    pub counts: BTreeMap<String, usize>,
}

impl Counts {
    /// Adds one to a key.
    pub fn add(&mut self, key: &str) {
        *self.counts.entry(key.to_string()).or_insert(0) += 1;
    }

    /// The count for a key.
    pub fn get(&self, key: &str) -> usize {
        self.counts.get(key).copied().unwrap_or(0)
    }
}

/// What the audit command reports.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Summary {
    /// The number of events in the log.
    pub events: usize,
    /// The first and last timestamps in the log.
    pub first_ts: Option<String>,
    pub last_ts: Option<String>,
    /// How many events of each kind.
    pub by_event: Counts,
    /// How many tool calls were allowed, denied or needed approval.
    pub by_decision: Counts,
    /// How many calls each tool received.
    pub by_tool: Counts,
    /// How many findings each rule produced.
    pub by_rule: Counts,
    /// How many findings of each kind.
    pub by_kind: Counts,
    /// How many events of each severity.
    pub by_severity: Counts,
    /// The highest severity seen.
    pub max_severity: Option<Severity>,
    /// The alerts, in the order they happened.
    pub alerts: Vec<Value>,
    /// The number of lines that could not be parsed.
    pub malformed_lines: usize,
}

impl Summary {
    /// Summarises a log file.
    pub fn from_file(path: &Path) -> Result<Self, AuditError> {
        let file = File::open(path).map_err(|source| AuditError::Read {
            path: path.display().to_string(),
            source,
        })?;
        Summary::from_reader(file)
    }

    /// Summarises a log read from anything.
    pub fn from_reader(reader: impl Read) -> Result<Self, AuditError> {
        let mut summary = Summary::default();
        let mut buffer = String::new();
        let mut reader = reader;

        loop {
            buffer.clear();
            let read =
                std::io::Read::read_to_string(&mut reader, &mut buffer).map_err(|source| {
                    AuditError::Read {
                        path: "<reader>".to_string(),
                        source,
                    }
                })?;
            if read == 0 {
                break;
            }

            for line in buffer.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                match serde_json::from_str::<Value>(line) {
                    Ok(event) => summary.add_event(&event),
                    Err(_) => summary.malformed_lines += 1,
                }
            }
        }

        Ok(summary)
    }

    /// Folds one event into the summary.
    fn add_event(&mut self, event: &Value) {
        self.events += 1;

        if let Some(ts) = event.get("ts").and_then(Value::as_str) {
            match &self.first_ts {
                None => self.first_ts = Some(ts.to_string()),
                Some(first) if ts < first.as_str() => self.first_ts = Some(ts.to_string()),
                _ => {}
            }
            match &self.last_ts {
                None => self.last_ts = Some(ts.to_string()),
                Some(last) if ts > last.as_str() => self.last_ts = Some(ts.to_string()),
                _ => {}
            }
        }

        let kind = event
            .get("event")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        self.by_event.add(kind);

        let severity = match event.get("severity").and_then(Value::as_str) {
            Some("error") => Severity::Error,
            Some("warning") => Severity::Warning,
            Some("info") => Severity::Info,
            _ => Severity::Info,
        };
        self.by_severity.add(severity.as_str());
        self.max_severity = Some(match self.max_severity {
            Some(current) => current.max(severity),
            None => severity,
        });

        if let Some(decision) = event.get("decision").and_then(Value::as_str) {
            self.by_decision.add(decision);
        }
        if let Some(tool) = event.get("tool").and_then(Value::as_str) {
            self.by_tool.add(tool);
        }

        if let Some(findings) = event.get("findings").and_then(Value::as_array) {
            for finding in findings {
                if let Some(rule) = finding.get("rule").and_then(Value::as_str) {
                    self.by_rule.add(rule);
                }
                if let Some(finding_kind) = finding.get("kind").and_then(Value::as_str) {
                    self.by_kind.add(finding_kind);
                }
            }
        }

        if kind == "alert" {
            self.alerts.push(event.clone());
        }
    }

    /// The summary as plain text.
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("mcp-firewall audit summary\n");
        out.push_str(&format!("  events        {}\n", self.events));
        if let (Some(first), Some(last)) = (&self.first_ts, &self.last_ts) {
            out.push_str(&format!("  period        {first} .. {last}\n"));
        }
        if let Some(severity) = self.max_severity {
            out.push_str(&format!("  max severity  {}\n", severity.as_str()));
        }
        if self.malformed_lines > 0 {
            out.push_str(&format!("  malformed     {}\n", self.malformed_lines));
        }

        if !self.by_event.counts.is_empty() {
            out.push_str("\nevents\n");
            render_counts(&mut out, &self.by_event);
        }
        if !self.by_decision.counts.is_empty() {
            out.push_str("\ndecisions\n");
            render_counts(&mut out, &self.by_decision);
        }
        if !self.by_tool.counts.is_empty() {
            out.push_str("\ntools\n");
            render_counts(&mut out, &self.by_tool);
        }
        if !self.by_rule.counts.is_empty() {
            out.push_str("\nfindings by rule\n");
            render_counts(&mut out, &self.by_rule);
        }
        if !self.by_kind.counts.is_empty() {
            out.push_str("\nfindings by kind\n");
            render_counts(&mut out, &self.by_kind);
        }
        if !self.alerts.is_empty() {
            out.push_str(&format!("\nalerts ({} shown)\n", self.alerts.len()));
            for alert in &self.alerts {
                let kind = alert.get("kind").and_then(Value::as_str).unwrap_or("alert");
                let detail = alert.get("detail").and_then(Value::as_str).unwrap_or("");
                out.push_str(&format!("  {kind}: {detail}\n"));
            }
        }

        out
    }
}

/// Writes a table of counts.
fn render_counts(out: &mut String, counts: &Counts) {
    let mut rows: Vec<(&String, &usize)> = counts.counts.iter().collect();
    rows.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    for (key, count) in rows {
        out.push_str(&format!("  {count:>6}  {key}\n"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn temp_path(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("mcp-firewall-audit-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("audit.jsonl")
    }

    #[test]
    fn writes_one_json_object_per_line() {
        let path = temp_path("write");
        let _ = std::fs::remove_file(&path);
        let mut log = AuditLog::open(&path).unwrap();
        log.write(&Event::new("session_start", Severity::Info).with("server", "demo"))
            .unwrap();
        log.write(&Event::new("session_end", Severity::Info))
            .unwrap();
        drop(log);

        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        let first: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["event"], "session_start");
        assert_eq!(first["server"], "demo");
        assert!(first["ts"].as_str().unwrap().ends_with('Z'));
    }

    #[test]
    fn appends_to_an_existing_log() {
        let path = temp_path("append");
        let _ = std::fs::remove_file(&path);
        for _ in 0..2 {
            let mut log = AuditLog::open(&path).unwrap();
            log.write(&Event::new("message", Severity::Info)).unwrap();
        }
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 2);
    }

    #[test]
    fn summarises_a_log() {
        let path = temp_path("summary");
        let _ = std::fs::remove_file(&path);
        let mut log = AuditLog::open(&path).unwrap();
        log.write(
            &Event::new("tool_call", Severity::Info)
                .with("tool", "read_file")
                .with("decision", "allow"),
        )
        .unwrap();
        log.write(
            &Event::new("tool_call", Severity::Warning)
                .with("tool", "write_file")
                .with("decision", "deny"),
        )
        .unwrap();
        log.write(&Event::new("tool_result", Severity::Error).with(
            "findings",
            json!([{"rule": "ignore_previous_instructions", "kind": "injection"}]),
        ))
        .unwrap();
        log.write(
            &Event::new("alert", Severity::Error)
                .with("kind", "tool_definition_changed")
                .with("detail", "hash differs"),
        )
        .unwrap();
        drop(log);

        let summary = Summary::from_file(&path).unwrap();
        assert_eq!(summary.events, 4);
        assert_eq!(summary.by_event.get("tool_call"), 2);
        assert_eq!(summary.by_decision.get("allow"), 1);
        assert_eq!(summary.by_decision.get("deny"), 1);
        assert_eq!(summary.by_tool.get("read_file"), 1);
        assert_eq!(summary.by_rule.get("ignore_previous_instructions"), 1);
        assert_eq!(summary.by_kind.get("injection"), 1);
        assert_eq!(summary.alerts.len(), 1);
        assert_eq!(summary.max_severity, Some(Severity::Error));

        let rendered = summary.render();
        assert!(rendered.contains("tool_definition_changed"), "{rendered}");
    }

    #[test]
    fn a_malformed_line_is_counted_not_fatal() {
        let path = temp_path("malformed");
        std::fs::write(&path, "{\"event\":\"message\"}\nnot json\n").unwrap();
        let summary = Summary::from_file(&path).unwrap();
        assert_eq!(summary.events, 1);
        assert_eq!(summary.malformed_lines, 1);
    }

    #[test]
    fn an_empty_log_summarises_to_nothing() {
        let path = temp_path("empty");
        std::fs::write(&path, "").unwrap();
        let summary = Summary::from_file(&path).unwrap();
        assert_eq!(summary.events, 0);
        assert!(summary.render().contains("events        0"));
    }
}
