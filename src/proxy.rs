//! The stdio proxy.
//!
//! The firewall owns the client's standard streams and runs the real server
//! as a child process. Two threads move data, one per direction, so a slow
//! server cannot stop the client from sending a cancellation and a client
//! that stops talking does not stop the server from finishing.
//!
//! What the proxy does:
//!
//! * evaluates every `tools/call` against the policy, and answers a denied
//!   call itself with a JSON-RPC error carrying the request's own id;
//! * hashes the tool list and reports when it changes;
//! * scans tool descriptions, tool results and outgoing arguments;
//! * writes every decision to the audit log;
//! * forwards everything else byte for byte.

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::audit::{AuditError, AuditLog, Event};
use crate::hash;
use crate::inspect::{Finding, Scanner, Severity};
use crate::jsonrpc::{self, Message};
use crate::policy::{CompiledPolicy, Outcome, Violation};
use crate::state::{PinState, StateError};

/// The error code the firewall uses for its own refusals.
///
/// It is outside the JSON-RPC reserved range and outside the range the MCP
/// specification reserves, so it cannot be mistaken for a protocol error.
pub const FIREWALL_ERROR_CODE: i64 = -32001;

/// How long the proxy waits for the other direction to finish.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

/// Something that stopped the proxy from running.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("no server command was given")]
    NoCommand,
    #[error("cannot start `{command}`: {source}")]
    Spawn {
        command: String,
        #[source]
        source: std::io::Error,
    },
    #[error("audit log: {0}")]
    Audit(#[from] AuditError),
    #[error("state file: {0}")]
    State(#[from] StateError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// How the proxy should behave.
pub struct ProxyOptions {
    /// The policy to enforce.
    pub policy: CompiledPolicy,
    /// The scanner used for inspection.
    pub scanner: Scanner,
    /// Where the audit log goes.
    pub audit: AuditLog,
    /// Where the pinned tool list is remembered.
    pub state_path: PathBuf,
    /// A name for the server, used in the audit log.
    pub server_label: String,
    /// Whether a human may approve a call that needs approval.
    pub allow_approval: bool,
}

/// The result of asking a human for permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Approval {
    /// The operator said yes.
    Granted,
    /// The operator said no.
    Declined,
    /// There was nobody to ask.
    Unavailable,
}

/// The shared state of the two pump threads.
struct Context {
    policy: CompiledPolicy,
    scanner: Scanner,
    audit: Mutex<AuditLog>,
    state: Mutex<PinState>,
    state_path: PathBuf,
    server_label: String,
    allow_approval: bool,
    /// The method of every request that is still waiting for a response.
    pending: Mutex<HashMap<String, String>>,
    /// The server's input.
    server_in: Mutex<Option<ChildStdin>>,
    /// The client's output.
    client_out: Mutex<Option<std::io::Stdout>>,
}

/// Runs the proxy until the client or the server goes away.
pub fn run(options: ProxyOptions, command: &[String]) -> Result<(), ProxyError> {
    let Some((program, arguments)) = command.split_first() else {
        return Err(ProxyError::NoCommand);
    };

    let state = PinState::load(&options.state_path)?;

    let mut child = Command::new(program)
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|source| ProxyError::Spawn {
            command: command.join(" "),
            source,
        })?;

    let server_in = child.stdin.take().expect("stdin was piped");
    let server_out = child.stdout.take().expect("stdout was piped");

    let context = Arc::new(Context {
        policy: options.policy,
        scanner: options.scanner,
        audit: Mutex::new(options.audit),
        state: Mutex::new(state),
        state_path: options.state_path,
        server_label: options.server_label.clone(),
        allow_approval: options.allow_approval,
        pending: Mutex::new(HashMap::new()),
        server_in: Mutex::new(Some(server_in)),
        client_out: Mutex::new(Some(std::io::stdout())),
    });

    context.log(
        Event::new("session_start", Severity::Info)
            .with("server", options.server_label.clone())
            .with("command", command.join(" ")),
    );

    let (done_tx, done_rx) = mpsc::channel::<&'static str>();

    let client_context = Arc::clone(&context);
    let client_done = done_tx.clone();
    let client_thread = std::thread::spawn(move || {
        client_context.pump_client_to_server();
        let _ = client_done.send("client");
    });

    let server_context = Arc::clone(&context);
    let server_done = done_tx.clone();
    let server_thread = std::thread::spawn(move || {
        server_context.pump_server_to_client(server_out);
        let _ = server_done.send("server");
    });

    drop(done_tx);

    // Wait for the first direction to end, then let the other one wind down.
    let _ = done_rx.recv();
    context.close_server_input();
    let _ = done_rx.recv_timeout(SHUTDOWN_GRACE);

    let status = wait_with_timeout(&mut child, SHUTDOWN_GRACE);

    let _ = client_thread.join();
    let _ = server_thread.join();

    context.log(
        Event::new("session_end", Severity::Info).with(
            "exit",
            status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
        ),
    );

    Ok(())
}

/// Waits for a child, killing it if it takes too long.
fn wait_with_timeout(child: &mut Child, timeout: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {}
            Err(_) => return None,
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

impl Context {
    /// Reads from the client and passes messages to the server.
    fn pump_client_to_server(&self) {
        let stdin = std::io::stdin();
        let mut reader = BufReader::new(stdin.lock());
        let mut line = String::new();

        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {}
                Err(error) => {
                    self.log(
                        Event::new("error", Severity::Error)
                            .with("where", "client_stdin")
                            .with("message", error.to_string()),
                    );
                    break;
                }
            }

            let raw = line.trim_end_matches(['\n', '\r']).to_string();
            if raw.trim().is_empty() {
                continue;
            }
            self.handle_client_line(&raw);
        }

        // The client has gone: let the server know.
        self.close_server_input();
    }

    /// Reads from the server and passes messages to the client.
    fn pump_server_to_client(&self, server_out: ChildStdout) {
        let mut reader = BufReader::new(server_out);
        let mut line = String::new();

        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {}
                Err(error) => {
                    self.log(
                        Event::new("error", Severity::Error)
                            .with("where", "server_stdout")
                            .with("message", error.to_string()),
                    );
                    break;
                }
            }

            let raw = line.trim_end_matches(['\n', '\r']).to_string();
            if raw.trim().is_empty() {
                continue;
            }
            self.handle_server_line(&raw);
        }
    }

    /// Handles one line from the client.
    fn handle_client_line(&self, raw: &str) {
        let message = match Message::parse(raw) {
            Ok(message) => message,
            Err(error) => {
                self.log(
                    Event::new("message", Severity::Warning)
                        .with("direction", "client_to_server")
                        .with("parsed", false)
                        .with("message", error.to_string()),
                );
                // Forwarding keeps the protocol intact; dropping the line
                // would leave the peer waiting for an answer.
                self.forward_to_server(raw);
                return;
            }
        };

        if message.is_request() && message.has_method(jsonrpc::METHOD_TOOLS_CALL) {
            self.handle_tool_call(raw, &message);
            return;
        }

        if let (Some(id), Some(method)) = (&message.id, &message.method) {
            self.pending
                .lock()
                .expect("pending map is not poisoned")
                .insert(id_key(id), method.clone());
        }

        self.log(
            Event::new("message", Severity::Info)
                .with("direction", "client_to_server")
                .with("method", message.method.clone().unwrap_or_default())
                .with("id", message.id.clone().unwrap_or(Value::Null)),
        );

        self.forward_to_server(raw);
    }

    /// Handles one line from the server.
    fn handle_server_line(&self, raw: &str) {
        let message = match Message::parse(raw) {
            Ok(message) => message,
            Err(error) => {
                self.log(
                    Event::new("message", Severity::Warning)
                        .with("direction", "server_to_client")
                        .with("parsed", false)
                        .with("message", error.to_string()),
                );
                self.forward_to_client(raw);
                return;
            }
        };

        if message.is_response() {
            let method = message
                .id
                .as_ref()
                .and_then(|id| {
                    self.pending
                        .lock()
                        .expect("pending map is not poisoned")
                        .remove(&id_key(id))
                })
                .unwrap_or_default();

            if method == jsonrpc::METHOD_TOOLS_LIST {
                if let Some(replacement) = self.handle_tool_list(&message) {
                    self.forward_to_client(&replacement);
                    return;
                }
            } else if (method == jsonrpc::METHOD_TOOLS_CALL
                || method == jsonrpc::METHOD_RESOURCES_READ)
                && let Some(replacement) = self.handle_tool_result(&method, &message)
            {
                self.forward_to_client(&replacement);
                return;
            }
        }
        self.forward_to_client(raw);
    }

    /// Evaluates a tool call and either forwards it or answers it.
    fn handle_tool_call(&self, raw: &str, message: &Message) {
        let tool = message.tool_name().unwrap_or_default().to_string();
        let arguments = message
            .tool_arguments()
            .cloned()
            .unwrap_or(Value::Object(Default::default()));
        let evaluation = self.policy.evaluate(&tool, &arguments);
        let findings = self.scanner.scan_value(&arguments);

        let mut event = Event::new("tool_call", Severity::Info)
            .with("server", self.server_label.clone())
            .with("tool", tool.clone())
            .with("mode", evaluation.mode.as_str())
            .with("decision", decision_name(evaluation.outcome))
            .with("reason", evaluation.reason.clone())
            .with("code", evaluation.code)
            .with("id", message.id.clone().unwrap_or(Value::Null));

        let mut redacted_arguments = arguments.clone();
        self.scanner.redact_value(&mut redacted_arguments);
        event = event.with("arguments", redacted_arguments);

        if !evaluation.violations.is_empty() {
            event = event.with("violations", violations_json(&evaluation.violations));
        }
        if !findings.is_empty() {
            event = event.with("findings", findings_json(&findings));
        }
        self.log(event);

        if !findings.is_empty() {
            self.log(
                Event::new("alert", Severity::Warning)
                    .with("kind", "credential_in_arguments")
                    .with("tool", tool.clone())
                    .with("findings", findings_json(&findings)),
            );
        }

        if !evaluation.violations.is_empty() && evaluation.mode == crate::policy::Mode::LogOnly {
            self.log(
                Event::new("alert", Severity::Warning)
                    .with("kind", "argument_violation")
                    .with("tool", tool.clone())
                    .with("violations", violations_json(&evaluation.violations))
                    .with("enforced", false),
            );
        }

        let approval = match evaluation.outcome {
            Outcome::Allow => Approval::Granted,
            Outcome::Deny => Approval::Declined,
            Outcome::Ask => {
                self.ask_for_approval(&tool, &evaluation.reason, &evaluation.violations)
            }
        };

        if approval != Approval::Granted {
            let (code, reason) = match (evaluation.outcome, approval) {
                (_, Approval::Unavailable) => (
                    "approval_unavailable",
                    format!("tool `{tool}` needs approval and nobody could be asked"),
                ),
                (Outcome::Ask, _) => (
                    "operator_declined",
                    format!("tool `{tool}` was not approved"),
                ),
                _ => (evaluation.code, evaluation.reason.clone()),
            };
            self.log(
                Event::new("tool_call_denied", Severity::Warning)
                    .with("tool", tool.clone())
                    .with("code", code)
                    .with("reason", reason.clone())
                    .with("id", message.id.clone().unwrap_or(Value::Null)),
            );
            self.deny(message, &tool, code, &reason, &evaluation.violations);
            return;
        }

        if let (Some(id), Some(method)) = (&message.id, &message.method) {
            self.pending
                .lock()
                .expect("pending map is not poisoned")
                .insert(id_key(id), method.clone());
        }
        self.forward_to_server(raw);
    }

    /// Answers a denied call with a JSON-RPC error.
    fn deny(
        &self,
        message: &Message,
        tool: &str,
        code: &str,
        reason: &str,
        violations: &[Violation],
    ) {
        let id = message.id.clone().unwrap_or(Value::Null);
        let mut data = json!({
            "reason": code,
            "tool": tool,
        });
        if !violations.is_empty() {
            data["violations"] = violations_json(violations);
        }
        let response = jsonrpc::error_response(
            &id,
            FIREWALL_ERROR_CODE,
            &format!("mcp-firewall: {reason}"),
            data,
        );
        let text = serde_json::to_string(&response).unwrap_or_else(|_| {
            format!("{{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{{\"code\":{FIREWALL_ERROR_CODE},\"message\":\"mcp-firewall: refused\"}}}}")
        });
        self.forward_to_client(&text);
    }

    /// Inspects a tool list, updating the pin and reporting changes.
    ///
    /// Returns a replacement message when the policy refuses to serve the
    /// list.
    fn handle_tool_list(&self, message: &Message) -> Option<String> {
        let tools = message.tool_list()?.clone();
        let digest = hash::tools_hash(&tools);
        let prints = hash::fingerprints(&tools);
        let names: Vec<String> = prints.iter().map(|p| p.name.clone()).collect();

        let mut changed = false;
        let mut alert: Option<Event> = None;

        {
            let mut state = self.state.lock().expect("state is not poisoned");
            let diff = hash::diff(&state.tools, &prints);

            if let Some(expected) = self.policy.pin.expected_sha256.as_deref()
                && expected != digest
            {
                changed = true;
                alert = Some(
                    Event::new("alert", Severity::Error)
                        .with("kind", "tool_pin_mismatch")
                        .with("expected", expected)
                        .with("observed", digest.clone())
                        .with("detail", format!("expected {expected}, observed {digest}")),
                );
            } else if let Some(previous) = state.tools_sha256.as_deref()
                && previous != digest
            {
                changed = true;
                alert = Some(
                    Event::new("alert", Severity::Error)
                        .with("kind", "tool_definition_changed")
                        .with("previous", previous)
                        .with("observed", digest.clone())
                        .with("added", diff.added.clone())
                        .with("removed", diff.removed.clone())
                        .with("changed", diff.changed.clone())
                        .with("detail", diff.describe()),
                );
            }

            state.tools_sha256 = Some(digest.clone());
            if state.first_seen_sha256.is_none() {
                state.first_seen_sha256 = Some(digest.clone());
                state.first_seen = Some(crate::time::now_rfc3339());
            }
            state.tools = prints.clone();
            if let Err(error) = state.save(&self.state_path) {
                self.log(
                    Event::new("error", Severity::Error)
                        .with("where", "state")
                        .with("message", error.to_string()),
                );
            }
        }

        if let Some(alert) = alert {
            self.log(alert);
        }

        self.log(
            Event::new("tool_list", Severity::Info)
                .with("tools", names)
                .with("sha256", digest.clone())
                .with("changed", changed),
        );

        self.scan_tool_descriptions(&tools);

        if changed
            && self.policy.pin.enforce
            && self
                .policy
                .pin
                .expected_sha256
                .as_deref()
                .is_some_and(|expected| expected != digest)
        {
            let id = message.id.clone().unwrap_or(Value::Null);
            let response = jsonrpc::error_response(
                &id,
                FIREWALL_ERROR_CODE,
                "mcp-firewall: the tool list does not match the pinned digest",
                json!({
                    "reason": "tool_pin_mismatch",
                    "expected": self.policy.pin.expected_sha256,
                    "observed": digest,
                }),
            );
            return Some(serde_json::to_string(&response).unwrap_or_default());
        }

        None
    }

    /// Scans tool descriptions for injected instructions.
    fn scan_tool_descriptions(&self, tools: &[Value]) {
        for tool in tools {
            let name = tool
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let mut findings = Vec::new();
            for field in ["description", "title"] {
                let Some(text) = tool.get(field).and_then(Value::as_str) else {
                    continue;
                };
                findings.extend(self.scanner.scan_text(text));
            }
            if findings.is_empty() {
                continue;
            }
            self.log(
                Event::new("alert", Severity::Error)
                    .with("kind", "poisoned_tool_description")
                    .with("tool", name)
                    .with("findings", findings_json(&findings)),
            );
        }
    }

    /// Scans a tool result and, when the policy says so, redacts it.
    ///
    /// Returns a replacement message when the result was rewritten.
    fn handle_tool_result(&self, method: &str, message: &Message) -> Option<String> {
        let result = message.result.as_ref()?;
        let findings = self.scanner.scan_value(result);

        self.log(
            Event::new("tool_result", Severity::Info)
                .with("method", method)
                .with("id", message.id.clone().unwrap_or(Value::Null))
                .with("findings", findings_json(&findings)),
        );

        if !findings.is_empty() {
            self.log(
                Event::new("alert", Severity::Error)
                    .with("kind", "suspicious_tool_result")
                    .with("method", method)
                    .with("id", message.id.clone().unwrap_or(Value::Null))
                    .with("findings", findings_json(&findings)),
            );
        }

        if !self.policy.redact.forward_results || findings.is_empty() {
            return None;
        }

        let mut rewritten = message.raw.clone();
        let result = rewritten.get_mut("result")?;
        self.scanner.redact_value(result);
        Some(serde_json::to_string(&rewritten).unwrap_or_default())
    }

    /// Asks the operator on the terminal whether a call may go through.
    fn ask_for_approval(&self, tool: &str, reason: &str, violations: &[Violation]) -> Approval {
        if !self.allow_approval {
            self.log(
                Event::new("alert", Severity::Warning)
                    .with("kind", "approval_unavailable")
                    .with("tool", tool)
                    .with(
                        "detail",
                        "approval is switched off, so the call was refused",
                    ),
            );
            return Approval::Unavailable;
        }

        let Ok(mut tty) = OpenOptions::new().read(true).write(true).open("/dev/tty") else {
            self.log(
                Event::new("alert", Severity::Warning)
                    .with("kind", "approval_unavailable")
                    .with("tool", tool)
                    .with("detail", "no terminal is attached, so the call was refused"),
            );
            return Approval::Unavailable;
        };

        let mut prompt = String::new();
        prompt.push_str("\nmcp-firewall: this call needs approval\n");
        prompt.push_str(&format!("  tool:   {tool}\n"));
        prompt.push_str(&format!("  reason: {reason}\n"));
        for violation in violations {
            prompt.push_str(&format!(
                "  broken: {} on `{}`: {}\n",
                violation.rule, violation.argument, violation.detail
            ));
        }
        prompt.push_str("allow this call? [y/N] ");
        let _ = tty.write_all(prompt.as_bytes());
        let _ = tty.flush();

        let mut answer = String::new();
        if BufReader::new(&mut tty).read_line(&mut answer).is_err() {
            return Approval::Unavailable;
        }
        let answer = answer.trim().to_ascii_lowercase();
        if answer == "y" || answer == "yes" {
            Approval::Granted
        } else {
            Approval::Declined
        }
    }

    /// Writes a message to the server.
    fn forward_to_server(&self, raw: &str) {
        let mut guard = self.server_in.lock().expect("server input is not poisoned");
        let Some(input) = guard.as_mut() else {
            return;
        };
        if let Err(error) = writeln!(input, "{raw}") {
            self.log(
                Event::new("error", Severity::Error)
                    .with("where", "server_stdin")
                    .with("message", error.to_string()),
            );
        }
        let _ = input.flush();
    }

    /// Writes a message to the client.
    fn forward_to_client(&self, raw: &str) {
        let mut guard = self
            .client_out
            .lock()
            .expect("client output is not poisoned");
        let Some(output) = guard.as_mut() else {
            return;
        };
        if let Err(error) = writeln!(output, "{raw}") {
            self.log(
                Event::new("error", Severity::Error)
                    .with("where", "client_stdout")
                    .with("message", error.to_string()),
            );
        }
        let _ = output.flush();
    }

    /// Closes the server's input, which is how it is told to stop.
    fn close_server_input(&self) {
        let mut guard = self.server_in.lock().expect("server input is not poisoned");
        guard.take();
    }

    /// Writes an event to the audit log.
    fn log(&self, event: Event) {
        let mut audit = self.audit.lock().expect("audit log is not poisoned");
        if let Err(error) = audit.write(&event) {
            eprintln!("mcp-firewall: cannot write to the audit log: {error}");
        }
    }
}

/// The name of a decision, for the audit log.
fn decision_name(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Allow => "allow",
        Outcome::Ask => "ask",
        Outcome::Deny => "deny",
    }
}

/// A key for the pending map.
fn id_key(id: &Value) -> String {
    match id {
        Value::String(text) => format!("s:{text}"),
        other => format!("n:{other}"),
    }
}

/// Violations as JSON.
fn violations_json(violations: &[Violation]) -> Value {
    Value::Array(
        violations
            .iter()
            .map(|violation| {
                json!({
                    "rule": violation.rule,
                    "argument": violation.argument,
                    "detail": violation.detail,
                })
            })
            .collect(),
    )
}

/// Findings as JSON.
fn findings_json(findings: &[Finding]) -> Value {
    Value::Array(
        findings
            .iter()
            .map(|finding| {
                json!({
                    "rule": finding.rule,
                    "kind": finding.kind.as_str(),
                    "severity": finding.severity.as_str(),
                    "excerpt": finding.excerpt,
                })
            })
            .collect(),
    )
}
