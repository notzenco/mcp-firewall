//! Integration tests: the real proxy, in front of a real (tiny) MCP server.
//!
//! Nothing here touches the network. The server is the `fake_mcp_server`
//! example in this package, spoken to over the proxy's own standard streams.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{Value, json};

/// The firewall binary under test.
const FIREWALL: &str = env!("CARGO_BIN_EXE_mcp-firewall");

/// Where the fake server example was built.
fn fake_server() -> PathBuf {
    // The example is built next to the test binary's directory.
    let test_binary = std::env::current_exe().expect("the test binary has a path");
    let debug = test_binary
        .parent()
        .and_then(|deps| deps.parent())
        .expect("the test binary is in a target directory");
    let path = debug.join("examples").join("fake_mcp_server");
    assert!(
        path.exists(),
        "the fake server example was not built at {}",
        path.display()
    );
    path
}

/// A running proxy session.
struct Session {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    directory: PathBuf,
}

impl Session {
    /// Starts the proxy in front of the fake server.
    ///
    /// The fake server records everything it receives, so a test can prove
    /// that a denied call never got there.
    fn start(policy: &str, server_arguments: &[&str]) -> Self {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let directory = directory.keep();
        let policy_path = directory.join("policy.toml");
        std::fs::write(&policy_path, policy).expect("the policy can be written");
        let record = directory.join("received.jsonl");

        let mut child = Command::new(FIREWALL)
            .arg("run")
            .arg("--policy")
            .arg(&policy_path)
            .arg("--audit")
            .arg(directory.join("audit.jsonl"))
            .arg("--state")
            .arg(directory.join("state.json"))
            .arg("--no-approval")
            .arg("--")
            .arg(fake_server())
            .arg("--record")
            .arg(&record)
            .args(server_arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("the proxy starts");

        let stdin = child.stdin.take().expect("stdin is piped");
        let stdout = BufReader::new(child.stdout.take().expect("stdout is piped"));

        Session {
            child,
            stdin,
            stdout,
            directory,
        }
    }

    /// Sends a message.
    fn send(&mut self, message: &Value) {
        writeln!(self.stdin, "{message}").expect("the message can be sent");
        self.stdin.flush().expect("the message can be flushed");
    }

    /// Sends a raw line, for the tests that send something that is not JSON.
    fn send_raw(&mut self, line: &str) {
        writeln!(self.stdin, "{line}").expect("the line can be sent");
        self.stdin.flush().expect("the line can be flushed");
    }

    /// Reads the next message.
    fn read(&mut self) -> Value {
        let mut line = String::new();
        let read = self
            .stdout
            .read_line(&mut line)
            .expect("a line can be read");
        assert!(read > 0, "the proxy closed the stream unexpectedly");
        serde_json::from_str(line.trim()).expect("the proxy wrote valid JSON")
    }

    /// Sends a request and reads the response that answers it.
    fn request(&mut self, method: &str, id: i64, params: Value) -> Value {
        self.send(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        }));
        self.read_response(id)
    }

    /// Reads messages until the one with `id` arrives.
    fn read_response(&mut self, id: i64) -> Value {
        loop {
            let message = self.read();
            if message.get("id").and_then(Value::as_i64) == Some(id) {
                return message;
            }
        }
    }

    /// The audit log, as parsed events.
    fn audit(&self) -> Vec<Value> {
        self.audit_text()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).expect("audit lines are JSON"))
            .collect()
    }

    /// The audit log, as text.
    fn audit_text(&self) -> String {
        std::fs::read_to_string(self.directory.join("audit.jsonl")).unwrap_or_default()
    }

    /// What the fake server received.
    fn received(&self) -> String {
        std::fs::read_to_string(self.directory.join("received.jsonl")).unwrap_or_default()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

/// A policy that permits everything.
const PERMISSIVE: &str = r#"
[policy]
version = 1

[policy.defaults]
mode = "allow"
"#;

/// A policy that denies one tool by name.
const DENYING: &str = r#"
[policy]
version = 1

[policy.defaults]
mode = "allow"

[policy.filters]
deny_tools = ["read_file"]
"#;

/// A policy that allows one tool but restricts where it may read.
const RESTRICTED: &str = r#"
[policy]
version = 1

[[policy.tools]]
name = "read_file"
mode = "allow"

[[policy.tools.args]]
name = "path"
allow = ["/srv/**"]
"#;

#[test]
fn an_allowed_tool_call_reaches_the_server_and_comes_back() {
    let mut session = Session::start(PERMISSIVE, &[]);
    let response = session.request(
        "tools/call",
        1,
        json!({"name": "echo", "arguments": {"message": "hi"}}),
    );
    assert_eq!(response["id"], 1);
    assert_eq!(response["result"]["content"][0]["text"], "echo: hi");
    assert!(
        session.received().contains("tools/call"),
        "{:?}",
        session.received()
    );
}

#[test]
fn a_denied_tool_call_never_reaches_the_server() {
    let mut session = Session::start(DENYING, &[]);
    let response = session.request(
        "tools/call",
        7,
        json!({"name": "read_file", "arguments": {"path": "/etc/passwd"}}),
    );

    assert_eq!(response["id"], 7, "the error carries the request's own id");
    assert_eq!(response["error"]["code"], -32001);
    assert!(
        response["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("deny list"),
        "{response}"
    );
    assert_eq!(response["error"]["data"]["reason"], "deny_list");
    assert!(response.get("result").is_none(), "{response}");

    assert!(
        !session.received().contains("tools/call"),
        "the denied call reached the server: {}",
        session.received()
    );
}

#[test]
fn an_argument_outside_the_allowed_tree_is_refused() {
    let mut session = Session::start(RESTRICTED, &[]);
    let response = session.request(
        "tools/call",
        3,
        json!({"name": "read_file", "arguments": {"path": "/etc/shadow"}}),
    );
    assert_eq!(response["error"]["code"], -32001);
    assert_eq!(response["error"]["data"]["reason"], "argument_violation");

    let allowed = session.request(
        "tools/call",
        4,
        json!({"name": "read_file", "arguments": {"path": "/srv/notes.txt"}}),
    );
    assert!(
        allowed.get("result").is_some(),
        "an allowed path was refused: {allowed}"
    );
}

#[test]
fn a_tool_list_is_hashed_and_written_to_the_audit_log() {
    let mut session = Session::start(PERMISSIVE, &[]);
    let response = session.request("tools/list", 1, json!({}));
    assert_eq!(response["result"]["tools"].as_array().unwrap().len(), 2);

    let events = session.audit();
    let tool_list = events
        .iter()
        .find(|event| event["event"] == "tool_list")
        .expect("the tool list is logged");
    assert_eq!(tool_list["sha256"].as_str().unwrap().len(), 64);
    assert_eq!(tool_list["changed"], false);
}

#[test]
fn a_changed_tool_list_is_reported() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let directory = directory.keep();
    let policy_path = directory.join("policy.toml");
    std::fs::write(&policy_path, PERMISSIVE).expect("the policy can be written");

    let run = |tools_profile: &str| {
        let mut child = Command::new(FIREWALL)
            .arg("run")
            .arg("--policy")
            .arg(&policy_path)
            .arg("--audit")
            .arg(directory.join("audit.jsonl"))
            .arg("--state")
            .arg(directory.join("state.json"))
            .arg("--no-approval")
            .arg("--")
            .arg(fake_server())
            .arg("--tools")
            .arg(tools_profile)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("the proxy starts");
        let mut stdin = child.stdin.take().expect("stdin is piped");
        let mut stdout = BufReader::new(child.stdout.take().expect("stdout is piped"));

        writeln!(
            stdin,
            "{}",
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        )
        .expect("the request can be sent");
        stdin.flush().expect("the request can be flushed");

        let mut line = String::new();
        stdout.read_line(&mut line).expect("a line can be read");
        drop(stdin);
        let _ = child.wait();
    };

    run("normal");
    run("changed");

    let text =
        std::fs::read_to_string(directory.join("audit.jsonl")).expect("the audit log exists");
    assert!(
        text.contains("tool_definition_changed"),
        "the change was not reported: {text}"
    );
    assert!(
        text.contains("run_command"),
        "the new tool was not named: {text}"
    );

    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn a_poisoned_tool_description_is_reported() {
    let mut session = Session::start(PERMISSIVE, &["--description", "poisoned"]);
    let _ = session.request("tools/list", 1, json!({}));

    let events = session.audit();
    let alert = events
        .iter()
        .find(|event| event["event"] == "alert" && event["kind"] == "poisoned_tool_description")
        .expect("the poisoned description is reported");
    assert_eq!(alert["tool"], "read_file");
}

#[test]
fn a_credential_in_a_result_is_never_written_to_the_audit_log() {
    let mut session = Session::start(PERMISSIVE, &["--result", "secret"]);
    let _ = session.request(
        "tools/call",
        1,
        json!({"name": "echo", "arguments": {"message": "hi"}}),
    );

    let text = session.audit_text();
    assert!(
        !text.contains("AKIAIOSFODNN7EXAMPLE"),
        "the credential reached the audit log: {text}"
    );

    let events = session.audit();
    let result = events
        .iter()
        .find(|event| event["event"] == "tool_result")
        .expect("the result is logged");
    let rules: Vec<&str> = result["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|finding| finding["rule"].as_str().unwrap_or_default())
        .collect();
    assert!(rules.contains(&"aws_access_key_id"), "{rules:?}");
}

#[test]
fn a_honeytoken_in_a_result_is_reported() {
    let mut session = Session::start(PERMISSIVE, &["--result", "honeytoken"]);
    let _ = session.request(
        "tools/call",
        1,
        json!({"name": "echo", "arguments": {"message": "hi"}}),
    );

    let text = session.audit_text();
    assert!(text.contains("honeytoken"), "{text}");
    assert!(!text.contains("EXTRATAILVALUE"), "{text}");
}

#[test]
fn a_notification_is_not_answered() {
    let mut session = Session::start(PERMISSIVE, &[]);
    session.send(&json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
    }));
    // A request after the notification is still answered, and nothing else
    // arrives in between.
    let response = session.request("ping", 1, json!({}));
    assert_eq!(response["id"], 1);
}

#[test]
fn a_line_that_is_not_json_is_forwarded_rather_than_dropped() {
    let mut session = Session::start(PERMISSIVE, &[]);
    session.send_raw("{not json}");
    let response = session.request("ping", 1, json!({}));
    assert_eq!(response["id"], 1);

    assert!(
        session.received().contains("{not json}"),
        "the unparseable line was dropped: {}",
        session.received()
    );
}

#[test]
fn a_policy_that_cannot_be_parsed_stops_the_proxy() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let policy_path = directory.path().join("policy.toml");
    std::fs::write(&policy_path, "[policy]\nversion = 1\nmdoe = \"allow\"\n")
        .expect("the policy can be written");

    let output = Command::new(FIREWALL)
        .arg("run")
        .arg("--policy")
        .arg(&policy_path)
        .arg("--audit")
        .arg(directory.path().join("audit.jsonl"))
        .arg("--no-approval")
        .arg("--")
        .arg(fake_server())
        .output()
        .expect("the proxy runs");

    assert!(
        !output.status.success(),
        "the proxy started with a bad policy"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cannot parse policy"), "{stderr}");
}

#[test]
fn the_audit_command_summarises_a_log() {
    let mut session = Session::start(PERMISSIVE, &[]);
    let _ = session.request("tools/list", 1, json!({}));
    let _ = session.request(
        "tools/call",
        2,
        json!({"name": "echo", "arguments": {"message": "hi"}}),
    );
    let audit_path = session.directory.join("audit.jsonl");

    let output = Command::new(FIREWALL)
        .arg("audit")
        .arg("--audit")
        .arg(&audit_path)
        .arg("--json")
        .output()
        .expect("the audit command runs");

    assert!(output.status.success());
    let summary: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(summary["by_event"]["tool_call"], 1);
    assert_eq!(summary["by_tool"]["echo"], 1);
}
