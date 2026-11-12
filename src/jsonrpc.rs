//! The JSON-RPC message model used by MCP.
//!
//! The proxy is transparent: it forwards messages it does not act on, byte
//! for byte where it can. The parsed form therefore keeps the original JSON
//! alongside the fields the firewall needs, and never rewrites an id or a
//! parameter it does not understand.
//!
//! The shapes follow the MCP specification, revision `2026-07-28`, and the
//! legacy `initialize` handshake of earlier revisions:
//!
//! * a request carries `jsonrpc`, a string or integer `id`, a `method` and
//!   optional `params`;
//! * a notification carries `jsonrpc`, a `method` and optional `params`, and
//!   no `id`;
//! * a response carries `jsonrpc`, the `id` of the request it answers, and
//!   exactly one of `result` or `error`.

use serde_json::{Map, Value};

/// The JSON-RPC version every MCP message carries.
pub const JSONRPC_VERSION: &str = "2.0";

/// The method that lists the tools a server offers.
pub const METHOD_TOOLS_LIST: &str = "tools/list";
/// The method that calls a tool.
pub const METHOD_TOOLS_CALL: &str = "tools/call";
/// The method that reads a resource.
pub const METHOD_RESOURCES_READ: &str = "resources/read";
/// The legacy handshake method.
pub const METHOD_INITIALIZE: &str = "initialize";
/// The modern discovery method.
pub const METHOD_DISCOVER: &str = "server/discover";

/// A line that was not valid JSON.
#[derive(Debug, thiserror::Error)]
#[error("not valid JSON: {source}")]
pub struct ParseError {
    #[source]
    pub source: serde_json::Error,
}

/// What a message is.
#[derive(Debug, Clone, PartialEq)]
pub enum Kind {
    /// A request: it has an id and expects exactly one response.
    Request,
    /// A notification: it has no id and expects no response.
    Notification,
    /// A successful response.
    Response,
    /// An error response.
    ErrorResponse,
    /// Something else, for example a JSON-RPC batch.
    Other,
}

/// A parsed message.
#[derive(Debug, Clone)]
pub struct Message {
    /// The message as it arrived, so it can be forwarded unchanged.
    pub raw: Value,
    /// What kind of message it is.
    pub kind: Kind,
    /// The request id, for requests and responses.
    pub id: Option<Value>,
    /// The method, for requests and notifications.
    pub method: Option<String>,
    /// The parameters, for requests and notifications.
    pub params: Option<Value>,
    /// The result, for a successful response.
    pub result: Option<Value>,
    /// The error, for an error response.
    pub error: Option<Value>,
}

impl Message {
    /// Parses one line of the stream.
    ///
    /// A line that is not a JSON object is not an error: the proxy forwards
    /// it untouched and records that it could not be inspected.
    pub fn parse(text: &str) -> Result<Self, ParseError> {
        let raw: Value = serde_json::from_str(text).map_err(|source| ParseError { source })?;
        Ok(Self::from_value(raw))
    }

    /// Classifies an already parsed JSON value.
    pub fn from_value(raw: Value) -> Self {
        let mut message = Message {
            raw: raw.clone(),
            kind: Kind::Other,
            id: None,
            method: None,
            params: None,
            result: None,
            error: None,
        };

        let Some(object) = raw.as_object() else {
            return message;
        };

        message.id = object.get("id").cloned();
        message.params = object.get("params").cloned();
        message.result = object.get("result").cloned();
        message.error = object.get("error").cloned();

        if let Some(method) = object.get("method").and_then(Value::as_str) {
            message.method = Some(method.to_string());
        }

        message.kind = if message.method.is_some() {
            if object.contains_key("id") {
                Kind::Request
            } else {
                Kind::Notification
            }
        } else if message.error.is_some() {
            Kind::ErrorResponse
        } else if message.result.is_some() {
            Kind::Response
        } else {
            Kind::Other
        };

        message
    }

    /// True when the message expects a response.
    pub fn is_request(&self) -> bool {
        self.kind == Kind::Request
    }

    /// True when the message is a response of either kind.
    pub fn is_response(&self) -> bool {
        matches!(self.kind, Kind::Response | Kind::ErrorResponse)
    }

    /// True when the message carries the given method.
    pub fn has_method(&self, method: &str) -> bool {
        self.method.as_deref() == Some(method)
    }

    /// The tool name of a `tools/call` request.
    pub fn tool_name(&self) -> Option<&str> {
        if !self.has_method(METHOD_TOOLS_CALL) {
            return None;
        }
        self.params
            .as_ref()
            .and_then(|p| p.get("name"))
            .and_then(Value::as_str)
    }

    /// The arguments of a `tools/call` request.
    pub fn tool_arguments(&self) -> Option<&Value> {
        if !self.has_method(METHOD_TOOLS_CALL) {
            return None;
        }
        self.params
            .as_ref()
            .and_then(|p| p.get("arguments"))
            .filter(|value| !value.is_null())
    }

    /// The tool list of a `tools/list` response.
    pub fn tool_list(&self) -> Option<&Vec<Value>> {
        self.result
            .as_ref()
            .and_then(|r| r.get("tools"))
            .and_then(Value::as_array)
    }

    /// The protocol version a request declares, if any.
    ///
    /// Modern requests carry it in `params._meta`; earlier revisions
    /// negotiated it in the `initialize` handshake instead.
    pub fn protocol_version(&self) -> Option<&str> {
        self.params
            .as_ref()?
            .get("_meta")?
            .get("io.modelcontextprotocol/protocolVersion")?
            .as_str()
    }
}

/// Builds a JSON-RPC error response.
pub fn error_response(id: &Value, code: i64, message: &str, data: Value) -> Value {
    let mut object = Map::new();
    object.insert(
        "jsonrpc".to_string(),
        Value::String(JSONRPC_VERSION.to_string()),
    );
    object.insert("id".to_string(), id.clone());

    let mut error = Map::new();
    error.insert("code".to_string(), Value::from(code));
    error.insert("message".to_string(), Value::String(message.to_string()));
    error.insert("data".to_string(), data);

    object.insert("error".to_string(), Value::Object(error));
    Value::Object(object)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_a_request() {
        let message =
            Message::parse(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#)
                .unwrap();
        assert_eq!(message.kind, Kind::Request);
        assert_eq!(message.id, Some(json!(1)));
        assert!(message.has_method(METHOD_TOOLS_LIST));
    }

    #[test]
    fn parses_a_notification() {
        let message =
            Message::parse(r#"{"jsonrpc":"2.0","method":"notifications/cancelled"}"#).unwrap();
        assert_eq!(message.kind, Kind::Notification);
        assert!(message.id.is_none());
    }

    #[test]
    fn parses_a_result_response() {
        let message = Message::parse(r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}"#).unwrap();
        assert_eq!(message.kind, Kind::Response);
        assert_eq!(message.tool_list().map(Vec::len), Some(0));
    }

    #[test]
    fn parses_an_error_response() {
        let message =
            Message::parse(r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"nope"}}"#)
                .unwrap();
        assert_eq!(message.kind, Kind::ErrorResponse);
    }

    #[test]
    fn a_string_id_is_kept_verbatim() {
        let message = Message::parse(r#"{"jsonrpc":"2.0","id":"abc","method":"ping"}"#).unwrap();
        assert_eq!(message.id, Some(json!("abc")));
    }

    #[test]
    fn reads_the_tool_name_and_arguments() {
        let message = Message::parse(
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/passwd"}}}"#,
        )
        .unwrap();
        assert_eq!(message.tool_name(), Some("read_file"));
        assert_eq!(
            message.tool_arguments(),
            Some(&json!({"path": "/etc/passwd"}))
        );
    }

    #[test]
    fn reads_the_declared_protocol_version() {
        let message = Message::parse(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}"#,
        )
        .unwrap();
        assert_eq!(message.protocol_version(), Some("2026-07-28"));
    }

    #[test]
    fn a_batch_is_not_a_message_the_proxy_acts_on() {
        let message = Message::parse(r#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#).unwrap();
        assert_eq!(message.kind, Kind::Other);
    }

    #[test]
    fn invalid_json_is_reported() {
        assert!(Message::parse("{not json").is_err());
    }

    #[test]
    fn builds_an_error_response_with_the_same_id() {
        let response = error_response(&json!(7), -32001, "denied", json!({"reason": "policy"}));
        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], 7);
        assert_eq!(response["error"]["code"], -32001);
        assert_eq!(response["error"]["data"]["reason"], "policy");
    }
}
