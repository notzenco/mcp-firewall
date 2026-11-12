//! mcp-firewall: a security proxy for MCP traffic.

pub mod glob;
pub mod policy;
pub mod time;

/// Version reported by `mcp-firewall version`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
