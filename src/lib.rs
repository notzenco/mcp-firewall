//! mcp-firewall: a security proxy for MCP traffic.

pub mod audit;
pub mod glob;
pub mod hash;
pub mod inspect;
pub mod jsonrpc;
pub mod policy;
pub mod proxy;
pub mod state;
pub mod time;

/// Version reported by `mcp-firewall version`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
