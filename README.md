# mcp-firewall

A security proxy that sits between an AI agent (the MCP client) and its MCP
servers.

`mcp-firewall` speaks the MCP protocol to both sides, so the agent cannot
tell the difference. It logs every call, enforces a policy on what may be
called and with which arguments, and flags or blocks the traffic that looks
dangerous: injected instructions in tool descriptions and results, credentials
travelling through tool arguments, tools that changed their definitions after
you approved them, and `agent-tripwire` honeytokens.

It is the third piece of an agent security set: `sentinel` scans AI apps,
agents and MCP servers offline; `agent-tripwire` plants honeytokens and tells
you when they are used; `mcp-firewall` watches the traffic itself.

## Install

```sh
cargo install --locked --path .
```

The binary is called `mcp-firewall`. It runs on macOS and Linux and needs no
network access.

## Quick start

Write a policy. The smallest useful one watches everything and denies one
tool:

```toml
# policy.toml
[policy]
version = 1

[policy.defaults]
# allow | ask | deny | log-only
mode = "log-only"

[policy.filters]
deny_tools = ["shell_exec"]
```

Check it, then put the firewall in front of a server:

```sh
mcp-firewall check-policy --policy policy.toml
mcp-firewall run --policy policy.toml -- npx -y @modelcontextprotocol/server-filesystem .
```

The proxy speaks stdio to the client and to the server, so it only works with
servers that are launched as a subprocess. The Streamable HTTP transport is
not in v1; see [docs/design.md](docs/design.md).

### Claude Code

Add the server to `.mcp.json` in the project, or to `~/.claude.json` for
every project:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "mcp-firewall",
      "args": [
        "run",
        "--policy",
        "/absolute/path/to/policy.toml",
        "--label",
        "filesystem",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/absolute/path/to/allowed/directory"
      ]
    }
  }
}
```

The paths have to be absolute: the proxy does not change the working
directory of the server it starts.

### Codex

Add the server to `~/.codex/config.toml`:

```toml
[mcp_servers.filesystem]
command = "mcp-firewall"
args = [
  "run",
  "--policy",
  "/absolute/path/to/policy.toml",
  "--label",
  "filesystem",
  "--",
  "npx",
  "-y",
  "@modelcontextprotocol/server-filesystem",
  "/absolute/path/to/allowed/directory"
]
```

### Other clients

Any client that launches an MCP server over stdio works. The command is the
same: the firewall first, the server after a `--`.

## What it does

| Threat | What the firewall does |
| --- | --- |
| Tool poisoning | Scans tool descriptions and titles for injected instructions. A policy can deny the tool outright. |
| Prompt injection in results | Scans tool results and resource contents for instruction-shaped text. |
| Exfiltration through arguments | Scans outgoing arguments for credentials, and applies the policy's path, regex and size rules. |
| Over-broad tools | Per-tool modes: `allow`, `ask`, `deny` and `log-only`. |
| Rug pulls | Hashes the tool list and reports when it changes, naming the tools that changed. |
| Credential and honeytoken leakage | Detects credentials and `agent-tripwire` honeytokens, and keeps both out of the audit log. |

## The policy

The whole policy lives inside one `[policy]` table, so the order of the
sections in the file never matters.

```toml
[policy]
version = 1

[policy.defaults]
mode = "log-only"

[policy.filters]
# Tool name globs that are always refused.
deny_tools = ["*_admin", "shell_exec"]
# When this is not empty, every tool outside it is denied.
allow_tools = []

[[policy.tools]]
name = "read_file"
mode = "allow"

  # Argument rules. `name` matches the argument's key, or its path inside
  # arguments, for example "files[0].path".
  [[policy.tools.args]]
  name = "path"
  allow = ["/Users/you/project/**"]
  deny = ["/Users/you/.ssh/**"]
  max_bytes = 4096

[policy.redact]
# Use the built-in credential patterns.
builtin = true
# Also strip credentials from tool results before the agent sees them.
forward_results = false

[policy.pin]
# The sha256 of the tool list you approved.
expected_sha256 = "…"
# Refuse a tool list whose digest does not match.
enforce = false
```

The modes:

| Mode | What it does |
| --- | --- |
| `allow` | The call goes through. An argument that breaks a rule is refused. |
| `ask` | The call waits for a human, on the firewall's terminal. With no terminal it is refused. |
| `deny` | The call is always refused. |
| `log-only` | The call goes through and the broken rules are reported. The default. |

Globs are deliberately narrow: `*` does not cross a `/`, `**` does, `?` is one
character, and `[abc]` is a character set.

The full format is in [docs/design.md](docs/design.md). There is a worked
example in [examples/policy.toml](examples/policy.toml).

## Denials

A refused call is answered with a JSON-RPC error that carries the request's
own id, so the agent sees a normal protocol error rather than a hung call.
The code is `-32001`, outside the ranges the JSON-RPC and MCP specifications
reserve:

```json
{
  "jsonrpc": "2.0",
  "id": 7,
  "error": {
    "code": -32001,
    "message": "mcp-firewall: tool `read_file` violates 1 argument rule(s)",
    "data": {
      "reason": "argument_violation",
      "tool": "read_file",
      "violations": [
        {
          "rule": "allow",
          "argument": "path",
          "detail": "value does not match any allowed pattern: /etc/shadow"
        }
      ]
    }
  }
}
```

The refused call never reaches the server.

## The audit log

Every decision, finding and alert is one JSON object per line, flushed as it
happens. Credentials are redacted before they are written, so the log is not
a place where secrets accumulate.

```sh
mcp-firewall audit --audit mcp-firewall-audit.jsonl
mcp-firewall audit --audit mcp-firewall-audit.jsonl --json | jq .by_tool
mcp-firewall audit --audit mcp-firewall-audit.jsonl --fail-on warning
```

`--fail-on` exits with status 2 when the log holds a finding of that
severity or worse, which is what you want in CI.

The log is written to `mcp-firewall-audit.jsonl` by default. The pinned tool
list is remembered in a `state.json` beside it.

## Commands

| Command | What it does |
| --- | --- |
| `mcp-firewall run --policy P -- CMD…` | Run the proxy in front of `CMD` |
| `mcp-firewall audit [--audit P] [--json] [--fail-on LEVEL]` | Summarise an audit log |
| `mcp-firewall check-policy --policy P` | Check that a policy is valid |

## Safety

- **The proxy fails closed.** A policy that cannot be read stops the proxy
  before it starts. It never runs unprotected because of a typo.
- **Nothing is silently dropped.** A line that cannot be parsed is forwarded
  untouched and flagged in the log, because dropping it would leave the peer
  waiting for an answer.
- **The audit log is not optional.** If it cannot be written, the session
  stops.
- **It is a mitigation, not a sandbox.** A malicious server running on your
  machine can still damage the host directly. The firewall limits what it can
  do through the agent, and leaves a trail.

## Development

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

The integration tests drive the real binary against a small MCP server that
lives in this package as an example, over the proxy's own standard streams.
Nothing in the test suite touches the network.

## Licence

MIT. See [LICENSE](LICENSE).
