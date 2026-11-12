//! The `mcp-firewall` command line.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

use mcp_firewall::audit::{AuditLog, Summary};
use mcp_firewall::inspect::{Scanner, Severity};
use mcp_firewall::policy::CompiledPolicy;
use mcp_firewall::proxy::ProxyOptions;
use mcp_firewall::state::PinState;

/// The default audit log, next to where the proxy is started.
const DEFAULT_AUDIT_LOG: &str = "mcp-firewall-audit.jsonl";

/// A security proxy for MCP traffic.
#[derive(Debug, Parser)]
#[command(name = "mcp-firewall", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the proxy in front of an MCP server.
    Run(RunArgs),
    /// Summarise an audit log.
    Audit(AuditArgs),
    /// Check that a policy file is valid.
    CheckPolicy(CheckPolicyArgs),
}

#[derive(Debug, Args)]
struct RunArgs {
    /// The policy file to enforce.
    #[arg(long, value_name = "PATH")]
    policy: PathBuf,

    /// Where the audit log goes.
    #[arg(long, value_name = "PATH", default_value = DEFAULT_AUDIT_LOG)]
    audit: PathBuf,

    /// Where the pinned tool list is remembered.
    ///
    /// Defaults to a `state.json` beside the audit log.
    #[arg(long, value_name = "PATH")]
    state: Option<PathBuf>,

    /// A name for the server, used in the audit log.
    #[arg(long, value_name = "NAME")]
    label: Option<String>,

    /// Refuse calls that need approval instead of asking on the terminal.
    #[arg(long)]
    no_approval: bool,

    /// The server to run, after a `--` separator.
    #[arg(last = true, required = true, value_name = "COMMAND")]
    command: Vec<String>,
}

#[derive(Debug, Args)]
struct AuditArgs {
    /// The audit log to summarise.
    #[arg(long, value_name = "PATH", default_value = DEFAULT_AUDIT_LOG)]
    audit: PathBuf,

    /// Print the summary as JSON.
    #[arg(long)]
    json: bool,

    /// Exit non-zero when a finding of this severity or worse is present.
    #[arg(long, value_name = "LEVEL", value_parser = ["info", "warning", "error"])]
    fail_on: Option<String>,
}

#[derive(Debug, Args)]
struct CheckPolicyArgs {
    /// The policy file to check.
    #[arg(long, value_name = "PATH")]
    policy: PathBuf,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Run(args) => run_proxy(args),
        Command::Audit(args) => audit(args),
        Command::CheckPolicy(args) => check_policy(args),
    }
}

/// Runs the proxy.
fn run_proxy(args: RunArgs) -> ExitCode {
    let policy = match CompiledPolicy::load(&args.policy) {
        Ok(policy) => policy,
        Err(error) => {
            eprintln!("mcp-firewall: {error}");
            return ExitCode::FAILURE;
        }
    };

    let state_path = args
        .state
        .clone()
        .unwrap_or_else(|| PinState::default_path_for(&args.audit));

    let label = args.label.clone().unwrap_or_else(|| {
        Path::new(&args.command[0])
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| args.command[0].clone())
    });

    let audit = match AuditLog::open(&args.audit) {
        Ok(log) => log,
        Err(error) => {
            eprintln!("mcp-firewall: {error}");
            return ExitCode::FAILURE;
        }
    };

    let scanner = Scanner::new(&policy.redact);

    let options = ProxyOptions {
        policy,
        scanner,
        audit,
        state_path,
        server_label: label,
        allow_approval: !args.no_approval,
    };

    match mcp_firewall::proxy::run(options, &args.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("mcp-firewall: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Summarises an audit log.
fn audit(args: AuditArgs) -> ExitCode {
    let summary = match Summary::from_file(&args.audit) {
        Ok(summary) => summary,
        Err(error) => {
            eprintln!("mcp-firewall: {error}");
            return ExitCode::FAILURE;
        }
    };

    if args.json {
        match serde_json::to_string_pretty(&summary) {
            Ok(text) => println!("{text}"),
            Err(error) => {
                eprintln!("mcp-firewall: cannot render the summary: {error}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        print!("{}", summary.render());
    }

    if let Some(level) = args.fail_on {
        let threshold = match level.as_str() {
            "info" => Severity::Info,
            "warning" => Severity::Warning,
            "error" => Severity::Error,
            _ => Severity::Error,
        };
        if summary
            .max_severity
            .is_some_and(|severity| severity >= threshold)
        {
            return ExitCode::from(2);
        }
    }

    ExitCode::SUCCESS
}

/// Checks that a policy is valid.
fn check_policy(args: CheckPolicyArgs) -> ExitCode {
    match CompiledPolicy::load(&args.policy) {
        Ok(policy) => {
            println!("{}: ok", args.policy.display());
            println!("  version         {}", policy.version);
            println!("  default mode    {}", policy.defaults.mode.as_str());
            println!(
                "  builtin redaction {}",
                if policy.redact.builtin { "on" } else { "off" }
            );
            println!(
                "  forward results {}",
                if policy.redact.forward_results {
                    "on"
                } else {
                    "off"
                }
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("mcp-firewall: {error}");
            ExitCode::FAILURE
        }
    }
}
