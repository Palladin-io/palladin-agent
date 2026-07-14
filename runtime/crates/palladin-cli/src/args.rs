use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "palladin", version, about = "Palladin native Agent runtime")]
pub struct Cli {
    /// Local Agent profile alias.
    #[arg(long, global = true)]
    pub id: Option<String>,
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Release-only verification of a signed policy against this native executable.
    #[command(name = "verify-release-policy", hide = true)]
    VerifyReleasePolicy {
        /// Candidate signed policy file supplied by the protected release workflow.
        #[arg(long)]
        policy: PathBuf,
    },
    /// Create the default Agent profile when it does not exist.
    Init {
        /// In-place identity rotation is intentionally unsupported.
        #[arg(long)]
        force: bool,
    },
    /// Check the native runtime boundary without opening Agent Identity.
    Doctor,
    /// Connect an Agent using a masked prompt or protected standard input.
    Connect(ConnectArgs),
    /// Show registration status for an Agent profile.
    Status,
    /// Disconnect and deliberately remove one local Agent identity.
    Disconnect {
        /// Remove the selected profile's native identity and unreferenced organization key.
        #[arg(long)]
        purge: bool,
        /// Required acknowledgement; disconnect never runs from npm lifecycle hooks.
        #[arg(long, requires = "purge")]
        confirm: bool,
    },
    /// Search metadata visible to the active Agent.
    Search(SearchArgs),
    /// Intentionally retrieve a credential granted to this Agent.
    #[command(visible_alias = "retrieve")]
    Get(GetArgs),
    /// Run a command with a credential in a sanitized child environment.
    Exec(ExecArgs),
    /// Refuse browser injection until an authenticated browser boundary is installed.
    Inject(InjectArgs),
    /// Report that a credential is stale without sending its value.
    ReportStale(ReportStaleArgs),
    /// Serve Palladin tools over the Model Context Protocol.
    Mcp {
        #[command(subcommand)]
        command: McpCommand,
    },
    /// Manage local Agent profiles.
    Agents {
        #[command(subcommand)]
        command: AgentsCommand,
    },
    /// Verify or upgrade local secure storage.
    Security {
        #[command(subcommand)]
        command: SecurityCommand,
    },
    /// Explicitly remove every native profile and secret.
    Purge {
        /// Required acknowledgement; purge is never run by npm uninstall hooks.
        #[arg(long)]
        confirm: bool,
    },
}

#[derive(Debug, Args)]
pub struct ConnectArgs {
    /// Read the organization API key from one line of standard input.
    #[arg(long)]
    pub api_key_stdin: bool,
    /// Palladin API base URL.
    #[arg(long, default_value = "https://api.palladin.io")]
    pub host: String,
    /// Backend display name; the local profile alias remains unchanged.
    #[arg(long)]
    pub name: Option<String>,
    /// Agent category, for example ci, browser, or backend.
    #[arg(long)]
    pub r#type: Option<String>,
}

#[derive(Debug, Args)]
pub struct SearchArgs {
    /// Search phrase; at least two non-whitespace characters.
    pub query: String,
    /// Emit the exact machine-readable API result.
    #[arg(long)]
    pub json: bool,
    /// Continue from a cursor returned by an earlier search.
    #[arg(long)]
    pub cursor: Option<String>,
    /// Maximum result count requested from the API.
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..=100))]
    pub page_size: Option<u32>,
}

#[derive(Debug, Args)]
pub struct GetArgs {
    pub vault_id: String,
    pub entry_id: String,
    /// Explain why this Agent needs access.
    #[arg(long)]
    pub reason: Option<String>,
    /// Return one field by label.
    #[arg(long)]
    pub field: Option<String>,
    /// Return one custom field by its public identifier.
    #[arg(long)]
    pub field_id: Option<String>,
    /// Do not emit the intentional plaintext warning on stderr.
    #[arg(long)]
    pub quiet: bool,
    /// Maximum approval wait, for example 30s or 2m.
    #[arg(long, overrides_with = "no_wait")]
    pub wait: Option<String>,
    /// Return immediately when approval is pending.
    #[arg(long, overrides_with = "wait")]
    pub no_wait: bool,
    /// Approval polling interval, for example 10s.
    #[arg(long)]
    pub poll_interval: Option<String>,
    /// Approval heartbeat format written to stderr.
    #[arg(long, value_enum)]
    pub progress: Option<ProgressArg>,
}

#[derive(Debug, Args)]
pub struct ExecArgs {
    pub vault_id: String,
    pub entry_id: String,
    /// Explain why this Agent needs access.
    #[arg(long)]
    pub reason: Option<String>,
    /// Map NAME to a credential field selected by label.
    #[arg(long = "env", value_name = "NAME=FIELD")]
    pub env_mappings: Vec<String>,
    /// Maximum approval wait, for example 30s or 2m.
    #[arg(long, overrides_with = "no_wait")]
    pub wait: Option<String>,
    /// Return immediately when approval is pending.
    #[arg(long, overrides_with = "wait")]
    pub no_wait: bool,
    /// Approval polling interval, for example 10s.
    #[arg(long)]
    pub poll_interval: Option<String>,
    /// Approval heartbeat format written to stderr.
    #[arg(long, value_enum)]
    pub progress: Option<ProgressArg>,
    /// Executable and arguments after `--`; omit for a Script entry.
    #[arg(last = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
}

#[derive(Debug, Args)]
pub struct InjectArgs {
    pub vault_id: String,
    pub entry_id: String,
    /// Deprecated and rejected unauthenticated CDP endpoint.
    #[arg(long)]
    pub cdp: String,
    /// Reserved for a future reviewed implementation.
    #[arg(long)]
    pub reason: Option<String>,
    /// Reserved for a future reviewed implementation.
    #[arg(long)]
    pub page_url: Option<String>,
    /// Reserved for a future reviewed implementation.
    #[arg(long)]
    pub username_selector: Option<String>,
    /// Reserved for a future reviewed implementation.
    #[arg(long)]
    pub password_selector: Option<String>,
    /// Reserved for a future reviewed implementation.
    #[arg(long)]
    pub submit_selector: Option<String>,
    /// Reserved for a future reviewed implementation.
    #[arg(long)]
    pub no_submit: bool,
    /// Reserved for a future reviewed implementation.
    #[arg(long)]
    pub fill_only: bool,
    /// Reserved for a future reviewed implementation.
    #[arg(long)]
    pub field: Option<String>,
    /// Reserved for a future reviewed implementation.
    #[arg(long)]
    pub field_id: Option<String>,
    /// Reserved for value-free diagnostics in a future reviewed implementation.
    #[arg(long)]
    pub verbose: bool,
    /// Reserved for a future reviewed implementation.
    #[arg(long, overrides_with = "no_wait")]
    pub wait: Option<String>,
    /// Reserved for a future reviewed implementation.
    #[arg(long, overrides_with = "wait")]
    pub no_wait: bool,
    /// Reserved for a future reviewed implementation.
    #[arg(long)]
    pub poll_interval: Option<String>,
    /// Reserved for the reviewed browser extension.
    #[arg(long, value_enum)]
    pub progress: Option<ProgressArg>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum ProgressArg {
    Plain,
    Json,
    None,
}

#[derive(Debug, Args)]
pub struct ReportStaleArgs {
    pub vault_id: String,
    pub entry_id: String,
    /// Machine-readable stale reason.
    #[arg(long, value_enum, default_value_t = StaleCodeArg::Manual)]
    pub code: StaleCodeArg,
    /// Optional secret-free context for the vault owner.
    #[arg(long)]
    pub note: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum StaleCodeArg {
    #[value(name = "login_rejected", alias = "login-rejected")]
    LoginRejected,
    #[value(name = "auth_failed", alias = "auth-failed")]
    AuthFailed,
    #[default]
    Manual,
}

#[derive(Debug, Subcommand)]
pub enum AgentsCommand {
    /// List Agent profile aliases.
    List,
    /// Create a profile with a fresh native identity.
    Create {
        name: String,
        #[arg(long)]
        r#type: Option<String>,
    },
    /// Delete a non-default Agent profile.
    Delete { name: String },
    /// Change the default profile.
    SetDefault { name: String },
    /// Rename an alias without moving or rewriting secret slots.
    Rename { old_name: String, new_name: String },
}

#[derive(Debug, Subcommand)]
pub enum SecurityCommand {
    /// Verify that this profile already uses the operating-system secure store.
    Upgrade,
    /// Inspect legacy TypeScript state without opening identity or credential bytes.
    LegacyStatus,
    /// Archive legacy TypeScript state and create fresh native identities (dev/test only).
    LegacyCutover {
        /// Acknowledge that old local identities will not be reused.
        #[arg(long)]
        confirm_pre_production_reset: bool,
    },
    /// Delete an archived TypeScript state after all fresh Agents are enrolled (dev/test only).
    LegacyCleanup {
        /// Exact identifier printed by legacy-cutover.
        cutover_id: String,
        /// Acknowledge deletion of the archived legacy files and OS credential entries.
        #[arg(long)]
        confirm: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum McpCommand {
    /// Start the long-lived MCP server over standard input and output.
    Serve,
}
