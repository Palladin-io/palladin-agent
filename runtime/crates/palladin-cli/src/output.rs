use std::fmt::Write as _;

use palladin_api::{AgentRegistrationResult, EntrySearchResult};
use palladin_core::public_store::PublicRegistry;
use palladin_core::terminal::{safe_terminal_text, shorten_identifier};
use serde::Serialize;

use crate::CreatedProfile;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RenderedOutput {
    pub exit_code: u8,
    pub stdout: String,
    pub stderr: String,
}

impl RenderedOutput {
    fn stdout_line(&mut self, line: impl std::fmt::Display) {
        let _ = writeln!(self.stdout, "{line}");
    }

    fn stderr_line(&mut self, line: impl std::fmt::Display) {
        let _ = writeln!(self.stderr, "{line}");
    }
}

#[must_use]
pub fn render_init(
    profile: &str,
    security: &str,
    already_initialized: bool,
    is_default: bool,
) -> RenderedOutput {
    let mut output = RenderedOutput::default();
    if already_initialized {
        output.stdout_line(format_args!("Palladin already initialized: {profile}"));
    } else {
        output.stdout_line(format_args!("Palladin initialized: {profile}"));
    }
    output.stdout_line(format_args!("Security: {security}"));
    if !already_initialized {
        if is_default {
            output.stdout_line("Next: palladin connect");
        } else {
            output.stdout_line(format_args!("Next: palladin --id {profile} connect"));
        }
    }
    output
}

#[must_use]
pub fn render_connect(
    registration: &AgentRegistrationResult,
    config_saved: bool,
    security: &str,
) -> RenderedOutput {
    let mut output = RenderedOutput::default();
    output.stdout_line(format_args!("Security: {security}"));
    match registration {
        AgentRegistrationResult::Pending { agent_id } => {
            output.stdout_line("Agent registered - awaiting approval");
            output.stdout_line(format_args!("Agent ID: {}", shorten_identifier(agent_id)));
            output.stdout_line("Approve this Agent in the Palladin panel.");
        }
        AgentRegistrationResult::Active { agent_id, name } => {
            output.stdout_line("Agent active");
            output.stdout_line(format_args!("Agent ID: {}", shorten_identifier(agent_id)));
            if let Some(name) = name {
                output.stdout_line(format_args!("Backend name: {}", safe_terminal_text(name)));
            }
        }
        AgentRegistrationResult::Deactivated { agent_id } => {
            output.exit_code = 1;
            output.stderr_line(format_args!(
                "Error: Agent is deactivated ({})",
                shorten_identifier(agent_id)
            ));
        }
        AgentRegistrationResult::InvalidKey => {
            output.exit_code = 1;
            output.stderr_line("Error: API key is invalid or revoked");
        }
        AgentRegistrationResult::Unreachable { error } => {
            output.stderr_line(format_args!(
                "Warning: server unreachable ({})",
                safe_terminal_text(error)
            ));
            if config_saved {
                output.stderr_line("Configuration saved. Run: palladin status");
            } else {
                output.stderr_line("Existing working configuration was preserved.");
            }
        }
    }
    output
}

#[must_use]
pub fn render_status(
    profile: &str,
    host: &str,
    registration: &AgentRegistrationResult,
    security: &str,
) -> RenderedOutput {
    let mut output = RenderedOutput::default();
    output.stdout_line(format_args!("Profile: {profile}"));
    output.stdout_line(format_args!("Host: {host}"));
    output.stdout_line(format_args!("Security: {security}"));
    match registration {
        AgentRegistrationResult::Pending { agent_id } => output.stdout_line(format_args!(
            "Agent: pending approval ({})",
            shorten_identifier(agent_id)
        )),
        AgentRegistrationResult::Active { agent_id, name } => {
            output.stdout_line(format_args!(
                "Agent: active ({})",
                shorten_identifier(agent_id)
            ));
            if let Some(name) = name {
                output.stdout_line(format_args!("Backend name: {}", safe_terminal_text(name)));
            }
        }
        AgentRegistrationResult::Deactivated { agent_id } => output.stdout_line(format_args!(
            "Agent: deactivated ({})",
            shorten_identifier(agent_id)
        )),
        AgentRegistrationResult::InvalidKey => {
            output.exit_code = 1;
            output.stderr_line("Error: API key is invalid or revoked");
        }
        AgentRegistrationResult::Unreachable { error } => {
            output.exit_code = 1;
            output.stderr_line(format_args!(
                "Error: server unreachable ({})",
                safe_terminal_text(error)
            ));
        }
    }
    output
}

#[must_use]
pub fn render_agent_list(registry: &PublicRegistry) -> RenderedOutput {
    let mut output = RenderedOutput::default();
    if registry.agents.is_empty() {
        output.stdout_line("No agents. Run: palladin agents create <name>");
    } else {
        for agent in &registry.agents {
            let marker = if agent.name == registry.default {
                "*"
            } else {
                " "
            };
            output.stdout_line(format_args!("{marker} {}", agent.name));
        }
    }
    output
}

#[must_use]
pub fn render_profile_created(profile: &CreatedProfile, security: &str) -> RenderedOutput {
    let mut output = RenderedOutput::default();
    output.stdout_line(format_args!("Agent profile created: {}", profile.name));
    output.stdout_line(format_args!(
        "Encryption key: {}",
        shorten_identifier(&profile.encryption_public_key)
    ));
    output.stdout_line(format_args!(
        "Signing key: {}",
        shorten_identifier(&profile.signing_public_key)
    ));
    output.stdout_line(format_args!("Security: {security}"));
    output.stdout_line(format_args!("Next: palladin --id {} connect", profile.name));
    output
}

#[must_use]
pub fn render_agent_action(action: &str, value: &str) -> RenderedOutput {
    let mut output = RenderedOutput::default();
    output.stdout_line(format_args!("{action}: {value}"));
    output
}

#[must_use]
pub fn render_security_upgrade(profile: &str, security: &str, migrated: bool) -> RenderedOutput {
    let mut output = RenderedOutput::default();
    output.stdout_line(format_args!("Profile: {}", safe_terminal_text(profile)));
    output.stdout_line(format_args!("Security: {security}"));
    if migrated {
        output.stdout_line(
            "Upgrade: completed - local metadata and secure-storage slots now use schema v3.",
        );
    } else {
        output
            .stdout_line("Upgrade: not required - schema v3 integrity binding is already active.");
    }
    output
}

#[must_use]
pub fn render_search_human(result: &EntrySearchResult) -> RenderedOutput {
    let mut output = RenderedOutput::default();
    if result.items.is_empty() {
        output.stdout_line("No entries found.");
    } else {
        for item in &result.items {
            output.stdout_line(format_args!(
                "{}  {}  vault={}",
                shorten_identifier(&item.entry_id),
                safe_terminal_text(&item.label),
                shorten_identifier(&item.vault_id)
            ));
            if let Some(domain) = &item.url_domain {
                output.stdout_line(format_args!("  domain: {}", safe_terminal_text(domain)));
            }
            if let Some(description) = &item.description {
                output.stdout_line(format_args!(
                    "  description: {}",
                    safe_terminal_text(description)
                ));
            }
            for field in &item.agent_fields {
                output.stdout_line(format_args!(
                    "  {}: {}",
                    safe_terminal_text(&field.label),
                    safe_terminal_text(&field.value)
                ));
            }
        }
    }
    if let Some(cursor) = &result.next_cursor {
        output.stdout_line(format_args!("Next cursor: {}", shorten_identifier(cursor)));
    }
    output
}

#[must_use]
pub fn render_report_stale() -> RenderedOutput {
    let mut output = RenderedOutput::default();
    output.stdout_line(
        "Reported credential as not working - the vault owners have been notified to rotate it.",
    );
    output
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialOutput<'a> {
    pub entry_id: &'a str,
    pub label: &'a str,
    pub secret: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldValueOutput<'a> {
    pub entry_id: &'a str,
    pub label: &'a str,
    pub field: &'a str,
    pub value: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpOutput<'a> {
    pub entry_id: &'a str,
    pub label: &'a str,
    pub field: &'a str,
    pub code: &'a str,
    pub expires_in: u64,
}
