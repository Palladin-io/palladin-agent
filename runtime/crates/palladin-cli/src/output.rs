use std::fmt::Write as _;

use palladin_api::{AgentRegistrationResult, EntrySearchResult};
use palladin_core::public_store::PublicRegistry;
use palladin_core::terminal::{safe_terminal_text, shorten_identifier};
use serde::Serialize;

use crate::{CreatedProfile, LegacyCleanupOutcome, LegacyCutoverOutcome};
use palladin_runtime::{
    ReTrustedApproverKey, RewrapOutcome, SubmissionHint, SubmissionResult, SubmissionStatusItem,
};

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
pub fn render_legacy_cutover(outcome: &LegacyCutoverOutcome) -> RenderedOutput {
    let mut output = RenderedOutput::default();
    output.stdout_line("Legacy TypeScript cutover: prepared");
    output.stdout_line(format_args!("Fresh profiles: {}", outcome.profiles));
    output.stdout_line(format_args!("New identities created: {}", outcome.created));
    output.stdout_line(format_args!("Cutover ID: {}", outcome.cutover_id));
    output.stdout_line("Next:");
    output.stdout_line("1. Create a new organization API key in the Palladin panel.");
    for profile in &outcome.profile_names {
        output.stdout_line(format_args!(
            "2. palladin --id {} connect --api-key-stdin",
            safe_terminal_text(profile)
        ));
    }
    output.stdout_line("3. Approve every fresh Agent in the Palladin panel.");
    output.stdout_line(format_args!(
        "4. palladin security legacy-cleanup {} --confirm",
        outcome.cutover_id
    ));
    output.stdout_line(
        "5. Revoke the old shared organization API key and deactivate the old Agents in the panel.",
    );
    output
}

#[must_use]
pub fn render_legacy_cleanup(outcome: &LegacyCleanupOutcome) -> RenderedOutput {
    let mut output = RenderedOutput::default();
    output.stdout_line("Legacy TypeScript cleanup: completed");
    output.stdout_line(format_args!("Profiles cleaned: {}", outcome.profiles));
    output.stdout_line(
        "Required: revoke the old shared organization API key and deactivate the old Agents in the Palladin panel.",
    );
    output.stdout_line(
        "Note: local deletion cannot erase copies retained by SSD snapshots, backups, or parent-shell environment variables.",
    );
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

/// Reports submitted browser actions, never remote authentication success.
#[must_use]
pub fn render_live_flow(provider: &str, steps: usize, outcome: &str) -> RenderedOutput {
    let mut output = RenderedOutput::default();
    output.stderr_line(format_args!(
        "Login flow through {provider} submitted {steps} step(s); stopped: {outcome}. No authentication success is inferred. Inspect the page before any further action; do not replay a submitted step."
    ));
    output.exit_code = if steps > 0 && matches!(outcome, "no-form" | "origin-changed") {
        0
    } else {
        2
    };
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

/// The contract's value-free `agentResult`; it has no field that could carry a secret.
#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentSubmissionResult {
    pub submission_status: &'static str,
    pub site_status: &'static str,
    pub submission_id: Option<String>,
    pub submission_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<&'static str>,
    pub message: String,
}

impl AgentSubmissionResult {
    #[must_use]
    pub fn from_result(result: &SubmissionResult) -> Self {
        let kind = result.kind.name();
        match &result.outcome {
            Ok(saved) => {
                let id = result.submission_id.as_deref().unwrap_or_default();
                Self {
                    submission_status: "saved",
                    site_status: "not-attempted",
                    submission_id: result.submission_id.clone(),
                    submission_state: Some(saved.state.clone()),
                    code: None,
                    message: format!(
                        "Saved to Palladin as a pending {kind} submission ({id}). A reviewer must approve it in Palladin Inbox."
                    ),
                }
            }
            Err(code) => {
                let message = format!(
                    "Not saved to Palladin ({}). Nothing was submitted to any site.",
                    code.code()
                );
                Self {
                    submission_status: "not-saved",
                    site_status: "not-attempted",
                    submission_id: result.submission_id.clone(),
                    submission_state: None,
                    code: Some(code.code()),
                    message,
                }
            }
        }
    }
}

#[must_use]
pub fn render_submission_result(result: &SubmissionResult, json: bool) -> RenderedOutput {
    let agent_result = AgentSubmissionResult::from_result(result);
    let mut output = RenderedOutput::default();
    if json {
        output.stdout_line(serde_json::to_string(&agent_result).unwrap_or_default());
    } else if agent_result.code.is_none() {
        output.stdout_line(&agent_result.message);
    } else {
        output.stderr_line(format_args!("Error: {}", agent_result.message));
    }
    // Hints are operator guidance on stderr; they never extend the contract result.
    for hint in &result.hints {
        match hint {
            SubmissionHint::ApproverReintroduction {
                signing_key_fingerprint,
            } => {
                let fingerprint = safe_terminal_text(signing_key_fingerprint);
                output.stderr_line(format_args!(
                    "The organization approver key was re-created without continuity from the pinned key. Verify signing key fingerprint {fingerprint} with a Palladin administrator, then run: palladin submit trust-approvers --fingerprint {fingerprint} --confirm"
                ));
            }
            SubmissionHint::UsernameNeededForAutofill => output.stderr_line(
                "Note: this update has no username. Login autofill with this submission needs one; resubmit with --username if the login form asks for it.",
            ),
        }
    }
    if agent_result.code.is_some() {
        output.exit_code = 1;
    }
    output
}

#[must_use]
pub fn render_approver_retrust(key: &ReTrustedApproverKey) -> RenderedOutput {
    let mut output = RenderedOutput::default();
    output.stdout_line(format_args!(
        "Re-trusted organization approver key {} (key version {}, manifest revision {}). Run palladin submit status to re-wrap pending submissions.",
        safe_terminal_text(&key.signing_key_fingerprint),
        key.key_version,
        key.manifest_revision
    ));
    output
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SubmissionStatusOutput<'a> {
    submission_id: &'a str,
    submission_kind: &'static str,
    entry_type: &'static str,
    state: &'a str,
    agent_use_suspended: bool,
    submission_revision: &'a str,
    approver_key_version: u32,
    current_approver_key_version: Option<u32>,
    decision: Option<&'a palladin_api::SubmissionDecision>,
    created_at: &'a str,
    decided_at: Option<&'a str>,
    rewrap: RewrapOutput,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RewrapOutput {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    submission_revision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<&'static str>,
}

const fn submission_kind_name(kind: u16) -> &'static str {
    match kind {
        1 => "new",
        2 => "update",
        _ => "unknown",
    }
}

const fn submission_entry_type_name(entry_type: u16) -> &'static str {
    match entry_type {
        0 => "key",
        1 => "credential",
        _ => "unknown",
    }
}

#[must_use]
pub fn render_submission_status(items: &[SubmissionStatusItem], json: bool) -> RenderedOutput {
    let mut output = RenderedOutput::default();
    let rewrap_failed = items
        .iter()
        .any(|item| matches!(item.rewrap, RewrapOutcome::Failed(_)));
    if json {
        let items = items
            .iter()
            .map(|item| {
                let summary = &item.summary;
                SubmissionStatusOutput {
                    submission_id: &summary.submission_id,
                    submission_kind: submission_kind_name(summary.submission_kind),
                    entry_type: submission_entry_type_name(summary.entry_type),
                    state: &summary.state,
                    agent_use_suspended: summary.agent_use_suspended,
                    submission_revision: &summary.submission_revision,
                    approver_key_version: summary.approver_key_version,
                    current_approver_key_version: summary.current_approver_key_version,
                    decision: summary.decision.as_ref(),
                    created_at: &summary.created_at,
                    decided_at: summary.decided_at.as_deref(),
                    rewrap: match &item.rewrap {
                        RewrapOutcome::NotRequired => RewrapOutput {
                            status: "not-required",
                            submission_revision: None,
                            code: None,
                        },
                        RewrapOutcome::Rewrapped {
                            submission_revision,
                        } => RewrapOutput {
                            status: "rewrapped",
                            submission_revision: Some(submission_revision.to_string()),
                            code: None,
                        },
                        RewrapOutcome::Failed(code) => RewrapOutput {
                            status: "failed",
                            submission_revision: None,
                            code: Some(code),
                        },
                    },
                }
            })
            .collect::<Vec<_>>();
        output.stdout_line(serde_json::json!({ "items": items }));
    } else if items.is_empty() {
        output.stdout_line("No submissions.");
    } else {
        for item in items {
            let summary = &item.summary;
            let mut line = format!(
                "{}  {}  {} {}  revision {}",
                safe_terminal_text(&summary.submission_id),
                safe_terminal_text(&summary.state),
                submission_kind_name(summary.submission_kind),
                submission_entry_type_name(summary.entry_type),
                safe_terminal_text(&summary.submission_revision),
            );
            if summary.agent_use_suspended {
                line.push_str("  use suspended");
            }
            match &item.rewrap {
                RewrapOutcome::NotRequired => {}
                RewrapOutcome::Rewrapped {
                    submission_revision,
                } => {
                    let _ = write!(
                        line,
                        "  re-wrapped for the rotated approver key (revision {submission_revision})"
                    );
                }
                RewrapOutcome::Failed(code) => {
                    let _ = write!(line, "  re-wrap failed ({code})");
                }
            }
            output.stdout_line(line);
        }
    }
    if rewrap_failed {
        output.exit_code = 1;
    }
    output
}

#[cfg(test)]
mod submission_tests {
    use palladin_crypto::SubmissionKind;
    use palladin_runtime::{SubmissionNotSaved, SubmissionSaved};

    use super::render_approver_retrust;

    use super::*;

    const FORBIDDEN_FIELDS: [&str; 6] = [
        "secret",
        "password",
        "value",
        "payload",
        "dek",
        "ciphertext",
    ];

    #[test]
    fn saved_result_matches_the_contract_message_and_exit_code() {
        let result = SubmissionResult {
            kind: SubmissionKind::Update,
            outcome: Ok(SubmissionSaved {
                state: "pending".to_owned(),
            }),
            submission_id: Some("0d0d0d0d-0d0d-4d0d-8d0d-0d0d0d0d0d0d".to_owned()),
            hints: Vec::new(),
        };
        let human = render_submission_result(&result, false);
        assert_eq!(human.exit_code, 0);
        assert_eq!(
            human.stdout,
            "Saved to Palladin as a pending update submission (0d0d0d0d-0d0d-4d0d-8d0d-0d0d0d0d0d0d). A reviewer must approve it in Palladin Inbox.\n"
        );
        let json = render_submission_result(&result, true);
        let value: serde_json::Value = serde_json::from_str(&json.stdout).unwrap();
        assert_eq!(value["submissionStatus"], "saved");
        assert_eq!(value["submissionState"], "pending");
        assert!(value.get("code").is_none());
    }

    #[test]
    fn every_not_saved_code_is_value_free_and_fails_the_process() {
        for code in [
            SubmissionNotSaved::NoApprovers,
            SubmissionNotSaved::ApproverKeyUnavailable,
            SubmissionNotSaved::ApproverKeyUntrusted,
            SubmissionNotSaved::UpdateNotGranted,
            SubmissionNotSaved::InvalidInput,
            SubmissionNotSaved::UnsupportedEntryType,
            SubmissionNotSaved::PasswordPolicyUnsatisfiable,
            SubmissionNotSaved::SubmissionConflict,
            SubmissionNotSaved::ServiceUnavailable,
        ] {
            let result = SubmissionResult {
                kind: SubmissionKind::New,
                outcome: Err(code),
                submission_id: None,
                hints: Vec::new(),
            };
            let human = render_submission_result(&result, false);
            assert_eq!(human.exit_code, 1);
            assert!(human.stdout.is_empty());
            assert_eq!(
                human.stderr,
                format!(
                    "Error: Not saved to Palladin ({}). Nothing was submitted to any site.\n",
                    code.code()
                )
            );
            let json = render_submission_result(&result, true);
            assert_eq!(json.exit_code, 1);
            let value: serde_json::Value = serde_json::from_str(&json.stdout).unwrap();
            assert_eq!(value["submissionStatus"], "not-saved");
            assert_eq!(value["code"], code.code());
            for field in FORBIDDEN_FIELDS {
                assert!(value.get(field).is_none());
            }
        }
    }

    #[test]
    fn not_saved_uses_the_contract_message_and_keeps_an_unconfirmed_id() {
        let result = SubmissionResult {
            kind: SubmissionKind::New,
            outcome: Err(SubmissionNotSaved::ServiceUnavailable),
            submission_id: Some("0d0d0d0d-0d0d-4d0d-8d0d-0d0d0d0d0d0d".to_owned()),
            hints: Vec::new(),
        };
        let output = render_submission_result(&result, true);
        let value: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
        assert_eq!(
            value["message"],
            "Not saved to Palladin (service-unavailable). Nothing was submitted to any site."
        );
        assert_eq!(
            value["submissionId"],
            "0d0d0d0d-0d0d-4d0d-8d0d-0d0d0d0d0d0d"
        );
        assert_eq!(value["code"], "service-unavailable");
    }

    #[test]
    fn hints_go_to_stderr_and_never_into_the_contract_result() {
        let result = SubmissionResult {
            kind: SubmissionKind::New,
            outcome: Err(SubmissionNotSaved::ApproverKeyUntrusted),
            submission_id: None,
            hints: vec![SubmissionHint::ApproverReintroduction {
                signing_key_fingerprint: "CddpQldl…ksknV0".to_owned(),
            }],
        };
        for json in [false, true] {
            let output = render_submission_result(&result, json);
            assert!(output.stderr.contains(
                "palladin submit trust-approvers --fingerprint CddpQldl…ksknV0 --confirm"
            ));
            assert!(!output.stdout.contains("trust-approvers"));
        }
        let updated = SubmissionResult {
            kind: SubmissionKind::Update,
            outcome: Ok(SubmissionSaved {
                state: "pending".to_owned(),
            }),
            submission_id: Some("0d0d0d0d-0d0d-4d0d-8d0d-0d0d0d0d0d0d".to_owned()),
            hints: vec![SubmissionHint::UsernameNeededForAutofill],
        };
        let output = render_submission_result(&updated, true);
        assert_eq!(output.exit_code, 0);
        assert!(
            output
                .stderr
                .contains("Login autofill with this submission needs one")
        );
        let value: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 5);
        assert!(
            render_approver_retrust(&ReTrustedApproverKey {
                key_version: 2,
                manifest_revision: 2,
                signing_key_fingerprint: "CddpQldl…ksknV0".to_owned(),
            })
            .stdout
            .contains("Run palladin submit status to re-wrap pending submissions")
        );
    }

    #[test]
    fn status_output_is_structural_and_marks_failed_rewraps() {
        let summary: palladin_api::AgentSubmissionSummary =
            serde_json::from_value(serde_json::json!({
                "submissionId": "0d0d0d0d-0d0d-4d0d-8d0d-0d0d0d0d0d0d", "submissionKind": 1,
                "entryType": 1, "target": { "kind": "new" }, "state": "pending",
                "agentUseSuspended": false, "submissionRevision": "1", "approverKeyVersion": 1,
                "currentApproverKeyVersion": 2, "createdAt": "2026-10-29T08:00:00Z"
            }))
            .unwrap();
        let items = [SubmissionStatusItem {
            summary,
            rewrap: RewrapOutcome::Failed("approver-key-untrusted"),
        }];
        let human = render_submission_status(&items, false);
        assert_eq!(human.exit_code, 1);
        assert!(human.stdout.contains(
            "pending  new credential  revision 1  re-wrap failed (approver-key-untrusted)"
        ));
        let json: serde_json::Value =
            serde_json::from_str(&render_submission_status(&items, true).stdout).unwrap();
        assert_eq!(json["items"][0]["rewrap"]["status"], "failed");
        assert_eq!(json["items"][0]["submissionKind"], "new");
    }
}
