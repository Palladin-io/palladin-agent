use std::collections::BTreeMap;
use std::process::Command;

use clap::Parser;
use palladin_api::{
    AgentRegistrationResult, AgentVisibleField, CredentialAccess, EntrySearchItem,
    EntrySearchResult,
};
use palladin_cli::CreatedProfile;
use palladin_cli::args::{Cli, Commands};
use palladin_cli::output::{
    CredentialOutput, FieldValueOutput, RenderedOutput, TotpOutput, render_agent_list,
    render_connect, render_init, render_profile_created, render_report_stale, render_search_human,
    render_security_upgrade, render_status,
};
use palladin_core::public_store::{PUBLIC_SCHEMA_VERSION, PublicAgentEntry, PublicRegistry};
use palladin_credential::access::exit_code_for_access;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Contract {
    contract: String,
    status: String,
    synthetic_only: bool,
    identity_model: IdentityModel,
    commands: Vec<CommandCase>,
    process_cases: Vec<ProcessCase>,
    exit_codes: ExitCodes,
    credential_output_snapshots: CredentialOutputSnapshots,
    command_output_snapshots: Vec<CommandOutputSnapshot>,
    output_rules: OutputRules,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdentityModel {
    api_key_owner: String,
    organization_key_may_be_shared_by_agents: bool,
    agent_identity: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CommandCase {
    argv: Vec<String>,
    name: String,
    secret_output: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProcessCase {
    name: String,
    argv: Vec<String>,
    exit_code: i32,
    stdout_exact: String,
    #[serde(default)]
    environment: BTreeMap<String, String>,
    #[serde(default)]
    stderr_exact: Option<String>,
    #[serde(default)]
    stderr_contains: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExitCodes {
    success: u8,
    failure: u8,
    usage: u8,
    pending_or_unavailable: u8,
    not_permitted: u8,
    unsafe_environment: u8,
}

#[derive(Deserialize)]
struct CredentialOutputSnapshots {
    whole: String,
    field: String,
    totp: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CommandOutputSnapshot {
    name: String,
    exit_code: u8,
    stdout: String,
    stderr: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OutputRules {
    stdout_may_contain_plaintext_secret_only_for: Vec<String>,
    errors_and_progress: String,
    machine_output: String,
    identifier_display: String,
    api_key_argv: String,
}

fn contract() -> Contract {
    serde_json::from_str(include_str!("../../../contracts/v1/cli.json")).expect("CLI contract")
}

fn command_name(command: &Commands) -> &'static str {
    match command {
        Commands::Init { .. } => "init",
        Commands::Doctor => "doctor",
        Commands::Connect(_) => "connect",
        Commands::Status => "status",
        Commands::Search(_) => "search",
        Commands::Get(_) => "get",
        Commands::ReportStale(_) => "report-stale",
        Commands::Agents { .. } => "agents",
        Commands::Security { .. } => "security",
        Commands::Purge { .. } => "purge",
    }
}

#[test]
fn frozen_contract_parses_every_supported_command() {
    let contract = contract();
    assert_eq!(contract.contract, "native-cli-v2");
    assert_eq!(contract.status, "frozen");
    assert!(contract.synthetic_only);
    assert_eq!(contract.identity_model.api_key_owner, "organization");
    assert!(
        contract
            .identity_model
            .organization_key_may_be_shared_by_agents
    );
    assert_eq!(
        contract.identity_model.agent_identity,
        ["agentId", "x25519", "ed25519"]
    );
    assert_eq!(
        contract
            .output_rules
            .stdout_may_contain_plaintext_secret_only_for,
        ["get", "retrieve"]
    );
    assert_eq!(contract.output_rules.errors_and_progress, "stderr");
    assert_eq!(contract.output_rules.machine_output, "stdout");
    assert_eq!(
        contract.output_rules.identifier_display,
        "first8-ellipsis-last6"
    );
    assert_eq!(
        contract.output_rules.api_key_argv,
        "reject-before-parser-without-echo"
    );
    for case in contract.commands {
        let mut argv = vec!["palladin".to_owned()];
        argv.extend(case.argv);
        let parsed = Cli::try_parse_from(argv)
            .unwrap_or_else(|error| panic!("contract case {} did not parse: {error}", case.name));
        assert_eq!(command_name(&parsed.command), case.name);
        assert_eq!(
            case.secret_output,
            matches!(parsed.command, Commands::Get(_)),
            "only explicit get/retrieve may write a plaintext credential"
        );
    }
}

#[test]
fn contradictory_wait_flags_preserve_legacy_last_option_wins_behavior() {
    let parsed = Cli::try_parse_from([
        "palladin",
        "get",
        "vault",
        "entry",
        "--wait",
        "30s",
        "--no-wait",
    ])
    .expect("no-wait last");
    let Commands::Get(args) = parsed.command else {
        panic!("get command");
    };
    assert!(args.no_wait);
    assert!(args.wait.is_none());

    let parsed = Cli::try_parse_from([
        "palladin",
        "get",
        "vault",
        "entry",
        "--no-wait",
        "--wait",
        "30s",
    ])
    .expect("wait last");
    let Commands::Get(args) = parsed.command else {
        panic!("get command");
    };
    assert!(!args.no_wait);
    assert_eq!(args.wait.as_deref(), Some("30s"));
}

#[test]
fn frozen_process_outputs_keep_stdout_stderr_and_exit_codes_distinct() {
    for case in contract().process_cases {
        let output = Command::new(env!("CARGO_BIN_EXE_palladin"))
            .env_clear()
            .envs(&case.environment)
            .args(&case.argv)
            .output()
            .unwrap_or_else(|error| panic!("run {}: {error}", case.name));
        let stdout = String::from_utf8(output.stdout)
            .expect("UTF-8 stdout")
            .replace("\r\n", "\n");
        let stderr = String::from_utf8(output.stderr)
            .expect("UTF-8 stderr")
            .replace("\r\n", "\n");
        assert_eq!(output.status.code(), Some(case.exit_code), "{}", case.name);
        assert_eq!(
            stdout,
            expand_platform_tokens(&case.stdout_exact),
            "{} stdout",
            case.name
        );
        if let Some(expected) = case.stderr_exact {
            assert_eq!(
                stderr,
                expand_platform_tokens(&expected),
                "{} stderr",
                case.name
            );
        }
        if let Some(expected) = case.stderr_contains {
            assert!(stderr.contains(&expected), "{} stderr: {stderr}", case.name);
        }
    }
}

fn expand_platform_tokens(value: &str) -> String {
    value
        .replace("{{VERSION}}", env!("CARGO_PKG_VERSION"))
        .replace("{{EXE}}", std::env::consts::EXE_SUFFIX)
}

#[test]
fn frozen_exit_codes_cover_usage_environment_retry_and_permission_classes() {
    let exit = contract().exit_codes;
    assert_eq!(exit.success, 0);
    assert_eq!(exit.failure, 1);
    assert_eq!(exit.usage, 2);
    assert_eq!(exit.unsafe_environment, 78);
    assert_eq!(
        exit_code_for_access(&CredentialAccess::Unavailable),
        exit.pending_or_unavailable
    );
    assert_eq!(
        exit_code_for_access(&CredentialAccess::Denied),
        exit.not_permitted
    );
}

#[test]
fn frozen_get_outputs_match_the_legacy_json_shape_byte_for_byte() {
    let snapshots = contract().credential_output_snapshots;
    let whole = CredentialOutput {
        entry_id: "entry-fixture",
        label: "Fixture credential",
        secret: "synthetic-secret",
    };
    let field = FieldValueOutput {
        entry_id: "entry-fixture",
        label: "Fixture credential",
        field: "password",
        value: "synthetic-secret",
    };
    let totp = TotpOutput {
        entry_id: "entry-fixture",
        label: "Fixture credential",
        field: "Authenticator",
        code: "123456",
        expires_in: 17,
    };
    assert_eq!(
        format!("{}\n", serde_json::to_string_pretty(&whole).expect("whole")),
        snapshots.whole
    );
    assert_eq!(
        format!("{}\n", serde_json::to_string_pretty(&field).expect("field")),
        snapshots.field
    );
    assert_eq!(
        format!("{}\n", serde_json::to_string_pretty(&totp).expect("totp")),
        snapshots.totp
    );
}

#[test]
fn frozen_command_outputs_cover_every_ported_public_surface() {
    let registry = PublicRegistry {
        schema_version: PUBLIC_SCHEMA_VERSION,
        default: "build".to_owned(),
        agents: vec![
            PublicAgentEntry {
                name: "build".to_owned(),
                identity_id: "11111111111111111111111111111111".to_owned(),
                created_at: "2026-01-01T00:00:00Z".to_owned(),
                agent_type: None,
            },
            PublicAgentEntry {
                name: "second".to_owned(),
                identity_id: "22222222222222222222222222222222".to_owned(),
                created_at: "2026-01-01T00:00:00Z".to_owned(),
                agent_type: None,
            },
        ],
    };
    let created = CreatedProfile {
        name: "build".to_owned(),
        identity_id: "11111111111111111111111111111111".to_owned(),
        encryption_public_key: "ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_owned(),
        signing_public_key: "12345678901234567890".to_owned(),
    };
    let search = EntrySearchResult {
        items: vec![EntrySearchItem {
            entry_id: "entry-1234567890abcdef".to_owned(),
            vault_id: "vault-1234567890abcdef".to_owned(),
            label: "Fixture\nEntry".to_owned(),
            url_domain: Some("example.test".to_owned()),
            description: Some("metadata\u{202e}spoof".to_owned()),
            agent_fields: vec![AgentVisibleField {
                label: "Region".to_owned(),
                value: "eu-central-1".to_owned(),
            }],
        }],
        next_cursor: Some("cursor-1234567890abcdef".to_owned()),
    };
    let cases = [
        (
            "init-created",
            render_init("build", "OS secure storage", false, false),
        ),
        (
            "connect-pending",
            render_connect(
                &AgentRegistrationResult::Pending {
                    agent_id: "1234567890abcdefghijklmnopqrstuvwxyz".to_owned(),
                },
                true,
                "OS secure storage",
            ),
        ),
        (
            "connect-unreachable",
            render_connect(
                &AgentRegistrationResult::Unreachable {
                    error: "transport\nforged".to_owned(),
                },
                true,
                "OS secure storage",
            ),
        ),
        (
            "connect-invalid-key",
            render_connect(
                &AgentRegistrationResult::InvalidKey,
                false,
                "OS secure storage",
            ),
        ),
        (
            "status-active",
            render_status(
                "build",
                "https://api.example.test",
                &AgentRegistrationResult::Active {
                    agent_id: "agent-build".to_owned(),
                    name: Some("Build\nforged".to_owned()),
                },
                "OS secure storage",
            ),
        ),
        ("agents-list", render_agent_list(&registry)),
        (
            "agents-created",
            render_profile_created(&created, "OS secure storage"),
        ),
        (
            "security-upgrade",
            render_security_upgrade("build", "OS secure storage"),
        ),
        ("search-human", render_search_human(&search)),
        ("report-stale", render_report_stale()),
    ];
    let expected = contract()
        .command_output_snapshots
        .into_iter()
        .map(|snapshot| (snapshot.name.clone(), snapshot))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(cases.len(), expected.len());
    for (name, actual) in cases {
        let expected = expected
            .get(name)
            .unwrap_or_else(|| panic!("snapshot {name}"));
        assert_rendered(actual, expected, name);
    }
}

fn assert_rendered(actual: RenderedOutput, expected: &CommandOutputSnapshot, name: &str) {
    assert_eq!(actual.exit_code, expected.exit_code, "{name} exit");
    assert_eq!(actual.stdout, expected.stdout, "{name} stdout");
    assert_eq!(actual.stderr, expected.stderr, "{name} stderr");
}

#[test]
fn api_key_canary_is_rejected_anywhere_in_argv_without_echo() {
    let canary = "pl_synthetic_cli_contract_must_not_echo";
    for argument in [
        canary.to_owned(),
        format!("--api-key={canary}"),
        format!("key={canary}"),
        format!("prefix-{canary}-suffix"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_palladin"))
            .env_clear()
            .args(["connect", &argument])
            .output()
            .expect("run canary case");
        let stdout = String::from_utf8(output.stdout).expect("UTF-8 stdout");
        let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");
        assert_eq!(output.status.code(), Some(1));
        assert!(!stdout.contains(canary));
        assert!(!stderr.contains(canary));
        assert!(stderr.contains("API keys are forbidden in argv"));
    }
}

#[test]
fn clap_never_receives_terminal_control_or_bidi_arguments() {
    for argument in [
        "unknown\nforged-line",
        "unknown\u{1b}[31mred",
        "unknown\u{202e}spoofed",
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_palladin"))
            .env_clear()
            .arg(argument)
            .output()
            .expect("run terminal canary");
        let stdout = String::from_utf8(output.stdout).expect("UTF-8 stdout");
        let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");
        assert_eq!(output.status.code(), Some(1));
        assert!(stdout.is_empty());
        assert_eq!(
            stderr,
            "Error: command-line arguments contain unsupported control characters\n"
        );
        assert!(!stderr.contains(argument));
    }
}

#[test]
fn connect_word_inside_another_command_does_not_trigger_the_id_deprecation() {
    let output = Command::new(env!("CARGO_BIN_EXE_palladin"))
        .env_clear()
        .args(["search", "connect", "--id", "build", "--help"])
        .output()
        .expect("run search help");
    assert!(output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");
    assert!(!stderr.contains("connect --id no longer"));
}
