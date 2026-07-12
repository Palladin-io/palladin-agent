#![forbid(unsafe_code)]

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use palladin_core::environment::{EnvironmentReport, EnvironmentRequirement, enforce_environment};
use palladin_core::panic::install_redacted_panic_hook;

const EXIT_UNSAFE_ENVIRONMENT: u8 = 78;

#[derive(Debug, Parser)]
#[command(name = "palladin", version, about = "Palladin native Agent runtime")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Check the native runtime boundary without opening Agent Identity.
    Doctor,
}

impl Commands {
    const fn environment_requirement(&self) -> EnvironmentRequirement {
        match self {
            Self::Doctor => EnvironmentRequirement::DiagnosticOnly,
        }
    }
}

fn main() -> ExitCode {
    install_redacted_panic_hook();
    let environment = EnvironmentReport::inspect_current();
    let cli = Cli::parse();

    if enforce_environment(cli.command.environment_requirement(), &environment).is_err() {
        print_unsafe_environment(&environment);
        return ExitCode::from(EXIT_UNSAFE_ENVIRONMENT);
    }

    match cli.command {
        Commands::Doctor => doctor(&environment),
    }
}

fn doctor(environment: &EnvironmentReport) -> ExitCode {
    let platform = palladin_platform::current();

    println!("Palladin Runtime Doctor");
    println!("version: {}", env!("CARGO_PKG_VERSION"));
    println!(
        "platform: {}/{}",
        platform.operating_system, platform.architecture
    );
    println!("standalone-security-tier: {}", platform.standalone_tier);
    println!("hardened-candidate: {}", platform.hardened_candidate);
    println!("identity-opened: no");
    println!("project-runtime-dependencies: disabled");

    if environment.is_safe() {
        println!("environment: safe");
        ExitCode::SUCCESS
    } else {
        println!("environment: unsafe");
        print_unsafe_environment(environment);
        ExitCode::from(EXIT_UNSAFE_ENVIRONMENT)
    }
}

fn print_unsafe_environment(environment: &EnvironmentReport) {
    println!(
        "dangerous-variable-names: {}",
        environment.dangerous_names().join(",")
    );
}
