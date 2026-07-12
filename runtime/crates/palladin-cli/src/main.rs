#![forbid(unsafe_code)]

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use palladin_core::environment::EnvironmentReport;
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

fn main() -> ExitCode {
    install_redacted_panic_hook();
    let cli = Cli::parse();

    match cli.command {
        Commands::Doctor => doctor(),
    }
}

fn doctor() -> ExitCode {
    let platform = palladin_platform::current();
    let environment = EnvironmentReport::inspect_current();

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
        println!(
            "dangerous-variable-names: {}",
            environment.dangerous_names().join(",")
        );
        ExitCode::from(EXIT_UNSAFE_ENVIRONMENT)
    }
}
