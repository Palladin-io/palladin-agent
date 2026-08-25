#![forbid(unsafe_code)]

use std::process::ExitCode;

#[cfg(target_os = "macos")]
fn main() -> ExitCode {
    if std::env::args_os().count() != 1 {
        return ExitCode::FAILURE;
    }
    match palladin_platform::serve_development_keychain_helper() {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}

#[cfg(not(target_os = "macos"))]
fn main() -> ExitCode {
    ExitCode::FAILURE
}
