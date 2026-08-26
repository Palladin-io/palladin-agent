#![forbid(unsafe_code)]

use std::process::ExitCode;

#[cfg(target_os = "macos")]
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}

#[cfg(target_os = "macos")]
fn run() -> Result<(), ()> {
    let mut arguments = std::env::args_os();
    arguments.next().ok_or(())?;
    match (
        arguments.next(),
        arguments.next(),
        arguments.next(),
        arguments.next(),
    ) {
        (None, None, None, None) => {
            palladin_platform::serve_development_keychain_helper().map_err(|_| ())
        }
        (Some(mode), Some(owner_id), Some(slot_code), None) => {
            let owner_id = owner_id.to_str().ok_or(())?;
            let slot_code = slot_code
                .to_str()
                .ok_or(())?
                .parse::<u8>()
                .map_err(|_| ())?;
            if mode == "--authorize-existing" {
                palladin_platform::authorize_existing_development_keychain_item(owner_id, slot_code)
                    .map_err(|_| ())
            } else if mode == "--verify-existing" {
                palladin_platform::verify_existing_development_keychain_item(owner_id, slot_code)
                    .map_err(|_| ())
            } else {
                Err(())
            }
        }
        _ => Err(()),
    }
}

#[cfg(not(target_os = "macos"))]
fn main() -> ExitCode {
    ExitCode::FAILURE
}
