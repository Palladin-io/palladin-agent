#![forbid(unsafe_code)]

use std::env;
use std::path::Path;
use std::process::ExitCode;

use palladin_linux_broker::store::LinuxBrokerSecretStore;
use palladin_platform::secure_store::{SecretSlot, SecretStore};
use secrecy::ExposeSecret;

// Synthetic test data. The value is intentionally kept inside this test-only
// binary so package lifecycle tests never pass credential material in argv,
// environment variables, or logs.
const ORGANIZATION_CREDENTIAL_FIXTURE: &[u8] =
    b"palladin-package-compatibility-organization-credential-v1";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(()) => {
            eprintln!("package compatibility state verification failed");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), ()> {
    let mut arguments = env::args_os().skip(1);
    let operation = arguments.next().ok_or(())?;
    let profile_root = arguments.next().ok_or(())?;
    let master_key = arguments.next().ok_or(())?;
    let owner_id = arguments.next().ok_or(())?;
    if arguments.next().is_some() {
        return Err(());
    }
    let operation = operation.to_str().ok_or(())?;
    let owner_id = owner_id.to_str().ok_or(())?;
    let store = LinuxBrokerSecretStore::new(Path::new(&profile_root), Path::new(&master_key))
        .map_err(|_| ())?;

    match operation {
        "seed" => store
            .set(
                owner_id,
                SecretSlot::OrganizationApiKey,
                ORGANIZATION_CREDENTIAL_FIXTURE,
            )
            .map_err(|_| ()),
        "verify" => {
            let stored = store
                .get(owner_id, SecretSlot::OrganizationApiKey)
                .map_err(|_| ())?
                .ok_or(())?;
            if stored.expose_secret() == ORGANIZATION_CREDENTIAL_FIXTURE {
                Ok(())
            } else {
                Err(())
            }
        }
        _ => Err(()),
    }
}
