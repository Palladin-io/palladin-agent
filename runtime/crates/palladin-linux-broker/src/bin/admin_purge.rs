#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    use std::path::Path;
    use std::process::ExitCode;

    use nix::unistd::{Uid, User};
    use palladin_linux_broker::{STATE_ROOT, purge::purge_principal_namespace};

    if !Uid::effective().is_root() {
        eprintln!("Error: the Linux Hardened purge helper must run as root");
        return ExitCode::from(77);
    }
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let [principal, confirmation] = arguments.as_slice() else {
        eprintln!("Usage: palladin-linux-admin-purge PRINCIPAL --confirm-purge");
        return ExitCode::from(64);
    };
    if confirmation != "--confirm-purge" {
        eprintln!("Error: Linux Hardened purge requires --confirm-purge");
        return ExitCode::from(64);
    }
    let broker = match User::from_name("palladin-runtime") {
        Ok(Some(user)) if !user.uid.is_root() => user,
        _ => {
            eprintln!("Error: the Linux Hardened broker account is unavailable");
            return ExitCode::from(78);
        }
    };
    match purge_principal_namespace(Path::new(STATE_ROOT), principal, broker.uid.as_raw()) {
        Ok(()) => {
            println!("Revoked Palladin principal state was permanently purged.");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Error: {error}");
            ExitCode::from(78)
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("Error: the Linux Hardened purge helper is unavailable on this platform");
    std::process::ExitCode::from(78)
}
