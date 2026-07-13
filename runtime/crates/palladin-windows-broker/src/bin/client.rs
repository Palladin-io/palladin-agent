use std::process::ExitCode;

fn main() -> ExitCode {
    #[cfg(not(windows))]
    {
        eprintln!("Error: Palladin Windows client can run only on Windows");
        ExitCode::FAILURE
    }

    #[cfg(windows)]
    {
        use std::process::{Command, Stdio};

        let companion = match palladin_windows_broker::companion_alias_path() {
            Ok(path) => path,
            Err(error) => {
                eprintln!("Error: {error}");
                return ExitCode::FAILURE;
            }
        };
        let status = Command::new(companion)
            .args(std::env::args_os().skip(1))
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .and_then(|mut child| child.wait());
        match status {
            Ok(status) => status
                .code()
                .and_then(|code| u8::try_from(code).ok())
                .map_or(ExitCode::FAILURE, ExitCode::from),
            Err(_) => {
                eprintln!("Error: signed Palladin companion alias is unavailable");
                ExitCode::FAILURE
            }
        }
    }
}
