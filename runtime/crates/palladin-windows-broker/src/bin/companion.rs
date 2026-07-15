use std::process::ExitCode;

fn main() -> ExitCode {
    #[cfg(not(windows))]
    {
        eprintln!("Error: Palladin Windows companion can run only on Windows");
        ExitCode::FAILURE
    }

    #[cfg(windows)]
    {
        match palladin_windows_broker::run_companion() {
            Ok(code) => u8::try_from(code)
                .map(ExitCode::from)
                .unwrap_or(ExitCode::FAILURE),
            Err(error) => {
                eprintln!("Error: {error}");
                ExitCode::FAILURE
            }
        }
    }
}
