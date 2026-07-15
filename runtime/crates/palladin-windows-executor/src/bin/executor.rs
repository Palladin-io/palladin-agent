#[cfg(not(windows))]
fn main() {
    eprintln!("Error: Palladin Windows executor can run only on Windows");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() {
    std::panic::set_hook(Box::new(|_| {
        eprintln!("Error: Palladin hardened executor terminated unexpectedly");
    }));
    let exit_code = match palladin_windows_executor::run_executor_from_standard_input() {
        Ok(exit_code) => exit_code,
        Err(palladin_windows_executor::ExecutorError::ExecutableUnavailable) => 127,
        Err(_) => palladin_windows_executor::EXECUTOR_FAILURE_EXIT_CODE,
    };
    std::process::exit(exit_code);
}
