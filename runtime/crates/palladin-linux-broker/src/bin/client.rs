#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    let Ok(runtime) = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    else {
        eprintln!("Error: could not start the Linux client runtime");
        return ExitCode::FAILURE;
    };
    let arguments = std::env::args().skip(1).collect();
    let code = runtime.block_on(async {
        match palladin_linux_broker::client::run(arguments).await {
            Ok(code) => code,
            Err(error) => {
                eprintln!("Error: {error}");
                ExitCode::FAILURE
            }
        }
    });
    // Tokio cannot cancel a pending stdin read. The CLI must terminate after
    // broker shutdown even when its MCP host keeps stdin open.
    runtime.shutdown_background();
    code
}
