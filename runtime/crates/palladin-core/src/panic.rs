use std::io::Write;

const REDACTED_PANIC: &[u8] = b"palladin: fatal runtime error (details redacted)\n";

pub fn install_redacted_panic_hook() {
    std::panic::set_hook(Box::new(|_| {
        let _ = std::io::stderr().write_all(REDACTED_PANIC);
    }));
}
