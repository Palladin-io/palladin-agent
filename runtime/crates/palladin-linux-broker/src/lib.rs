#![forbid(unsafe_code)]

pub mod client;
pub mod peer;
pub mod protocol;
#[cfg(unix)]
pub mod purge;
pub mod store;

pub const SYSTEM_CLIENT: &str = "/usr/lib/palladin/runtime/palladin-linux-client";
pub const SYSTEM_SERVICE: &str = "/usr/lib/palladin/runtime/palladin-linux-service";
pub const SYSTEM_ADMIN_PURGE: &str = "/usr/lib/palladin/runtime/palladin-linux-admin-purge";
pub const SYSTEM_WORKER: &str = "/usr/lib/palladin/runtime/palladin-worker";
pub const INSTALL_MARKER: &str = "/etc/palladin/runtime-v1";
pub const SOCKET_PATH: &str = "/run/palladin-runtime/broker.sock";
pub const STATE_ROOT: &str = "/var/lib/palladin-runtime/v1";

#[cfg(not(target_os = "linux"))]
pub fn unsupported_platform() -> ! {
    panic!("Palladin Linux broker binaries can run only on Linux")
}
