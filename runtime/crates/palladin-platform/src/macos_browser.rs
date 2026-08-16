use security_framework::os::macos::code_signing::{
    Flags, GuestAttributes, SecCode, SecRequirement,
};

use crate::PlatformError;

const GOOGLE_CHROME_REQUIREMENT: &str = "(identifier \"com.google.Chrome\" or identifier \"com.google.Chrome.helper\") and anchor apple generic and certificate leaf[subject.OU] = \"EQHXZ8M8AV\"";

/// Attest the direct process that launched a macOS Native Messaging host.
///
/// Chrome's origin argument is not accepted on its own: another same-user process can invoke an
/// executable with arbitrary argv. Dynamic code-signing validation binds the invocation to the
/// running Google Chrome process before the browser-host key or local socket is opened.
pub fn authenticate_chrome_native_messaging_parent() -> Result<(), PlatformError> {
    let parent = nix::unistd::getppid();
    if parent.as_raw() <= 1 {
        return Err(PlatformError::BrowserHostParentInvalid);
    }
    let mut attributes = GuestAttributes::new();
    attributes.set_pid(parent.as_raw());
    let code = SecCode::copy_guest_with_attribues(None, &attributes, Flags::NONE)
        .map_err(|_| PlatformError::BrowserHostParentInvalid)?;
    let requirement = GOOGLE_CHROME_REQUIREMENT
        .parse::<SecRequirement>()
        .map_err(|_| PlatformError::BrowserHostParentInvalid)?;
    code.check_validity(
        Flags::STRICT_VALIDATE | Flags::NO_NETWORK_ACCESS,
        &requirement,
    )
    .map_err(|_| PlatformError::BrowserHostParentInvalid)
}

#[cfg(test)]
mod tests {
    use super::GOOGLE_CHROME_REQUIREMENT;

    #[test]
    fn chrome_requirement_is_exact_and_team_scoped() {
        assert!(GOOGLE_CHROME_REQUIREMENT.contains("identifier \"com.google.Chrome\""));
        assert!(GOOGLE_CHROME_REQUIREMENT.contains("identifier \"com.google.Chrome.helper\""));
        assert!(GOOGLE_CHROME_REQUIREMENT.contains("EQHXZ8M8AV"));
        assert!(!GOOGLE_CHROME_REQUIREMENT.contains('*'));
        GOOGLE_CHROME_REQUIREMENT
            .parse::<security_framework::os::macos::code_signing::SecRequirement>()
            .expect("valid Security framework requirement");
    }
}
