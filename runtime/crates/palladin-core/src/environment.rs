use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::process::Command;

const EXACT_DANGEROUS_NAMES: &[&str] = &[
    "CLAW_VAULT_HOME",
    "CLAW_VAULT_PRIVATE_KEY",
    "CLAW_VAULT_SIGNING_KEY",
    "CURL_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
    "NODE_OPTIONS",
    "NODE_PATH",
    "PALLADIN_API_KEY",
    "PALLADIN_HOME",
    "PALLADIN_PRIVATE_KEY",
    "PALLADIN_SIGNING_KEY",
    "PALLADIN_SIGNING_PRIVATE_KEY",
    "REQUESTS_CA_BUNDLE",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvironmentReport {
    dangerous_names: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvironmentRequirement {
    DiagnosticOnly,
    Clean,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnsafeEnvironment;

impl EnvironmentReport {
    #[must_use]
    pub fn inspect_current() -> Self {
        Self::inspect_names(std::env::vars_os().map(|(name, _)| name))
    }

    #[must_use]
    pub fn inspect_names<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        Self::inspect_names_with_case(names, cfg!(windows))
    }

    fn inspect_names_with_case<I, S>(names: I, case_insensitive: bool) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let dangerous_names = names
            .into_iter()
            .filter_map(|name| {
                name.as_ref()
                    .to_str()
                    .filter(|name| is_dangerous_name_with_case(name, case_insensitive))
                    .map(str::to_owned)
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();

        Self { dangerous_names }
    }

    #[must_use]
    pub fn is_safe(&self) -> bool {
        self.dangerous_names.is_empty()
    }

    #[must_use]
    pub fn dangerous_names(&self) -> &[String] {
        &self.dangerous_names
    }
}

pub fn enforce_environment(
    requirement: EnvironmentRequirement,
    report: &EnvironmentReport,
) -> Result<(), UnsafeEnvironment> {
    if requirement == EnvironmentRequirement::Clean && !report.is_safe() {
        Err(UnsafeEnvironment)
    } else {
        Ok(())
    }
}

#[must_use]
pub fn is_dangerous_name(name: &str) -> bool {
    is_dangerous_name_with_case(name, cfg!(windows))
}

fn is_dangerous_name_with_case(name: &str, case_insensitive: bool) -> bool {
    let normalized = if case_insensitive {
        name.to_ascii_uppercase()
    } else {
        name.to_owned()
    };

    normalized.starts_with("DYLD_")
        || normalized.starts_with("CLAW_VAULT_PRIVATE_KEY_")
        || normalized.starts_with("CLAW_VAULT_SIGNING_KEY_")
        || normalized.starts_with("LD_")
        || normalized.starts_with("PALLADIN_PRIVATE_KEY_")
        || normalized.starts_with("PALLADIN_SIGNING_KEY_")
        || EXACT_DANGEROUS_NAMES.contains(&normalized.as_str())
}

pub fn sanitize_child(command: &mut Command) {
    for name in EXACT_DANGEROUS_NAMES {
        command.env_remove(name);
    }

    let dangerous_names = std::env::vars_os()
        .map(|(name, _)| name)
        .chain(command.get_envs().map(|(name, _)| name.to_os_string()))
        .filter(|name| name.to_str().is_some_and(is_dangerous_name))
        .collect::<Vec<OsString>>();

    for name in dangerous_names {
        command.env_remove(name);
    }
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use super::{
        EnvironmentReport, EnvironmentRequirement, enforce_environment, is_dangerous_name,
        is_dangerous_name_with_case, sanitize_child,
    };

    #[test]
    fn classifies_loader_and_node_injection_names_without_values() {
        let report = EnvironmentReport::inspect_names([
            "PATH",
            "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES",
            "NODE_OPTIONS",
            "PALLADIN_API_KEY",
            "PALLADIN_HOME",
        ]);

        assert_eq!(
            report.dangerous_names(),
            [
                "DYLD_INSERT_LIBRARIES",
                "LD_PRELOAD",
                "NODE_OPTIONS",
                "PALLADIN_API_KEY",
                "PALLADIN_HOME"
            ]
        );
        assert!(!report.is_safe());
    }

    #[test]
    fn matching_is_exact_except_for_dyld_namespace() {
        assert!(is_dangerous_name("LD_PRELOAD"));
        assert!(is_dangerous_name("LD_FUTURE_INJECTION_FLAG"));
        assert!(is_dangerous_name("DYLD_FUTURE_INJECTION_FLAG"));
        assert!(!is_dangerous_name("SAFE_DYLD_VALUE"));
        assert!(is_dangerous_name("SSL_CERT_FILE"));
        assert!(is_dangerous_name("PALLADIN_SIGNING_KEY"));
        assert!(is_dangerous_name("PALLADIN_PRIVATE_KEY_BUILD_AGENT"));
        assert!(is_dangerous_name("PALLADIN_SIGNING_KEY_BUILD_AGENT"));
        assert!(is_dangerous_name("CLAW_VAULT_HOME"));
        assert!(is_dangerous_name("CLAW_VAULT_PRIVATE_KEY_BUILD_AGENT"));
        assert!(is_dangerous_name("CLAW_VAULT_SIGNING_KEY_BUILD_AGENT"));
    }

    #[test]
    fn windows_policy_is_ascii_case_insensitive() {
        assert!(is_dangerous_name_with_case("node_options", true));
        assert!(is_dangerous_name_with_case("palladin_api_key", true));
        assert!(is_dangerous_name_with_case("ld_preload", true));
        assert!(!is_dangerous_name_with_case("node_options", false));

        let report = EnvironmentReport::inspect_names_with_case(
            ["node_options", "palladin_api_key", "SAFE_VALUE"],
            true,
        );
        assert_eq!(
            report.dangerous_names(),
            ["node_options", "palladin_api_key"]
        );
    }

    #[test]
    fn clean_guard_blocks_identity_commands_but_allows_diagnostics() {
        let report = EnvironmentReport::inspect_names(["NODE_OPTIONS"]);
        assert!(enforce_environment(EnvironmentRequirement::Clean, &report).is_err());
        assert!(enforce_environment(EnvironmentRequirement::DiagnosticOnly, &report).is_ok());
    }

    #[test]
    fn strips_known_dangerous_variables_from_children() {
        let mut command = Command::new("ignored-program");
        command.env("LD_PRELOAD", "synthetic-not-a-library");
        command.env("NODE_OPTIONS", "--synthetic");
        command.env("PALLADIN_API_KEY", "synthetic-not-a-secret");
        command.env("PALLADIN_PRIVATE_KEY_BUILD", "synthetic-not-a-secret");
        command.env("PALLADIN_SIGNING_KEY_BUILD", "synthetic-not-a-secret");
        command.env("SSL_CERT_FILE", "synthetic-ca-path");
        command.env("SAFE_VALUE", "preserved");
        if cfg!(windows) {
            command.env("node_options", "--synthetic-lowercase");
        }

        sanitize_child(&mut command);
        let environment = command
            .get_envs()
            .map(|(name, value)| (name.to_string_lossy().into_owned(), value.is_some()))
            .collect::<std::collections::BTreeMap<_, _>>();

        assert_eq!(environment.get("LD_PRELOAD"), Some(&false));
        assert_eq!(environment.get("NODE_OPTIONS"), Some(&false));
        assert_eq!(environment.get("PALLADIN_API_KEY"), Some(&false));
        assert_eq!(environment.get("PALLADIN_PRIVATE_KEY_BUILD"), Some(&false));
        assert_eq!(environment.get("PALLADIN_SIGNING_KEY_BUILD"), Some(&false));
        assert_eq!(environment.get("SSL_CERT_FILE"), Some(&false));
        assert_eq!(environment.get("SAFE_VALUE"), Some(&true));
        if cfg!(windows) {
            assert!(!environment.iter().any(|(name, has_value)| {
                *has_value && is_dangerous_name_with_case(name, true)
            }));
        }
    }
}
