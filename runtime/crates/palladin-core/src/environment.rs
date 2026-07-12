use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::process::Command;

const EXACT_DANGEROUS_NAMES: &[&str] = &[
    "LD_AUDIT",
    "LD_DEBUG",
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "NODE_EXTRA_CA_CERTS",
    "NODE_OPTIONS",
    "NODE_PATH",
    "PALLADIN_API_KEY",
    "PALLADIN_PRIVATE_KEY",
    "PALLADIN_SIGNING_PRIVATE_KEY",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvironmentReport {
    dangerous_names: Vec<String>,
}

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
        let dangerous_names = names
            .into_iter()
            .filter_map(|name| {
                name.as_ref()
                    .to_str()
                    .filter(|name| is_dangerous_name(name))
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

#[must_use]
pub fn is_dangerous_name(name: &str) -> bool {
    name.starts_with("DYLD_") || EXACT_DANGEROUS_NAMES.binary_search(&name).is_ok()
}

pub fn sanitize_child(command: &mut Command) {
    for name in EXACT_DANGEROUS_NAMES {
        command.env_remove(name);
    }

    let dyld_names = std::env::vars_os()
        .map(|(name, _)| name)
        .filter(|name| name.to_str().is_some_and(|name| name.starts_with("DYLD_")))
        .collect::<Vec<OsString>>();

    for name in dyld_names {
        command.env_remove(name);
    }
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use super::{EnvironmentReport, is_dangerous_name, sanitize_child};

    #[test]
    fn classifies_loader_and_node_injection_names_without_values() {
        let report = EnvironmentReport::inspect_names([
            "PATH",
            "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES",
            "NODE_OPTIONS",
            "PALLADIN_API_KEY",
        ]);

        assert_eq!(
            report.dangerous_names(),
            [
                "DYLD_INSERT_LIBRARIES",
                "LD_PRELOAD",
                "NODE_OPTIONS",
                "PALLADIN_API_KEY"
            ]
        );
        assert!(!report.is_safe());
    }

    #[test]
    fn matching_is_exact_except_for_dyld_namespace() {
        assert!(is_dangerous_name("LD_PRELOAD"));
        assert!(!is_dangerous_name("LD_PRELOAD_BACKUP"));
        assert!(is_dangerous_name("DYLD_FUTURE_INJECTION_FLAG"));
        assert!(!is_dangerous_name("SAFE_DYLD_VALUE"));
    }

    #[test]
    fn strips_known_dangerous_variables_from_children() {
        let mut command = Command::new("ignored-program");
        command.env("LD_PRELOAD", "synthetic-not-a-library");
        command.env("NODE_OPTIONS", "--synthetic");
        command.env("PALLADIN_API_KEY", "synthetic-not-a-secret");
        command.env("SAFE_VALUE", "preserved");

        sanitize_child(&mut command);
        let environment = command
            .get_envs()
            .map(|(name, value)| (name.to_string_lossy().into_owned(), value.is_some()))
            .collect::<std::collections::BTreeMap<_, _>>();

        assert_eq!(environment.get("LD_PRELOAD"), Some(&false));
        assert_eq!(environment.get("NODE_OPTIONS"), Some(&false));
        assert_eq!(environment.get("PALLADIN_API_KEY"), Some(&false));
        assert_eq!(environment.get("SAFE_VALUE"), Some(&true));
    }
}
