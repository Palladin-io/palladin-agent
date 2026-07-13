use palladin_api::{CredentialAccess, CredentialMethod};
use palladin_core::terminal::shorten_identifier;

pub const EX_OK: u8 = 0;
pub const EX_GENERIC: u8 = 1;
pub const EX_TEMPFAIL: u8 = 75;
pub const EX_NOPERM: u8 = 77;

#[must_use]
pub const fn exit_code_for_access(access: &CredentialAccess) -> u8 {
    match access {
        CredentialAccess::Granted { .. } => EX_OK,
        CredentialAccess::Pending { .. } | CredentialAccess::Unavailable => EX_TEMPFAIL,
        CredentialAccess::Denied
        | CredentialAccess::Revoked
        | CredentialAccess::Expired
        | CredentialAccess::Consumed
        | CredentialAccess::MethodNotAllowed
        | CredentialAccess::ScriptExecOnly
        | CredentialAccess::Blocked => EX_NOPERM,
    }
}

#[must_use]
pub fn access_message(access: &CredentialAccess, method: CredentialMethod) -> Option<String> {
    match access {
        CredentialAccess::Granted { .. } => None,
        CredentialAccess::Pending { grant_id, .. } => Some(format!(
            "Access requested (grant {}) - awaiting user approval. Try again shortly.",
            shorten_identifier(grant_id)
        )),
        CredentialAccess::Denied => Some("Access was denied by the vault owner.".to_owned()),
        CredentialAccess::Revoked => {
            Some("Access to this credential was revoked.".to_owned())
        }
        CredentialAccess::Expired => {
            Some("The grant for this credential has expired.".to_owned())
        }
        CredentialAccess::Consumed => {
            Some("The grant has no remaining uses (consumed).".to_owned())
        }
        CredentialAccess::Unavailable => Some(
            "A grant covers this entry but no credential material is available yet - request access."
                .to_owned(),
        ),
        CredentialAccess::Blocked => Some("This Agent is deactivated.".to_owned()),
        CredentialAccess::MethodNotAllowed => Some(method_not_allowed_message(method)),
        CredentialAccess::ScriptExecOnly => Some(
            "Script entries can only be executed - run palladin exec without a command to execute the stored script."
                .to_owned(),
        ),
    }
}

fn method_not_allowed_message(method: CredentialMethod) -> String {
    let requested = method_name(method);
    let alternatives = [
        CredentialMethod::Exec,
        CredentialMethod::Inject,
        CredentialMethod::Get,
    ]
    .into_iter()
    .filter(|candidate| *candidate != method)
    .map(method_name)
    .map(|name| format!("palladin {name}"))
    .collect::<Vec<_>>()
    .join(" or ");
    format!(
        "This grant does not permit {requested}. The owner restricted how this credential may be used - try {alternatives}, or ask them to allow {requested}."
    )
}

const fn method_name(method: CredentialMethod) -> &'static str {
    match method {
        CredentialMethod::Get => "get",
        CredentialMethod::Exec => "exec",
        CredentialMethod::Inject => "inject",
    }
}

#[cfg(test)]
mod tests {
    use palladin_api::{CredentialAccess, CredentialMethod};

    use super::{EX_NOPERM, EX_TEMPFAIL, access_message, exit_code_for_access};

    #[test]
    fn every_access_state_has_the_expected_retry_class() {
        for access in [
            CredentialAccess::Pending {
                grant_id: "grant-1".to_owned(),
                created: None,
                poll_interval_ms: None,
                max_wait_ms: None,
            },
            CredentialAccess::Unavailable,
        ] {
            assert_eq!(exit_code_for_access(&access), EX_TEMPFAIL);
        }
        for access in [
            CredentialAccess::Denied,
            CredentialAccess::Revoked,
            CredentialAccess::Expired,
            CredentialAccess::Consumed,
            CredentialAccess::MethodNotAllowed,
            CredentialAccess::ScriptExecOnly,
            CredentialAccess::Blocked,
        ] {
            assert_eq!(exit_code_for_access(&access), EX_NOPERM);
            assert!(access_message(&access, CredentialMethod::Get).is_some());
        }
    }

    #[test]
    fn pending_message_shortens_long_public_grant_ids() {
        let message = access_message(
            &CredentialAccess::Pending {
                grant_id: "1234567890abcdefghijklmnopqrstuvwxyz".to_owned(),
                created: None,
                poll_interval_ms: None,
                max_wait_ms: None,
            },
            CredentialMethod::Get,
        )
        .expect("message");
        assert!(message.contains("12345678…uvwxyz"));
        assert!(!message.contains("1234567890abcdefghijklmnopqrstuvwxyz"));
    }
}
