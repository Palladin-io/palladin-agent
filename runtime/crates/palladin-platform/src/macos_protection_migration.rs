//! In-place upgrade of Keychain items whose class is unavailable on a locked screen.
//!
//! Releases up to 0.0.14 wrote `WhenUnlockedThisDeviceOnly` items, and overwriting an
//! item changes only its data. One `SecItemUpdate` per item replaces only the access
//! control, so an interruption leaves each item wholly old or wholly new and no secret
//! is read, deleted or re-created. Items that require user presence never match.

use std::sync::OnceLock;

use core_foundation::base::{CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
use core_foundation::string::{CFString, CFStringRef};
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::base::Error;
use security_framework::passwords::PasswordOptions;
use security_framework_sys::base::errSecItemNotFound;
use security_framework_sys::item::{kSecAttrAccessControl, kSecReturnAttributes};
use security_framework_sys::keychain_item::{SecItemCopyMatching, SecItemUpdate};

// Not exposed by security-framework-sys.
#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecAttrAccessible: CFStringRef;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct MigrationReport {
    pub upgraded: usize,
    pub failed: usize,
}

static COMPLETED: OnceLock<MigrationReport> = OnceLock::new();

/// Runs once per process. The caller must have just read an item successfully,
/// which proves that this login session can currently decrypt old items.
pub(crate) fn run_once(queries: impl FnOnce() -> Vec<PasswordOptions>) {
    COMPLETED.get_or_init(|| upgrade_all(queries(), access_control, upgrade));
}

/// `(upgraded, failed)` shared items in this process, or `None` if nothing was readable.
pub(crate) fn summary() -> Option<(usize, usize)> {
    COMPLETED
        .get()
        .map(|report| (report.upgraded, report.failed))
}

/// Upgrades one identity item that was just read successfully.
pub(crate) fn upgrade_item(query: PasswordOptions) {
    upgrade_all(vec![query], access_control, upgrade);
}

fn upgrade_all<Q>(
    items: Vec<Q>,
    read: impl Fn(&Q) -> Result<Option<SecAccessControl>, Error>,
    write: impl Fn(&Q) -> Result<(), Error>,
) -> MigrationReport {
    let mut report = MigrationReport::default();
    for item in items {
        match read(&item) {
            Ok(Some(current)) if is_legacy(&current) => match write(&item) {
                Ok(()) => report.upgraded += 1,
                Err(_) => report.failed += 1,
            },
            Ok(_) => {}
            Err(_) => report.failed += 1,
        }
    }
    report
}

pub(crate) fn current_protection() -> Result<SecAccessControl, Error> {
    SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleAfterFirstUnlockThisDeviceOnly),
        0,
    )
}

fn is_legacy(current: &SecAccessControl) -> bool {
    SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
        0,
    )
    .is_ok_and(|legacy| legacy.as_CFType() == current.as_CFType())
}

#[allow(deprecated)]
fn access_control(options: &PasswordOptions) -> Result<Option<SecAccessControl>, Error> {
    let mut pairs = options.query.clone();
    // SAFETY: immutable Security.framework constants.
    pairs.push(unsafe {
        (
            CFString::wrap_under_get_rule(kSecReturnAttributes),
            CFBoolean::true_value().into_CFType(),
        )
    });
    let query = CFDictionary::from_CFType_pairs(&pairs);
    let mut raw = std::ptr::null();
    // SAFETY: `query` outlives the call; a successful attributes-only query
    // returns one owned CFDictionary.
    let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut raw) };
    if status == errSecItemNotFound {
        return Ok(None);
    }
    if status != 0 || raw.is_null() {
        return Err(Error::from_code(status));
    }
    let attributes: CFDictionary<CFString, CFType> =
        unsafe { CFDictionary::wrap_under_create_rule(raw as CFDictionaryRef) };
    let key = unsafe { CFString::wrap_under_get_rule(kSecAttrAccessControl) };
    if let Some(value) = attributes.find(&key) {
        return Ok(value.downcast::<SecAccessControl>());
    }
    // An item without constraints may report only its accessibility class.
    let key = unsafe { CFString::wrap_under_get_rule(kSecAttrAccessible) };
    let legacy = unsafe {
        CFString::wrap_under_get_rule(
            security_framework_sys::access_control::kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        )
    };
    match attributes
        .find(&key)
        .and_then(|value| value.downcast::<CFString>())
    {
        Some(class) if class == legacy => SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            0,
        )
        .map(Some),
        _ => Ok(None),
    }
}

#[allow(deprecated)]
fn upgrade(options: &PasswordOptions) -> Result<(), Error> {
    let query = CFDictionary::from_CFType_pairs(&options.query);
    let key = unsafe { CFString::wrap_under_get_rule(kSecAttrAccessControl) };
    let update = CFDictionary::from_CFType_pairs(&[(key, current_protection()?.into_CFType())]);
    // SAFETY: both dictionaries outlive the call.
    match unsafe { SecItemUpdate(query.as_concrete_TypeRef(), update.as_concrete_TypeRef()) } {
        0 => Ok(()),
        status => Err(Error::from_code(status)),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;
    use security_framework::passwords::AccessControlOptions;

    fn protection(mode: ProtectionMode, flags: usize) -> SecAccessControl {
        SecAccessControl::create_with_protection(Some(mode), flags).expect("access control")
    }

    fn legacy() -> SecAccessControl {
        protection(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly, 0)
    }

    #[test]
    fn only_the_exact_promptless_legacy_class_is_upgraded() {
        assert!(is_legacy(&legacy()));
        assert!(!is_legacy(&current_protection().expect("current")));
        assert!(!is_legacy(&protection(
            ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly,
            AccessControlOptions::USER_PRESENCE.bits(),
        )));
        assert!(!is_legacy(&protection(
            ProtectionMode::AccessibleWhenUnlocked,
            0
        )));
    }

    #[test]
    fn interrupted_upgrade_resumes_and_repeating_is_a_no_op() {
        let store = RefCell::new(vec![legacy(), legacy(), current_protection().expect("new")]);
        let read = |index: &usize| Ok(Some(store.borrow()[*index].clone()));
        let write = |index: &usize| {
            store.borrow_mut()[*index] = current_protection()?;
            Ok(())
        };
        let first = upgrade_all(vec![0, 1, 2], read, |index| {
            if *index == 1 {
                return Err(Error::from_code(-25308));
            }
            write(index)
        });
        assert_eq!(
            first,
            MigrationReport {
                upgraded: 1,
                failed: 1
            }
        );
        assert!(is_legacy(&store.borrow()[1]));
        let second = upgrade_all(vec![0, 1, 2], read, write);
        assert_eq!(
            second,
            MigrationReport {
                upgraded: 1,
                failed: 0
            }
        );
        let third = upgrade_all(vec![0, 1, 2], read, |_| panic!("nothing left to write"));
        assert_eq!(third, MigrationReport::default());
    }

    #[test]
    fn presence_items_and_missing_items_are_never_written() {
        let presence = protection(
            ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly,
            AccessControlOptions::USER_PRESENCE.bits(),
        );
        let report = upgrade_all(
            vec![Some(presence), None],
            |item| Ok(item.clone()),
            |_| panic!("must not write"),
        );
        assert_eq!(report, MigrationReport::default());
    }
}
