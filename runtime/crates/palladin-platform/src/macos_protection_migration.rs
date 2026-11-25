//! In-place upgrade of Keychain items whose class is unavailable on a locked screen.
//!
//! Releases up to 0.0.14 wrote `WhenUnlockedThisDeviceOnly` items, and overwriting an
//! item changes only its data. One `SecItemUpdate` per item replaces only the access
//! control, so an interruption leaves each item wholly old or wholly new and no secret
//! is read, deleted or re-created. Items that require user presence never match.

use std::sync::OnceLock;

use core_foundation::array::{CFArray, CFArrayRef};
use core_foundation::base::{CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::{CFString, CFStringRef};
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::base::Error;
use security_framework_sys::access_control::kSecAttrAccessibleWhenUnlockedThisDeviceOnly as LEGACY_CLASS;
use security_framework_sys::base::errSecItemNotFound;
use security_framework_sys::item::{
    kSecAttrAccessControl, kSecAttrAccessGroup, kSecAttrAccount, kSecAttrService,
    kSecAttrSynchronizable, kSecClass, kSecClassGenericPassword, kSecMatchLimit, kSecMatchLimitAll,
    kSecReturnAttributes, kSecUseDataProtectionKeychain,
};
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

struct StoredItem {
    service: &'static str,
    account: String,
    protection: Option<SecAccessControl>,
}

/// Runs once per process over every stored item. The caller must have just read an
/// item successfully, which proves that this session can currently decrypt old items.
pub(crate) fn run_once(access_group: &str, services: &[&'static str]) {
    COMPLETED.get_or_init(|| {
        let mut report = MigrationReport::default();
        for service in services {
            match list(access_group, service) {
                Ok(items) => {
                    let outcome = upgrade_all(
                        items,
                        |item| Ok(item.protection.clone()),
                        |item| upgrade(access_group, item),
                    );
                    report.upgraded += outcome.upgraded;
                    report.failed += outcome.failed;
                }
                Err(_) => report.failed += 1,
            }
        }
        report
    });
}

/// `(upgraded, failed)` items in this process, or `None` if nothing was readable.
pub(crate) fn summary() -> Option<(usize, usize)> {
    COMPLETED
        .get()
        .map(|report| (report.upgraded, report.failed))
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

fn scope(access_group: &str, service: &str, account: Option<&str>) -> Vec<(CFString, CFType)> {
    // SAFETY: immutable Security.framework constants.
    unsafe {
        let mut pairs = vec![
            (
                CFString::wrap_under_get_rule(kSecClass),
                CFString::wrap_under_get_rule(kSecClassGenericPassword).into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecUseDataProtectionKeychain),
                CFBoolean::true_value().into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrAccessGroup),
                CFString::new(access_group).into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrSynchronizable),
                CFBoolean::false_value().into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrService),
                CFString::new(service).into_CFType(),
            ),
        ];
        if let Some(account) = account {
            pairs.push((
                CFString::wrap_under_get_rule(kSecAttrAccount),
                CFString::new(account).into_CFType(),
            ));
        }
        pairs
    }
}

/// Attributes only: no secret data is requested, so presence items cannot prompt.
fn list(access_group: &str, service: &'static str) -> Result<Vec<StoredItem>, Error> {
    let mut pairs = scope(access_group, service, None);
    // SAFETY: immutable Security.framework constants.
    unsafe {
        pairs.push((
            CFString::wrap_under_get_rule(kSecReturnAttributes),
            CFBoolean::true_value().into_CFType(),
        ));
        pairs.push((
            CFString::wrap_under_get_rule(kSecMatchLimit),
            CFString::wrap_under_get_rule(kSecMatchLimitAll).into_CFType(),
        ));
    }
    let query = CFDictionary::from_CFType_pairs(&pairs);
    let mut raw = std::ptr::null();
    // SAFETY: `query` outlives the call; success returns one owned CFArray of
    // attribute dictionaries because of kSecMatchLimitAll.
    let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut raw) };
    if status == errSecItemNotFound {
        return Ok(Vec::new());
    }
    if status != 0 || raw.is_null() {
        return Err(Error::from_code(status));
    }
    let found: CFArray<CFDictionary<CFString, CFType>> =
        unsafe { CFArray::wrap_under_create_rule(raw as CFArrayRef) };
    found
        .iter()
        .map(|attributes| {
            let account = unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) };
            Ok(StoredItem {
                service,
                account: attributes
                    .find(&account)
                    .and_then(|value| value.downcast::<CFString>())
                    .ok_or_else(|| Error::from_code(errSecItemNotFound))?
                    .to_string(),
                protection: protection(&attributes)?,
            })
        })
        .collect()
}

fn protection(
    attributes: &CFDictionary<CFString, CFType>,
) -> Result<Option<SecAccessControl>, Error> {
    let key = unsafe { CFString::wrap_under_get_rule(kSecAttrAccessControl) };
    if let Some(value) = attributes.find(&key) {
        return Ok(value.downcast::<SecAccessControl>());
    }
    // An item without constraints may report only its accessibility class.
    let key = unsafe { CFString::wrap_under_get_rule(kSecAttrAccessible) };
    let legacy = unsafe { CFString::wrap_under_get_rule(LEGACY_CLASS) };
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

fn upgrade(access_group: &str, item: &StoredItem) -> Result<(), Error> {
    let query =
        CFDictionary::from_CFType_pairs(&scope(access_group, item.service, Some(&item.account)));
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
