use std::ptr::NonNull;
use std::sync::{Mutex, OnceLock, Weak};

use block2::RcBlock;
use objc2::rc::Retained;
use objc2_app_kit::{
    NSWorkspace, NSWorkspaceDidWakeNotification, NSWorkspaceScreensDidSleepNotification,
    NSWorkspaceScreensDidWakeNotification, NSWorkspaceSessionDidBecomeActiveNotification,
    NSWorkspaceSessionDidResignActiveNotification, NSWorkspaceWillPowerOffNotification,
    NSWorkspaceWillSleepNotification,
};
use objc2_foundation::{
    NSDistributedNotificationCenter, NSNotification, NSNotificationCenter, NSNotificationName,
    NSString,
};

use crate::secure_store::{OperationLease, OperationLeaseState};

static ACTIVE_LEASES: OnceLock<Mutex<Vec<Weak<OperationLeaseState>>>> = OnceLock::new();
static OBSERVERS_INSTALLED: OnceLock<()> = OnceLock::new();

pub(crate) fn register(lease: &OperationLease) {
    OBSERVERS_INSTALLED.get_or_init(install_observers);
    let mut leases = active_leases()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    leases.retain(|lease| lease.strong_count() > 0);
    leases.push(lease.weak_state());
}

fn active_leases() -> &'static Mutex<Vec<Weak<OperationLeaseState>>> {
    ACTIVE_LEASES.get_or_init(|| Mutex::new(Vec::new()))
}

fn revoke_all() {
    let mut leases = active_leases()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    leases.retain(|lease| {
        let Some(lease) = lease.upgrade() else {
            return false;
        };
        lease.revoke();
        true
    });
}

fn install_observers() {
    let workspace = NSWorkspace::sharedWorkspace();
    let center = workspace.notificationCenter();
    // SAFETY: these are immutable AppKit notification-name constants exported
    // for the lifetime of the process.
    let workspace_events = unsafe {
        [
            NSWorkspaceWillPowerOffNotification,
            NSWorkspaceWillSleepNotification,
            NSWorkspaceDidWakeNotification,
            NSWorkspaceScreensDidSleepNotification,
            NSWorkspaceScreensDidWakeNotification,
            NSWorkspaceSessionDidBecomeActiveNotification,
            NSWorkspaceSessionDidResignActiveNotification,
        ]
    };
    for name in workspace_events {
        install_observer(&center, name);
    }

    let distributed = NSDistributedNotificationCenter::defaultCenter();
    let locked = NSString::from_str("com.apple.screenIsLocked");
    let unlocked = NSString::from_str("com.apple.screenIsUnlocked");
    install_observer(&distributed, &locked);
    install_observer(&distributed, &unlocked);
}

fn install_observer(center: &NSNotificationCenter, name: &NSNotificationName) {
    let callback = RcBlock::new(|_: NonNull<NSNotification>| revoke_all());
    // SAFETY: the notification name and center are valid Foundation objects,
    // the object and queue filters are intentionally nil, and the block is
    // retained by the center. The observer token is deliberately retained for
    // the process lifetime so no callback can target a released token.
    let observer = unsafe {
        center.addObserverForName_object_queue_usingBlock(Some(name), None, None, &callback)
    };
    let _process_lifetime_observer = Retained::into_raw(observer);
}

#[cfg(test)]
mod tests {
    use super::{active_leases, revoke_all};
    use crate::secure_store::OperationLease;
    use std::time::Duration;

    #[test]
    fn lifecycle_event_revokes_registered_lease() {
        let lease = OperationLease::new(Duration::from_secs(1)).expect("lease");
        active_leases()
            .lock()
            .expect("leases")
            .push(lease.weak_state());
        revoke_all();
        assert!(lease.ensure_active().is_err());
    }
}
