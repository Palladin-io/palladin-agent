use objc2::rc::Retained;
use objc2_foundation::NSString;
use objc2_local_authentication::LAContext;
use security_framework::item::ItemSearchOptions;

/// A fresh LocalAuthentication context for exactly one Palladin operation.
///
/// The context is never cached or cloned outside this module. Keychain queries
/// within the same operation may retain it so that one explicit approval can
/// unlock the operation seed and the organization credential without a second
/// prompt.
pub(crate) struct FreshLocalAuthenticationContext {
    context: Retained<LAContext>,
}

impl FreshLocalAuthenticationContext {
    pub(crate) fn new(reason: &str) -> Self {
        let reason = NSString::from_str(reason);
        // SAFETY: `new` returns an owned (+1) LAContext. The setters copy the
        // NSString and only mutate this fresh context before any query uses it.
        let context = unsafe { LAContext::new() };
        unsafe {
            context.setLocalizedReason(&reason);
            context.setTouchIDAuthenticationAllowableReuseDuration(0.0);
            context.setInteractionNotAllowed(false);
        }
        Self { context }
    }

    #[allow(deprecated)]
    pub(crate) fn bind(&self, query: &mut ItemSearchOptions) {
        // SAFETY: cloning `Retained` creates a new +1 retain count. `into_raw`
        // transfers that ownership to ItemSearchOptions::authentication_context,
        // which wraps the pointer under the create rule and releases it when the
        // query is dropped. LAContext is toll-free usable as a CFType value for
        // kSecUseAuthenticationContext, as required by Security.framework.
        let retained = self.context.clone();
        let pointer = Retained::into_raw(retained).cast();
        unsafe {
            query.authentication_context(pointer);
        }
    }
}

impl Drop for FreshLocalAuthenticationContext {
    fn drop(&mut self) {
        // SAFETY: invalidating an owned LAContext is idempotent and prevents a
        // pending or accidentally retained authorization from outliving the
        // bounded Palladin operation.
        unsafe {
            self.context.invalidate();
        }
    }
}
