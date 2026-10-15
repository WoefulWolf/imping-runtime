//! The seam between [`Hook`](crate::Hook) and the hooking engine.
//!
//! Private for now. Making it public would let a mod loader supply one shared
//! engine, so that several mods can hook the same function.

/// An installed, initially disabled patch redirecting a function.
pub(crate) trait Patch<F>: Send + Sync {
    /// Redirects the target to the detour.
    fn enable(&self) -> Result<(), imping_hook::Error>;
    /// Restores the target.
    fn disable(&self) -> Result<(), imping_hook::Error>;
    /// Whether the target is redirected.
    fn is_enabled(&self) -> bool;
    /// Redirects the target without suspending other threads.
    ///
    /// # Safety
    ///
    /// No other thread may execute the patched instructions meanwhile.
    unsafe fn enable_unsuspended(&self) -> Result<(), imping_hook::Error>;
    /// Restores the target without suspending other threads.
    ///
    /// # Safety
    ///
    /// No other thread may execute the patched instructions meanwhile.
    unsafe fn disable_unsuspended(&self) -> Result<(), imping_hook::Error>;
}

impl<F: imping_hook::Function + Send + Sync> Patch<F> for imping_hook::Hook<F> {
    fn enable(&self) -> Result<(), imping_hook::Error> {
        imping_hook::Hook::enable(self)
    }

    fn disable(&self) -> Result<(), imping_hook::Error> {
        imping_hook::Hook::disable(self)
    }

    fn is_enabled(&self) -> bool {
        imping_hook::Hook::is_enabled(self)
    }

    unsafe fn enable_unsuspended(&self) -> Result<(), imping_hook::Error> {
        // SAFETY: forwarded from the caller.
        unsafe { imping_hook::Hook::enable_unsuspended(self) }
    }

    unsafe fn disable_unsuspended(&self) -> Result<(), imping_hook::Error> {
        // SAFETY: forwarded from the caller.
        unsafe { imping_hook::Hook::disable_unsuspended(self) }
    }
}

/// Installs a disabled patch redirecting `target` to `detour`, returning it
/// and a callable original (the trampoline).
///
/// The returned patch must never be dropped: the trampoline lives only as
/// long as it does, and a thread may call it at any time.
///
/// # Safety
///
/// `target` must be the address of a function with signature `F`, and
/// `detour` must have that signature too.
pub(crate) unsafe fn install<F: imping_hook::Function + Send + Sync>(
    target: *const (),
    detour: F,
) -> Result<(Box<dyn Patch<F>>, F), imping_hook::Error> {
    // SAFETY: Forwarded from the caller.
    let hook = unsafe { imping_hook::Hook::at(target).redirect(detour).install() }?;
    // SAFETY: The caller keeps the returned patch, and so the trampoline, for
    // the rest of the process.
    let original = unsafe { hook.trampoline() };
    Ok((Box::new(hook), original))
}
