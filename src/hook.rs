//! Hooks on functions with a generated closure slot, and their guard.
//!
//! Each hooked function has a static [`Slot`] in the generated code, plus a
//! generated `thunk` with the function's signature that calls the slot's
//! closure. The first [`install`] patches the function to jump to the thunk;
//! that patch is kept for the rest of the process, so its trampoline (the
//! callable original) is never freed. A [`Hook`] guard owns the slot while it
//! is alive: dropping it disables the patch, and the next `install` reuses it
//! with a new closure. Replaced closures are leaked, never freed, because a
//! thread may still be running one.

use crate::backend::{self, Patch};
use crate::error::{Error, Result};
use crate::module::Module;
use core::fmt;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::OnceLock;

/// A hook on a function, returned disabled by a generated function's `hook`.
///
/// While the guard is alive, the function can't be hooked again by this mod.
/// Dropping it disables the hook (if that fails, the hook stays in place and
/// the function stays reserved); the function can then be hooked again. A
/// thread still running the closure when the guard is dropped is unaffected:
/// nothing it uses is freed.
///
/// `F` is the function's signature, its generated `Signature` type.
pub struct Hook<F: 'static> {
    installed: &'static Installed<F>,
    owned: &'static AtomicBool,
}

impl<F: Copy + 'static> Hook<F> {
    /// Redirects the function to the hook's closure.
    ///
    /// Every other thread of the process is suspended while the function is
    /// patched. Don't call this from within the hooked function itself. Inside
    /// an `imping_hook::batch` the change is queued and applied when the batch
    /// ends, together with the batch's other changes.
    ///
    /// # Errors
    ///
    /// [`Error::Hook`] if the hooking engine fails.
    pub fn enable(&self) -> Result<()> {
        self.installed
            .patch
            .enable()
            .map_err(|source| self.installed.error(source))?;
        log::debug!("imping: enabled hook at {}", self.installed.location());
        Ok(())
    }

    /// Restores the function, so calls no longer reach the closure.
    ///
    /// Every other thread of the process is suspended while the function is
    /// patched. Don't call this from within the hooked function itself. Inside
    /// an `imping_hook::batch` the change is queued and applied when the batch
    /// ends.
    ///
    /// # Errors
    ///
    /// [`Error::Hook`] if the hooking engine fails.
    pub fn disable(&self) -> Result<()> {
        self.installed
            .patch
            .disable()
            .map_err(|source| self.installed.error(source))?;
        log::debug!("imping: disabled hook at {}", self.installed.location());
        Ok(())
    }

    /// Redirects the function to the hook's closure without suspending other
    /// threads: faster than [`enable`](Self::enable), which has to find and
    /// suspend them all. Takes effect at once, also inside a batch.
    ///
    /// # Errors
    ///
    /// [`Error::Hook`] if the hooking engine fails.
    ///
    /// # Safety
    ///
    /// No other thread may execute the function's first instructions while
    /// they are patched, or it may run a half-written instruction.
    pub unsafe fn enable_unsuspended(&self) -> Result<()> {
        // SAFETY: forwarded from the caller.
        unsafe { self.installed.patch.enable_unsuspended() }
            .map_err(|source| self.installed.error(source))?;
        log::debug!("imping: enabled hook at {}", self.installed.location());
        Ok(())
    }

    /// Restores the function without suspending other threads; see
    /// [`enable_unsuspended`](Self::enable_unsuspended).
    ///
    /// # Errors
    ///
    /// [`Error::Hook`] if the hooking engine fails.
    ///
    /// # Safety
    ///
    /// No other thread may execute the function's first instructions while
    /// the original ones are written back.
    pub unsafe fn disable_unsuspended(&self) -> Result<()> {
        // SAFETY: forwarded from the caller.
        unsafe { self.installed.patch.disable_unsuspended() }
            .map_err(|source| self.installed.error(source))?;
        log::debug!("imping: disabled hook at {}", self.installed.location());
        Ok(())
    }

    /// Whether the function is currently redirected to the closure.
    pub fn is_enabled(&self) -> bool {
        self.installed.patch.is_enabled()
    }

    /// The original, un-hooked function. It stays valid for the rest of the
    /// process, even after the guard is dropped.
    pub fn original(&self) -> F {
        self.installed.original
    }

    /// Keeps the hook, in its current state, for the rest of the process.
    ///
    /// The function stays reserved, and the mod must then never be unloaded.
    pub fn leak(self) {
        core::mem::forget(self);
    }
}

impl<F: 'static> Drop for Hook<F> {
    fn drop(&mut self) {
        if self.installed.patch.disable().is_ok() {
            log::debug!("imping: dropped hook at {}", self.installed.location());
            self.owned.store(false, Ordering::Release);
        }
    }
}

impl<F: 'static> fmt::Debug for Hook<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hook")
            .field("module", &self.installed.module.name())
            .field("rva", &format_args!("{:#x}", self.installed.rva))
            .field("enabled", &self.installed.patch.is_enabled())
            .finish()
    }
}

/// A function's patch, installed once and kept for the rest of the process.
struct Installed<F: 'static> {
    module: &'static Module,
    rva: u32,
    patch: Box<dyn Patch<F>>,
    original: F,
}

impl<F> Installed<F> {
    fn error(&self, source: imping_hook::Error) -> Error {
        Error::Hook {
            module: self.module.name(),
            rva: self.rva,
            source,
        }
    }

    fn location(&self) -> String {
        format!("`{}`+{:#x}", self.module.name(), self.rva)
    }
}

/// The per-function state behind a generated hook: the patch, the current
/// closure, and whether a [`Hook`] guard owns it.
///
/// Generated code declares one `static` per hookable function, with `D` the
/// closure's `dyn Fn` type and `F` the function's signature.
pub struct Slot<D: ?Sized + 'static, F: 'static> {
    installed: OnceLock<Installed<F>>,
    /// The current closure: a leaked `Box<D>`, or null before the first
    /// install. Never freed.
    detour: AtomicPtr<Box<D>>,
    /// Whether a live guard owns the slot.
    owned: AtomicBool,
    /// Makes the slot `Send`/`Sync` only if the closure is.
    _closure: PhantomData<Box<D>>,
}

impl<D: ?Sized + 'static, F: 'static> Slot<D, F> {
    /// An empty slot.
    pub const fn new() -> Self {
        Self {
            installed: OnceLock::new(),
            detour: AtomicPtr::new(core::ptr::null_mut()),
            owned: AtomicBool::new(false),
            _closure: PhantomData,
        }
    }
}

impl<D: ?Sized + 'static, F: 'static> Default for Slot<D, F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<D: ?Sized + Send + Sync + 'static, F: Copy + 'static> Slot<D, F> {
    /// The current closure and the original function, for the thunk.
    ///
    /// # Panics
    ///
    /// If nothing was installed yet. The thunk is only reachable after an
    /// install, so this is a bug in the generated code; since the thunk is an
    /// `extern` function, the panic aborts the process.
    pub fn get(&self) -> (&D, F) {
        let detour = self.detour.load(Ordering::Acquire);
        match self.installed.get() {
            Some(installed) if !detour.is_null() => {
                // SAFETY: A non-null `detour` points to a `Box<D>` leaked by
                // `install`, which is never freed.
                (unsafe { &**detour }, installed.original)
            }
            _ => panic!("imping: hook slot used before anything was installed; this is a bug"),
        }
    }
}

/// Hooks the function at `rva` in `module` with `detour`, through `slot` and
/// `thunk`. Called by a generated function's `hook`; returns the guard,
/// disabled.
///
/// On the first install for a function, its first bytes are compared with
/// `verification` (when non-empty) before it is patched.
///
/// # Errors
///
/// [`Error::NotInitialized`], [`Error::AlreadyHooked`],
/// [`Error::VerificationFailed`] or [`Error::Hook`].
///
/// # Safety
///
/// - The function at `rva` must have signature `F`, and `thunk` must have it
///   too.
/// - `thunk` must call the closure and original returned by `slot.get()`, and
///   `slot` must only ever be used with this function.
pub unsafe fn install<D, F>(
    module: &'static Module,
    rva: u32,
    verification: &'static [u8],
    slot: &'static Slot<D, F>,
    detour: Box<D>,
    thunk: F,
) -> Result<Hook<F>>
where
    D: ?Sized + Send + Sync + 'static,
    F: imping_hook::Function + Copy + Send + Sync + 'static,
{
    let Some(base) = module.base() else {
        return Err(Error::NotInitialized {
            module: module.name(),
        });
    };
    if slot.owned.swap(true, Ordering::AcqRel) {
        return Err(Error::AlreadyHooked {
            module: module.name(),
            rva,
        });
    }
    // Only the owner gets here, so the first install is never contended.
    let installed = match slot.installed.get() {
        Some(installed) => installed,
        None => {
            // SAFETY: Forwarded from the caller.
            match unsafe { install_patch(module, base, rva, verification, thunk) } {
                Ok(installed) => slot.installed.get_or_init(|| installed),
                Err(error) => {
                    slot.owned.store(false, Ordering::Release);
                    return Err(error);
                }
            }
        }
    };

    // Publish the new closure. The previous one, if any, is leaked: a thread
    // may still be running it.
    let detour = Box::into_raw(Box::new(detour));
    slot.detour.swap(detour, Ordering::AcqRel);

    Ok(Hook {
        installed,
        owned: &slot.owned,
    })
}

/// Verifies the function's first bytes and patches it, disabled.
///
/// # Safety
///
/// As for [`install`].
unsafe fn install_patch<F>(
    module: &'static Module,
    base: usize,
    rva: u32,
    verification: &'static [u8],
    thunk: F,
) -> Result<Installed<F>>
where
    F: imping_hook::Function + Copy + Send + Sync + 'static,
{
    let target = base + rva as usize;
    if !verification.is_empty() {
        // SAFETY: `target` is a function in a loaded module (the caller's
        // promise), so at least its first bytes are mapped readable.
        let found = unsafe { core::slice::from_raw_parts(target as *const u8, verification.len()) };
        if found != verification {
            return Err(Error::VerificationFailed {
                module: module.name(),
                rva,
                expected: verification,
                found: found.to_vec(),
            });
        }
    }
    // SAFETY: Forwarded from the caller: the function and `thunk` share the
    // signature `F`.
    let (patch, original) =
        unsafe { backend::install(target as *const (), thunk) }.map_err(|source| Error::Hook {
            module: module.name(),
            rva,
            source,
        })?;
    log::debug!("imping: hooked `{}`+{rva:#x}", module.name());
    Ok(Installed {
        module,
        rva,
        patch,
        original,
    })
}
