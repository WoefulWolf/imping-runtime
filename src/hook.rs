//! Function hooks for generated bindings, and their guard.
//!
//! Each hookable function has a static [`Slot`] and a generated `thunk` that
//! calls the slot's closure. The first [`install`] creates the patch, which is
//! kept for the rest of the process so its trampoline is never freed; guards
//! only enable and disable it. Replaced closures are leaked, as a thread may
//! still be running one.

use crate::backend::{self, Patch};
use crate::error::{Error, Result};
use crate::module::Module;
use core::fmt;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::OnceLock;

/// A hook on a function, returned disabled by a generated function's `hook`.
///
/// `F` is the function's generated `Signature` type. While the guard is alive,
/// this mod can't hook the function again.
///
/// # Dropping
///
/// Dropping the guard disables the hook as [`disable`](Self::disable) does,
/// and the function can then be hooked again. If disabling fails, the hook
/// stays in place and the function stays reserved. A thread still running the
/// closure is unaffected, as nothing it uses is freed.
///
/// # Threads and batches
///
/// [`enable`](Self::enable) and [`disable`](Self::disable) suspend every other
/// thread of the process while patching, so don't call them from inside the
/// hooked function. Inside an [`imping_hook::batch`] they are queued and
/// applied together when the batch ends. The `_unsuspended` variants skip the
/// suspension and take effect at once, even inside a batch.
pub struct Hook<F: 'static> {
    installed: &'static Installed<F>,
    owned: &'static AtomicBool,
}

impl<F: Copy + 'static> Hook<F> {
    /// Redirects the function to the hook's closure.
    ///
    /// Suspends other threads while patching; see [`Hook`] for threads and batches.
    ///
    /// # Errors
    ///
    /// [`Error::Hook`] if patching fails.
    pub fn enable(&self) -> Result<()> {
        self.installed
            .patch
            .enable()
            .map_err(|source| self.installed.error(source))?;
        log::debug!("imping: enabled hook at {}", self.installed.location());
        Ok(())
    }

    /// Restores the function, so calls skip the closure.
    ///
    /// Suspends other threads while patching; see [`Hook`] for threads and batches.
    ///
    /// # Errors
    ///
    /// [`Error::Hook`] if patching fails.
    pub fn disable(&self) -> Result<()> {
        self.installed
            .patch
            .disable()
            .map_err(|source| self.installed.error(source))?;
        log::debug!("imping: disabled hook at {}", self.installed.location());
        Ok(())
    }

    /// Redirects the function to the hook's closure without suspending other
    /// threads.
    ///
    /// Faster than [`enable`](Self::enable); see [`Hook`] for threads and
    /// batches.
    ///
    /// # Errors
    ///
    /// [`Error::Hook`] if patching fails.
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

    /// Restores the function without suspending other threads.
    ///
    /// Faster than [`disable`](Self::disable); see [`Hook`] for threads and
    /// batches.
    ///
    /// # Errors
    ///
    /// [`Error::Hook`] if patching fails.
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

    /// Returns whether the function is redirected to the closure.
    pub fn is_enabled(&self) -> bool {
        self.installed.patch.is_enabled()
    }

    /// Returns the original, unhooked function.
    ///
    /// It stays valid for the rest of the process, even after the guard is
    /// dropped.
    pub fn original(&self) -> F {
        self.installed.original
    }

    /// Keeps the hook, in its current state, for the rest of the process.
    ///
    /// The function stays reserved, and the mod must never be unloaded.
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
    /// The current closure as a leaked, never freed `Box<D>`; null before the
    /// first install.
    detour: AtomicPtr<Box<D>>,
    /// Whether a live guard owns the slot.
    owned: AtomicBool,
    /// Makes the slot `Send`/`Sync` only if the closure is.
    _closure: PhantomData<Box<D>>,
}

impl<D: ?Sized + 'static, F: 'static> Slot<D, F> {
    /// Creates an empty slot.
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
    /// Returns the current closure and the original function, for the thunk.
    ///
    /// # Panics
    ///
    /// If nothing was installed yet, which is a bug in the generated code. The
    /// panic aborts the process, since the thunk is an `extern` function.
    pub fn get(&self) -> (&D, F) {
        let detour = self.detour.load(Ordering::Acquire);
        match self.installed.get() {
            Some(installed) if !detour.is_null() => {
                // SAFETY: a non-null `detour` is a `Box<D>` leaked by `install`
                // and never freed.
                (unsafe { &**detour }, installed.original)
            }
            _ => panic!("imping: hook slot used before anything was installed; this is a bug"),
        }
    }
}

/// Hooks the function at `rva` in `module` with `detour`, returning the guard
/// disabled.
///
/// Called by a generated function's `hook`. The first install for a function
/// compares its first bytes with `verification`, when non-empty, before
/// patching.
///
/// # Errors
///
/// - [`Error::NotInitialized`] if `module` isn't initialized.
/// - [`Error::AlreadyHooked`] if a guard for this function is alive.
/// - [`Error::VerificationFailed`] if the first bytes differ from
///   `verification`.
/// - [`Error::Hook`] if patching fails.
///
/// # Safety
///
/// - The function at `rva` and `thunk` must both have signature `F`.
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
            // SAFETY: forwarded from the caller.
            match unsafe { install_patch(module, base, rva, verification, thunk) } {
                Ok(installed) => slot.installed.get_or_init(|| installed),
                Err(error) => {
                    slot.owned.store(false, Ordering::Release);
                    return Err(error);
                }
            }
        }
    };

    // The previous closure is leaked: a thread may still be running it.
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
/// The function at `base + rva` in `module` and `thunk` must both have
/// signature `F`.
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
        // SAFETY: the caller promises `target` is a function in a loaded
        // module, so its first bytes are mapped readable.
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
    // SAFETY: the caller promises the function and `thunk` share signature `F`.
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
