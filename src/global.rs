//! Typed global variables.

use crate::module::Module;
use crate::plain::Plain;
use core::fmt;
use core::marker::PhantomData;

/// A global variable of type `T` at an address in a [`Module`].
///
/// Generated bindings declare one per IR global; it holds only the address.
/// When `T` is [`Plain`], [`read`](Self::read) and [`write`](Self::write)
/// access it safely; otherwise use [`ptr`](Self::ptr).
///
/// # Data races
///
/// Each read or write is a single volatile access that doesn't synchronise
/// with the target. If the target uses the global on another thread at the
/// same time, a value larger than a machine word can be seen half-updated.
///
/// # Examples
///
/// ```no_run
/// use imping_runtime::{Build, Global, Module};
///
/// static TARGET: Module = Module::new(
///     "target.exe",
///     &[Build { timestamp: 0x64b8f2a1, image_size: 0xa2b000 }],
/// );
/// static GRAVITY: Global<f32> = Global::new(&TARGET, 0x3a1200);
///
/// # fn main() -> imping_runtime::Result<()> {
/// // SAFETY: this build of `target.exe` keeps an `f32` at RVA 0x3a1200.
/// unsafe { TARGET.init() }?;
/// let gravity = GRAVITY.read();
/// GRAVITY.write(gravity / 2.0);
/// # Ok(())
/// # }
/// ```
pub struct Global<T> {
    module: &'static Module,
    rva: u32,
    _type: PhantomData<fn() -> T>,
}

impl<T> Global<T> {
    /// Describes the global at `rva`, an address relative to `module`'s base.
    pub const fn new(module: &'static Module, rva: u32) -> Self {
        Self {
            module,
            rva,
            _type: PhantomData,
        }
    }

    /// Returns a pointer to the global in this process.
    ///
    /// # Panics
    ///
    /// If the module's [`init`](Module::init) has not succeeded.
    pub fn ptr(&self) -> *mut T {
        self.module.address(self.rva) as *mut T
    }

    /// Returns the global's address relative to its module's base.
    pub const fn rva(&self) -> u32 {
        self.rva
    }

    /// Returns the module the global is in.
    pub const fn module(&self) -> &'static Module {
        self.module
    }
}

impl<T: Plain> Global<T> {
    /// Reads the global.
    ///
    /// Doesn't synchronise with the target; see [`Global`] for data races.
    ///
    /// # Panics
    ///
    /// If the module's [`init`](Module::init) has not succeeded.
    pub fn read(&self) -> T {
        let ptr = self.ptr();
        // SAFETY: `ptr` returned, so `init`'s caller promised a `T` lives here
        // in the mapped image, and every bit pattern is a valid `T`.
        unsafe {
            if ptr.is_aligned() {
                ptr.read_volatile()
            } else {
                ptr.read_unaligned()
            }
        }
    }

    /// Writes the global.
    ///
    /// Doesn't synchronise with the target; see [`Global`] for data races.
    ///
    /// # Panics
    ///
    /// If the module's [`init`](Module::init) has not succeeded.
    pub fn write(&self, value: T) {
        let ptr = self.ptr();
        // SAFETY: as for `read`; any `T` may be stored there.
        unsafe {
            if ptr.is_aligned() {
                ptr.write_volatile(value);
            } else {
                ptr.write_unaligned(value);
            }
        }
    }
}

impl<T> fmt::Debug for Global<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Global")
            .field("module", &self.module.name())
            .field("rva", &format_args!("{:#x}", self.rva))
            .finish()
    }
}
