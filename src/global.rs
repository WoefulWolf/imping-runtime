//! Typed global variables.

use crate::module::Module;
use crate::plain::Plain;
use core::fmt;
use core::marker::PhantomData;

/// A global variable of type `T` at an address in a [`Module`].
///
/// Generated bindings declare one per IR global. It holds only the address.
/// When `T` is [`Plain`], [`read`](Self::read) and [`write`](Self::write)
/// access the variable safely; otherwise go through [`ptr`](Self::ptr).
///
/// ```no_run
/// use imping_runtime::{Build, Global, Module};
///
/// static GAME: Module = Module::new(
///     "game.exe",
///     &[Build { timestamp: 0x64b8f2a1, image_size: 0xa2b000 }],
/// );
/// static GRAVITY: Global<f32> = Global::new(&GAME, 0x3a1200);
///
/// # fn main() -> imping_runtime::Result<()> {
/// // SAFETY: this build of `game.exe` keeps an `f32` at RVA 0x3a1200.
/// unsafe { GAME.init() }?;
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

    /// A pointer to the global in this process.
    ///
    /// # Panics
    ///
    /// If the module's [`init`](Module::init) has not succeeded.
    pub fn ptr(&self) -> *mut T {
        self.module.address(self.rva) as *mut T
    }

    /// The global's address relative to its module's base.
    pub const fn rva(&self) -> u32 {
        self.rva
    }

    /// The module the global is in.
    pub const fn module(&self) -> &'static Module {
        self.module
    }
}

impl<T: Plain> Global<T> {
    /// Reads the global.
    ///
    /// This is a single volatile read that does not synchronise with the
    /// target: if the target writes the global at the same time on another
    /// thread, a value larger than a machine word can be read half-updated.
    ///
    /// # Panics
    ///
    /// If the module's [`init`](Module::init) has not succeeded.
    pub fn read(&self) -> T {
        let ptr = self.ptr();
        // SAFETY: `ptr` panics unless `init` succeeded, whose caller promised
        // that a `T` lives at this address in the module's image, which stays
        // mapped while the module is loaded; every bit pattern is a valid `T`.
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
    /// This is a single volatile write that does not synchronise with the
    /// target: if the target accesses the global at the same time on another
    /// thread, a value larger than a machine word can be seen half-updated.
    ///
    /// # Panics
    ///
    /// If the module's [`init`](Module::init) has not succeeded.
    pub fn write(&self, value: T) {
        let ptr = self.ptr();
        // SAFETY: As for `read`; any `T` may be stored there.
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
