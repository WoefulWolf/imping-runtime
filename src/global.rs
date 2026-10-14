//! Typed global variables.

use crate::module::Module;
use core::fmt;
use core::marker::PhantomData;

/// A global variable of type `T` at an address in a [`Module`].
///
/// Generated bindings declare one per IR global. It holds only the address;
/// reading or writing the variable goes through [`ptr`](Self::ptr).
///
/// ```no_run
/// use imping_runtime::{Global, Module};
///
/// static GAME: Module = Module::new("game.exe", 0x64b8f2a1, 0xa2b000);
/// static GRAVITY: Global<f32> = Global::new(&GAME, 0x3a1200);
///
/// # fn main() -> imping_runtime::Result<()> {
/// // SAFETY: this build of `game.exe` keeps an `f32` at RVA 0x3a1200.
/// unsafe { GAME.init() }?;
/// // SAFETY: `init` succeeded, so the pointer is the game's global, and
/// // nothing else is writing it right now.
/// let gravity = unsafe { *GRAVITY.ptr() };
/// # let _ = gravity;
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

impl<T> fmt::Debug for Global<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Global")
            .field("module", &self.module.name())
            .field("rva", &format_args!("{:#x}", self.rva))
            .finish()
    }
}
