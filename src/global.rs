//! Typed global variables.

use crate::module::Module;
use crate::plain::Plain;
use core::fmt;
use core::marker::PhantomData;

/// A global variable of type `T` at an address in a [`Module`].
///
/// Generated bindings declare one per IR global; it holds only the address,
/// one per build when they were generated from several. When `T` is
/// [`Plain`], [`read`](Self::read) and [`write`](Self::write) access it
/// safely; otherwise use [`ptr`](Self::ptr).
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
    address: Address,
    _type: PhantomData<fn() -> T>,
}

/// Where a global is.
#[derive(Clone, Copy)]
enum Address {
    /// At one RVA in every build.
    One(u32),
    /// Per labelled build, in the module's label order; `None` where that
    /// build's IR lacks it.
    PerBuild {
        name: &'static str,
        rvas: &'static [Option<u32>],
    },
}

impl<T> Global<T> {
    /// Describes the global at `rva`, an address relative to `module`'s base.
    pub const fn new(module: &'static Module, rva: u32) -> Self {
        Self {
            module,
            address: Address::One(rva),
            _type: PhantomData,
        }
    }

    /// Describes the global `name` with an address per labelled build of
    /// `module`.
    pub(crate) const fn per_build(
        module: &'static Module,
        name: &'static str,
        rvas: &'static [Option<u32>],
    ) -> Self {
        Self {
            module,
            address: Address::PerBuild { name, rvas },
            _type: PhantomData,
        }
    }

    /// Returns a pointer to the global in this process.
    ///
    /// # Panics
    ///
    /// If the module's [`init`](Module::init) has not succeeded, or the loaded
    /// build's IR lacks the global; [`try_ptr`](Self::try_ptr) checks first.
    pub fn ptr(&self) -> *mut T {
        if let Some(ptr) = self.try_ptr() {
            return ptr;
        }
        match (self.module.base(), self.address) {
            (Some(_), Address::PerBuild { name, .. }) => {
                let build = self
                    .module
                    .build_index()
                    .map_or("loaded", |index| self.module.label(index));
                panic!(
                    "imping: `{name}` isn't in the {build} IR of `{}`",
                    self.module.name()
                )
            }
            _ => panic!(
                "imping: `{}` is not initialized; call its `init()` first",
                self.module.name()
            ),
        }
    }

    /// Returns a pointer to the global in this process, or `None` if the
    /// module's [`init`](Module::init) has not succeeded or the loaded build's
    /// IR lacks the global.
    ///
    /// On a build none of the IRs is, after
    /// [`init_any_build`](Module::init_any_build), it's the first build's
    /// address that has the global, unchecked, as nothing can search for a
    /// global.
    pub fn try_ptr(&self) -> Option<*mut T> {
        let base = self.module.base()?;
        Some((base + self.used_rva()? as usize) as *mut T)
    }

    /// Returns the global's address relative to its module's base in the
    /// loaded build, as its IR has it: `None` before `init`, where that build's
    /// IR lacks the global, or on a build none of the IRs is.
    ///
    /// A global made with [`new`](Self::new) has one address, which this always
    /// returns.
    pub fn rva(&self) -> Option<u32> {
        match self.address {
            Address::One(rva) => Some(rva),
            Address::PerBuild { rvas, .. } => {
                let index = self.module.build_index()?;
                rvas.get(index).copied().flatten()
            }
        }
    }

    /// The RVA [`try_ptr`](Self::try_ptr) uses: [`rva`](Self::rva), or on a
    /// build none of the IRs is, the first build's that has the global.
    fn used_rva(&self) -> Option<u32> {
        match self.address {
            Address::PerBuild { rvas, .. }
                if self.module.base().is_some() && self.module.build_index().is_none() =>
            {
                rvas.iter().flatten().next().copied()
            }
            _ => self.rva(),
        }
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
    /// As [`ptr`](Self::ptr) does.
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
    /// As [`ptr`](Self::ptr) does.
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
        let mut debug = f.debug_struct("Global");
        debug.field("module", &self.module.name());
        match self.address {
            Address::One(rva) => debug.field("rva", &format_args!("{rva:#x}")),
            Address::PerBuild { name, rvas } => debug.field("name", &name).field("rvas", &rvas),
        };
        debug.finish()
    }
}
