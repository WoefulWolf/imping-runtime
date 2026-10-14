//! Module identity and address resolution.

use crate::error::{Error, Result};
use crate::sys;
use core::fmt;
use core::sync::atomic::{AtomicUsize, Ordering};

/// A module (executable or DLL) of the target process, as the bindings expect
/// it: its file name and the build identity from its image header.
///
/// Declare one as a `static`, call [`init`](Self::init) once the module is
/// loaded, then resolve addresses with [`address`](Self::address). Generated
/// bindings declare one per IR module as `MODULE`, and their `init()` calls
/// [`Module::init`].
///
/// ```no_run
/// use imping_runtime::Module;
///
/// static GAME: Module = Module::new("game.exe", 0x64b8f2a1, 0xa2b000);
///
/// # fn main() -> imping_runtime::Result<()> {
/// // SAFETY: the addresses used with `GAME` belong to this build.
/// unsafe { GAME.init() }?;
/// let update = GAME.address(0x15040);
/// # let _ = update;
/// # Ok(())
/// # }
/// ```
pub struct Module {
    name: &'static str,
    timestamp: u32,
    image_size: u32,
    /// The module's base address once `init` has succeeded, otherwise 0.
    base: AtomicUsize,
}

impl Module {
    /// Describes a module by its file name (e.g. `"game.exe"`) and the
    /// timestamp and image size from its image header.
    pub const fn new(name: &'static str, timestamp: u32, image_size: u32) -> Self {
        Self {
            name,
            timestamp,
            image_size,
            base: AtomicUsize::new(0),
        }
    }

    /// Finds the module in this process and checks it is the expected build,
    /// by comparing the timestamp and image size in its loaded image header.
    ///
    /// Once this succeeds, further calls do nothing and return `Ok`. A failure
    /// is not remembered, so a module that is loaded later (such as a DLL the
    /// target loads on demand) can be initialized once it is there.
    ///
    /// # Errors
    ///
    /// - [`Error::ModuleNotLoaded`] if no module of this name is loaded.
    /// - [`Error::BuildMismatch`] if it is a different build.
    /// - [`Error::InvalidImage`] if its image header can't be read.
    /// - [`Error::UnsupportedPlatform`] on platforms other than Windows.
    ///
    /// # Safety
    ///
    /// Everything later done through this module — addresses, function
    /// signatures, type layouts — must be correct for the build with this
    /// timestamp and image size. `init` checks the identity; the rest is the
    /// caller's promise. For generated bindings, that means the IR they were
    /// generated from must correctly describe this build.
    pub unsafe fn init(&self) -> Result<()> {
        if self.base().is_some() {
            return Ok(());
        }
        let (base, identity) = sys::locate(self.name).map_err(|error| match error {
            sys::LocateError::NotLoaded => Error::ModuleNotLoaded { module: self.name },
            sys::LocateError::InvalidImage => Error::InvalidImage { module: self.name },
            sys::LocateError::Unsupported => Error::UnsupportedPlatform,
        })?;
        if identity.timestamp != self.timestamp || identity.image_size != self.image_size {
            return Err(Error::BuildMismatch {
                module: self.name,
                expected_timestamp: self.timestamp,
                found_timestamp: identity.timestamp,
                expected_image_size: self.image_size,
                found_image_size: identity.image_size,
            });
        }
        self.base.store(base, Ordering::Release);
        log::debug!("imping: `{}` found at {base:#x}", self.name);
        Ok(())
    }

    /// The module's file name.
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The module's base address, or `None` until [`init`](Self::init) has
    /// succeeded.
    pub fn base(&self) -> Option<usize> {
        match self.base.load(Ordering::Acquire) {
            0 => None,
            base => Some(base),
        }
    }

    /// The address of `rva`, an address relative to the module's base.
    ///
    /// # Panics
    ///
    /// If [`init`](Self::init) has not succeeded.
    pub fn address(&self, rva: u32) -> usize {
        match self.base() {
            Some(base) => base + rva as usize,
            None => panic!(
                "imping: `{}` is not initialized; call its `init()` first",
                self.name
            ),
        }
    }
}

impl fmt::Debug for Module {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Module")
            .field("name", &self.name)
            .field("timestamp", &format_args!("{:#x}", self.timestamp))
            .field("image_size", &format_args!("{:#x}", self.image_size))
            .field("base", &self.base().map(|base| base as *const ()))
            .finish()
    }
}
