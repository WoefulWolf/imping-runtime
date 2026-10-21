//! Module identity and address resolution.

use crate::error::{Error, Result};
use crate::sys;
use core::fmt;
use core::sync::atomic::{AtomicUsize, Ordering};

/// One build of a module, identified by the timestamp and image size in its
/// image header.
///
/// A packer or DRM wrapper can change the image size while keeping the
/// timestamp, so the file a disassembler analysed and the one that runs may
/// be two builds with the same code; a [`Module`] can accept both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Build {
    /// The `TimeDateStamp` from the module's file header.
    pub timestamp: u32,
    /// The `SizeOfImage` from the module's optional header.
    pub image_size: u32,
}

/// A module (executable or DLL) of the target process, as the bindings expect
/// it: its file name and the builds they accept.
///
/// Declare one as a `static`, call [`init`](Self::init) once the module is
/// loaded, then resolve addresses with [`address`](Self::address). Generated
/// bindings declare one per IR module as `MODULE`, and their `init()` calls
/// [`Module::init`].
///
/// # Examples
///
/// ```no_run
/// use imping_runtime::{Build, Module};
///
/// static TARGET: Module = Module::new(
///     "target.exe",
///     &[Build { timestamp: 0x64b8f2a1, image_size: 0xa2b000 }],
/// );
///
/// # fn main() -> imping_runtime::Result<()> {
/// // SAFETY: the addresses used with `TARGET` belong to this build.
/// unsafe { TARGET.init() }?;
/// let update = TARGET.address(0x15040);
/// # let _ = update;
/// # Ok(())
/// # }
/// ```
pub struct Module {
    name: &'static str,
    builds: &'static [Build],
    /// The module's base address once `init` has succeeded, otherwise 0.
    base: AtomicUsize,
}

impl Module {
    /// Describes a module by its file name, such as `"target.exe"`, and the
    /// builds it accepts.
    ///
    /// With no builds, [`init`](Self::init) always fails.
    pub const fn new(name: &'static str, builds: &'static [Build]) -> Self {
        Self {
            name,
            builds,
            base: AtomicUsize::new(0),
        }
    }

    /// Finds the module in this process and checks its image header against
    /// the accepted builds.
    ///
    /// Once this succeeds, further calls return `Ok` and do nothing. Failures
    /// aren't remembered, so a DLL the target loads later can be initialized
    /// once it's there.
    ///
    /// # Errors
    ///
    /// - [`Error::ModuleNotLoaded`] if no module of this name is loaded.
    /// - [`Error::BuildMismatch`] if it is none of the accepted builds.
    /// - [`Error::InvalidImage`] if its image header can't be read.
    /// - [`Error::UnsupportedPlatform`] on platforms other than Windows.
    ///
    /// # Safety
    ///
    /// Everything later done through this module (addresses, function
    /// signatures, type layouts) must be correct for every accepted build;
    /// `init` only checks the identity. For generated bindings, the IR they
    /// came from must describe each accepted build correctly.
    pub unsafe fn init(&self) -> Result<()> {
        if self.base().is_some() {
            return Ok(());
        }
        let (base, identity) = sys::locate(self.name).map_err(|error| match error {
            sys::LocateError::NotLoaded => Error::ModuleNotLoaded { module: self.name },
            sys::LocateError::InvalidImage => Error::InvalidImage { module: self.name },
            sys::LocateError::Unsupported => Error::UnsupportedPlatform,
        })?;
        let found = Build {
            timestamp: identity.timestamp,
            image_size: identity.image_size,
        };
        if !self.builds.contains(&found) {
            return Err(Error::BuildMismatch {
                module: self.name,
                found,
                expected: self.builds,
            });
        }
        self.base.store(base, Ordering::Release);
        log::debug!("imping: `{}` found at {base:#x}", self.name);
        Ok(())
    }

    /// Finds the module in this process and records its base whatever its
    /// build, returning the build found.
    ///
    /// For trying a build the bindings don't list; [`init`](Self::init) is the
    /// checked way in. An unlisted build is logged as a warning. If the module
    /// is already initialized, nothing changes and the loaded build is returned.
    ///
    /// # Errors
    ///
    /// - [`Error::ModuleNotLoaded`] if no module of this name is loaded.
    /// - [`Error::InvalidImage`] if its image header can't be read.
    /// - [`Error::UnsupportedPlatform`] on platforms other than Windows.
    ///
    /// # Safety
    ///
    /// Everything later done through this module (addresses, function
    /// signatures, type layouts) must be correct for the build actually
    /// loaded, which nothing has checked. Hooks still verify a function's
    /// first bytes where the bindings know them; calls, globals and raw
    /// addresses are used unchecked.
    pub unsafe fn init_any_build(&self) -> Result<Build> {
        let (base, identity) = sys::locate(self.name).map_err(|error| match error {
            sys::LocateError::NotLoaded => Error::ModuleNotLoaded { module: self.name },
            sys::LocateError::InvalidImage => Error::InvalidImage { module: self.name },
            sys::LocateError::Unsupported => Error::UnsupportedPlatform,
        })?;
        let found = Build {
            timestamp: identity.timestamp,
            image_size: identity.image_size,
        };
        if self.base().is_none() {
            if !self.builds.contains(&found) {
                log::warn!(
                    "imping: `{}` (timestamp {:#x}, image size {:#x}) is not a build the \
                     bindings accept; initialized anyway",
                    self.name,
                    found.timestamp,
                    found.image_size
                );
            }
            self.base.store(base, Ordering::Release);
            log::debug!("imping: `{}` found at {base:#x}", self.name);
        }
        Ok(found)
    }

    /// Returns the module's file name.
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Returns the module's base address, or `None` until [`init`](Self::init)
    /// has succeeded.
    pub fn base(&self) -> Option<usize> {
        match self.base.load(Ordering::Acquire) {
            0 => None,
            base => Some(base),
        }
    }

    /// Returns the address of `rva`, an address relative to the module's base.
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
            .field("builds", &self.builds)
            .field("base", &self.base().map(|base| base as *const ()))
            .finish()
    }
}
