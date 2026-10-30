//! The error type.

use crate::module::Build;
use core::fmt;

/// The result type of this crate's fallible functions.
pub type Result<T> = core::result::Result<T, Error>;

/// Everything that can go wrong finding a module or hooking a function.
///
/// Messages name the module, and the address relative to its base where one
/// is involved.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The module is not loaded in this process.
    ModuleNotLoaded {
        /// The module's file name.
        module: &'static str,
    },
    /// The loaded module is none of the builds the bindings accept.
    BuildMismatch {
        /// The module's file name.
        module: &'static str,
        /// The build that is loaded.
        found: Build,
        /// The builds the bindings accept.
        expected: &'static [Build],
    },
    /// The loaded module's headers could not be read.
    InvalidImage {
        /// The module's file name.
        module: &'static str,
    },
    /// The module has not been initialized; call its `init` first.
    NotInitialized {
        /// The module's file name.
        module: &'static str,
    },
    /// A function does not start with the bytes the bindings expect, and
    /// nothing else found it; see [`Mismatch`].
    VerificationFailed(Box<Mismatch>),
    /// The function is already hooked by this mod: a [`Hook`](crate::Hook) for
    /// it is still alive.
    AlreadyHooked {
        /// The module's file name.
        module: &'static str,
        /// The function's address relative to the module's base.
        rva: u32,
    },
    /// The hooking engine failed to install, enable or disable a hook.
    Hook {
        /// The module's file name.
        module: &'static str,
        /// The function's address relative to the module's base.
        rva: u32,
        /// The engine's error.
        source: imping_hook::Error,
    },
    /// This platform is not supported; only Windows is.
    UnsupportedPlatform,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::ModuleNotLoaded { module } => {
                write!(f, "`{module}` is not loaded in this process")
            }
            Error::BuildMismatch {
                module,
                found,
                expected,
            } => {
                write!(
                    f,
                    "`{module}` is a different build than the bindings accept: \
                     found timestamp {:#x}, image size {:#x}; accepted ",
                    found.timestamp, found.image_size
                )?;
                if expected.is_empty() {
                    return f.write_str("none");
                }
                for (i, build) in expected.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{:#x}/{:#x}", build.timestamp, build.image_size)?;
                }
                Ok(())
            }
            Error::InvalidImage { module } => write!(f, "`{module}` has unreadable PE headers"),
            Error::NotInitialized { module } => {
                write!(f, "`{module}` is not initialized; call its `init()` first")
            }
            Error::VerificationFailed(mismatch) => mismatch.fmt(f),
            Error::AlreadyHooked { module, rva } => {
                write!(f, "`{module}`+{rva:#x} is already hooked by this mod")
            }
            Error::Hook {
                module,
                rva,
                source,
            } => write!(f, "failed to hook `{module}`+{rva:#x}: {source}"),
            Error::UnsupportedPlatform => {
                f.write_str("imping-runtime does not support this platform yet")
            }
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Error::Hook { source, .. } => Some(source),
            Error::VerificationFailed(mismatch) => match &mismatch.scan {
                Some(source) => Some(source),
                None => None,
            },
            _ => None,
        }
    }
}

/// Why a function wasn't where the bindings expect, and why nothing else found
/// it: the details of [`Error::VerificationFailed`].
///
/// Boxed, so the error stays small as ways to find a function are added.
///
/// # Examples
///
/// ```no_run
/// # fn check(error: imping_runtime::Error) {
/// use imping_runtime::{Error, VtableMiss};
///
/// if let Error::VerificationFailed(mismatch) = &error {
///     if let Some(VtableMiss::ClassNotFound { type_name }) = &mismatch.vtable {
///         eprintln!("{type_name} is gone from this build");
///     }
/// }
/// # }
/// ```
#[derive(Debug)]
#[non_exhaustive]
pub struct Mismatch {
    /// The module's file name.
    pub module: &'static str,
    /// The function's address relative to the module's base.
    pub rva: u32,
    /// The bytes the bindings expect.
    pub expected: &'static [u8],
    /// The bytes found, empty if they'd be past the end of the module.
    pub found: Vec<u8>,
    /// Why the function's byte pattern didn't find it, if it has one and
    /// that's why.
    pub scan: Option<imping_hook::Error>,
    /// Why its class's vtable didn't lead to it, if it's in one.
    pub vtable: Option<VtableMiss>,
}

impl fmt::Display for Mismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Mismatch { module, rva, .. } = self;
        if self.found.is_empty() {
            write!(
                f,
                "`{module}`+{rva:#x} is past the end of the module; the build differs"
            )?;
        } else {
            write!(
                f,
                "`{module}`+{rva:#x} starts with {}, expected {}; the build differs or another \
                 mod hooked it",
                Hex(&self.found),
                Hex(self.expected)
            )?;
        }
        if let Some(scan) = &self.scan {
            write!(f, ", and {scan}")?;
        }
        match &self.vtable {
            Some(vtable) => write!(f, ", and {vtable}"),
            None => Ok(()),
        }
    }
}

/// Why a function couldn't be found through its class's vtable.
///
/// Part of a [`Mismatch`]; type names are MSVC's decorated ones, such as
/// `.?AVEntity@game@@`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VtableMiss {
    /// The module has no type information for the class.
    ClassNotFound {
        /// The class's type name.
        type_name: &'static str,
    },
    /// The class has no vtable at this offset.
    VtableNotFound {
        /// The class's type name.
        type_name: &'static str,
        /// The locator's offset, which tells apart a class's vtables.
        offset: u32,
    },
    /// The slot holds a function that doesn't start like this one.
    ShapeDiffers {
        /// The class's type name.
        type_name: &'static str,
        /// The slot's index.
        index: u32,
        /// The bytes the slot's function starts with, empty if it's outside
        /// the module.
        found: Vec<u8>,
    },
}

impl fmt::Display for VtableMiss {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VtableMiss::ClassNotFound { type_name } => {
                write!(f, "class `{type_name}` was not found")
            }
            VtableMiss::VtableNotFound { type_name, offset } => {
                write!(f, "class `{type_name}` has no vtable at offset {offset}")
            }
            VtableMiss::ShapeDiffers {
                type_name,
                index,
                found,
            } if found.is_empty() => {
                write!(f, "slot {index} of `{type_name}` points outside the module")
            }
            VtableMiss::ShapeDiffers {
                type_name,
                index,
                found,
            } => write!(
                f,
                "slot {index} of `{type_name}` starts with {}",
                Hex(found)
            ),
        }
    }
}

/// Bytes as space-separated lowercase hex, e.g. `48 83 ec 28`.
struct Hex<'a>(&'a [u8]);

impl fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, byte) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}
