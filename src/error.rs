//! The error type.

use core::fmt;

/// The result of a runtime operation.
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
    /// The loaded module is a different build than the one expected.
    BuildMismatch {
        /// The module's file name.
        module: &'static str,
        /// The timestamp the bindings expect.
        expected_timestamp: u32,
        /// The timestamp of the loaded module.
        found_timestamp: u32,
        /// The image size the bindings expect.
        expected_image_size: u32,
        /// The image size of the loaded module.
        found_image_size: u32,
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
    /// A function does not start with the bytes the bindings expect.
    VerificationFailed {
        /// The module's file name.
        module: &'static str,
        /// The function's address relative to the module's base.
        rva: u32,
        /// The bytes the bindings expect.
        expected: &'static [u8],
        /// The bytes found.
        found: Vec<u8>,
    },
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
    /// This platform is not supported yet.
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
                expected_timestamp,
                found_timestamp,
                expected_image_size,
                found_image_size,
            } => write!(
                f,
                "`{module}` is a different build than the bindings were generated from: \
                 timestamp {found_timestamp:#x} (expected {expected_timestamp:#x}), \
                 image size {found_image_size:#x} (expected {expected_image_size:#x})"
            ),
            Error::InvalidImage { module } => write!(f, "`{module}` has unreadable PE headers"),
            Error::NotInitialized { module } => {
                write!(f, "`{module}` is not initialized; call its `init()` first")
            }
            Error::VerificationFailed {
                module,
                rva,
                expected,
                found,
            } => write!(
                f,
                "`{module}`+{rva:#x} starts with {}, expected {}; the build differs or another \
                 mod hooked it",
                Hex(found),
                Hex(expected)
            ),
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
            _ => None,
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
