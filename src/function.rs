//! Where a generated function is: its RVA if the first bytes there match,
//! otherwise wherever its byte pattern leads.

use crate::error::{Error, Result};
use crate::module::Module;
use core::sync::atomic::{AtomicUsize, Ordering};

/// A byte pattern that finds a function when its RVA is wrong.
#[derive(Debug, Clone, Copy)]
pub struct Pattern {
    /// Hex bytes separated by spaces, with `??` for any byte.
    pub bytes: &'static str,
    /// Bytes from the start of the match to the function, or to the call.
    pub offset: isize,
    /// Whether there's a call to the function at `offset`, rather than the
    /// function itself.
    pub follow_call: bool,
}

/// A function of a module as generated code knows it, and where it turned out
/// to be.
#[derive(Debug)]
pub struct Function {
    module: &'static Module,
    name: &'static str,
    rva: u32,
    verification: &'static [u8],
    pattern: Option<Pattern>,
    /// The address once checked or found by pattern, otherwise 0.
    found: AtomicUsize,
}

impl Function {
    /// Describes the function `name` at `rva` in `module`, with the bytes it
    /// should start with (empty if unknown) and a pattern to find it by.
    pub const fn new(
        module: &'static Module,
        name: &'static str,
        rva: u32,
        verification: &'static [u8],
        pattern: Option<Pattern>,
    ) -> Self {
        Self {
            module,
            name,
            rva,
            verification,
            pattern,
            found: AtomicUsize::new(0),
        }
    }

    /// Returns the module the function is in.
    pub fn module(&self) -> &'static Module {
        self.module
    }

    /// Returns the function's address relative to the module's base, as the
    /// bindings know it.
    pub fn rva(&self) -> u32 {
        self.rva
    }

    /// Returns the function's address, for calling it.
    ///
    /// On a build the module lists, that's its RVA, unchecked. On another, the
    /// first call checks the bytes there and falls back to the pattern, and
    /// the result is kept.
    ///
    /// # Errors
    ///
    /// - [`Error::NotInitialized`] if the module isn't initialized.
    /// - [`Error::VerificationFailed`] if the bytes differ and the pattern
    ///   doesn't find the function either.
    pub fn resolve(&self) -> Result<usize> {
        let base = self.base()?;
        let target = base + self.rva as usize;
        if self.module.is_listed() {
            return Ok(target);
        }
        match self.found.load(Ordering::Acquire) {
            0 => {}
            found => return Ok(found),
        }
        if self.matches(target) {
            self.found.store(target, Ordering::Release);
            return Ok(target);
        }
        self.scan(base, target)
    }

    /// Returns the function's address, for hooking it: its RVA if the bytes
    /// there match, otherwise where its pattern leads.
    ///
    /// Unlike [`resolve`](Self::resolve) this checks on every build, as
    /// another mod may have hooked the function first.
    pub(crate) fn locate(&self) -> Result<usize> {
        let base = self.base()?;
        let target = base + self.rva as usize;
        if self.matches(target) {
            self.found.store(target, Ordering::Release);
            return Ok(target);
        }
        let address = self.scan(base, target)?;
        // The pattern agrees with the RVA, so the bytes there changed after
        // loading, most likely under another mod's hook.
        if address == target {
            return Err(self.mismatch(target, None));
        }
        Ok(address)
    }

    fn base(&self) -> Result<usize> {
        self.module.base().ok_or(Error::NotInitialized {
            module: self.module.name(),
        })
    }

    /// Whether the function at `target` starts with the expected bytes, or
    /// there are none to check.
    fn matches(&self, target: usize) -> bool {
        self.verification.is_empty()
            || self
                .first_bytes(target)
                .is_some_and(|found| found == self.verification)
    }

    /// Reads as many bytes at `target` as there are to verify, or `None` if
    /// they'd run past the end of the module.
    fn first_bytes(&self, target: usize) -> Option<Vec<u8>> {
        let end = self.rva as usize + self.verification.len();
        if end > self.module.image_size() {
            return None;
        }
        // SAFETY: the bytes lie inside the module's image, which the loader
        // has mapped and keeps mapped while the module is loaded.
        let bytes =
            unsafe { core::slice::from_raw_parts(target as *const u8, self.verification.len()) };
        Some(bytes.to_vec())
    }

    /// Finds the function by its pattern and remembers where.
    fn scan(&self, base: usize, target: usize) -> Result<usize> {
        let Some(pattern) = self.pattern else {
            return Err(self.mismatch(target, None));
        };
        let mut search = imping_hook::scan::Pattern::new(pattern.bytes)
            .in_module(self.module.name())
            .offset(pattern.offset);
        if pattern.follow_call {
            search = search.follow_call();
        }
        let address = search
            .find()
            .map_err(|error| self.mismatch(target, Some(error)))? as usize;
        if address != target {
            log::warn!(
                "imping: `{}`+{:#x} didn't match; found `{}` by pattern at +{:#x}, update the IR",
                self.module.name(),
                self.rva,
                self.name,
                address.wrapping_sub(base)
            );
        }
        self.found.store(address, Ordering::Release);
        Ok(address)
    }

    fn mismatch(&self, target: usize, scan: Option<imping_hook::Error>) -> Error {
        Error::VerificationFailed {
            module: self.module.name(),
            rva: self.rva,
            expected: self.verification,
            found: self.first_bytes(target).unwrap_or_default(),
            scan,
        }
    }
}
