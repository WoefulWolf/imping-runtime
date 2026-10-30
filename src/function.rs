//! Where a generated function is: its RVA if the first bytes there match,
//! otherwise wherever its byte pattern leads, otherwise its class's vtable
//! slot.

use crate::error::{Error, Mismatch, Result, VtableMiss};
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

/// A vtable slot that holds a function, by the class's RTTI type name.
#[derive(Debug, Clone, Copy)]
pub struct VtableSlot {
    /// The class's decorated type name, e.g. `.?AVEntity@game@@`.
    pub type_name: &'static str,
    /// The locator's offset, which tells apart a class's vtables.
    pub offset: u32,
    /// The slot's index.
    pub index: u32,
}

/// A function of a module as generated code knows it, and where it turned out
/// to be.
#[derive(Debug)]
pub struct Function {
    module: &'static Module,
    name: &'static str,
    rva: u32,
    verification: &'static [u8],
    shape: &'static str,
    pattern: Option<Pattern>,
    slot: Option<VtableSlot>,
    /// The address once checked or found another way, otherwise 0.
    found: AtomicUsize,
}

impl Function {
    /// Describes the function `name` at `rva` in `module`: the bytes it should
    /// start with (empty if unknown), the same with `??` for addresses, and
    /// what else finds it.
    pub const fn new(
        module: &'static Module,
        name: &'static str,
        rva: u32,
        verification: &'static [u8],
        shape: &'static str,
        pattern: Option<Pattern>,
        slot: Option<VtableSlot>,
    ) -> Self {
        Self {
            module,
            name,
            rva,
            verification,
            shape,
            pattern,
            slot,
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
    /// first call finds it as [`locate`](Self::locate) does, and the result is
    /// kept.
    ///
    /// # Errors
    ///
    /// - [`Error::NotInitialized`] if the module isn't initialized.
    /// - [`Error::VerificationFailed`] if the bytes differ and nothing else
    ///   finds the function.
    pub fn resolve(&self) -> Result<usize> {
        let base = self.base()?;
        if self.module.is_listed() {
            return Ok(base + self.rva as usize);
        }
        match self.found.load(Ordering::Acquire) {
            0 => {}
            found => return Ok(found),
        }
        let address = self.find(base, false)?;
        self.found.store(address, Ordering::Release);
        Ok(address)
    }

    /// Returns the function's address, for hooking it: its RVA if the bytes
    /// there match, otherwise where its pattern leads, otherwise its vtable
    /// slot.
    ///
    /// Unlike [`resolve`](Self::resolve) this checks on every build, as
    /// another mod may have hooked the function first.
    pub(crate) fn locate(&self) -> Result<usize> {
        let base = self.base()?;
        let address = self.find(base, true)?;
        self.found.store(address, Ordering::Release);
        Ok(address)
    }

    fn base(&self) -> Result<usize> {
        self.module.base().ok_or(Error::NotInitialized {
            module: self.module.name(),
        })
    }

    fn find(&self, base: usize, hooking: bool) -> Result<usize> {
        let target = base + self.rva as usize;
        if self.matches(target) {
            return Ok(target);
        }
        let mut scan = None;
        if let Some(pattern) = self.pattern {
            match self.scan(pattern) {
                Ok(address) if address != target => {
                    self.moved(base, address, "by pattern");
                    return Ok(address);
                }
                // The pattern agrees with the RVA. If the shape does too, only
                // the addresses in it changed; otherwise its start changed
                // after loading, most likely under another mod's hook, which
                // only matters when hooking.
                Ok(address) => {
                    if !hooking || self.shape_at(address).is_ok() {
                        return Ok(address);
                    }
                    return Err(self.mismatch(target, None, None));
                }
                Err(error) => scan = Some(error),
            }
        }
        let mut vtable = None;
        // A slot is only trusted if the shape confirms it, and the RTTI read is
        // the x64 layout.
        let slot = self
            .slot
            .filter(|_| !self.shape.is_empty() && cfg!(target_pointer_width = "64"));
        if let Some(slot) = slot {
            match self.through_vtable(base, slot) {
                Ok(address) => {
                    if address != target {
                        self.moved(base, address, "through its class's vtable");
                    }
                    return Ok(address);
                }
                Err(miss) => vtable = Some(miss),
            }
        }
        Err(self.mismatch(target, scan, vtable))
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
        self.read(target, self.verification.len())
    }

    /// Reads `len` bytes at `address`, or `None` if they're not all inside the
    /// module.
    fn read(&self, address: usize, len: usize) -> Option<Vec<u8>> {
        let base = self.module.base()?;
        let end = address.checked_sub(base)?.checked_add(len)?;
        if end > self.module.image_size() {
            return None;
        }
        // SAFETY: the bytes lie inside the module's image, which the loader
        // has mapped and keeps mapped while the module is loaded.
        let bytes = unsafe { core::slice::from_raw_parts(address as *const u8, len) };
        Some(bytes.to_vec())
    }

    /// Checks the function's shape at `address`, returning the bytes found if
    /// it differs (empty if they're not inside the module).
    fn shape_at(&self, address: usize) -> core::result::Result<(), Vec<u8>> {
        let tokens: Vec<&str> = self.shape.split_ascii_whitespace().collect();
        if tokens.is_empty() {
            return Err(Vec::new());
        }
        let found = self.read(address, tokens.len()).ok_or_else(Vec::new)?;
        let fits = tokens.iter().zip(&found).all(|(token, byte)| match *token {
            "??" | "?" => true,
            hex => u8::from_str_radix(hex, 16) == Ok(*byte),
        });
        if fits { Ok(()) } else { Err(found) }
    }

    /// Finds the function by its pattern.
    fn scan(&self, pattern: Pattern) -> core::result::Result<usize, imping_hook::Error> {
        let mut search = imping_hook::scan::Pattern::new(pattern.bytes)
            .in_module(self.module.name())
            .offset(pattern.offset);
        if pattern.follow_call {
            search = search.follow_call();
        }
        search.find().map(|address| address as usize)
    }

    /// Finds the function in its class's vtable, if the slot holds something
    /// shaped like it.
    fn through_vtable(
        &self,
        base: usize,
        slot: VtableSlot,
    ) -> core::result::Result<usize, VtableMiss> {
        let vtable = crate::rtti::vtable(self.module, base, slot.type_name, slot.offset)?;
        let entry = vtable + slot.index as usize * size_of::<usize>();
        let pointer = self.read(entry, size_of::<usize>());
        let address = pointer.map(|bytes| usize::from_le_bytes(bytes.try_into().unwrap()));
        let shape = match address {
            Some(address) => self.shape_at(address).map(|()| address),
            None => Err(Vec::new()),
        };
        shape.map_err(|found| VtableMiss::ShapeDiffers {
            type_name: slot.type_name,
            index: slot.index,
            found,
        })
    }

    fn moved(&self, base: usize, address: usize, how: &str) {
        log::warn!(
            "imping: `{}`+{:#x} didn't match; found `{}` {how} at +{:#x}, update the IR",
            self.module.name(),
            self.rva,
            self.name,
            address.wrapping_sub(base)
        );
    }

    fn mismatch(
        &self,
        target: usize,
        scan: Option<imping_hook::Error>,
        vtable: Option<VtableMiss>,
    ) -> Error {
        Error::VerificationFailed(Box::new(Mismatch {
            module: self.module.name(),
            rva: self.rva,
            expected: self.verification,
            found: self.first_bytes(target).unwrap_or_default(),
            scan,
            vtable,
        }))
    }
}
