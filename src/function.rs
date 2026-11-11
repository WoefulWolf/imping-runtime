//! Where a generated function is: its RVA in the loaded build if the first
//! bytes there match, otherwise wherever its byte pattern leads, otherwise its
//! class's vtable slot.

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

/// Where a function is in one build, as that build's IR has it.
#[derive(Debug, Clone, Copy)]
pub struct Site {
    /// The function's address relative to the module's base.
    pub rva: u32,
    /// The bytes it should start with, empty if unknown.
    pub verification: &'static [u8],
    /// The same with `??` for addresses, empty if unknown.
    pub shape: &'static str,
    /// The pattern that finds it if it moves.
    pub pattern: Option<Pattern>,
}

/// A function of a module as generated code knows it, and where it turned out
/// to be.
#[derive(Debug)]
pub struct Function {
    module: &'static Module,
    name: &'static str,
    /// Per labelled build, in the module's label order; `None` where that
    /// build's IR lacks the function.
    sites: &'static [Option<Site>],
    slot: Option<VtableSlot>,
    /// The address once checked or found another way, otherwise 0.
    found: AtomicUsize,
}

impl Function {
    /// Describes the function `name` in `module`: where each build has it, and
    /// the vtable slot that finds it otherwise.
    pub const fn new(
        module: &'static Module,
        name: &'static str,
        sites: &'static [Option<Site>],
        slot: Option<VtableSlot>,
    ) -> Self {
        Self {
            module,
            name,
            sites,
            slot,
            found: AtomicUsize::new(0),
        }
    }

    /// Returns the module the function is in.
    pub fn module(&self) -> &'static Module {
        self.module
    }

    /// Returns the function's address relative to the module's base in the
    /// loaded build, as its IR has it: `None` before `init`, where that build's
    /// IR lacks the function, or on a build none of the IRs is.
    pub fn rva(&self) -> Option<u32> {
        let index = self.module.build_index()?;
        self.site(index).map(|site| site.rva)
    }

    /// The function's address relative to the module's base as last found,
    /// otherwise its RVA in the loaded build, otherwise 0; for messages.
    pub(crate) fn known_rva(&self) -> u32 {
        let base = self.module.base().unwrap_or(0);
        match self.found.load(Ordering::Acquire) {
            0 => self.rva().unwrap_or(0),
            found => found.wrapping_sub(base) as u32,
        }
    }

    /// Returns the function's address, for calling it.
    ///
    /// On a build the module lists whose IR has the function, that's its RVA,
    /// unchecked. Otherwise the first call finds it as
    /// [`locate`](Self::locate) does, and the result is kept.
    ///
    /// # Errors
    ///
    /// - [`Error::NotInitialized`] if the module isn't initialized.
    /// - [`Error::VerificationFailed`] if the bytes differ and nothing else
    ///   finds the function.
    /// - [`Error::NotInBuild`] if the loaded build's IR lacks the function and
    ///   nothing else finds it.
    pub fn resolve(&self) -> Result<usize> {
        let base = self.base()?;
        if let Some(site) = self.module.build_index().and_then(|index| self.site(index)) {
            return Ok(base + site.rva as usize);
        }
        match self.found.load(Ordering::Acquire) {
            0 => {}
            found => return Ok(found),
        }
        let address = self.find(base, false)?;
        self.found.store(address, Ordering::Release);
        Ok(address)
    }

    /// Returns the function's address, for hooking it: its RVA in the loaded
    /// build if the bytes there match, otherwise where its pattern leads,
    /// otherwise its vtable slot.
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

    fn site(&self, index: usize) -> Option<Site> {
        self.sites.get(index).copied().flatten()
    }

    fn find(&self, base: usize, hooking: bool) -> Result<usize> {
        match self.module.build_index() {
            Some(index) => match self.site(index) {
                Some(site) => self.find_from(base, site, hooking),
                None => self.find_elsewhere(base, index),
            },
            None => self.find_on_unlisted(base, hooking),
        }
    }

    /// On a build no IR describes: the first build whose site checks out, as
    /// [`find_from`](Self::find_from) has it, otherwise the first's failure.
    fn find_on_unlisted(&self, base: usize, hooking: bool) -> Result<usize> {
        let mut first = None;
        for site in self.sites.iter().flatten() {
            match self.find_from(base, *site, hooking) {
                Ok(address) => return Ok(address),
                Err(error) => {
                    first.get_or_insert(error);
                }
            }
        }
        Err(first.unwrap_or(Error::NotInBuild {
            module: self.module.name(),
            item: self.name,
            build: "",
            scan: None,
        }))
    }

    /// Where a build's site leads: its RVA if the bytes there match, otherwise
    /// its pattern, otherwise the vtable slot.
    fn find_from(&self, base: usize, site: Site, hooking: bool) -> Result<usize> {
        let target = base + site.rva as usize;
        if self.matches(target, site) {
            return Ok(target);
        }
        let mut scan = None;
        if let Some(pattern) = site.pattern {
            match self.scan(pattern) {
                Ok(address) if address != target => {
                    self.moved(base, site.rva, address, "by pattern");
                    return Ok(address);
                }
                // The pattern agrees with the RVA. If the shape does too, only
                // the addresses in it changed; otherwise its start changed
                // after loading, most likely under another mod's hook, which
                // only matters when hooking.
                Ok(address) => {
                    if !hooking || self.shape_at(address, site.shape).is_ok() {
                        return Ok(address);
                    }
                    return Err(self.mismatch(target, site, None, None));
                }
                Err(error) => scan = Some(error),
            }
        }
        let mut vtable = None;
        if let Some(slot) = self.trusted_slot(site.shape) {
            match self.through_vtable(base, slot, site.shape) {
                Ok(address) => {
                    if address != target {
                        self.moved(base, site.rva, address, "through its class's vtable");
                    }
                    return Ok(address);
                }
                Err(miss) => vtable = Some(miss),
            }
        }
        Err(self.mismatch(target, site, scan, vtable))
    }

    /// Where the loaded build's IR lacks the function: another build's
    /// pattern, otherwise the vtable slot.
    fn find_elsewhere(&self, base: usize, index: usize) -> Result<usize> {
        let build = self.module.label(index);
        let mut scan = None;
        for (other, site) in self.sites.iter().enumerate() {
            let Some(pattern) = site.and_then(|site| site.pattern) else {
                continue;
            };
            match self.scan(pattern) {
                Ok(address) => {
                    log::debug!(
                        "imping: found `{}` in the {build} build of `{}` at +{:#x}, by the {} \
                         pattern",
                        self.name,
                        self.module.name(),
                        address.wrapping_sub(base),
                        self.module.label(other)
                    );
                    return Ok(address);
                }
                Err(error) => {
                    scan.get_or_insert(error);
                }
            }
        }
        let shape = self
            .sites
            .iter()
            .flatten()
            .map(|site| site.shape)
            .find(|shape| !shape.is_empty())
            .unwrap_or("");
        if let Some(slot) = self.trusted_slot(shape)
            && let Ok(address) = self.through_vtable(base, slot, shape)
        {
            return Ok(address);
        }
        Err(Error::NotInBuild {
            module: self.module.name(),
            item: self.name,
            build,
            scan,
        })
    }

    /// The vtable slot, if a shape can confirm it and the RTTI read is the x64
    /// layout.
    fn trusted_slot(&self, shape: &str) -> Option<VtableSlot> {
        self.slot
            .filter(|_| !shape.is_empty() && cfg!(target_pointer_width = "64"))
    }

    /// Whether the function at `target` starts with the site's expected bytes,
    /// or there are none to check.
    fn matches(&self, target: usize, site: Site) -> bool {
        site.verification.is_empty()
            || self
                .read(target, site.verification.len())
                .is_some_and(|found| found == site.verification)
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

    /// Checks a shape at `address`, returning the bytes found if it differs
    /// (empty if they're not inside the module).
    fn shape_at(&self, address: usize, shape: &str) -> core::result::Result<(), Vec<u8>> {
        let tokens: Vec<&str> = shape.split_ascii_whitespace().collect();
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

    /// Finds the function by a pattern.
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
        shape: &str,
    ) -> core::result::Result<usize, VtableMiss> {
        let vtable = crate::rtti::vtable(self.module, base, slot.type_name, slot.offset)?;
        let entry = vtable + slot.index as usize * size_of::<usize>();
        let pointer = self.read(entry, size_of::<usize>());
        let address = pointer.map(|bytes| usize::from_le_bytes(bytes.try_into().unwrap()));
        let found = match address {
            Some(address) => self.shape_at(address, shape).map(|()| address),
            None => Err(Vec::new()),
        };
        found.map_err(|found| VtableMiss::ShapeDiffers {
            type_name: slot.type_name,
            index: slot.index,
            found,
        })
    }

    fn moved(&self, base: usize, rva: u32, address: usize, how: &str) {
        log::warn!(
            "imping: `{}`+{rva:#x} didn't match; found `{}` {how} at +{:#x}, update the IR",
            self.module.name(),
            self.name,
            address.wrapping_sub(base)
        );
    }

    fn mismatch(
        &self,
        target: usize,
        site: Site,
        scan: Option<imping_hook::Error>,
        vtable: Option<VtableMiss>,
    ) -> Error {
        Error::VerificationFailed(Box::new(Mismatch {
            module: self.module.name(),
            rva: site.rva,
            expected: site.verification,
            found: self
                .read(target, site.verification.len())
                .unwrap_or_default(),
            scan,
            vtable,
        }))
    }
}
