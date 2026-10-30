//! Finding a class's vtable by its MSVC run-time type information, x64 only.
//!
//! The class's decorated type name (`.?AVEntity@game@@`) is the end of its
//! type descriptor. A complete object locator points at the descriptor by RVA,
//! and the pointer just before a vtable points at the locator. Names survive a
//! rebuild where addresses don't.

use crate::error::VtableMiss;
use crate::module::Module;

/// Returns the address of the vtable of class `type_name` whose locator has
/// `offset`, looking each one up once per module.
pub(crate) fn vtable(
    module: &Module,
    base: usize,
    type_name: &'static str,
    offset: u32,
) -> Result<usize, VtableMiss> {
    let mut cache = module
        .vtables
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some((.., found)) = cache
        .iter()
        .find(|(name, at, _)| *name == type_name && *at == offset)
    {
        return found.clone();
    }
    let found = find(base, module.image_size(), type_name, offset);
    cache.push((type_name, offset, found.clone()));
    found
}

fn find(
    base: usize,
    image_size: usize,
    type_name: &'static str,
    offset: u32,
) -> Result<usize, VtableMiss> {
    // SAFETY: `base` is an initialized module's base, so its whole image is
    // mapped, readable where its sections say so, and stays mapped while it's
    // loaded.
    let sections = unsafe { readable_data(base, image_size) };

    // Type descriptors: the name, NUL-terminated, 16 bytes in.
    let name = type_name.as_bytes();
    let mut descriptors = Vec::new();
    for &(rva, bytes) in &sections {
        for at in 16..bytes.len().saturating_sub(name.len()) {
            if bytes[at + name.len()] == 0 && &bytes[at..at + name.len()] == name {
                descriptors.push(rva + at as u32 - 16);
            }
        }
    }
    if descriptors.is_empty() {
        return Err(VtableMiss::ClassNotFound { type_name });
    }

    // Locators: signature 1, the offset, the descriptor's RVA at +12 and their
    // own RVA at +20. Then the vtable, after a pointer to the locator.
    for &(rva, bytes) in &sections {
        for at in (0..bytes.len().saturating_sub(24)).step_by(4) {
            let field =
                |i: usize| u32::from_le_bytes(bytes[at + i..at + i + 4].try_into().unwrap());
            if field(0) != 1
                || field(4) != offset
                || field(20) != rva + at as u32
                || !descriptors.contains(&field(12))
            {
                continue;
            }
            let locator = (base + field(20) as usize) as u64;
            for &(rva, bytes) in &sections {
                for at in (0..bytes.len().saturating_sub(8)).step_by(8) {
                    if u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap()) == locator {
                        return Ok(base + rva as usize + at + 8);
                    }
                }
            }
        }
    }
    Err(VtableMiss::VtableNotFound { type_name, offset })
}

/// Returns each readable, non-executable section of the image at `base`, by
/// RVA.
///
/// # Safety
///
/// `base` must be the base of a loaded module whose image is `image_size`
/// bytes, which must stay mapped while the slices are used.
unsafe fn readable_data<'a>(base: usize, image_size: usize) -> Vec<(u32, &'a [u8])> {
    const READ: u32 = 0x4000_0000;
    const EXECUTE: u32 = 0x2000_0000;
    let read = |offset: usize, len: usize| -> Option<&'a [u8]> {
        if offset.checked_add(len)? > image_size {
            return None;
        }
        // SAFETY: the bytes are inside the image, which the caller keeps
        // mapped; headers and data sections are readable.
        Some(unsafe { core::slice::from_raw_parts((base + offset) as *const u8, len) })
    };
    let u16_at = |offset| read(offset, 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let u32_at = |offset| read(offset, 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()));

    let mut sections = Vec::new();
    let Some(nt) = u32_at(0x3c).map(|nt| nt as usize) else {
        return sections;
    };
    let (Some(count), Some(optional_size)) = (u16_at(nt + 6), u16_at(nt + 20)) else {
        return sections;
    };
    let table = nt + 24 + optional_size as usize;
    for i in 0..count as usize {
        let header = table + i * 40;
        let (Some(size), Some(rva), Some(characteristics)) =
            (u32_at(header + 8), u32_at(header + 12), u32_at(header + 36))
        else {
            break;
        };
        if characteristics & READ == 0 || characteristics & EXECUTE != 0 {
            continue;
        }
        if let Some(bytes) = read(rva as usize, size as usize) {
            sections.push((rva, bytes));
        }
    }
    sections
}
