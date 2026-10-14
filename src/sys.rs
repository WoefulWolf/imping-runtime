//! The only OS-specific code: finding a loaded module and reading its build
//! identity.

/// A module's build identity, from its image header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Identity {
    pub(crate) timestamp: u32,
    pub(crate) image_size: u32,
}

/// Why a module couldn't be located.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Each platform constructs only some of the variants.
#[allow(dead_code)]
pub(crate) enum LocateError {
    NotLoaded,
    InvalidImage,
    Unsupported,
}

/// Finds the loaded module `name`, returning its base address and identity.
pub(crate) fn locate(name: &str) -> Result<(usize, Identity), LocateError> {
    imp::locate(name)
}

/// Decodes bytes in the system's ANSI code page; lossy UTF-8 where there is
/// no such code page.
pub(crate) fn ansi_to_string(bytes: &[u8]) -> String {
    imp::ansi_to_string(bytes)
}

#[cfg(windows)]
mod imp {
    use super::{Identity, LocateError};
    use windows_sys::Win32::Globalization::{CP_ACP, MultiByteToWideChar};
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;

    pub(super) fn ansi_to_string(bytes: &[u8]) -> String {
        let Ok(len) = i32::try_from(bytes.len()) else {
            return String::from_utf8_lossy(bytes).into_owned();
        };
        if len == 0 {
            return String::new();
        }
        // SAFETY: `bytes` is valid for `len` bytes; a null output buffer of
        // size 0 asks only for the length needed.
        let needed = unsafe {
            MultiByteToWideChar(CP_ACP, 0, bytes.as_ptr(), len, core::ptr::null_mut(), 0)
        };
        let Ok(capacity) = usize::try_from(needed) else {
            return String::from_utf8_lossy(bytes).into_owned();
        };
        let mut wide = vec![0u16; capacity];
        // SAFETY: `bytes` is valid for `len` bytes and `wide` for `needed`
        // code units.
        let written = unsafe {
            MultiByteToWideChar(CP_ACP, 0, bytes.as_ptr(), len, wide.as_mut_ptr(), needed)
        };
        let written = usize::try_from(written).unwrap_or(0).min(capacity);
        String::from_utf16_lossy(&wide[..written])
    }

    /// Headers beyond this offset are not plausible; it bounds every read.
    const MAX_HEADER_OFFSET: u32 = 0x1000;

    pub(super) fn locate(name: &str) -> Result<(usize, Identity), LocateError> {
        let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        // SAFETY: `wide` is a NUL-terminated UTF-16 string that outlives the
        // call. `GetModuleHandleW` only looks the name up; it neither keeps the
        // pointer nor changes the module's reference count.
        let handle = unsafe { GetModuleHandleW(wide.as_ptr()) };
        if handle.is_null() {
            return Err(LocateError::NotLoaded);
        }
        let base = handle as usize;
        // SAFETY: `base` is the base of a module loaded in this process, whose
        // image header is mapped readable.
        let identity = unsafe { pe_identity(base) }.ok_or(LocateError::InvalidImage)?;
        Ok((base, identity))
    }

    /// Reads the timestamp and image size from the PE header at `base`.
    ///
    /// # Safety
    ///
    /// `base` must be the base address of a loaded module, so that its first
    /// `MAX_HEADER_OFFSET` + 0x100 bytes are mapped readable.
    unsafe fn pe_identity(base: usize) -> Option<Identity> {
        let read_u16 = |offset: u32| {
            // SAFETY: Callers only pass offsets below `MAX_HEADER_OFFSET` +
            // 0x100, which the caller guarantees are readable.
            unsafe { core::ptr::read_unaligned((base + offset as usize) as *const u16) }
        };
        let read_u32 = |offset: u32| {
            // SAFETY: As for `read_u16`.
            unsafe { core::ptr::read_unaligned((base + offset as usize) as *const u32) }
        };

        // IMAGE_DOS_HEADER: "MZ", then e_lfanew at 0x3c.
        if read_u16(0) != 0x5a4d {
            return None;
        }
        let nt = read_u32(0x3c);
        if nt == 0 || nt > MAX_HEADER_OFFSET {
            return None;
        }
        // IMAGE_NT_HEADERS: "PE\0\0", IMAGE_FILE_HEADER (20 bytes), then the
        // optional header. TimeDateStamp is at file header + 4; SizeOfImage is
        // at optional header + 56 in both PE32 and PE32+.
        if read_u32(nt) != 0x0000_4550 {
            return None;
        }
        let optional = nt + 4 + 20;
        let magic = read_u16(optional);
        if magic != 0x10b && magic != 0x20b {
            return None;
        }
        Some(Identity {
            timestamp: read_u32(nt + 4 + 4),
            image_size: read_u32(optional + 56),
        })
    }
}

#[cfg(not(windows))]
mod imp {
    use super::{Identity, LocateError};

    pub(super) fn ansi_to_string(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).into_owned()
    }

    pub(super) fn locate(_name: &str) -> Result<(usize, Identity), LocateError> {
        Err(LocateError::Unsupported)
    }
}
