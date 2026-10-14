//! Strings in the target's memory: pointers to NUL-terminated narrow (`char*`)
//! and UTF-16 (`wchar_t*`) strings, fixed-size buffers inside structs, and an
//! owned UTF-16 string to pass to the target.
//!
//! Every type here has the layout of the C type it stands for, so generated
//! structs and function signatures use them directly.

use crate::sys;
use core::ffi::{CStr, c_char};
use core::fmt;
use core::str::Utf8Error;
use std::borrow::Cow;
use widestring::{U16CStr, U16CString};

/// A pointer to a NUL-terminated narrow string (`char*`), possibly null.
///
/// Reading it is `unsafe`: the pointer comes from the target and can't be
/// checked. A null pointer reads as an empty string.
///
/// ```
/// use imping_runtime::CStrPtr;
///
/// let greeting = CStrPtr::from(c"hello");
/// // SAFETY: `greeting` points to a static, NUL-terminated string.
/// assert_eq!(unsafe { greeting.to_string_lossy() }, "hello");
/// assert_eq!(unsafe { CStrPtr::null().to_string_lossy() }, "");
/// ```
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CStrPtr(*const c_char);

impl CStrPtr {
    /// Wraps a raw pointer.
    pub const fn new(ptr: *const c_char) -> Self {
        Self(ptr)
    }

    /// A null pointer.
    pub const fn null() -> Self {
        Self(core::ptr::null())
    }

    /// Whether the pointer is null.
    pub fn is_null(self) -> bool {
        self.0.is_null()
    }

    /// The raw pointer.
    pub const fn as_ptr(self) -> *const c_char {
        self.0
    }

    /// The raw pointer, for functions that write through it.
    pub const fn as_mut_ptr(self) -> *mut c_char {
        self.0.cast_mut()
    }

    /// The string's bytes, without the terminating NUL. Empty if the pointer
    /// is null.
    ///
    /// As with [`CStr::from_ptr`], the caller chooses the lifetime `'a`.
    ///
    /// # Safety
    ///
    /// A non-null pointer must point to a NUL-terminated string that stays
    /// valid and unchanged for `'a`.
    pub unsafe fn to_bytes<'a>(self) -> &'a [u8] {
        if self.0.is_null() {
            return &[];
        }
        // SAFETY: Forwarded from the caller.
        unsafe { CStr::from_ptr(self.0) }.to_bytes()
    }

    /// The string as UTF-8.
    ///
    /// # Errors
    ///
    /// If the bytes are not valid UTF-8.
    ///
    /// # Safety
    ///
    /// As for [`to_bytes`](Self::to_bytes).
    pub unsafe fn to_str<'a>(self) -> Result<&'a str, Utf8Error> {
        // SAFETY: Forwarded from the caller.
        core::str::from_utf8(unsafe { self.to_bytes() })
    }

    /// The string as UTF-8, with invalid sequences replaced by `�`.
    ///
    /// # Safety
    ///
    /// As for [`to_bytes`](Self::to_bytes).
    pub unsafe fn to_string_lossy<'a>(self) -> Cow<'a, str> {
        // SAFETY: Forwarded from the caller.
        String::from_utf8_lossy(unsafe { self.to_bytes() })
    }

    /// The string decoded with the system's ANSI code page, as the target's
    /// Windows "A" functions would. On other platforms, the same as
    /// [`to_string_lossy`](Self::to_string_lossy).
    ///
    /// # Safety
    ///
    /// A non-null pointer must point to a NUL-terminated string that stays
    /// valid and unchanged during the call.
    pub unsafe fn to_string_ansi(self) -> String {
        // SAFETY: Forwarded from the caller.
        sys::ansi_to_string(unsafe { self.to_bytes() })
    }
}

impl Default for CStrPtr {
    /// A null pointer.
    fn default() -> Self {
        Self::null()
    }
}

impl From<&'static CStr> for CStrPtr {
    /// Points to a static C string, such as a `c"…"` literal.
    fn from(value: &'static CStr) -> Self {
        Self(value.as_ptr())
    }
}

impl fmt::Debug for CStrPtr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CStrPtr({:p})", self.0)
    }
}

/// A pointer to a NUL-terminated UTF-16 string (`wchar_t*` on Windows),
/// possibly null.
///
/// Reading it is `unsafe`: the pointer comes from the target and can't be
/// checked. A null pointer reads as an empty string.
///
/// ```
/// use imping_runtime::WString;
///
/// let title = WString::from("Héllo");
/// // SAFETY: `title` is alive and NUL-terminated.
/// assert_eq!(unsafe { title.as_ptr().to_string_lossy() }, "Héllo");
/// ```
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct WStrPtr(*const u16);

impl WStrPtr {
    /// Wraps a raw pointer.
    pub const fn new(ptr: *const u16) -> Self {
        Self(ptr)
    }

    /// A null pointer.
    pub const fn null() -> Self {
        Self(core::ptr::null())
    }

    /// Whether the pointer is null.
    pub fn is_null(self) -> bool {
        self.0.is_null()
    }

    /// The raw pointer.
    pub const fn as_ptr(self) -> *const u16 {
        self.0
    }

    /// The raw pointer, for functions that write through it.
    pub const fn as_mut_ptr(self) -> *mut u16 {
        self.0.cast_mut()
    }

    /// The string's UTF-16 code units, without the terminating NUL. Empty if
    /// the pointer is null.
    ///
    /// As with [`CStr::from_ptr`], the caller chooses the lifetime `'a`.
    ///
    /// # Safety
    ///
    /// A non-null pointer must point to a NUL-terminated UTF-16 string that
    /// stays valid and unchanged for `'a`.
    pub unsafe fn to_wide<'a>(self) -> &'a [u16] {
        if self.0.is_null() {
            return &[];
        }
        // SAFETY: Forwarded from the caller.
        unsafe { U16CStr::from_ptr_str(self.0) }.as_slice()
    }

    /// The string as UTF-8, with unpaired surrogates replaced by `�`.
    ///
    /// # Safety
    ///
    /// A non-null pointer must point to a NUL-terminated UTF-16 string that
    /// stays valid and unchanged during the call.
    pub unsafe fn to_string_lossy(self) -> String {
        // SAFETY: Forwarded from the caller.
        String::from_utf16_lossy(unsafe { self.to_wide() })
    }
}

impl Default for WStrPtr {
    /// A null pointer.
    fn default() -> Self {
        Self::null()
    }
}

impl fmt::Debug for WStrPtr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WStrPtr({:p})", self.0)
    }
}

/// An owned, NUL-terminated UTF-16 string, to pass to the target as a
/// `wchar_t*`.
///
/// ```
/// use imping_runtime::WString;
///
/// let name = WString::from("Hero");
/// assert_eq!(name.to_wide(), [72, 101, 114, 111]);
/// ```
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct WString(U16CString);

impl WString {
    /// An empty string.
    pub fn new() -> Self {
        Self::default()
    }

    /// A pointer to the string, valid while it is alive and unchanged.
    pub fn as_ptr(&self) -> WStrPtr {
        WStrPtr(self.0.as_ptr())
    }

    /// The string's UTF-16 code units, without the terminating NUL.
    pub fn to_wide(&self) -> &[u16] {
        self.0.as_slice()
    }

    /// The string as UTF-8.
    pub fn to_string_lossy(&self) -> String {
        self.0.to_string_lossy()
    }
}

impl From<&str> for WString {
    /// Encodes `value` as UTF-16, stopping at its first NUL, if any.
    fn from(value: &str) -> Self {
        Self(U16CString::from_str_truncate(value))
    }
}

impl fmt::Debug for WString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("WString")
            .field(&self.to_string_lossy())
            .finish()
    }
}

/// A fixed-size narrow string buffer inside a struct (`char name[N]`),
/// holding a string up to the first NUL.
///
/// ```
/// use imping_runtime::CStrBuf;
///
/// let mut tag = CStrBuf::<8>::new();
/// tag.set("Héllo, world");
/// assert_eq!(tag.to_string_lossy(), "Héllo,"); // at most 7 bytes, then the NUL
/// ```
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CStrBuf<const N: usize>([u8; N]);

impl<const N: usize> CStrBuf<N> {
    /// An empty buffer: all zero.
    pub const fn new() -> Self {
        Self([0; N])
    }

    /// The string's bytes: up to the first NUL, or the whole buffer if it has
    /// none.
    pub fn to_bytes(&self) -> &[u8] {
        let end = self.0.iter().position(|&byte| byte == 0).unwrap_or(N);
        &self.0[..end]
    }

    /// The string as UTF-8.
    ///
    /// # Errors
    ///
    /// If the bytes are not valid UTF-8.
    pub fn to_str(&self) -> Result<&str, Utf8Error> {
        core::str::from_utf8(self.to_bytes())
    }

    /// The string as UTF-8, with invalid sequences replaced by `�`.
    pub fn to_string_lossy(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(self.to_bytes())
    }

    /// The string decoded with the system's ANSI code page. On other
    /// platforms, the same as [`to_string_lossy`](Self::to_string_lossy).
    pub fn to_string_ansi(&self) -> String {
        sys::ansi_to_string(self.to_bytes())
    }

    /// Stores `value` as UTF-8: as much as fits before the terminating NUL,
    /// without splitting a character, then zeros. A NUL in `value` ends it.
    pub fn set(&mut self, value: &str) {
        let value = value.split('\0').next().unwrap_or_default();
        let mut len = value.len().min(N.saturating_sub(1));
        while !value.is_char_boundary(len) {
            len -= 1;
        }
        self.0 = [0; N];
        self.0[..len].copy_from_slice(&value.as_bytes()[..len]);
    }

    /// The whole buffer.
    pub fn as_array(&self) -> &[u8; N] {
        &self.0
    }

    /// The whole buffer, to write to it directly.
    pub fn as_array_mut(&mut self) -> &mut [u8; N] {
        &mut self.0
    }

    /// A pointer to the buffer, valid while it is alive and unmoved. Reading
    /// through it needs a NUL within the buffer, which [`set`](Self::set)
    /// guarantees.
    pub fn as_ptr(&self) -> CStrPtr {
        CStrPtr(self.0.as_ptr().cast())
    }
}

impl<const N: usize> Default for CStrBuf<N> {
    /// An empty buffer: all zero.
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> fmt::Debug for CStrBuf<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("CStrBuf")
            .field(&self.to_string_lossy())
            .finish()
    }
}

/// A fixed-size UTF-16 string buffer inside a struct (`wchar_t name[N]`),
/// holding a string up to the first NUL.
///
/// ```
/// use imping_runtime::WStrBuf;
///
/// let mut name = WStrBuf::<4>::new();
/// name.set("Héllo");
/// assert_eq!(name.to_string_lossy(), "Hél"); // at most 3 code units, then the NUL
/// ```
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct WStrBuf<const N: usize>([u16; N]);

impl<const N: usize> WStrBuf<N> {
    /// An empty buffer: all zero.
    pub const fn new() -> Self {
        Self([0; N])
    }

    /// The string's UTF-16 code units: up to the first NUL, or the whole
    /// buffer if it has none.
    pub fn to_wide(&self) -> &[u16] {
        let end = self.0.iter().position(|&unit| unit == 0).unwrap_or(N);
        &self.0[..end]
    }

    /// The string as UTF-8, with unpaired surrogates replaced by `�`.
    pub fn to_string_lossy(&self) -> String {
        String::from_utf16_lossy(self.to_wide())
    }

    /// Stores `value` as UTF-16: as much as fits before the terminating NUL,
    /// without splitting a surrogate pair, then zeros. A NUL in `value` ends
    /// it.
    pub fn set(&mut self, value: &str) {
        let value = value.split('\0').next().unwrap_or_default();
        let capacity = N.saturating_sub(1);
        self.0 = [0; N];
        let mut len = 0;
        for c in value.chars() {
            let mut units = [0; 2];
            let encoded = c.encode_utf16(&mut units);
            if len + encoded.len() > capacity {
                break;
            }
            self.0[len..len + encoded.len()].copy_from_slice(encoded);
            len += encoded.len();
        }
    }

    /// The whole buffer.
    pub fn as_array(&self) -> &[u16; N] {
        &self.0
    }

    /// The whole buffer, to write to it directly.
    pub fn as_array_mut(&mut self) -> &mut [u16; N] {
        &mut self.0
    }

    /// A pointer to the buffer, valid while it is alive and unmoved. Reading
    /// through it needs a NUL within the buffer, which [`set`](Self::set)
    /// guarantees.
    pub fn as_ptr(&self) -> WStrPtr {
        WStrPtr(self.0.as_ptr())
    }
}

impl<const N: usize> Default for WStrBuf<N> {
    /// An empty buffer: all zero.
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> fmt::Debug for WStrBuf<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("WStrBuf")
            .field(&self.to_string_lossy())
            .finish()
    }
}
