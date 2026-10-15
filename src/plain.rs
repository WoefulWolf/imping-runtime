//! Plain data: types for which every bit pattern is a valid value.

use crate::strings::{CStrBuf, CStrPtr, WStrBuf, WStrPtr};

/// A type for which every bit pattern of its size is a valid value, so it can
/// be read from and written to the target's memory without checks.
///
/// Implemented for the integer and float types, raw pointers to sized types,
/// the string types, and arrays of plain types. Generated bindings implement it
/// for their enum newtypes and for structs and unions made only of plain
/// fields. It is not implemented for `bool`, function pointers or references,
/// which have invalid bit patterns.
///
/// [`Global::read`](crate::Global::read) and
/// [`Global::write`](crate::Global::write) are safe for plain types.
///
/// # Safety
///
/// Every bit pattern of `size_of::<Self>()` bytes must be a valid value of
/// `Self`.
pub unsafe trait Plain: Copy + 'static {}

macro_rules! plain {
    ($($ty:ty),*) => {
        $(
            // SAFETY: Every bit pattern is a valid value of a primitive
            // integer or float.
            unsafe impl Plain for $ty {}
        )*
    };
}

plain!(
    u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize, f32, f64
);

// SAFETY: A raw pointer to a sized type is an address; every address is a
// valid (if not necessarily dereferenceable) value.
unsafe impl<T: 'static> Plain for *const T {}

// SAFETY: As for `*const T`.
unsafe impl<T: 'static> Plain for *mut T {}

// SAFETY: An array has no padding between elements, and every bit pattern of
// each element is valid.
unsafe impl<T: Plain, const N: usize> Plain for [T; N] {}

// SAFETY: A transparent wrapper of a raw pointer.
unsafe impl Plain for CStrPtr {}

// SAFETY: A transparent wrapper of a raw pointer.
unsafe impl Plain for WStrPtr {}

// SAFETY: A transparent wrapper of a byte array.
unsafe impl<const N: usize> Plain for CStrBuf<N> {}

// SAFETY: A transparent wrapper of a `u16` array.
unsafe impl<const N: usize> Plain for WStrBuf<N> {}
