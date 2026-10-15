//! The string types: reading, writing, truncation, encodings and layouts.

use imping_runtime::{CStrBuf, CStrPtr, WStrBuf, WStrPtr, WString};
use std::ffi::{CString, c_char};
use std::mem::{align_of, size_of};

#[test]
fn layouts_match_the_c_types() {
    assert_eq!(size_of::<CStrPtr>(), size_of::<*const c_char>());
    assert_eq!(size_of::<WStrPtr>(), size_of::<*const u16>());
    assert_eq!(
        (size_of::<CStrBuf<32>>(), align_of::<CStrBuf<32>>()),
        (32, 1)
    );
    assert_eq!((size_of::<WStrBuf<4>>(), align_of::<WStrBuf<4>>()), (8, 2));
    assert_eq!(
        size_of::<Option<CStrPtr>>(),
        size_of::<[usize; 2]>(),
        "no niche: null is a value"
    );
}

#[test]
fn narrow_pointers_read_bytes_utf8_and_null() {
    let text = CStrPtr::from(c"Hello, world");
    // SAFETY: `text` points to a static string.
    unsafe {
        assert_eq!(text.to_bytes(), b"Hello, world");
        assert_eq!(text.to_str(), Ok("Hello, world"));
        assert_eq!(text.to_string_lossy(), "Hello, world");
        assert_eq!(text.to_string_ansi(), "Hello, world");
    }

    let null = CStrPtr::null();
    assert!(null.is_null());
    assert_eq!(CStrPtr::default(), null);
    // SAFETY: Null pointers read as empty strings.
    unsafe {
        assert_eq!(null.to_bytes(), b"");
        assert_eq!(null.to_string_lossy(), "");
        assert_eq!(null.to_string_ansi(), "");
    }
}

#[test]
fn invalid_utf8_is_reported_or_replaced() {
    let owned = CString::new(vec![b'h', 0xff, b'i']).unwrap();
    let text = CStrPtr::new(owned.as_ptr());
    // SAFETY: `owned` outlives every use of `text`.
    unsafe {
        assert!(text.to_str().is_err());
        assert_eq!(text.to_string_lossy(), "h\u{fffd}i");
    }
}

#[test]
fn wide_strings_round_trip_including_surrogate_pairs() {
    let owned = WString::from("Héllo 😀");
    assert_eq!(owned.to_string_lossy(), "Héllo 😀");
    assert_eq!(owned.to_wide().len(), 8, "the emoji is a surrogate pair");
    let pointer = owned.as_ptr();
    // SAFETY: `owned` is alive and NUL-terminated.
    unsafe {
        assert_eq!(pointer.to_wide(), owned.to_wide());
        assert_eq!(pointer.to_string_lossy(), "Héllo 😀");
    }
    assert_eq!(WString::from("cut\0here").to_string_lossy(), "cut");
    // SAFETY: Null pointers read as empty strings.
    assert_eq!(unsafe { WStrPtr::null().to_string_lossy() }, "");
}

#[test]
fn narrow_buffers_truncate_at_character_boundaries_and_clear() {
    let mut buffer = CStrBuf::<6>::new();
    assert_eq!(buffer.to_string_lossy(), "");
    buffer.set("Héllo");
    // 5 bytes fit before the NUL; "Héll" is 5 bytes, "é" is 2.
    assert_eq!(buffer.to_str(), Ok("Héll"));
    assert_eq!(buffer.as_array(), b"H\xc3\xa9ll\0");

    buffer.set("ab");
    assert_eq!(buffer.as_array(), b"ab\0\0\0\0", "the rest is cleared");
    buffer.set("x\0y");
    assert_eq!(buffer.to_str(), Ok("x"));

    // A buffer the target filled to the end, without a NUL.
    buffer.as_array_mut().copy_from_slice(b"abcdef");
    assert_eq!(buffer.to_bytes(), b"abcdef");
    assert_eq!(format!("{buffer:?}"), "CStrBuf(\"abcdef\")");

    let mut empty = CStrBuf::<0>::new();
    empty.set("anything");
    assert_eq!(empty.to_bytes(), b"");
}

#[test]
fn narrow_buffer_pointers_read_back() {
    let mut buffer = CStrBuf::<16>::default();
    buffer.set("inline");
    // SAFETY: `buffer` is alive, unmoved and NUL-terminated.
    assert_eq!(unsafe { buffer.as_ptr().to_string_lossy() }, "inline");
}

#[test]
fn wide_buffers_never_split_a_surrogate_pair() {
    let mut buffer = WStrBuf::<4>::new();
    buffer.set("ab😀");
    // 3 code units fit before the NUL; the emoji needs 2, so it is dropped.
    assert_eq!(buffer.to_string_lossy(), "ab");
    buffer.set("a😀");
    assert_eq!(buffer.to_string_lossy(), "a😀");
    assert_eq!(buffer.as_array()[3], 0);
    assert_eq!(format!("{buffer:?}"), "WStrBuf(\"a😀\")");
    // SAFETY: `buffer` is alive, unmoved and NUL-terminated.
    assert_eq!(unsafe { buffer.as_ptr().to_string_lossy() }, "a😀");
}

#[cfg(windows)]
#[test]
fn ansi_decoding_uses_the_system_code_page() {
    // Plain ASCII reads the same in every ANSI code page.
    let mut buffer = CStrBuf::<8>::new();
    buffer.set("ascii");
    assert_eq!(buffer.to_string_ansi(), "ascii");
    // A byte that is invalid UTF-8 still decodes to some text, never panics.
    buffer.as_array_mut()[..2].copy_from_slice(&[0xe9, 0]);
    assert_eq!(buffer.to_string_ansi().chars().count(), 1);
}

#[test]
fn string_types_are_plain_data() {
    fn assert_plain<T: imping_runtime::Plain>() {}
    assert_plain::<CStrPtr>();
    assert_plain::<WStrPtr>();
    assert_plain::<CStrBuf<16>>();
    assert_plain::<WStrBuf<16>>();
    assert_plain::<[CStrPtr; 4]>();
}
