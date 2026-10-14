//! Reads and writes strings the way generated bindings expose them: pointers
//! to NUL-terminated text, fixed-size buffers inside structs, and owned UTF-16
//! text to pass to a function.
//!
//! Run with: `cargo run --example strings`

use imping_runtime::{CStrBuf, CStrPtr, WStrBuf, WStrPtr, WString};

/// A struct as the target might lay it out, with string fields.
#[repr(C)]
#[derive(Debug)]
struct Player {
    name: CStrPtr,
    tag: CStrBuf<8>,
    title: WStrBuf<16>,
}

/// A function taking a `wchar_t*`, as the target might have.
unsafe extern "system" fn set_title(title: WStrPtr) {
    // SAFETY: Callers pass a valid, NUL-terminated string.
    println!("set_title({:?})", unsafe { title.to_string_lossy() });
}

fn main() {
    let mut player = Player {
        name: CStrPtr::from(c"Hero"),
        tag: CStrBuf::new(),
        title: WStrBuf::new(),
    };
    player.tag.set("[Guild Of Many]");
    player.title.set("Dragon Slayer");

    // SAFETY: `name` points to a static string.
    println!("name: {}", unsafe { player.name.to_string_lossy() });
    println!("tag (truncated to fit): {}", player.tag.to_string_lossy());
    println!("title: {}", player.title.to_string_lossy());
    println!("{player:?}");

    let title = WString::from("Défenseur");
    // SAFETY: `title` stays alive for the call.
    unsafe { set_title(title.as_ptr()) };
}
