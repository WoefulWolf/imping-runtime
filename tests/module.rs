//! Module identity checks and globals, against `kernel32.dll`, which every
//! Windows process has loaded.

#![cfg(windows)]

use imping_runtime::{Error, Global, Module};

/// Learns `kernel32.dll`'s identity from the mismatch reported for a wrong
/// one.
fn kernel32_identity() -> (u32, u32) {
    let probe = Module::new("kernel32.dll", 0, 0);
    // SAFETY: Nothing is done through `probe` beyond checking its identity.
    match unsafe { probe.init() } {
        Err(Error::BuildMismatch {
            found_timestamp,
            found_image_size,
            ..
        }) => (found_timestamp, found_image_size),
        other => panic!("expected a build mismatch, got {other:?}"),
    }
}

fn kernel32() -> &'static Module {
    let (timestamp, image_size) = kernel32_identity();
    Box::leak(Box::new(Module::new("kernel32.dll", timestamp, image_size)))
}

#[test]
fn init_accepts_the_right_build_and_resolves_addresses() {
    let module = kernel32();
    assert_eq!(module.base(), None);
    // SAFETY: Only the module header is read through this module.
    unsafe { module.init() }.expect("init");
    let base = module.base().expect("base after init");
    assert_ne!(base, 0);
    assert_eq!(module.address(0x10), base + 0x10);
    // SAFETY: As above.
    unsafe { module.init() }.expect("a second init is a no-op");
    assert_eq!(module.base(), Some(base));
}

#[test]
fn module_names_are_case_insensitive() {
    let (timestamp, image_size) = kernel32_identity();
    let module = Module::new("KERNEL32.DLL", timestamp, image_size);
    // SAFETY: Nothing is done through `module` beyond `init`.
    unsafe { module.init() }.expect("init");
}

#[test]
fn init_rejects_a_different_build() {
    let (timestamp, image_size) = kernel32_identity();
    let module = Module::new("kernel32.dll", timestamp ^ 1, image_size);
    // SAFETY: Nothing is done through `module` beyond `init`.
    let error = unsafe { module.init() }.unwrap_err();
    assert!(matches!(
        error,
        Error::BuildMismatch { module: "kernel32.dll", expected_timestamp, found_timestamp, .. }
            if expected_timestamp == timestamp ^ 1 && found_timestamp == timestamp
    ));
    assert_eq!(
        error.to_string(),
        format!(
            "`kernel32.dll` is a different build than the bindings were generated from: \
             timestamp {timestamp:#x} (expected {:#x}), image size {image_size:#x} \
             (expected {image_size:#x})",
            timestamp ^ 1
        )
    );
    assert_eq!(
        module.base(),
        None,
        "a failed init leaves the module uninitialized"
    );
}

#[test]
fn init_reports_a_module_that_is_not_loaded() {
    let module = Module::new("imping-no-such-module.dll", 1, 1);
    // SAFETY: Nothing is done through `module` beyond `init`.
    let error = unsafe { module.init() }.unwrap_err();
    assert!(matches!(
        error,
        Error::ModuleNotLoaded {
            module: "imping-no-such-module.dll"
        }
    ));
    assert_eq!(
        error.to_string(),
        "`imping-no-such-module.dll` is not loaded in this process"
    );
}

#[test]
#[should_panic(expected = "imping: `never.dll` is not initialized; call its `init()` first")]
fn address_panics_before_init() {
    static NEVER: Module = Module::new("never.dll", 1, 1);
    NEVER.address(0x10);
}

#[test]
fn globals_read_through_the_module() {
    let module = kernel32();
    let header: Global<u16> = Global::new(module, 0);
    assert_eq!(header.rva(), 0);
    assert_eq!(header.module().name(), "kernel32.dll");
    // SAFETY: Only the module header is read through this module.
    unsafe { module.init() }.expect("init");
    assert_eq!(header.ptr() as usize, module.base().unwrap());
    // SAFETY: Every loaded PE image starts with the "MZ" signature.
    assert_eq!(unsafe { *header.ptr() }, 0x5a4d);
}

#[test]
#[should_panic(expected = "is not initialized")]
fn global_pointers_panic_before_init() {
    static NEVER: Module = Module::new("never.dll", 1, 1);
    static VALUE: Global<u32> = Global::new(&NEVER, 0x10);
    VALUE.ptr();
}
