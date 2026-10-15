//! Module identity checks and globals, against `kernel32.dll`, which every
//! Windows process has loaded.

#![cfg(windows)]

use imping_runtime::{Build, Error, Global, Module};

/// Learns `kernel32.dll`'s build from the mismatch reported when no build
/// is accepted.
fn kernel32_build() -> Build {
    let probe = Module::new("kernel32.dll", &[]);
    // SAFETY: Nothing is done through `probe` beyond checking its identity.
    match unsafe { probe.init() } {
        Err(Error::BuildMismatch { found, .. }) => found,
        other => panic!("expected a build mismatch, got {other:?}"),
    }
}

/// A module accepting exactly `builds`.
fn module(name: &'static str, builds: Vec<Build>) -> &'static Module {
    Box::leak(Box::new(Module::new(name, builds.leak())))
}

fn kernel32() -> &'static Module {
    module("kernel32.dll", vec![kernel32_build()])
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
    let module = module("KERNEL32.DLL", vec![kernel32_build()]);
    // SAFETY: Nothing is done through `module` beyond `init`.
    unsafe { module.init() }.expect("init");
}

#[test]
fn init_accepts_any_listed_build() {
    let build = kernel32_build();
    let other = Build {
        timestamp: build.timestamp,
        image_size: build.image_size ^ 0x1000,
    };
    let module = module("kernel32.dll", vec![other, build]);
    // SAFETY: Nothing is done through `module` beyond `init`.
    unsafe { module.init() }.expect("the second build matches");
}

#[test]
fn init_rejects_a_different_build() {
    let build = kernel32_build();
    let unpacked = Build {
        timestamp: build.timestamp,
        image_size: build.image_size ^ 0x1000,
    };
    let other = Build {
        timestamp: build.timestamp ^ 1,
        image_size: build.image_size,
    };
    let module = module("kernel32.dll", vec![unpacked, other]);
    // SAFETY: Nothing is done through `module` beyond `init`.
    let error = unsafe { module.init() }.unwrap_err();
    assert!(matches!(
        error,
        Error::BuildMismatch { module: "kernel32.dll", found, expected }
            if found == build && expected == [unpacked, other]
    ));
    assert_eq!(
        error.to_string(),
        format!(
            "`kernel32.dll` is a different build than the bindings accept: \
             found timestamp {:#x}, image size {:#x}; accepted {:#x}/{:#x}, {:#x}/{:#x}",
            build.timestamp,
            build.image_size,
            unpacked.timestamp,
            unpacked.image_size,
            other.timestamp,
            other.image_size,
        )
    );
    assert_eq!(
        module.base(),
        None,
        "a failed init leaves the module uninitialized"
    );
}

#[test]
fn a_module_without_builds_accepts_none() {
    let module = Module::new("kernel32.dll", &[]);
    // SAFETY: Nothing is done through `module` beyond `init`.
    let error = unsafe { module.init() }.unwrap_err();
    assert!(error.to_string().ends_with("; accepted none"), "{error}");
}

#[test]
fn init_reports_a_module_that_is_not_loaded() {
    let module = Module::new(
        "imping-no-such-module.dll",
        &[Build {
            timestamp: 1,
            image_size: 1,
        }],
    );
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
    static NEVER: Module = Module::new(
        "never.dll",
        &[Build {
            timestamp: 1,
            image_size: 1,
        }],
    );
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
    static NEVER: Module = Module::new(
        "never.dll",
        &[Build {
            timestamp: 1,
            image_size: 1,
        }],
    );
    static VALUE: Global<u32> = Global::new(&NEVER, 0x10);
    VALUE.ptr();
}

#[test]
fn init_any_build_initializes_an_unlisted_build() {
    let build = kernel32_build();
    let module = module(
        "kernel32.dll",
        vec![Build {
            timestamp: build.timestamp ^ 1,
            image_size: build.image_size,
        }],
    );
    // SAFETY: Only the module header is read through this module.
    assert!(unsafe { module.init() }.is_err());
    // SAFETY: As above.
    let found = unsafe { module.init_any_build() }.expect("any build");
    assert_eq!(found, build);
    let base = module.base().expect("initialized anyway");
    // SAFETY: As above.
    unsafe { module.init() }.expect("init is a no-op once initialized");
    // SAFETY: As above.
    assert_eq!(unsafe { module.init_any_build() }.expect("again"), build);
    assert_eq!(module.base(), Some(base));
}

#[test]
fn init_any_build_still_needs_the_module_loaded() {
    let module = Module::new("imping-no-such-module.dll", &[]);
    // SAFETY: Nothing is done through `module` beyond `init_any_build`.
    let error = unsafe { module.init_any_build() }.unwrap_err();
    assert!(matches!(
        error,
        Error::ModuleNotLoaded {
            module: "imping-no-such-module.dll"
        }
    ));
}
