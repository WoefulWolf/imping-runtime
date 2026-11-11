//! Bindings generated from several labelled builds: which one is loaded, and
//! functions and globals that only some of them have.

#![cfg(all(windows, target_arch = "x86_64"))]

use imping_runtime::__private::{self, Function, Pattern, Site};
use imping_runtime::{Build, Error, Global, Module};
use std::hint::black_box;
use std::sync::OnceLock;

type Signature = unsafe extern "system" fn(u64) -> u64;

#[inline(never)]
extern "system" fn present(a: u64) -> u64 {
    black_box(a).wrapping_mul(0x5851_F42D_4C95_7F2D) ^ 0x1405_7B7E_F767_814F
}

#[inline(never)]
extern "system" fn elsewhere(a: u64) -> u64 {
    black_box(a).wrapping_mul(0x2127_599B_F432_5C37) ^ 0x6C62_272E_07BB_0142
}

fn exe_name() -> &'static str {
    static NAME: OnceLock<&'static str> = OnceLock::new();
    NAME.get_or_init(|| {
        let path = std::env::current_exe().expect("current exe");
        let name = path
            .file_name()
            .expect("file name")
            .to_str()
            .expect("UTF-8");
        Box::leak(name.to_owned().into_boxed_str())
    })
}

/// This test executable's build.
fn exe_build() -> Build {
    let probe = Module::new(exe_name(), &[]);
    // SAFETY: Nothing is done through `probe` beyond checking its identity.
    unsafe { probe.init_any_build() }.expect("probe")
}

/// A module that knows two builds, `old` and `new`, this executable being
/// `new`.
fn two_builds() -> &'static Module {
    static EXE: OnceLock<&'static Module> = OnceLock::new();
    EXE.get_or_init(|| {
        let build = exe_build();
        let old = Build {
            timestamp: build.timestamp ^ 1,
            image_size: build.image_size,
        };
        let module = Box::leak(Box::new(__private::module(
            exe_name(),
            vec![old, build].leak(),
            &[0, 1],
            &["old", "new"],
        )));
        // SAFETY: The fixtures are real functions of this executable with the
        // signatures used for them.
        unsafe { module.init() }.expect("init");
        module
    })
}

fn rva(function: Signature) -> u32 {
    u32::try_from(function as usize - two_builds().base().unwrap()).unwrap()
}

/// The first bytes of a function, as many as are unique in this executable,
/// as a pattern.
fn unique_pattern(function: Signature) -> &'static str {
    for len in 8..=64 {
        // SAFETY: The function is followed by more code in this executable.
        let bytes = unsafe { std::slice::from_raw_parts(function as *const u8, len) };
        let pattern: Vec<String> = bytes.iter().map(|b| format!("{b:02X}")).collect();
        let pattern = pattern.join(" ");
        if imping_hook::scan::find(&pattern).is_ok() {
            return Box::leak(pattern.into_boxed_str());
        }
    }
    panic!("no unique start for {:p}", function as *const ());
}

fn function(sites: Vec<Option<Site>>) -> &'static Function {
    Box::leak(Box::new(Function::new(
        two_builds(),
        "fixture",
        sites.leak(),
        None,
    )))
}

fn site(rva: u32, pattern: Option<&'static str>) -> Site {
    Site {
        rva,
        verification: &[],
        shape: "",
        pattern: pattern.map(|bytes| Pattern {
            bytes,
            offset: 0,
            follow_call: false,
        }),
    }
}

#[test]
fn init_tells_which_labelled_build_is_loaded() {
    assert_eq!(__private::build_index(two_builds()), Some(1));
}

#[test]
fn an_accepted_build_counts_as_its_label() {
    let build = exe_build();
    let module = Box::leak(Box::new(__private::module(
        exe_name(),
        vec![build].leak(),
        &[0],
        &["only"],
    )));
    assert_eq!(__private::build_index(module), None, "before init");
    // SAFETY: Nothing is done through `module` beyond `init`.
    unsafe { module.init() }.expect("init");
    assert_eq!(__private::build_index(module), Some(0));
}

#[test]
fn a_function_uses_the_loaded_builds_rva() {
    let function = function(vec![Some(site(0x10, None)), Some(site(rva(present), None))]);
    assert_eq!(function.rva(), Some(rva(present)));
    assert_eq!(function.resolve().unwrap(), present as *const () as usize);
}

#[test]
fn a_function_the_loaded_build_lacks_is_found_by_another_builds_pattern() {
    let function = function(vec![
        Some(site(0x10, Some(unique_pattern(elsewhere)))),
        None,
    ]);
    assert_eq!(function.rva(), None);
    assert_eq!(function.resolve().unwrap(), elsewhere as *const () as usize);
}

#[test]
fn a_function_nothing_finds_is_not_in_the_build() {
    let error = function(vec![Some(site(0x10, None)), None])
        .resolve()
        .unwrap_err();
    assert!(
        matches!(
            error,
            Error::NotInBuild {
                item: "fixture",
                build: "new",
                scan: None,
                ..
            }
        ),
        "{error:?}"
    );
    assert_eq!(
        error.to_string(),
        format!(
            "`fixture` isn't in the new IR of `{}`, and no other build has a pattern for it",
            exe_name()
        )
    );

    let missing = "F1 F1 F1 F1 F1 F1 F1 F1";
    let error = function(vec![Some(site(0x10, Some(missing))), None])
        .resolve()
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains(", and its pattern matched nothing ("),
        "{error}"
    );
}

#[test]
fn a_global_has_the_loaded_builds_address() {
    let module = two_builds();
    let global: &'static Global<u16> = Box::leak(Box::new(__private::global(
        module,
        "HEADER",
        &[Some(0x10), Some(0)],
    )));
    assert_eq!(global.rva(), Some(0));
    assert_eq!(global.read(), 0x5a4d, "the image's `MZ`");
}

#[test]
fn on_an_unlisted_build_only_a_globals_pointer_falls_back() {
    let build = exe_build();
    let other = |bit| Build {
        timestamp: build.timestamp ^ bit,
        image_size: build.image_size,
    };
    let module: &'static Module = Box::leak(Box::new(__private::module(
        exe_name(),
        vec![other(1), other(2)].leak(),
        &[0, 1],
        &["old", "older"],
    )));
    // SAFETY: Only the image's header is read through `module`.
    unsafe { module.init_any_build() }.expect("init any build");
    let global: &'static Global<u16> = Box::leak(Box::new(__private::global(
        module,
        "HEADER",
        &[None, Some(0)],
    )));
    assert_eq!(global.rva(), None, "no IR describes this build");
    assert_eq!(global.read(), 0x5a4d, "`ptr` uses `older`'s address");
    let function = Box::leak(Box::new(Function::new(
        module,
        "present",
        vec![Some(site(0x10, None)), None].leak(),
        None,
    )));
    assert_eq!(function.rva(), None, "the same for a function");
}

#[test]
fn a_global_the_loaded_build_lacks_has_no_pointer() {
    let module = two_builds();
    let global: &'static Global<u16> =
        Box::leak(Box::new(__private::global(module, "OLD", &[Some(0), None])));
    assert_eq!(global.rva(), None);
    assert_eq!(global.try_ptr(), None);
    let panic = std::panic::catch_unwind(|| global.ptr()).unwrap_err();
    let message = panic.downcast_ref::<String>().expect("a formatted message");
    assert_eq!(
        *message,
        format!("imping: `OLD` isn't in the new IR of `{}`", exe_name())
    );
}
