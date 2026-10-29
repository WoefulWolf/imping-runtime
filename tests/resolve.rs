//! Finding generated functions: at their RVA when the first bytes there match,
//! otherwise by their byte pattern.

#![cfg(all(windows, target_arch = "x86_64"))]

use imping_runtime::__private::{Function, Pattern, Slot, install};
use imping_runtime::{Error, Module};
use std::hint::black_box;
use std::sync::OnceLock;

type Signature = unsafe extern "system" fn(u64) -> u64;

#[inline(never)]
extern "system" fn in_place(a: u64) -> u64 {
    black_box(a).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0x0123_4567_89AB_CDEF
}

#[inline(never)]
extern "system" fn moved(a: u64) -> u64 {
    black_box(a).wrapping_mul(0xC2B2_AE3D_27D4_EB4F) ^ 0x1656_67B1_9E37_79F9
}

#[inline(never)]
extern "system" fn hooked(a: u64) -> u64 {
    black_box(a).wrapping_mul(0x27D4_EB2F_1656_67C5) ^ 0x85EB_CA77_C2B2_AE63
}

#[inline(never)]
extern "system" fn changed(a: u64) -> u64 {
    black_box(a).wrapping_mul(0x94D0_49BB_1331_11EB) ^ 0x2545_F491_4F6C_DD1D
}

/// Stands where a moved function used to be.
#[inline(never)]
extern "system" fn old_place(a: u64) -> u64 {
    black_box(a).wrapping_mul(0x7A3F_19C4_55E0_B2D1) ^ 0x3C6E_F372_FE94_F82B
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

/// This test executable, as a build the bindings list.
fn listed() -> &'static Module {
    static EXE: OnceLock<&'static Module> = OnceLock::new();
    EXE.get_or_init(|| {
        let probe = Module::new(exe_name(), &[]);
        // SAFETY: Nothing is done through `probe` beyond checking its identity.
        let build = unsafe { probe.init_any_build() }.expect("probe");
        let module = Box::leak(Box::new(Module::new(exe_name(), vec![build].leak())));
        // SAFETY: The fixtures are real functions of this executable with the
        // signatures used for them.
        unsafe { module.init() }.expect("init");
        module
    })
}

/// This test executable, as a build the bindings don't list.
fn unlisted() -> &'static Module {
    static EXE: OnceLock<&'static Module> = OnceLock::new();
    EXE.get_or_init(|| {
        let module = Box::leak(Box::new(Module::new(exe_name(), &[])));
        // SAFETY: As for `listed`.
        unsafe { module.init_any_build() }.expect("init");
        module
    })
}

fn rva(function: Signature) -> u32 {
    u32::try_from(function as usize - listed().base().unwrap()).unwrap()
}

/// Returns the shortest run of a function's first bytes that's unique in this
/// executable, as bytes and as a pattern.
fn unique_start(function: Signature) -> (&'static [u8], &'static str) {
    for len in 8..=64 {
        // SAFETY: The function is followed by more code in this executable.
        let bytes = unsafe { std::slice::from_raw_parts(function as *const u8, len) };
        let pattern: Vec<String> = bytes.iter().map(|b| format!("{b:02X}")).collect();
        let pattern = pattern.join(" ");
        if imping_hook::scan::find(&pattern).is_ok() {
            return (Box::leak(bytes.into()), Box::leak(pattern.into_boxed_str()));
        }
    }
    panic!("no unique start for {:p}", function as *const ());
}

fn wrong(bytes: &[u8]) -> &'static [u8] {
    Box::leak(bytes.iter().map(|b| !b).collect())
}

fn function(
    module: &'static Module,
    rva: u32,
    verification: &'static [u8],
    pattern: Option<&'static str>,
) -> &'static Function {
    let pattern = pattern.map(|bytes| Pattern {
        bytes,
        offset: 0,
        follow_call: false,
    });
    Box::leak(Box::new(Function::new(
        module,
        "fixture",
        rva,
        verification,
        pattern,
    )))
}

#[test]
fn a_listed_build_calls_the_rva_unchecked() {
    let (bytes, _) = unique_start(in_place);
    let function = function(listed(), rva(in_place), wrong(bytes), None);
    assert_eq!(function.resolve().unwrap(), in_place as *const () as usize);
}

#[test]
fn an_unlisted_build_checks_the_bytes_first() {
    let (bytes, _) = unique_start(in_place);
    let right = function(unlisted(), rva(in_place), bytes, None);
    assert_eq!(right.resolve().unwrap(), in_place as *const () as usize);

    let wrong = function(unlisted(), rva(in_place), wrong(bytes), None);
    let error = wrong.resolve().unwrap_err();
    assert!(
        matches!(&error, Error::VerificationFailed { found, scan: None, .. } if found == bytes),
        "{error:?}"
    );
}

#[test]
fn a_moved_function_is_found_by_its_pattern() {
    let (bytes, pattern) = unique_start(moved);
    let function = function(unlisted(), rva(old_place), bytes, Some(pattern));
    assert_eq!(function.resolve().unwrap(), moved as *const () as usize);
    assert_eq!(
        function.resolve().unwrap(),
        moved as *const () as usize,
        "and kept"
    );
}

#[test]
fn a_failed_scan_is_part_of_the_error() {
    let (bytes, _) = unique_start(in_place);
    // `int1` is never emitted.
    let missing = "F1 F1 F1 F1 F1 F1 F1 F1";
    let function = function(unlisted(), rva(in_place), wrong(bytes), Some(missing));
    let error = function.resolve().unwrap_err();
    assert!(
        matches!(
            &error,
            Error::VerificationFailed {
                scan: Some(imping_hook::Error::PatternNotFound { .. }),
                ..
            }
        ),
        "{error:?}"
    );
    assert!(
        error.to_string().ends_with(
            "the build differs or another mod hooked it, and pattern \
             `F1 F1 F1 F1 F1 F1 F1 F1` matched nothing"
        ),
        "{error}"
    );
    assert!(std::error::Error::source(&error).is_some());
}

#[test]
fn past_the_end_of_the_module_is_a_mismatch() {
    let function = function(unlisted(), 0xFFFF_FF00, &[0x48, 0x89], None);
    let error = function.resolve().unwrap_err();
    assert_eq!(
        error.to_string(),
        format!(
            "`{}`+0xffffff00 is past the end of the module; the build differs",
            exe_name()
        )
    );
}

#[test]
fn a_hook_goes_where_the_pattern_leads() {
    static SLOT: Slot<dyn Fn(Signature, u64) -> u64 + Send + Sync, Signature> = Slot::new();
    unsafe extern "system" fn thunk(a: u64) -> u64 {
        let (detour, original) = SLOT.get();
        detour(original, a)
    }

    // Hooks check the bytes on listed builds too.
    let (bytes, pattern) = unique_start(hooked);
    let function = function(listed(), rva(old_place), bytes, Some(pattern));
    let before = (hooked(3), old_place(3));
    // SAFETY: The pattern finds `hooked`, which has type `Signature`, as does
    // `thunk`, which calls the slot's closure.
    let hook = unsafe { install(function, &SLOT, Box::new(|_, a| a + 1), thunk) }.unwrap();
    hook.enable().unwrap();
    assert_eq!((hooked(3), old_place(3)), (4, before.1));
    drop(hook);
    assert_eq!(hooked(3), before.0);
}

#[test]
fn a_hook_refuses_changed_bytes_at_the_right_address() {
    static SLOT: Slot<dyn Fn(Signature, u64) -> u64 + Send + Sync, Signature> = Slot::new();
    unsafe extern "system" fn thunk(a: u64) -> u64 {
        let (detour, original) = SLOT.get();
        detour(original, a)
    }

    // The pattern still matches at the RVA, but the bytes there differ from
    // what's expected, as if another mod had hooked it.
    let (bytes, pattern) = unique_start(changed);
    let function = function(listed(), rva(changed), wrong(bytes), Some(pattern));
    let before = changed(3);
    // SAFETY: Nothing is patched, as the bytes differ.
    let error = unsafe { install(function, &SLOT, Box::new(|_, a| a + 1), thunk) }.unwrap_err();
    assert!(
        matches!(error, Error::VerificationFailed { scan: None, .. }),
        "{error:?}"
    );
    assert_eq!(changed(3), before);
}
