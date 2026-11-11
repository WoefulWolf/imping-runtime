//! Finding generated functions: at their RVA when the first bytes there match,
//! otherwise by their byte pattern.

#![cfg(all(windows, target_arch = "x86_64"))]

use imping_runtime::__private::{Function, Pattern, Site, Slot, VtableSlot, install};
use imping_runtime::{Error, Mismatch, Module, VtableMiss};
use std::hint::black_box;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

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

/// Returns a verification failure's details, or panics.
fn mismatch(error: &Error) -> &Mismatch {
    match error {
        Error::VerificationFailed(mismatch) => mismatch,
        other => panic!("expected a verification failure, got {other:?}"),
    }
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
        Box::leak(Box::new([Some(Site {
            rva,
            verification,
            shape: "",
            pattern,
        })])),
        None,
    )))
}

/// Returns bytes as a shape, with `??` at `wild`.
fn shape(bytes: &[u8], wild: &[usize]) -> &'static str {
    let tokens: Vec<String> = bytes
        .iter()
        .enumerate()
        .map(|(i, b)| {
            if wild.contains(&i) {
                "??".to_owned()
            } else {
                format!("{b:02x}")
            }
        })
        .collect();
    Box::leak(tokens.join(" ").into_boxed_str())
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
    assert_eq!(mismatch(&error).found, bytes);
    assert!(mismatch(&error).scan.is_none(), "{error:?}");
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
            mismatch(&error).scan,
            Some(imping_hook::Error::PatternNotFound { .. })
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
    assert!(mismatch(&error).scan.is_none(), "{error:?}");
    assert_eq!(changed(3), before);
}

#[inline(never)]
extern "system" fn data_moved(a: u64) -> u64 {
    black_box(a).wrapping_mul(0x1B87_3593_CC9E_2D51) ^ 0x4CF5_AD43_2745_937F
}

#[test]
fn a_hook_accepts_changed_addresses_at_the_right_address() {
    static SLOT: Slot<dyn Fn(Signature, u64) -> u64 + Send + Sync, Signature> = Slot::new();
    unsafe extern "system" fn thunk(a: u64) -> u64 {
        let (detour, original) = SLOT.get();
        detour(original, a)
    }

    // As if an address in its first bytes changed: the exact bytes differ at
    // one place, which the shape leaves out.
    let (bytes, pattern) = unique_start(data_moved);
    let mut expected = bytes.to_vec();
    expected[2] = !expected[2];
    let site = Site {
        rva: rva(data_moved),
        verification: Box::leak(expected.into_boxed_slice()),
        shape: shape(bytes, &[2]),
        pattern: Some(Pattern {
            bytes: pattern,
            offset: 0,
            follow_call: false,
        }),
    };
    let function = Box::leak(Box::new(Function::new(
        listed(),
        "data_moved",
        Box::leak(Box::new([Some(site)])),
        None,
    )));
    // SAFETY: The function is `data_moved`, which has type `Signature`, as
    // does `thunk`, which calls the slot's closure.
    let hook = unsafe { install(function, &SLOT, Box::new(|_, a| a + 1), thunk) }.unwrap();
    hook.enable().unwrap();
    assert_eq!(data_moved(3), 4);
}

#[inline(never)]
extern "system" fn virtual_first(a: u64) -> u64 {
    black_box(a).wrapping_mul(0x9FB2_1C65_1E98_DF25) ^ 0x2127_599B_F432_5C37
}

#[inline(never)]
extern "system" fn virtual_second(a: u64) -> u64 {
    black_box(a).wrapping_mul(0x8EBC_6AF0_9C88_C6E3) ^ 0x589E_C5B9_F3C2_5A1D
}

/// A type descriptor: the type_info vtable, a spare pointer, then the name.
#[repr(C)]
struct Descriptor {
    vtable: usize,
    spare: usize,
    name: [u8; 22],
}

static DESCRIPTOR: Descriptor = Descriptor {
    vtable: 0,
    spare: 0,
    name: *b".?AVImpingVirtuals@@\0\0",
};

/// A complete object locator, filled in once the module's base is known.
static LOCATOR: [AtomicU32; 6] = [const { AtomicU32::new(0) }; 6];

/// A pointer to the locator, then the vtable's two slots.
static VTABLE: [AtomicUsize; 3] = [const { AtomicUsize::new(0) }; 3];

/// Lays out MSVC RTTI for a class with two virtual functions, as a compiler
/// would, and returns its type name.
fn virtual_class() -> &'static str {
    static NAME: OnceLock<&'static str> = OnceLock::new();
    NAME.get_or_init(|| {
        let base = listed().base().unwrap();
        let rva = |address: usize| u32::try_from(address - base).unwrap();
        let locator = LOCATOR.as_ptr() as usize;
        for (field, value) in [
            1,
            0,
            0,
            rva(&DESCRIPTOR as *const Descriptor as usize),
            0,
            rva(locator),
        ]
        .into_iter()
        .enumerate()
        {
            LOCATOR[field].store(value, Ordering::SeqCst);
        }
        VTABLE[0].store(locator, Ordering::SeqCst);
        VTABLE[1].store(virtual_first as *const () as usize, Ordering::SeqCst);
        VTABLE[2].store(virtual_second as *const () as usize, Ordering::SeqCst);
        // The name only from the descriptor, so no other copy of it is around.
        let end = DESCRIPTOR.name.iter().position(|&b| b == 0).unwrap();
        std::str::from_utf8(&DESCRIPTOR.name[..end]).unwrap()
    })
}

fn virtual_function(type_name: &'static str, index: u32, target: Signature) -> &'static Function {
    let (bytes, _) = unique_start(target);
    let site = Site {
        rva: rva(old_place),
        verification: bytes,
        shape: shape(bytes, &[]),
        pattern: None,
    };
    Box::leak(Box::new(Function::new(
        unlisted(),
        "virtual",
        Box::leak(Box::new([Some(site)])),
        Some(VtableSlot {
            type_name,
            offset: 0,
            index,
        }),
    )))
}

#[test]
fn a_virtual_function_is_found_through_its_vtable() {
    let function = virtual_function(virtual_class(), 1, virtual_second);
    assert_eq!(
        function.resolve().unwrap(),
        virtual_second as *const () as usize
    );
}

#[test]
fn a_slot_that_holds_something_else_is_refused() {
    let function = virtual_function(virtual_class(), 0, virtual_second);
    let error = function.resolve().unwrap_err();
    assert!(
        matches!(
            mismatch(&error).vtable,
            Some(VtableMiss::ShapeDiffers { index: 0, .. })
        ),
        "{error:?}"
    );
    assert!(
        error.to_string().contains(&format!(
            ", and slot 0 of `{}` starts with ",
            virtual_class()
        )),
        "{error}"
    );
}

#[test]
fn a_missing_class_is_part_of_the_error() {
    // Built at run time, so the whole name appears nowhere in the module.
    let middle = black_box("ImpingNoSuchClass");
    let name: &'static str = Box::leak(format!(".?AV{middle}@@").into_boxed_str());
    let error = virtual_function(name, 0, virtual_first)
        .resolve()
        .unwrap_err();
    assert!(
        matches!(
            mismatch(&error).vtable,
            Some(VtableMiss::ClassNotFound { .. })
        ),
        "{error:?}"
    );
    assert!(
        error
            .to_string()
            .ends_with(&format!(", and class `{name}` was not found")),
        "{error}"
    );
}
