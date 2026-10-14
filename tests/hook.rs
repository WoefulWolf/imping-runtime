//! Hooks through the plumbing generated code uses, on fixture functions in
//! this test executable.

#![cfg(all(windows, target_arch = "x86_64"))]

use imping_runtime::__private::{Slot, install};
use imping_runtime::{Error, Hook, Module, Result};
use std::hint::black_box;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

/// This test executable as a [`Module`], initialized.
fn exe() -> &'static Module {
    static EXE: OnceLock<&'static Module> = OnceLock::new();
    EXE.get_or_init(|| {
        let path = std::env::current_exe().expect("current exe");
        let name = path
            .file_name()
            .expect("file name")
            .to_str()
            .expect("UTF-8 name");
        let name: &'static str = Box::leak(name.to_owned().into_boxed_str());
        let probe = Module::new(name, 0, 0);
        // SAFETY: Nothing is done through `probe` beyond checking its identity.
        let (timestamp, image_size) = match unsafe { probe.init() } {
            Err(Error::BuildMismatch {
                found_timestamp,
                found_image_size,
                ..
            }) => (found_timestamp, found_image_size),
            other => panic!("expected a build mismatch, got {other:?}"),
        };
        let module: &'static Module = Box::leak(Box::new(Module::new(name, timestamp, image_size)));
        // SAFETY: The fixtures below are real functions of this executable with
        // the signatures declared for them.
        unsafe { module.init() }.expect("init");
        module
    })
}

/// Declares a fixture function and the hook plumbing a generated binding
/// would have for it, with `hook` taking the verification bytes.
macro_rules! fixture {
    ($name:ident: fn($($arg:ident: $ty:ty),*) -> $ret:ty $body:block) => {
        mod $name {
            use super::*;

            pub type Signature = unsafe extern "system" fn($($ty),*) -> $ret;

            #[inline(never)]
            pub extern "system" fn target($($arg: $ty),*) -> $ret $body

            static SLOT: Slot<dyn Fn(Signature, $($ty),*) -> $ret + Send + Sync, Signature> = Slot::new();

            unsafe extern "system" fn thunk($($arg: $ty),*) -> $ret {
                let (detour, original) = SLOT.get();
                detour(original, $($arg),*)
            }

            pub fn rva() -> u32 {
                u32::try_from(target as *const () as usize - exe().base().unwrap()).unwrap()
            }

            pub fn hook(
                verification: &'static [u8],
                detour: impl Fn(Signature, $($ty),*) -> $ret + Send + Sync + 'static,
            ) -> Result<Hook<Signature>> {
                // SAFETY: `target` is at `rva()` and has type `Signature`, as
                // does `thunk`, which calls the slot's closure.
                unsafe { install(exe(), rva(), verification, &SLOT, Box::new(detour), thunk) }
            }
        }
    };
}

fixture!(lifecycle: fn(a: i32, b: i32) -> i32 { black_box(a) + b });
fixture!(rehook: fn(a: i32) -> i32 { black_box(a) + 1 });
fixture!(leaked: fn(a: i32) -> i32 { black_box(a) + 2 });
fixture!(verified: fn(a: i32) -> i32 { black_box(a) + 3 });
fixture!(captures: fn(a: i32) -> i32 { black_box(a) + 4 });
fixture!(stress: fn(a: i32) -> i32 { black_box(a) + 5 });

#[test]
fn install_enable_disable_original_and_drop() {
    let hook = lifecycle::hook(&[], |original, a, b| {
        // SAFETY: The original has this signature.
        let sum = unsafe { original(a, b) };
        sum * 10
    })
    .expect("hook");
    assert!(!hook.is_enabled(), "hooks are returned disabled");
    assert_eq!(lifecycle::target(2, 3), 5);

    hook.enable().expect("enable");
    assert!(hook.is_enabled());
    assert_eq!(lifecycle::target(2, 3), 50);
    // SAFETY: The original has this signature.
    assert_eq!(unsafe { hook.original()(2, 3) }, 5);

    hook.disable().expect("disable");
    assert_eq!(lifecycle::target(2, 3), 5);

    hook.enable().expect("enable");
    drop(hook);
    assert_eq!(
        lifecycle::target(2, 3),
        5,
        "dropping the guard disables the hook"
    );
}

#[test]
fn a_function_is_hooked_once_at_a_time_and_again_after_drop() {
    let first = rehook::hook(&[], |_, a| a * 10).expect("hook");
    let error = rehook::hook(&[], |_, a| a).unwrap_err();
    assert!(matches!(error, Error::AlreadyHooked { rva, .. } if rva == rehook::rva()));
    assert!(
        error.to_string().ends_with("is already hooked by this mod"),
        "{error}"
    );

    first.enable().expect("enable");
    assert_eq!(rehook::target(3), 30);
    let original = first.original();
    drop(first);

    let second = rehook::hook(&[], |_, a| a * 100).expect("hook again after drop");
    second.enable().expect("enable");
    assert_eq!(rehook::target(3), 300, "the new closure is used");
    // SAFETY: The original has this signature, and stays valid after a drop.
    assert_eq!(unsafe { original(3) }, 4);
    assert_eq!(
        second.original() as usize,
        original as usize,
        "the patch is reused"
    );
}

#[test]
fn a_leaked_hook_stays_enabled_and_reserved() {
    let hook = leaked::hook(&[], |_, a| -a).expect("hook");
    hook.enable().expect("enable");
    hook.leak();
    assert_eq!(leaked::target(7), -7);
    assert!(matches!(
        leaked::hook(&[], |_, a| a),
        Err(Error::AlreadyHooked { .. })
    ));
}

#[test]
fn verification_bytes_are_checked_before_patching() {
    // SAFETY: The function's first bytes are mapped readable.
    let actual: &'static [u8] = Box::leak(
        unsafe { std::slice::from_raw_parts(verified::target as *const u8, 4) }
            .to_vec()
            .into_boxed_slice(),
    );
    let wrong: &'static [u8] = Box::leak(actual.iter().map(|b| !b).collect::<Box<[u8]>>());

    let error = verified::hook(wrong, |_, a| a).unwrap_err();
    match &error {
        Error::VerificationFailed {
            rva,
            expected,
            found,
            ..
        } => {
            assert_eq!(*rva, verified::rva());
            assert_eq!(*expected, wrong);
            assert_eq!(found.as_slice(), actual);
        }
        other => panic!("expected a verification failure, got {other:?}"),
    }
    assert!(
        error
            .to_string()
            .ends_with("; the build differs or another mod hooked it"),
        "{error}"
    );
    assert_eq!(verified::target(1), 4, "nothing was patched");

    let hook = verified::hook(actual, |_, a| a * 2).expect("matching bytes");
    hook.enable().expect("enable");
    assert_eq!(verified::target(5), 10);
}

#[test]
fn hooks_need_an_initialized_module() {
    static NEVER: Module = Module::new("never.dll", 1, 1);
    type Signature = unsafe extern "system" fn() -> i32;
    static SLOT: Slot<dyn Fn(Signature) -> i32 + Send + Sync, Signature> = Slot::new();
    unsafe extern "system" fn thunk() -> i32 {
        let (detour, original) = SLOT.get();
        detour(original)
    }
    // SAFETY: The module is not initialized, so nothing is patched.
    let error = unsafe { install(&NEVER, 0x10, &[], &SLOT, Box::new(|_| 0), thunk) }.unwrap_err();
    assert!(matches!(
        error,
        Error::NotInitialized {
            module: "never.dll"
        }
    ));
    assert_eq!(
        error.to_string(),
        "`never.dll` is not initialized; call its `init()` first"
    );
}

#[test]
fn closures_keep_their_captured_state() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let hook = captures::hook(&[], move |original, a| {
        counter.fetch_add(1, Ordering::Relaxed);
        // SAFETY: The original has this signature.
        unsafe { original(a) }
    })
    .expect("hook");
    hook.enable().expect("enable");
    for i in 0..10 {
        assert_eq!(captures::target(i), i + 4);
    }
    assert_eq!(calls.load(Ordering::Relaxed), 10);
}

#[test]
fn dropping_and_rehooking_while_other_threads_call() {
    const THREADS: usize = 4;
    const CYCLES: i32 = 40;
    let stop = Arc::new(AtomicBool::new(false));
    let start = Arc::new(Barrier::new(THREADS + 1));
    let workers: Vec<_> = (0..THREADS)
        .map(|_| {
            let stop = Arc::clone(&stop);
            let start = Arc::clone(&start);
            thread::spawn(move || {
                start.wait();
                let mut calls = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    let result = stress::target(1);
                    assert!(
                        result == 6 || (1000..1000 + CYCLES + 6).contains(&result),
                        "unexpected result {result}"
                    );
                    calls += 1;
                }
                calls
            })
        })
        .collect();

    start.wait();
    for cycle in 0..CYCLES {
        let hook = stress::hook(&[], move |original, a| {
            // SAFETY: The original has this signature.
            let value = unsafe { original(a) };
            value + 1000 + cycle
        })
        .expect("hook");
        hook.enable().expect("enable");
        thread::yield_now();
        drop(hook);
    }
    stop.store(true, Ordering::Relaxed);
    let calls: u64 = workers
        .into_iter()
        .map(|worker| worker.join().expect("worker"))
        .sum();
    assert!(calls > 0);
    assert_eq!(stress::target(1), 6, "the last guard was dropped");
}
