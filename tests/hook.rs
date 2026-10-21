//! Hooks through the plumbing generated code uses, on fixture functions in
//! this test executable.

#![cfg(all(windows, target_arch = "x86_64"))]

use imping_runtime::__private::{Slot, install};
use imping_runtime::{Build, Error, Global, Hook, Module, Result};
use std::hint::black_box;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

/// Returns this test executable as an initialized [`Module`].
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
        let probe = Module::new(name, &[]);
        // SAFETY: Nothing is done through `probe` beyond checking its identity.
        let build = match unsafe { probe.init() } {
            Err(Error::BuildMismatch { found, .. }) => found,
            other => panic!("expected a build mismatch, got {other:?}"),
        };
        let module: &'static Module = Box::leak(Box::new(Module::new(name, vec![build].leak())));
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
            use std::marker::PhantomData;

            pub type Signature = unsafe extern "system" fn($($ty),*) -> $ret;

            #[inline(never)]
            pub extern "system" fn target($($arg: $ty),*) -> $ret $body

            /// The original function and the arguments of the hooked call.
            // Not every fixture uses both methods.
            #[allow(dead_code)]
            pub struct Original<'call>(Signature, ($($ty,)*), PhantomData<&'call ()>);

            #[allow(dead_code)]
            impl Original<'_> {
                pub fn forward(self) -> $ret {
                    let ($($arg,)*) = self.1;
                    // SAFETY: these are the hooked call's own arguments.
                    unsafe { (self.0)($($arg),*) }
                }

                pub unsafe fn call(self, $($arg: $ty),*) -> $ret {
                    // SAFETY: Forwarded from the caller.
                    unsafe { (self.0)($($arg),*) }
                }
            }

            static SLOT: Slot<dyn for<'call> Fn(Original<'call>, $($ty),*) -> $ret + Send + Sync, Signature> =
                Slot::new();

            unsafe extern "system" fn thunk($($arg: $ty),*) -> $ret {
                let (detour, original) = SLOT.get();
                detour(Original(original, ($($arg,)*), PhantomData), $($arg),*)
            }

            pub fn rva() -> u32 {
                u32::try_from(target as *const () as usize - exe().base().unwrap()).unwrap()
            }

            pub fn hook(
                verification: &'static [u8],
                detour: impl for<'call> Fn(Original<'call>, $($ty),*) -> $ret + Send + Sync + 'static,
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
fixture!(changed: fn(a: i32) -> i32 { black_box(a) + 6 });
fixture!(unsuspended: fn(a: i32) -> i32 { black_box(a) + 7 });
fixture!(batched: fn(a: i32) -> i32 { black_box(a) + 8 });

#[test]
fn install_enable_disable_original_and_drop() {
    let hook = lifecycle::hook(&[], |original, _, _| {
        let sum = original.forward();
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
    static NEVER: Module = Module::new(
        "never.dll",
        &[Build {
            timestamp: 1,
            image_size: 1,
        }],
    );
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
fn the_original_is_called_with_the_hooked_or_changed_arguments() {
    let hook = changed::hook(&[], |original, a| {
        if a < 0 {
            original.forward()
        } else {
            // SAFETY: Any `i32` is a valid argument for this function.
            unsafe { original.call(a * 2) }
        }
    })
    .expect("hook");
    hook.enable().expect("enable");
    assert_eq!(changed::target(-4), 2, "forwarded unchanged");
    assert_eq!(changed::target(5), 16, "called with a changed argument");
}

/// Globals of this executable, read and written through [`Global`].
static mut ALIGNED: u32 = 7;

#[repr(C, packed)]
struct Packed {
    tag: u8,
    value: u32,
}

static mut PACKED: Packed = Packed { tag: 1, value: 9 };

fn global<T>(address: usize) -> Global<T> {
    let rva = u32::try_from(address - exe().base().unwrap()).unwrap();
    Global::new(exe(), rva)
}

#[test]
fn plain_globals_read_and_write_aligned_or_not() {
    let aligned: Global<u32> = global((&raw const ALIGNED) as usize);
    assert_eq!(aligned.read(), 7);
    aligned.write(42);
    assert_eq!(aligned.read(), 42);
    // SAFETY: The test owns `ALIGNED`; no other thread uses it.
    assert_eq!(unsafe { (&raw const ALIGNED).read() }, 42);

    // SAFETY: Only the field's address is taken.
    let value_address = unsafe { &raw const PACKED.value } as usize;
    let unaligned: Global<u32> = global(value_address);
    assert!(!unaligned.ptr().is_aligned());
    assert_eq!(unaligned.read(), 9);
    unaligned.write(0x0102_0304);
    assert_eq!(unaligned.read(), 0x0102_0304);
    // SAFETY: The test owns `PACKED`; no other thread uses it.
    let tag = unsafe { (&raw const PACKED.tag).read() };
    assert_eq!(tag, 1, "the neighbour is untouched");
}

#[test]
fn closures_keep_their_captured_state() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let hook = captures::hook(&[], move |original, _| {
        counter.fetch_add(1, Ordering::Relaxed);
        original.forward()
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
        let hook =
            stress::hook(&[], move |original, _| original.forward() + 1000 + cycle).expect("hook");
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

#[test]
fn hooks_can_be_toggled_without_suspending_threads() {
    let hook = unsuspended::hook(&[], |_, a| a * 100).expect("hook");
    // SAFETY: No other thread calls this fixture.
    unsafe { hook.enable_unsuspended() }.expect("enable");
    assert!(hook.is_enabled());
    assert_eq!(unsuspended::target(1), 100);
    // SAFETY: As above.
    unsafe { hook.disable_unsuspended() }.expect("disable");
    assert_eq!(unsuspended::target(1), 8);
}

#[test]
fn hooks_join_an_imping_hook_batch() {
    let hook = batched::hook(&[], |_, a| a * 100).expect("hook");
    let failed = imping_hook::batch(|| {
        hook.enable().expect("queued");
        assert!(!hook.is_enabled(), "applied when the batch ends");
    });
    assert!(failed.is_empty(), "{failed:?}");
    assert_eq!(batched::target(1), 100);
}
