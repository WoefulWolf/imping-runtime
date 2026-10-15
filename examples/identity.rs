//! Checks a module's build identity and reads a global from it, without
//! generated code, using `kernel32.dll` since every Windows process has it.
//!
//! Run with: `cargo run --example identity`

use imping_runtime::{Build, Error, Global, Module};

/// `kernel32.dll` with a made-up identity, to show how a wrong build is
/// reported.
static WRONG_BUILD: Module = Module::new(
    "kernel32.dll",
    &[Build {
        timestamp: 0x1234_5678,
        image_size: 0x1000,
    }],
);

fn main() -> imping_runtime::Result<()> {
    // SAFETY: Nothing is done through `WRONG_BUILD` beyond checking it.
    let build = match unsafe { WRONG_BUILD.init() } {
        Err(error @ Error::BuildMismatch { found, .. }) => {
            println!("rejected the made-up build: {error}");
            found
        }
        Err(error) => return Err(error),
        Ok(()) => unreachable!("the made-up identity can't match"),
    };

    // A mod can still opt in to trying the build it found.
    // SAFETY: Nothing is done through `WRONG_BUILD` beyond reading its base.
    let found = unsafe { WRONG_BUILD.init_any_build() }?;
    println!(
        "initialized the unlisted build anyway (timestamp {:#x}, image size {:#x}) at {:#x}",
        found.timestamp,
        found.image_size,
        WRONG_BUILD.base().expect("initialized")
    );

    // Describe the build that is actually loaded, then read its first two
    // bytes through a global at RVA 0.
    let kernel32: &'static Module =
        Box::leak(Box::new(Module::new("kernel32.dll", vec![build].leak())));
    let signature: Global<u16> = Global::new(kernel32, 0);
    // SAFETY: Only the image header is read through `kernel32`, and every
    // loaded image starts with a 2-byte signature.
    unsafe { kernel32.init() }?;
    // SAFETY: `init` succeeded, so this points at the loaded image's start.
    let value = unsafe { *signature.ptr() };
    println!(
        "kernel32.dll (timestamp {:#x}, image size {:#x}) is at {:#x} and starts with {:?}",
        build.timestamp,
        build.image_size,
        kernel32.base().expect("initialized"),
        String::from_utf8_lossy(&value.to_le_bytes())
    );
    Ok(())
}
