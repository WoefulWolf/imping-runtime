//! Base classes the way generated bindings describe them: a class embeds its
//! base at offset 0, implements `Inherits` for each ancestor and derefs to its
//! direct base. Field access reaches base fields, references coerce to base
//! references, and `upcast()` turns raw pointers into base pointers.
//!
//! Run with `cargo run --example inherits`.

use core::ops::{Deref, DerefMut};
use imping_runtime::{Inherits, Upcast};

/// A base class, as a generated binding would declare it.
#[repr(C)]
struct Entity {
    position: [f32; 3],
    health: i32,
}

/// A class deriving from `Entity`.
#[repr(C)]
struct Player {
    base: Entity,
    level: i32,
}

// SAFETY: `Player` is `repr(C)` and starts with its `Entity`.
unsafe impl Inherits<Entity> for Player {}

impl Deref for Player {
    type Target = Entity;
    fn deref(&self) -> &Entity {
        &self.base
    }
}

impl DerefMut for Player {
    fn deref_mut(&mut self) -> &mut Entity {
        &mut self.base
    }
}

/// Stands in for a target function that takes any entity by pointer.
///
/// # Safety
///
/// `entity` must point to a live `Entity`.
unsafe fn teleport(entity: *mut Entity, to: [f32; 3]) {
    // SAFETY: forwarded from the caller.
    unsafe { (*entity).position = to };
}

/// Stands in for a safe wrapper that takes an entity by reference.
fn heal(entity: &mut Entity) {
    entity.health = 100;
}

fn main() {
    let mut player = Player {
        base: Entity {
            position: [0.0; 3],
            health: 20,
        },
        level: 5,
    };

    // Base fields read and write through `Deref`.
    player.health -= 5;
    // A `&mut Player` coerces to `&mut Entity`.
    heal(&mut player);
    // A `*mut Player` becomes a `*mut Entity` without an unchecked cast.
    let pointer: *mut Player = &mut player;
    // SAFETY: `pointer` points to `player`, which is live.
    unsafe { teleport(pointer.upcast(), [1.0, 2.0, 3.0]) };

    println!(
        "level {} player at {:?} with {} health",
        player.level, player.position, player.health
    );
}
