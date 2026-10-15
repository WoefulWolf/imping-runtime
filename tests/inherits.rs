//! Base classes: `Inherits`, `Upcast::upcast`, and the `Deref` chain generated
//! bindings add to a class.

use core::ops::{Deref, DerefMut};
use imping_runtime::{Inherits, Upcast};

#[repr(C)]
struct Object {
    id: u32,
}

#[repr(C)]
struct Entity {
    base: Object,
    health: i32,
}

#[repr(C)]
struct Player {
    base: Entity,
    level: i32,
}

// What generated bindings emit for `Player : Entity : Object`.

// SAFETY: `Entity` is `repr(C)` and starts with its `Object`.
unsafe impl Inherits<Object> for Entity {}
// SAFETY: `Player` is `repr(C)` and starts with its `Entity`.
unsafe impl Inherits<Entity> for Player {}
// SAFETY: `Player` starts with its `Entity`, which starts with its `Object`.
unsafe impl Inherits<Object> for Player {}

impl Deref for Entity {
    type Target = Object;
    fn deref(&self) -> &Object {
        &self.base
    }
}

impl DerefMut for Entity {
    fn deref_mut(&mut self) -> &mut Object {
        &mut self.base
    }
}

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

fn player() -> Player {
    Player {
        base: Entity {
            base: Object { id: 7 },
            health: 10,
        },
        level: 3,
    }
}

fn object_id(object: *const Object) -> u32 {
    // SAFETY: the tests pass pointers to live objects.
    unsafe { (*object).id }
}

fn set_health(entity: *mut Entity, health: i32) {
    // SAFETY: the tests pass pointers to live entities.
    unsafe { (*entity).health = health };
}

#[test]
fn upcast_infers_the_base_from_the_argument() {
    let mut player = player();
    let pointer: *mut Player = &mut player;
    set_health(pointer.upcast(), 55);
    assert_eq!(player.base.health, 55);
}

#[test]
fn upcast_reaches_every_ancestor() {
    let mut player = player();
    let pointer: *mut Player = &mut player;
    let object: *mut Object = pointer.upcast();
    assert_eq!(object.cast::<Player>(), pointer);
    assert_eq!(object_id(object), 7);
}

#[test]
fn upcast_keeps_const_pointers_const() {
    let player = player();
    let pointer: *const Player = &player;
    let entity = pointer.upcast::<Entity>();
    // SAFETY: `entity` points into `player`, which is live.
    assert_eq!(unsafe { (*entity).health }, 10);
}

#[test]
fn upcast_of_null_is_null() {
    let pointer: *mut Player = core::ptr::null_mut();
    assert!(pointer.upcast::<Object>().is_null());
}

#[test]
fn deref_reaches_fields_of_every_ancestor() {
    let mut player = player();
    player.health = 80;
    player.id = 9;
    assert_eq!((player.base.health, player.base.base.id), (80, 9));
    assert_eq!(player.level, 3);
}

#[test]
fn references_coerce_to_base_references() {
    fn heal(entity: &mut Entity) {
        entity.health = 100;
    }
    fn id(object: &Object) -> u32 {
        object.id
    }
    let mut player = player();
    heal(&mut player);
    assert_eq!(player.health, 100);
    assert_eq!(id(&player), 7);
}
