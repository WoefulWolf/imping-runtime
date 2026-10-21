//! Base classes: which types derive from which, and pointer upcasts.

/// Marks `Self` as deriving from `B`, so a pointer to a `Self` is also a valid
/// pointer to its `B`.
///
/// Generated bindings implement it for every ancestor of a class, and give the
/// class `Deref` and `DerefMut` to its direct base so references reach base
/// fields and coerce to base references. For raw pointers, use
/// [`Upcast::upcast`].
///
/// # Safety
///
/// `Self` must have a defined layout (`repr(C)` or `repr(transparent)`) with a
/// `B` at offset 0, and every valid `Self` must hold a valid `B` there.
///
/// # Examples
///
/// ```
/// use imping_runtime::{Inherits, Upcast};
///
/// #[repr(C)]
/// struct Entity { health: i32 }
/// #[repr(C)]
/// struct Player { base: Entity, level: i32 }
///
/// // SAFETY: `Player` is `repr(C)` and starts with its `Entity`.
/// unsafe impl Inherits<Entity> for Player {}
///
/// fn heal(entity: *mut Entity) {
///     // SAFETY: the caller passes a live entity.
///     unsafe { (*entity).health = 100 };
/// }
///
/// let mut player = Player { base: Entity { health: 1 }, level: 3 };
/// let pointer: *mut Player = &mut player;
/// heal(pointer.upcast());
/// assert_eq!(player.base.health, 100);
/// ```
pub unsafe trait Inherits<B> {}

mod sealed {
    pub trait Sealed {}
    impl<T> Sealed for *mut T {}
    impl<T> Sealed for *const T {}
}

/// Converts a raw pointer to a class into a pointer to one of its base
/// classes, keeping it `*mut` or `*const`.
///
/// A plain cast, valid because of [`Inherits`]. It never dereferences, so null
/// and dangling pointers stay null or dangling. Implemented only for raw
/// pointers.
///
/// # Examples
///
/// A type that isn't a base doesn't compile:
///
/// ```compile_fail
/// use imping_runtime::Upcast;
///
/// #[repr(C)]
/// struct Entity { health: i32 }
/// #[repr(C)]
/// struct Item { count: i32 }
///
/// let item: *mut Item = core::ptr::null_mut();
/// let entity: *mut Entity = item.upcast(); // `Item` does not inherit `Entity`
/// ```
pub trait Upcast: sealed::Sealed {
    /// The type the pointer points to.
    type Pointee;
    /// The same kind of pointer (`*mut` or `*const`) to a base class `B`.
    type Cast<B>;

    /// Returns this pointer as a pointer to its base class `B`.
    ///
    /// `B` is usually inferred from where the result goes; name it with
    /// `upcast::<B>()` otherwise.
    fn upcast<B>(self) -> Self::Cast<B>
    where
        Self::Pointee: Inherits<B>;
}

impl<T> Upcast for *mut T {
    type Pointee = T;
    type Cast<B> = *mut B;

    fn upcast<B>(self) -> *mut B
    where
        T: Inherits<B>,
    {
        self.cast()
    }
}

impl<T> Upcast for *const T {
    type Pointee = T;
    type Cast<B> = *const B;

    fn upcast<B>(self) -> *const B
    where
        T: Inherits<B>,
    {
        self.cast()
    }
}
