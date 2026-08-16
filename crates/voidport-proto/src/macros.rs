//! The two macros that define the crate's wire discipline.
//!
//! Keeping the derive set in one place is what makes "every wire struct is
//! fixed-layout, alignment-1 and zerocopy-viewable" a property of the crate,
//! not of forty individual declarations.

/// Validates one field declared by [`wire_struct`].
///
/// Reserved-field enforcement lives here so adding a `reserved` or
/// `reserved2` field cannot silently omit the parse- and encode-side check.
macro_rules! validate_wire_field {
    ($value:ident, reserved) => {
        if $value.reserved.get() != 0 {
            return Err($crate::error::FramingError::ReservedFieldNonZero);
        }
    };
    ($value:ident, reserved2) => {
        if $value.reserved2.get() != 0 {
            return Err($crate::error::FramingError::ReservedFieldNonZero);
        }
    };
    ($value:ident, $field:ident) => {};
}

/// Declares a wire struct: fixed C layout with the full zerocopy derive set.
///
/// `Unaligned` is the load-bearing one — it is a compile-time proof that the
/// struct has alignment 1 and can therefore be viewed at any offset of a byte
/// buffer, which the wire contract requires of every message. Fields named
/// `reserved` or `reserved2` are also wired into the common validation hook.
macro_rules! wire_struct {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident;
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
        #[derive(
            ::zerocopy::FromBytes,
            ::zerocopy::Immutable,
            ::zerocopy::IntoBytes,
            ::zerocopy::KnownLayout,
            ::zerocopy::Unaligned
        )]
        #[repr(C)]
        $vis struct $name;

        impl $crate::message::WireValidate for $name {}
    };
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident {
            $(
                $(#[$field_meta:meta])*
                $field_vis:vis $field:ident: $ty:ty
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
        #[derive(
            ::zerocopy::FromBytes,
            ::zerocopy::Immutable,
            ::zerocopy::IntoBytes,
            ::zerocopy::KnownLayout,
            ::zerocopy::Unaligned
        )]
        #[repr(C)]
        $vis struct $name {
            $(
                $(#[$field_meta])*
                $field_vis $field: $ty,
            )*
        }

        impl $crate::message::WireValidate for $name {
            fn validate(&self) -> Result<(), $crate::error::FramingError> {
                $($crate::macros::validate_wire_field!(self, $field);)*
                Ok(())
            }
        }
    };
}

/// Implements [`WirePayload`](crate::message::WirePayload), the opcode binding
/// and the direction marker for a message body.
///
/// The `regions` form lists the length fields describing the body's payload
/// regions, in wire order; without it the body declares no payload. The
/// `encode_validate` form supplies the asymmetric send-side validation used by
/// handshake negotiation fields. `notification` binds the body to the
/// server-initiated registry instead of the request one.
macro_rules! wire_body {
    // The payload half, shared by every direction: this is the single place
    // `payload_len` and `validate_encode` are implemented from a field list.
    (@payload $ty:ty, encode_validate = $validate:expr, regions = [$($field:ident),+ $(,)?]) => {
        impl $crate::message::WirePayload for $ty {
            fn validate_encode(&self) -> Result<(), $crate::error::FramingError> {
                $validate(self)
            }

            fn payload_len(&self) -> Result<u32, $crate::error::FramingError> {
                $crate::message::sum_regions(&[$(self.$field.get()),+])
            }
        }
    };
    (@payload $ty:ty, encode_validate = $validate:expr) => {
        impl $crate::message::WirePayload for $ty {
            fn validate_encode(&self) -> Result<(), $crate::error::FramingError> {
                $validate(self)
            }
        }
    };
    (@payload $ty:ty, regions = [$($field:ident),+ $(,)?]) => {
        impl $crate::message::WirePayload for $ty {
            fn payload_len(&self) -> Result<u32, $crate::error::FramingError> {
                $crate::message::sum_regions(&[$(self.$field.get()),+])
            }
        }
    };
    (@payload $ty:ty) => {
        impl $crate::message::WirePayload for $ty {}
    };

    (request $ty:ty => $op:expr $(, $($rest:tt)*)?) => {
        $crate::macros::wire_body!(@payload $ty $(, $($rest)*)?);
        impl $crate::message::WireMessage for $ty {
            const OPCODE: $crate::opcode::Opcode = $op;
        }
        impl $crate::message::RequestBody for $ty {}
    };
    (response $ty:ty => $op:expr $(, $($rest:tt)*)?) => {
        $crate::macros::wire_body!(@payload $ty $(, $($rest)*)?);
        impl $crate::message::WireMessage for $ty {
            const OPCODE: $crate::opcode::Opcode = $op;
        }
        impl $crate::message::ResponseBody for $ty {}
    };
    (notification $ty:ty => $op:expr $(, $($rest:tt)*)?) => {
        $crate::macros::wire_body!(@payload $ty $(, $($rest)*)?);
        impl $crate::message::NotificationBody for $ty {
            const OPCODE: $crate::opcode::NotificationOpcode = $op;
        }
    };
}

pub(crate) use {validate_wire_field, wire_body, wire_struct};
