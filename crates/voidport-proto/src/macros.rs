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

/// `Unaligned` proves at compile time that the struct has alignment 1, so it
/// can be viewed at any offset of a byte buffer.
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
/// The optional clauses must come in this order:
///
/// * `encode_validate = <closure>`, a check run only on the sending side;
/// * `regions = [field: Part, ...]`, the length fields of the variable parts in
///   wire order, each with the [`Part`](crate::limits::Part) that bounds it;
/// * `pieces = Stream`, for a body followed by streamed pieces;
/// * `data = field`, for a body followed by raw data of the length in that
///   field, outside the framed message.
macro_rules! wire_body {
    (@payload $ty:ty
        $(, encode_validate = $validate:expr)?
        $(, regions = [$($field:ident : $part:ident),+ $(,)?])?
        $(, pieces = $stream:ident)?
        $(, data = $data:ident)?
    ) => {
        impl $crate::message::WirePayload for $ty {
            $(
                fn validate_encode(&self) -> Result<(), $crate::error::FramingError> {
                    $validate(self)
                }
            )?
            $(
                fn regions(&self) -> $crate::limits::Regions {
                    $crate::limits::Regions::new(&[
                        $((self.$field.get(), $crate::limits::Part::$part)),+
                    ])
                }
            )?
            $(
                fn follows(&self) -> $crate::message::Follows {
                    $crate::message::Follows::Pieces($crate::piece::Stream::$stream)
                }
            )?
            $(
                fn follows(&self) -> $crate::message::Follows {
                    $crate::message::Follows::Data(self.$data.get())
                }
            )?
        }
    };

    (request $ty:ty => $op:expr $(, $($rest:tt)*)?) => {
        $crate::macros::wire_body!(@payload $ty $(, $($rest)*)?);
        impl $crate::message::WireMessage for $ty {
            const OPCODE: $crate::opcode::Opcode = $op;
        }
        impl $crate::message::RequestBody for $ty {}
        const _: () = assert!(
            $crate::table::names($crate::table::request($op).name, stringify!($ty)),
            "the opcode table names another request body for this opcode"
        );
    };
    (response $ty:ty => $op:expr $(, $($rest:tt)*)?) => {
        $crate::macros::wire_body!(@payload $ty $(, $($rest)*)?);
        impl $crate::message::WireMessage for $ty {
            const OPCODE: $crate::opcode::Opcode = $op;
        }
        impl $crate::message::ResponseBody for $ty {}
        const _: () = assert!(
            match $crate::table::response($op) {
                Some(layout) => $crate::table::names(layout.name, stringify!($ty)),
                None => false,
            },
            "the opcode table names another response body for this opcode"
        );
    };
    (notification $ty:ty => $op:expr $(, $($rest:tt)*)?) => {
        $crate::macros::wire_body!(@payload $ty $(, $($rest)*)?);
        impl $crate::message::NotificationBody for $ty {
            const OPCODE: $crate::opcode::NotificationOpcode = $op;
        }
        const _: () = assert!(
            $crate::table::names($crate::table::notification($op).name, stringify!($ty)),
            "the opcode table names another notification body for this opcode"
        );
    };
}

pub(crate) use {validate_wire_field, wire_body, wire_struct};
