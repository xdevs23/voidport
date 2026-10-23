// SPDX-License-Identifier: GPL-2.0

macro_rules! warn_limited {
    ($class:ident, $($arg:tt)*) => {
        if $crate::helpers::ratelimited($crate::helpers::DiagClass::$class) {
            ::kernel::pr_warn!("voidport: {}\n", ::kernel::prelude::fmt!($($arg)*));
        }
    };
}

macro_rules! info_limited {
    ($class:ident, $($arg:tt)*) => {
        if $crate::helpers::ratelimited($crate::helpers::DiagClass::$class) {
            ::kernel::pr_info!("voidport: {}\n", ::kernel::prelude::fmt!($($arg)*));
        }
    };
}

pub(crate) use {info_limited, warn_limited};
