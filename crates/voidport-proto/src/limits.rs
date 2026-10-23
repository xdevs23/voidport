use core::mem::size_of;

use crate::error::FramingError;
use crate::ops::xattr::XattrNameHeader;

#[cfg(feature = "userspace")]
pub const LIMITS: Limits = Limits {
    name_max: linux_raw_sys::general::NAME_MAX,
    path_max: linux_raw_sys::general::PATH_MAX,
    xattr_name_max: linux_raw_sys::general::XATTR_NAME_MAX,
    xattr_size_max: linux_raw_sys::general::XATTR_SIZE_MAX,
    xattr_list_max: linux_raw_sys::general::XATTR_LIST_MAX,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub name_max: u32,
    pub path_max: u32,
    pub xattr_name_max: u32,
    pub xattr_size_max: u32,
    pub xattr_list_max: u32,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Part {
    Name,
    Path,
    XattrName,
    XattrValue,
    XattrList,
    /// A part that the server checks itself before it reads it. The parser puts
    /// no bound on it.
    Handshake,
}

impl Limits {
    /// A path is bounded by `PATH_MAX` less one, because that number counts the
    /// terminator that a region of this wire does not contain. Every name of an
    /// attribute name list costs at least one byte of the list of the kernel,
    /// its terminator, and at most a whole [`XattrNameHeader`] more on this
    /// wire.
    #[must_use]
    pub fn bound(&self, part: Part) -> Option<u32> {
        match part {
            Part::Name => Some(self.name_max),
            Part::Path => Some(self.path_max.saturating_sub(1)),
            Part::XattrName => Some(self.xattr_name_max),
            Part::XattrValue => Some(self.xattr_size_max),
            Part::XattrList => Some(
                self.xattr_list_max
                    .saturating_mul(size_of::<XattrNameHeader>() as u32),
            ),
            Part::Handshake => None,
        }
    }

    pub fn check(&self, part: Part, declared: u32) -> Result<(), FramingError> {
        match self.bound(part) {
            Some(bound) if declared > bound => Err(FramingError::RegionTooLong {
                part,
                declared,
                bound,
            }),
            _ => Ok(()),
        }
    }
}

pub const MAX_REGIONS: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Regions {
    parts: [(u32, Part); MAX_REGIONS],
    count: usize,
}

impl Regions {
    pub const NONE: Self = Self {
        parts: [(0, Part::Name); MAX_REGIONS],
        count: 0,
    };

    #[must_use]
    pub fn new(parts: &[(u32, Part)]) -> Self {
        let mut regions = Self::NONE;
        for (slot, part) in regions.parts.iter_mut().zip(parts) {
            *slot = *part;
        }
        assert!(parts.len() <= MAX_REGIONS, "more regions than any body has");
        regions.count = parts.len();
        regions
    }

    #[must_use]
    pub fn parts(&self) -> &[(u32, Part)] {
        &self.parts[..self.count]
    }

    pub fn total(&self) -> Result<u32, FramingError> {
        let mut total: u32 = 0;
        for (len, _) in self.parts() {
            total = total
                .checked_add(*len)
                .ok_or(FramingError::LengthOverflow)?;
        }
        Ok(total)
    }

    pub fn check(&self, limits: &Limits) -> Result<u32, FramingError> {
        for (len, part) in self.parts() {
            limits.check(*part, *len)?;
        }
        self.total()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use linux_raw_sys::general as uapi;

    const UAPI: Limits = Limits {
        name_max: uapi::NAME_MAX,
        path_max: uapi::PATH_MAX,
        xattr_name_max: uapi::XATTR_NAME_MAX,
        xattr_size_max: uapi::XATTR_SIZE_MAX,
        xattr_list_max: uapi::XATTR_LIST_MAX,
    };

    #[test]
    fn every_part_is_held_to_its_own_bound() {
        let header = size_of::<XattrNameHeader>() as u32;
        for (part, bound) in [
            (Part::Name, uapi::NAME_MAX),
            (Part::Path, uapi::PATH_MAX - 1),
            (Part::XattrName, uapi::XATTR_NAME_MAX),
            (Part::XattrValue, uapi::XATTR_SIZE_MAX),
            (Part::XattrList, uapi::XATTR_LIST_MAX * header),
        ] {
            assert_eq!(UAPI.bound(part), Some(bound));
            assert_eq!(UAPI.check(part, bound), Ok(()));
            assert_eq!(
                UAPI.check(part, bound + 1),
                Err(FramingError::RegionTooLong {
                    part,
                    declared: bound + 1,
                    bound,
                })
            );
        }
        assert_eq!(UAPI.bound(Part::Handshake), None);
        assert_eq!(UAPI.check(Part::Handshake, u32::MAX), Ok(()));
    }

    #[test]
    fn regions_sum_and_check_in_order() {
        let regions = Regions::new(&[(3, Part::Name), (4, Part::Path)]);
        assert_eq!(regions.parts().len(), 2);
        assert_eq!(regions.check(&UAPI), Ok(7));
        let over = Regions::new(&[(3, Part::Name), (uapi::PATH_MAX, Part::Path)]);
        assert!(matches!(
            over.check(&UAPI),
            Err(FramingError::RegionTooLong {
                part: Part::Path,
                ..
            })
        ));
        let wide = Regions::new(&[(u32::MAX, Part::Handshake), (1, Part::Handshake)]);
        assert_eq!(wide.check(&UAPI), Err(FramingError::LengthOverflow));
        assert_eq!(Regions::NONE.check(&UAPI), Ok(0));
    }
}
