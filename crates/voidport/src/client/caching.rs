#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Pages {
    /// The server has a lease showing that nobody else writes the file.
    Kept,
    Uncached,
    UntilClose,
}

impl Pages {
    /// A reply that sets both bits caches nothing.
    #[must_use]
    pub fn of(flags: u32) -> Self {
        use voidport_proto::ops::file::open_flags::{KEEP_CACHE, UNCACHED};
        if flags & UNCACHED != 0 {
            Self::Uncached
        } else if flags & KEEP_CACHE != 0 {
            Self::Kept
        } else {
            Self::UntilClose
        }
    }
}

#[cfg(test)]
mod tests {
    use voidport_proto::ops::file::open_flags::{KEEP_CACHE, UNCACHED};

    use super::Pages;

    #[test]
    fn an_open_reply_caches_no_more_than_its_flags_promise() {
        assert_eq!(Pages::of(KEEP_CACHE), Pages::Kept);
        assert_eq!(Pages::of(UNCACHED), Pages::Uncached);
        assert_eq!(Pages::of(0), Pages::UntilClose);
        assert_eq!(Pages::of(KEEP_CACHE | UNCACHED), Pages::Uncached);
        assert_eq!(Pages::of(KEEP_CACHE | 1 << 31), Pages::Kept);
    }
}
