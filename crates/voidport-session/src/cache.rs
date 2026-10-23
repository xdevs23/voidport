use core::ops::Range;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Placement {
    /// At `offset`. After the reply, the client copies the bytes the server
    /// took into the cached pages of their range.
    At { offset: u64 },
    /// At `offset`, sent from the buffer of the program past the cache. The
    /// cached pages of the range may show the bytes from before the write.
    Direct { offset: u64 },
    /// At the end of the file on the server, which the client does not know,
    /// sent from the buffer of the program.
    End,
}

impl Placement {
    /// Whether the write leaves the page cache out, and holds the invalidate
    /// lock of its file shared.
    #[must_use]
    pub const fn is_direct(&self) -> bool {
        matches!(self, Self::Direct { .. })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct CacheChange {
    /// The cached pages of this range show bytes the file does not have.
    pub drop: Range<u64>,
    pub size: u64,
}

/// Every write also makes the presented attributes expire: the server changed
/// the modification time, and only its next reply with attributes shows it.
/// A write that took no byte leaves the size as it is, wherever it was placed.
pub fn after_write(placement: Placement, written: u64, size: u64) -> CacheChange {
    let grown = |end: u64| if written == 0 { size } else { size.max(end) };
    match placement {
        Placement::At { offset } => {
            let end = offset.saturating_add(written);
            CacheChange {
                drop: end..end,
                size: grown(end),
            }
        }
        Placement::Direct { offset } => {
            let end = offset.saturating_add(written);
            CacheChange {
                drop: offset..end,
                size: grown(end),
            }
        }
        // The pages past the old end show zeros where the server put the bytes.
        // The server appended at the end of the file on the server, which is
        // the presented end or past it, so the file is at least as long as the
        // presented size and the bytes written.
        Placement::End => CacheChange {
            drop: size..u64::MAX,
            size: size.saturating_add(written),
        },
    }
}

/// The size and the modification time of a file. Two different pairs show two
/// different contents of the file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Contents {
    pub size: u64,
    pub mtime_sec: i64,
    pub mtime_nsec: u32,
}

/// The client counts the writes of the mount: it adds one to the count each
/// time it applies the reply to a write with [`after_write`]. Every count here
/// is a value of that count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Presented {
    pub contents: Contents,
    /// The count after the client applied the reply to the latest write to the
    /// file.
    pub written_at: u64,
    pub writing: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum Attributes {
    Apply,
    /// Present the attributes of the reply, and drop the cached pages of the
    /// file: the file changed on the server.
    ApplyAndDrop,
    /// Leave the presented attributes as they are: the reply may show the
    /// file before a write of this client, or in the middle of one.
    Ignore,
}

/// Any change of the size or the modification time drops the cache, also the
/// new modification time of a write made by this client: another client may
/// have changed the file in the same window, and the two changes look alike.
pub fn after_attributes(presented: Presented, reply: Contents, sent_at: u64) -> Attributes {
    if presented.writing || presented.written_at > sent_at {
        Attributes::Ignore
    } else if presented.contents == reply {
        Attributes::Apply
    } else {
        Attributes::ApplyAndDrop
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const JAR: Contents = Contents {
        size: 41_877_504,
        mtime_sec: 1_760_000_000,
        mtime_nsec: 5,
    };

    fn presented(written_at: u64) -> Presented {
        Presented {
            contents: JAR,
            written_at,
            writing: false,
        }
    }

    #[test]
    fn a_whole_write_keeps_its_pages_and_grows_the_file() {
        let written = after_write(Placement::At { offset: 0 }, 41_943_040, 41_877_504);
        assert!(written.drop.is_empty(), "{written:?}");
        assert_eq!(written.size, 41_943_040);
    }

    #[test]
    fn a_write_inside_the_file_keeps_its_size() {
        let placement = Placement::At { offset: 4096 };
        assert_eq!(after_write(placement, 4096, 65_536).size, 65_536);
    }

    #[test]
    fn a_short_write_grows_the_file_to_the_bytes_the_server_took() {
        let written = after_write(Placement::At { offset: 4096 }, 1000, 0);
        assert!(written.drop.is_empty(), "{written:?}");
        assert_eq!(written.size, 5096);
    }

    #[test]
    fn a_write_past_the_end_that_took_nothing_keeps_the_size() {
        let written = after_write(Placement::At { offset: 1 << 30 }, 0, 65_536);
        assert_eq!(written.size, 65_536);
    }

    #[test]
    fn a_direct_write_drops_the_cached_pages_of_the_bytes_it_wrote() {
        let placement = Placement::Direct { offset: 4096 };
        let written = after_write(placement, 1000, 65_536);
        assert_eq!(written.drop, 4096..5096);
        assert_eq!(written.size, 65_536);
        assert_eq!(after_write(placement, 0, 65_536).drop, 4096..4096);
        assert_eq!(after_write(placement, 65_536, 0).size, 69_632);
    }

    #[test]
    fn an_append_drops_the_cache_past_the_old_end_and_grows_the_file_by_its_bytes() {
        let written = after_write(Placement::End, 4096, 65_536);
        assert_eq!(written.drop, 65_536..u64::MAX);
        assert_eq!(written.size, 69_632);
        assert_eq!(after_write(Placement::End, 0, 65_536).size, 65_536);
    }

    #[test]
    fn a_reply_showing_the_presented_contents_is_applied() {
        assert_eq!(after_attributes(presented(3), JAR, 9), Attributes::Apply);
    }

    #[test]
    fn a_file_changed_on_the_server_drops_its_cache() {
        let resized = Contents { size: 1, ..JAR };
        let touched = Contents {
            mtime_nsec: 6,
            ..JAR
        };
        for reply in [resized, touched] {
            assert_eq!(
                after_attributes(presented(3), reply, 9),
                Attributes::ApplyAndDrop,
                "{reply:?}"
            );
        }
    }

    #[test]
    fn a_reply_sent_before_a_write_of_this_client_was_answered_is_ignored() {
        let grown = Contents { size: 1, ..JAR };
        assert_eq!(
            after_attributes(presented(10), grown, 9),
            Attributes::Ignore
        );
        assert_eq!(after_attributes(presented(10), JAR, 9), Attributes::Ignore);
    }

    #[test]
    fn a_reply_while_a_write_waits_for_its_reply_is_ignored() {
        let writing = Presented {
            writing: true,
            ..presented(3)
        };
        assert_eq!(after_attributes(writing, JAR, 9), Attributes::Ignore);
    }

    #[test]
    fn a_reply_after_a_write_of_this_client_drops_the_cache_when_the_file_differs() {
        let written = Contents {
            mtime_sec: JAR.mtime_sec + 1,
            ..JAR
        };
        let rewritten = Contents {
            size: JAR.size + 1,
            ..written
        };
        for reply in [written, rewritten] {
            assert_eq!(
                after_attributes(presented(5), reply, 9),
                Attributes::ApplyAndDrop,
                "{reply:?}"
            );
        }
    }
}
