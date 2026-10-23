use core::cmp::Ordering;

/// What the client does next with one write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum Next<E> {
    /// Send the bytes from `from` on, at the offset of the write plus `from`.
    Send {
        from: u64,
    },
    Return(u64),
    Fail(E),
    /// Fail the write with `EIO`: the reply counted more bytes than its
    /// request contained.
    Overrun,
}

pub fn start<E>(length: u64) -> Next<E> {
    if length == 0 {
        Next::Return(0)
    } else {
        Next::Send { from: 0 }
    }
}

/// A short reply sends the rest from where it stopped. A reply that counts no
/// byte returns the bytes written so far. An errno fails the write only when no
/// byte was written, as a failing local write returns what it wrote. `from` is
/// below `length`.
pub fn next<E>(length: u64, from: u64, reply: Result<u32, E>) -> Next<E> {
    match reply {
        Err(error) if from == 0 => Next::Fail(error),
        Err(_) | Ok(0) => Next::Return(from),
        Ok(count) => match from.checked_add(u64::from(count)) {
            Some(written) => match written.cmp(&length) {
                Ordering::Less => Next::Send { from: written },
                Ordering::Equal => Next::Return(written),
                Ordering::Greater => Next::Overrun,
            },
            None => Next::Overrun,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Errno(i32);

    const ENOSPC: Errno = Errno(28);

    #[test]
    fn an_empty_write_sends_nothing() {
        assert_eq!(start::<Errno>(0), Next::Return(0));
        assert_eq!(start::<Errno>(41_943_040), Next::Send { from: 0 });
    }

    #[test]
    fn a_reply_that_takes_every_byte_returns_them() {
        assert_eq!(next::<Errno>(4096, 0, Ok(4096)), Next::Return(4096));
        assert_eq!(next::<Errno>(4096, 1000, Ok(3096)), Next::Return(4096));
    }

    #[test]
    fn a_short_reply_sends_the_rest_from_where_it_stopped() {
        assert_eq!(next::<Errno>(4096, 0, Ok(1000)), Next::Send { from: 1000 });
        assert_eq!(next::<Errno>(4096, 1000, Ok(96)), Next::Send { from: 1096 });
    }

    #[test]
    fn a_reply_that_takes_nothing_returns_the_bytes_so_far() {
        assert_eq!(next::<Errno>(4096, 0, Ok(0)), Next::Return(0));
        assert_eq!(next::<Errno>(4096, 1000, Ok(0)), Next::Return(1000));
    }

    #[test]
    fn an_errno_fails_the_write_only_before_any_progress() {
        assert_eq!(next(4096, 0, Err(ENOSPC)), Next::Fail(ENOSPC));
        assert_eq!(next(4096, 1000, Err(ENOSPC)), Next::Return(1000));
    }

    #[test]
    fn a_reply_counting_more_than_its_request_carried_breaks_the_protocol() {
        assert_eq!(next::<Errno>(4096, 0, Ok(4097)), Next::Overrun);
        assert_eq!(next::<Errno>(4096, 1000, Ok(3097)), Next::Overrun);
        assert_eq!(next::<Errno>(u64::MAX, u64::MAX - 1, Ok(2)), Next::Overrun);
    }
}
