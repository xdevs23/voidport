//! Walking and building length-prefixed entry streams.
//!
//! Two payload regions are sequences, not single blobs: the
//! readdirplus entry stream and the listxattr name list. Both are a fixed
//! per-entry header (parsed by zerocopy prefix parsing) followed by a
//! variable-length tail whose length the header declares — never a delimiter
//! scan, and never hand-written integer decoding.
//!
//! All wire structs are alignment-1, so entries pack back to back with no
//! padding and an entry header is viewable at whatever offset it lands on.

use core::marker::PhantomData;

use crate::error::FramingError;
use crate::message::WireStruct;

/// The fixed header of one entry in a length-prefixed entry stream.
pub trait StreamEntry: WireStruct {
    /// Length in bytes of the variable-length tail that follows this header.
    fn tail_len(&self) -> u32;
}

/// One entry of a stream: its fixed header and its tail bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamItem<'a, H: StreamEntry + 'a> {
    /// The fixed per-entry header.
    pub header: &'a H,
    /// The variable-length tail, exactly [`StreamEntry::tail_len`] bytes.
    pub tail: &'a [u8],
}

/// Iterator over a length-prefixed entry stream.
///
/// Yields a [`FramingError`] and then stops as soon as the stream is
/// malformed, so a truncated or lying entry can never be mistaken for the end
/// of the stream.
#[derive(Debug)]
pub struct StreamIter<'a, H: StreamEntry + 'a> {
    rest: &'a [u8],
    failed: bool,
    entry: PhantomData<fn() -> H>,
}

impl<'a, H: StreamEntry + 'a> StreamIter<'a, H> {
    /// Walks `payload` as a stream of `H` entries.
    #[must_use]
    pub fn new(payload: &'a [u8]) -> Self {
        Self {
            rest: payload,
            failed: false,
            entry: PhantomData,
        }
    }

    /// The bytes not yet consumed.
    #[must_use]
    pub fn remaining(&self) -> &'a [u8] {
        self.rest
    }
}

impl<'a, H: StreamEntry + 'a> Iterator for StreamIter<'a, H> {
    type Item = Result<StreamItem<'a, H>, FramingError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.rest.is_empty() {
            return None;
        }
        let Ok((header, rest)) = H::ref_from_prefix(self.rest) else {
            self.failed = true;
            return Some(Err(FramingError::BodyTooShort {
                needed: size_of::<H>(),
                found: self.rest.len(),
            }));
        };
        let tail_len = header.tail_len() as usize;
        let Some(tail) = rest.get(..tail_len) else {
            self.failed = true;
            return Some(Err(FramingError::PayloadLengthMismatch {
                declared: header.tail_len(),
                found: rest.len(),
            }));
        };
        self.rest = &rest[tail_len..];
        Some(Ok(StreamItem { header, tail }))
    }
}

/// Builds a length-prefixed entry stream in a caller-provided buffer.
///
/// The stream is built before the frame that carries it, because the frame's
/// declared payload length is the finished stream's length.
#[derive(Debug)]
pub struct StreamWriter<'a, H: StreamEntry + 'a> {
    buf: &'a mut [u8],
    written: usize,
    entry: PhantomData<fn() -> H>,
}

impl<'a, H: StreamEntry + 'a> StreamWriter<'a, H> {
    /// Starts an empty stream in `buf`.
    #[must_use]
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            written: 0,
            entry: PhantomData,
        }
    }

    /// Bytes written so far.
    #[must_use]
    pub fn written(&self) -> usize {
        self.written
    }

    /// Appends an entry.
    ///
    /// # Errors
    ///
    /// Returns [`FramingError::TailLengthMismatch`] when the header's declared
    /// tail length disagrees with `tail`, and [`FramingError::BufferTooSmall`]
    /// when the entry does not fit — the caller then stops enumerating and
    /// resumes from the entry's cookie in the next request.
    pub fn push(&mut self, header: &H, tail: &[u8]) -> Result<(), FramingError> {
        if header.tail_len() as usize != tail.len() {
            return Err(FramingError::TailLengthMismatch {
                declared: header.tail_len(),
                found: tail.len(),
            });
        }
        let needed = self.written + size_of::<H>() + tail.len();
        if self.buf.len() < needed {
            return Err(FramingError::BufferTooSmall {
                needed,
                found: self.buf.len(),
            });
        }
        let start = self.written;
        let split = start + size_of::<H>();
        self.buf[start..split].copy_from_slice(header.as_bytes());
        self.buf[split..needed].copy_from_slice(tail);
        self.written = needed;
        Ok(())
    }

    /// Finishes the stream and returns its bytes.
    #[must_use]
    pub fn finish(self) -> &'a [u8] {
        let Self { buf, written, .. } = self;
        &buf[..written]
    }
}
