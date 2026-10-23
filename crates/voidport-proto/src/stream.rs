use core::marker::PhantomData;

use crate::error::FramingError;
use crate::message::WireStruct;

pub trait StreamEntry: WireStruct {
    fn tail_len(&self) -> u32;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamItem<'a, H: StreamEntry> {
    pub header: &'a H,
    pub tail: &'a [u8],
}

#[derive(Debug)]
/// Yields an error and then stops, so a truncated or lying entry is never
/// mistaken for the end of the stream.
pub struct StreamIter<'a, H: StreamEntry + 'a> {
    rest: &'a [u8],
    failed: bool,
    entry: PhantomData<fn() -> H>,
}

impl<'a, H: StreamEntry + 'a> StreamIter<'a, H> {
    #[must_use]
    pub fn new(payload: &'a [u8]) -> Self {
        Self {
            rest: payload,
            failed: false,
            entry: PhantomData,
        }
    }

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

#[derive(Debug)]
/// The stream is built before the frame that contains it, because the payload
/// length that the frame declares is the length of the finished stream.
pub struct StreamWriter<'a, H: StreamEntry + 'a> {
    buf: &'a mut [u8],
    written: usize,
    entry: PhantomData<fn() -> H>,
}

impl<'a, H: StreamEntry + 'a> StreamWriter<'a, H> {
    #[must_use]
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            written: 0,
            entry: PhantomData,
        }
    }

    #[must_use]
    pub fn written(&self) -> usize {
        self.written
    }

    /// When the entry does not fit, the caller stops enumerating and resumes
    /// from the cookie of the entry in the next request.
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

    #[must_use]
    pub fn finish(self) -> &'a [u8] {
        let Self { buf, written, .. } = self;
        &buf[..written]
    }
}
