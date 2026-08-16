//! Error rendering shared by operator-facing surfaces.

use std::fmt::Write as _;

/// Renders an error and its complete source chain on one line.
///
/// The control protocol carries a string, not an error tree, and the
/// daemon writes one terminal line, so both surfaces use this exact framing.
#[must_use]
pub fn render(error: &dyn std::error::Error) -> String {
    let mut rendered = error.to_string();
    let mut current = error.source();
    while let Some(error) = current {
        write!(rendered, ": {error}").expect("writing to a String cannot fail");
        current = error.source();
    }
    rendered
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, thiserror::Error)]
    #[error("outer")]
    struct Outer {
        #[source]
        source: Inner,
    }

    #[derive(Debug, thiserror::Error)]
    #[error("inner")]
    struct Inner {
        #[source]
        source: std::io::Error,
    }

    #[test]
    fn every_source_is_rendered_in_order() {
        let error = Outer {
            source: Inner {
                source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
            },
        };
        assert_eq!(render(&error), "outer: inner: permission denied");
    }
}
