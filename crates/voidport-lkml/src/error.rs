use std::error::Error;

/// The message of `error` followed by the message of each error in its chain of
/// sources, joined by `: `.
pub fn error_text(error: &dyn Error) -> String {
    std::iter::successors(Some(error), |error| (*error).source())
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(": ")
}

pub fn list_text(texts: impl IntoIterator<Item = String>) -> String {
    texts.into_iter().collect::<Vec<_>>().join("; ")
}
