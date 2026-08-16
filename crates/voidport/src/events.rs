//! Rendering subscription events as JSON lines.
//!
//! Its own module, compiled into the binary only: JSON belongs to the command
//! line's output and never to the wire, which carries fixed-layout structs.
//! Keeping the rendering here — not in the library the subscription
//! lives in — is what keeps that boundary visible.
//!
//! The schema is normative (design: "Client surface"). Every line carries
//! `"v": 1` and an `"event"`:
//!
//! ```text
//! {"v":1,"event":"snapshot","entries":[{"path":"/docs","mode":"ro","kind":"directory"}]}
//! {"v":1,"event":"added","path":"/new","mode":"rw","kind":"directory"}
//! {"v":1,"event":"changed","path":"/docs","mode":"rw","kind":"directory"}
//! {"v":1,"event":"removed","path":"/docs"}
//! {"v":1,"event":"lapsed"}
//! {"v":1,"event":"disconnected"}
//! {"v":1,"event":"resumed"}
//! {"v":1,"event":"ended","reason":"namespace-removed"}
//! ```
//!
//! Paths are byte strings on the wire, because host entry names are. A path
//! that is not UTF-8 is rendered with the replacement character, not
//! dropped: a line a consumer cannot act on is still better than a share it
//! never hears about, and the alternative — refusing to print — would hide the
//! entry entirely.

use serde_json::{Value, json};
use voidport::subscribe::{ShareEntry, ShareEvent};

/// The schema version every line carries.
const SCHEMA_VERSION: u32 = 1;

/// Renders one event as its JSON line, without the terminator.
pub fn render(event: &ShareEvent) -> String {
    let value = match event {
        ShareEvent::Snapshot { entries } => json!({
            "v": SCHEMA_VERSION,
            "event": "snapshot",
            "entries": entries.iter().map(entry).collect::<Vec<Value>>(),
        }),
        ShareEvent::Added(share) => tagged("added", share),
        ShareEvent::Changed(share) => tagged("changed", share),
        ShareEvent::Removed { path } => json!({
            "v": SCHEMA_VERSION,
            "event": "removed",
            "path": text(path),
        }),
        ShareEvent::Lapsed => plain("lapsed"),
        ShareEvent::Disconnected => plain("disconnected"),
        ShareEvent::Resumed => plain("resumed"),
        ShareEvent::Ended { reason } => json!({
            "v": SCHEMA_VERSION,
            "event": "ended",
            "reason": reason.as_str(),
        }),
    };
    value.to_string()
}

/// An event whose whole content is its name.
fn plain(name: &str) -> Value {
    json!({ "v": SCHEMA_VERSION, "event": name })
}

/// An event carrying one entry inline.
fn tagged(name: &str, share: &ShareEntry) -> Value {
    json!({
        "v": SCHEMA_VERSION,
        "event": name,
        "path": text(&share.path),
        "mode": share.mode.as_str(),
        "kind": share.kind.as_str(),
    })
}

/// One entry of a snapshot.
fn entry(share: &ShareEntry) -> Value {
    json!({
        "path": text(&share.path),
        "mode": share.mode.as_str(),
        "kind": share.kind.as_str(),
    })
}

/// A wire path as text.
fn text(path: &[u8]) -> String {
    String::from_utf8_lossy(path).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use voidport::subscribe::{EndReason, ShareKind, ShareMode};

    fn share(path: &str, mode: ShareMode, kind: ShareKind) -> ShareEntry {
        ShareEntry {
            path: path.as_bytes().to_vec(),
            mode,
            kind,
        }
    }

    /// The schema is normative, so it is asserted as exact text, not
    /// re-parsed: a consumer's `jq` filter breaks on a renamed field, and this
    /// is where that would be noticed.
    #[test]
    fn every_event_renders_the_documented_line() {
        assert_eq!(
            render(&ShareEvent::Snapshot {
                entries: vec![
                    share("/", ShareMode::Rw, ShareKind::Directory),
                    share("/notes.txt", ShareMode::Ro, ShareKind::File),
                ],
            }),
            r#"{"entries":[{"kind":"directory","mode":"rw","path":"/"},{"kind":"file","mode":"ro","path":"/notes.txt"}],"event":"snapshot","v":1}"#
        );
        assert_eq!(
            render(&ShareEvent::Added(share(
                "/new",
                ShareMode::Rw,
                ShareKind::Unknown
            ))),
            r#"{"event":"added","kind":"unknown","mode":"rw","path":"/new","v":1}"#
        );
        assert_eq!(
            render(&ShareEvent::Changed(share(
                "/docs",
                ShareMode::Ro,
                ShareKind::Directory
            ))),
            r#"{"event":"changed","kind":"directory","mode":"ro","path":"/docs","v":1}"#
        );
        assert_eq!(
            render(&ShareEvent::Removed {
                path: b"/docs".to_vec()
            }),
            r#"{"event":"removed","path":"/docs","v":1}"#
        );
        assert_eq!(render(&ShareEvent::Lapsed), r#"{"event":"lapsed","v":1}"#);
        assert_eq!(
            render(&ShareEvent::Disconnected),
            r#"{"event":"disconnected","v":1}"#
        );
        assert_eq!(render(&ShareEvent::Resumed), r#"{"event":"resumed","v":1}"#);
        assert_eq!(
            render(&ShareEvent::Ended {
                reason: EndReason::NamespaceRemoved
            }),
            r#"{"event":"ended","reason":"namespace-removed","v":1}"#
        );
    }

    #[test]
    fn a_path_that_is_not_text_still_produces_a_line() {
        let rendered = render(&ShareEvent::Removed {
            path: vec![b'/', 0xFF],
        });
        assert!(rendered.contains(r#""event":"removed""#), "{rendered}");
        assert!(rendered.starts_with('{') && rendered.ends_with('}'));
        // It is still valid JSON, which is the only promise a consumer has.
        serde_json::from_str::<Value>(&rendered).expect("a line is always JSON");
    }
}
