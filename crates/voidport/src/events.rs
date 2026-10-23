use serde_json::{Value, json};
use voidport::subscribe::{ShareEntry, ShareEvent};

const SCHEMA_VERSION: u32 = 1;

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

fn plain(name: &str) -> Value {
    json!({ "v": SCHEMA_VERSION, "event": name })
}

fn tagged(name: &str, share: &ShareEntry) -> Value {
    json!({
        "v": SCHEMA_VERSION,
        "event": name,
        "path": text(&share.path),
        "mode": share.mode.as_str(),
        "kind": share.kind.as_str(),
    })
}

fn entry(share: &ShareEntry) -> Value {
    json!({
        "path": text(&share.path),
        "mode": share.mode.as_str(),
        "kind": share.kind.as_str(),
    })
}

/// A path that is not UTF-8 is rendered with the replacement character instead
/// of dropped.
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
        serde_json::from_str::<Value>(&rendered).expect("a line is always JSON");
    }
}
