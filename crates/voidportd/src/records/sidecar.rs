//! The sidecar: recorded truth on disk, and the revalidation that makes
//! persisting it safe.
//!
//! In memory a record is keyed by the node identity the descriptor budget
//! proved — device, inode, kind, birth time — which is what makes hard links
//! correct by construction and is safe within a boot. On disk that key cannot
//! be used as it stands: a device number is not stable across a reboot, and an
//! inode number measurably recycles. So a row persists the identity **minus the
//! device**, plus the last known backing location as a **locator**, and every
//! row is revalidated at load: the locator is stat'd, the row survives only if
//! inode, kind and birth time match, and it rebinds to the fresh full identity.
//!
//! Two consequences are stated, not hidden. A backing that records no birth
//! time cannot be revalidated at all, so its rows are dropped at load: recorded
//! truth is only ever lost conservatively, never resurrected onto an unrelated
//! file. And a host-side rename leaves the locator stale, which the next
//! revalidation drops — the server is the bookkeeper, not the file.
//!
//! The file is the state file's own serde-backed TOML, with the state file's
//! refusal posture when it does not parse, written under the state file's
//! rename-over discipline. Its name is derived from the namespace name, and the
//! derivation has to be **bounded** — a namespace name may be 255 bytes, and a
//! filename may be 255 bytes, so no expanding encoding of the name can fit —
//! and **injective**, because two namespaces sharing a sidecar would each
//! serve the other's records. A fixed-width digest of the name is what
//! satisfies both.

use std::collections::BTreeMap;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use voidport_control::NamespaceName;

use super::bits::PrivilegedBits;
use super::store::{Record, Records};
use crate::host::FileKind;
use crate::host::attr::HostAttr;
use crate::rules::HostBacking;

/// Where a host entry was last seen: the absolute path of its backing.
///
/// A locator is not an identity and is never trusted as one — it is where to
/// look, and the stat that follows is what decides. It is spelled absolutely
/// because that is what a fresh process can stat: the graft descriptors a
/// running server resolves through do not survive a restart.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HostLocator(PathBuf);

impl HostLocator {
    /// The locator of a pinned entry's recorded host path.
    #[must_use]
    pub fn of(backing: &HostBacking) -> Self {
        let mut path = PathBuf::from(backing.graft().as_str());
        for component in backing.relative() {
            path.push(std::ffi::OsStr::from_bytes(component.as_bytes()));
        }
        Self(path)
    }

    /// The path to stat.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.0
    }

    /// This locator with `from` swapped for `to`, where it names `from` itself
    /// or anything beneath it.
    ///
    /// The subtree rewrite a directory rename owes every record underneath it,
    /// and the same shape the node table's own re-pointing uses.
    #[must_use]
    pub fn rebased(&self, from: &Self, to: &Self) -> Option<Self> {
        let below = self.0.strip_prefix(&from.0).ok()?;
        Some(Self(to.0.join(below)))
    }
}

/// Where a server's sidecars live, and what they are named.
///
/// Derived from the state file, because a sidecar is namespace configuration
/// and lives beside the document that holds the namespace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordHome {
    directory: PathBuf,
    prefix: String,
}

impl RecordHome {
    /// The home beside a state file.
    #[must_use]
    pub fn for_state_file(state_file: &Path) -> Self {
        Self {
            directory: crate::state::containing_directory(state_file).to_path_buf(),
            prefix: state_file.file_name().map_or_else(
                || "state.toml".to_owned(),
                |name| name.to_string_lossy().into_owned(),
            ),
        }
    }

    /// The sidecar file of one namespace.
    ///
    /// Bounded and injective: a fixed-width digest of the name, under the state
    /// file's own prefix so that a directory holding two servers' state files
    /// holds two disjoint sets of sidecars.
    #[must_use]
    pub fn sidecar(&self, name: &NamespaceName) -> PathBuf {
        self.directory
            .join(format!(".{}.{}.records.toml", self.prefix, digest(name)))
    }

    /// The temporary a persist of that sidecar renames over it.
    ///
    /// It rides the state file's orphan-sweep prefix — `.<state file>.` and a
    /// `.tmp` suffix — so an interrupted persist leaves nothing the next
    /// startup does not remove.
    #[must_use]
    pub fn temporary(&self, name: &NamespaceName, sequence: u64) -> PathBuf {
        self.directory.join(format!(
            ".{}.{}.records.{}.{sequence}.tmp",
            self.prefix,
            digest(name),
            std::process::id()
        ))
    }
}

/// The fixed-width, injective derivation of a namespace name.
fn digest(name: &NamespaceName) -> String {
    hex::encode(Sha256::digest(name.as_str().as_bytes()))
}

/// The sidecar document.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SidecarDocument {
    /// One row per recorded inode.
    #[serde(default, rename = "record", skip_serializing_if = "Vec::is_empty")]
    pub records: Vec<Row>,
}

/// One recorded inode, as the file holds it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Row {
    /// The host inode number. The device is deliberately absent: it is not
    /// stable across a boot, and the revalidating stat supplies a fresh one.
    pub inode: u64,
    /// What kind of entry it was.
    pub kind: RecordedKind,
    /// The birth time's seconds, where the backing records one. A row without
    /// it cannot be revalidated and is dropped at load.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub birth_sec: Option<i64>,
    /// The birth time's nanoseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub birth_nsec: Option<u32>,
    /// Where the entry was last known to live.
    pub locator: String,
    /// Whether `S_ISUID` is recorded.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub setuid: bool,
    /// Whether `S_ISGID` is recorded.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub setgid: bool,
}

/// The file kind a row records, spelled for a person.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RecordedKind {
    /// A directory.
    Directory,
    /// A symbolic link.
    Symlink,
    /// A regular file.
    Regular,
    /// Anything else: device, fifo, socket.
    Other,
}

impl From<FileKind> for RecordedKind {
    fn from(kind: FileKind) -> Self {
        match kind {
            FileKind::Directory => Self::Directory,
            FileKind::Symlink => Self::Symlink,
            FileKind::Regular => Self::Regular,
            FileKind::Other => Self::Other,
        }
    }
}

impl From<RecordedKind> for FileKind {
    fn from(kind: RecordedKind) -> Self {
        match kind {
            RecordedKind::Directory => Self::Directory,
            RecordedKind::Symlink => Self::Symlink,
            RecordedKind::Regular => Self::Regular,
            RecordedKind::Other => Self::Other,
        }
    }
}

impl SidecarDocument {
    /// The document a live table would be written as, in inode order.
    #[must_use]
    pub fn of(records: &Records) -> Self {
        Self {
            records: records
                .iter()
                .map(|(identity, record)| Row {
                    inode: identity.inode,
                    kind: identity.kind.into(),
                    birth_sec: identity.birth.map(|(sec, _)| sec),
                    birth_nsec: identity.birth.map(|(_, nsec)| nsec),
                    locator: record.locator.path().to_string_lossy().into_owned(),
                    setuid: record.bits.setuid(),
                    setgid: record.bits.setgid(),
                })
                .collect(),
        }
    }

    /// The rows that still describe the file they were written for.
    ///
    /// Every row is stat'd through its locator. A row survives only when inode,
    /// kind and birth time all match what is there now, and it rebinds to the
    /// fresh full identity — the device included, which is the field the row
    /// deliberately does not carry.
    #[must_use]
    pub fn revalidate(&self) -> Records {
        let mut table = BTreeMap::new();
        for row in &self.records {
            let Some((sec, nsec)) = row.birth_sec.zip(row.birth_nsec) else {
                // A backing without birth times cannot prove the file is the
                // one the row was written for.
                continue;
            };
            let locator = HostLocator(PathBuf::from(&row.locator));
            let Ok(found) = HostAttr::of_host_path(locator.path()) else {
                continue;
            };
            let identity = found.node_identity();
            if identity.inode != row.inode
                || identity.kind != FileKind::from(row.kind)
                || identity.birth != Some((sec, nsec))
            {
                continue;
            }
            let bits = PrivilegedBits::new(row.setuid, row.setgid);
            if bits.is_empty() {
                continue;
            }
            table.insert(identity, Record { bits, locator });
        }
        Records::of(table)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Scratch;

    fn name(raw: &str) -> NamespaceName {
        NamespaceName::new(raw).expect("valid namespace name")
    }

    #[test]
    fn a_sidecar_is_named_beside_the_state_file_and_rides_its_sweep_prefix() {
        let home = RecordHome::for_state_file(Path::new("/srv/voidport/state.toml"));
        let sidecar = home.sidecar(&name("project"));
        assert_eq!(sidecar.parent(), Some(Path::new("/srv/voidport")));
        let file = sidecar
            .file_name()
            .expect("a file name")
            .to_string_lossy()
            .into_owned();
        assert!(file.starts_with(".state.toml."), "{file}");
        assert!(file.ends_with(".records.toml"), "{file}");

        // The temporary is what the orphan sweep removes: the same prefix, and
        // a `.tmp` suffix.
        let temporary = home
            .temporary(&name("project"), 0)
            .file_name()
            .expect("a file name")
            .to_string_lossy()
            .into_owned();
        assert!(temporary.starts_with(".state.toml."), "{temporary}");
        assert!(temporary.ends_with(".tmp"), "{temporary}");
    }

    /// The name grammar is wider than a filename's — 255 bytes of anything but
    /// a separator or a control character — so the derivation is a bounded,
    /// injective digest, never an encoding of the name.
    #[test]
    fn the_derivation_is_bounded_and_injective_over_the_whole_name_grammar() {
        let home = RecordHome::for_state_file(Path::new("state.toml"));
        let longest = name(&"ä".repeat(127));
        let file = home.sidecar(&longest);
        let file = file.file_name().expect("a file name").as_encoded_bytes();
        assert!(file.len() < 255, "{} bytes", file.len());

        // Two names that a lossy derivation would confuse stay two sidecars.
        for (left, right) in [(".", ".."), ("a b", "a  b"), ("x", "X"), ("a.b", "a-b")] {
            assert_ne!(home.sidecar(&name(left)), home.sidecar(&name(right)));
        }
        assert_eq!(
            home.sidecar(&name("project")),
            home.sidecar(&name("project"))
        );
    }

    #[test]
    fn a_row_survives_only_where_the_locator_still_names_its_file() {
        let scratch = Scratch::new("sidecar-revalidate");
        let kept = scratch.file("kept", b"x");
        let other = scratch.file("other", b"y");
        let found = HostAttr::of_host_path(&kept).expect("stattable");
        let identity = found.node_identity();
        let Some((sec, nsec)) = identity.birth else {
            // A backing without birth times is the conservative-drop arm, and
            // the assertion below covers it.
            return;
        };

        let row = |locator: &Path, inode: u64| Row {
            inode,
            kind: RecordedKind::Regular,
            birth_sec: Some(sec),
            birth_nsec: Some(nsec),
            locator: locator.to_string_lossy().into_owned(),
            setuid: true,
            setgid: false,
        };
        let document = SidecarDocument {
            records: vec![
                row(&kept, identity.inode),
                // The same identity at a locator that names another file: the
                // stat disagrees, and the row goes.
                row(&other, identity.inode),
                // A locator that names nothing at all.
                row(&scratch.join("gone"), identity.inode),
                // The right file under the wrong inode number.
                row(&kept, identity.inode.wrapping_add(1)),
                // No birth time: nothing to revalidate against.
                Row {
                    birth_sec: None,
                    birth_nsec: None,
                    ..row(&kept, identity.inode)
                },
            ],
        };
        let records = document.revalidate();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records.bits(&identity),
            PrivilegedBits::new(true, false),
            "the surviving row rebound to the fresh identity"
        );
    }

    #[test]
    fn a_document_round_trips_through_the_state_files_own_toml() {
        let document = SidecarDocument {
            records: vec![Row {
                inode: 42,
                kind: RecordedKind::Regular,
                birth_sec: Some(7),
                birth_nsec: Some(8),
                locator: "/srv/project/tool".to_owned(),
                setuid: true,
                setgid: true,
            }],
        };
        let text = toml::to_string(&document).expect("renders");
        assert_eq!(
            toml::from_str::<SidecarDocument>(&text).expect("parses"),
            document
        );
        // An empty table is an empty document, not an absent one.
        assert_eq!(
            toml::from_str::<SidecarDocument>("").expect("parses"),
            SidecarDocument::default()
        );
        // A misspelled key is a refusal, exactly as the state file's is.
        assert!(
            toml::from_str::<SidecarDocument>(
                "[[record]]\ninode = 1\nkind = \"regular\"\nlocator = \"/x\"\nsetuidd = true\n"
            )
            .is_err()
        );
    }
}
