//! On disk the node identity cannot be the key as it stands: a device number is
//! not stable across a reboot, and an inode number recycles. A row therefore
//! persists the identity without the device, plus the last known backing
//! location as a locator, and every row is revalidated at load. The locator is
//! stat'd, the row survives only if inode, kind and birth time match, and it
//! rebinds to the fresh full identity. A backing that records no birth time
//! cannot be revalidated, so its rows are dropped: records are lost
//! conservatively and never resurrected onto an unrelated file. A host-side
//! rename leaves the locator stale, which the next revalidation drops.
//!
//! The name of the file is derived from the namespace name and has to be
//! bounded, because a namespace name and a filename may both be 255 bytes, and
//! injective, because two namespaces sharing a sidecar would serve the records
//! of each other. A fixed-width digest of the name satisfies both.

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

/// A locator is where to look, never an identity: the stat that follows decides.
/// It is absolute because that is what a fresh process can stat, as the graft
/// descriptors do not survive a restart.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HostLocator(PathBuf);

impl HostLocator {
    #[must_use]
    pub fn of(backing: &HostBacking) -> Self {
        let mut path = PathBuf::from(backing.graft().as_str());
        for component in backing.relative() {
            path.push(std::ffi::OsStr::from_bytes(component.as_bytes()));
        }
        Self(path)
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.0
    }

    /// Swaps `from` for `to` where this locator names `from` itself or anything
    /// beneath it, as a directory rename requires.
    #[must_use]
    pub fn rebased(&self, from: &Self, to: &Self) -> Option<Self> {
        let below = self.0.strip_prefix(&from.0).ok()?;
        Some(Self(to.0.join(below)))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordHome {
    directory: PathBuf,
    prefix: String,
}

impl RecordHome {
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

    /// A fixed-width digest of the name, under the prefix of the state file, so a
    /// directory with the state files of two servers has disjoint sidecars.
    #[must_use]
    pub fn sidecar(&self, name: &NamespaceName) -> PathBuf {
        self.directory
            .join(format!(".{}.{}.records.toml", self.prefix, digest(name)))
    }

    /// The temporary uses the orphan-sweep prefix of the state file (`.<state
    /// file>.` and a `.tmp` suffix), so an interrupted persist leaves nothing
    /// that the next startup does not remove.
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

fn digest(name: &NamespaceName) -> String {
    hex::encode(Sha256::digest(name.as_str().as_bytes()))
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SidecarDocument {
    #[serde(default, rename = "record", skip_serializing_if = "Vec::is_empty")]
    pub records: Vec<Row>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Row {
    /// The host inode number. The device is absent because it is not stable
    /// across a boot.
    pub inode: u64,
    pub kind: RecordedKind,
    /// The seconds of the birth time, where the backing records one. A row
    /// without it cannot be revalidated and is dropped at load.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub birth_sec: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub birth_nsec: Option<u32>,
    pub locator: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub setuid: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub setgid: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RecordedKind {
    Directory,
    Symlink,
    Regular,
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
    use voidport_test_host::Scratch;

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

        let temporary = home
            .temporary(&name("project"), 0)
            .file_name()
            .expect("a file name")
            .to_string_lossy()
            .into_owned();
        assert!(temporary.starts_with(".state.toml."), "{temporary}");
        assert!(temporary.ends_with(".tmp"), "{temporary}");
    }

    #[test]
    fn the_derivation_is_bounded_and_injective_over_the_whole_name_grammar() {
        let home = RecordHome::for_state_file(Path::new("state.toml"));
        let longest = name(&"ä".repeat(127));
        let file = home.sidecar(&longest);
        let file = file.file_name().expect("a file name").as_encoded_bytes();
        assert!(file.len() < 255, "{} bytes", file.len());

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
                row(&other, identity.inode),
                row(&scratch.join("gone"), identity.inode),
                row(&kept, identity.inode.wrapping_add(1)),
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
        assert_eq!(
            toml::from_str::<SidecarDocument>("").expect("parses"),
            SidecarDocument::default()
        );
        assert!(
            toml::from_str::<SidecarDocument>(
                "[[record]]\ninode = 1\nkind = \"regular\"\nlocator = \"/x\"\nsetuidd = true\n"
            )
            .is_err()
        );
    }
}
