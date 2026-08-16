//! The host tree and the state file the data-plane tests run against.
//!
//! One fixture serves every data test: a real directory tree on the host, a
//! real state file grafting parts of it under three namespaces, and a real
//! server with both a tcp and a unix data listener bound. The namespaces are
//! chosen to cover the shapes the design distinguishes:
//!
//! * `project` — the design's worked example, with mapped ownership: a graft
//!   whose children default to hidden, the named entries the example shows, one
//!   admitted name that does not exist yet (so a create has somewhere to land),
//!   and one re-targeted literal rule that is absent from the host listing;
//! * `plain` — the same host tree grafted twice, read-write at `/tree` and
//!   read-only at `/readonly`, which is what makes read-only enforcement and
//!   mode-keyed node identity testable side by side;
//! * `deep` — a graft under two intermediate components, so a mount can land on
//!   a synthesized directory;
//! * `attrs` — the same two grafts as `plain`, under a set of extended-attribute
//!   rules covering every shape the design distinguishes: the layering pair, a
//!   read denial that must hide, an exact tie that deny wins, a passthrough
//!   allow, and an allow the ACL guard overrules.
#![allow(dead_code, reason = "each data test file uses part of this")]

use std::fs;
use std::path::{Path, PathBuf};

use voidportd::testing::{create_directory, daemon_config, invoking_environment};

use super::{RunningServer, TempDir};

/// A running server, its host tree, and the directory both live in.
#[derive(Debug)]
pub struct Fixture {
    /// The temporary directory holding the state file and the host tree.
    pub directory: TempDir,
    /// The running server.
    pub server: RunningServer,
    /// The host directory the `plain` namespace grafts at `/tree`, which is the
    /// fixture's own `tree` unless a test put the graft on a filesystem of its
    /// own.
    graft: PathBuf,
}

impl Fixture {
    /// Builds the host tree, writes the state file, and starts the server.
    #[must_use]
    pub fn start(label: &str) -> Self {
        Self::start_with(label, "")
    }

    /// The same, with extra state-file text inserted under `[server]` (a
    /// `node_descriptor_budget` scalar, or a `[server.limits]` table of caps).
    ///
    /// It goes *before* the listeners, so a bare key lands in `[server]` where
    /// an operator would write it, not inside the last listener's table.
    #[must_use]
    pub fn start_with(label: &str, extra: &str) -> Self {
        let directory = TempDir::new(label);
        let graft = directory.join("tree");
        Self::start_in(directory, extra, graft)
    }

    /// The same, grafting a directory of the caller's choosing at `/tree`.
    ///
    /// The one thing this buys is the filesystem *underneath* the graft: the
    /// identity criterion has to run on ext4, where inode reuse is immediate,
    /// and a fixture that can only graft its own scratch directory can never
    /// leave the filesystem the suite happens to run on.
    #[must_use]
    pub fn start_with_graft(label: &str, extra: &str, graft: &Path) -> Self {
        Self::start_in(TempDir::new(label), extra, graft.to_path_buf())
    }

    /// Writes the state file and starts the server.
    fn start_in(directory: TempDir, extra: &str, graft: PathBuf) -> Self {
        build_tree(directory.path());
        let state = state_file(directory.path(), extra, &graft);
        let state_file = directory.write("state.toml", &state);

        // The real invoking identity, not a pinned one: the ownership tests
        // assert on host-side ownership, which only the server's own identity
        // can be applied without CAP_CHOWN.
        let config = daemon_config(&state_file, invoking_environment(directory.path()));
        let server = RunningServer::start(&config).expect("the server starts");
        Self {
            directory,
            server,
            graft,
        }
    }

    /// A path inside the fixture's directory.
    #[must_use]
    pub fn join(&self, name: &str) -> PathBuf {
        self.directory.join(name)
    }

    /// A path inside the grafted host tree.
    #[must_use]
    pub fn tree(&self, name: &str) -> PathBuf {
        self.graft.join(name)
    }

    /// The host directory the `plain` namespace grafts.
    #[must_use]
    pub fn graft_root(&self) -> &Path {
        &self.graft
    }
}

/// Builds the host tree the state file grafts.
fn build_tree(root: &Path) {
    // The worked example.
    let project = root.join("project");
    create_directory(&project.join("foo"));
    create_directory(&project.join("bar"));
    create_directory(&project.join("secret"));
    fs::write(project.join("file.txt"), b"worked example").expect("writable");
    fs::write(project.join("secret/key"), b"secret").expect("writable");
    create_directory(&root.join("external"));
    fs::write(root.join("external/note"), b"re-targeted").expect("writable");

    // The general-purpose tree.
    let tree = root.join("tree");
    create_directory(&tree.join("sub"));
    fs::write(tree.join("data.bin"), b"0123456789").expect("writable");
    fs::write(tree.join("sub/inner"), b"inner").expect("writable");
}

/// The state file, with the fixture's absolute paths and listeners.
fn state_file(root: &Path, extra: &str, graft: &Path) -> String {
    let socket = root.join("data.sock");
    let graft = graft.display();
    format!(
        r#"
[server]
{extra}

[[server.listeners]]
transport = "tcp"
addr = "127.0.0.1:0"

[[server.listeners]]
transport = "unix"
path = "{socket}"

[[namespaces]]
name = "project"

[namespaces.ownership]
mode = "map"
unmapped = "squash"
uid_map = [{{ host = "uid", guest = 0 }}]
gid_map = [{{ host = "gid", guest = 0 }}]

[[namespaces.rules]]
path = "/project"
mode = "rw"
target = "project"

[[namespaces.rules]]
path = "/project/*"
mode = "hidden"

[[namespaces.rules]]
path = "/project/foo"
mode = "rw"

[[namespaces.rules]]
path = "/project/bar"
mode = "ro"

[[namespaces.rules]]
path = "/project/file.txt"
mode = "rw"

[[namespaces.rules]]
path = "/project/new"
mode = "rw"

[[namespaces.rules]]
path = "/project/vendor"
mode = "ro"
target = "external"

[[namespaces]]
name = "plain"

[[namespaces.rules]]
path = "/tree"
mode = "rw"
target = "{graft}"

[[namespaces.rules]]
path = "/readonly"
mode = "ro"
target = "{graft}"

[[namespaces]]
name = "deep"

[[namespaces.rules]]
path = "/deep/inside/graft"
mode = "rw"
target = "{graft}"

[[namespaces]]
name = "attrs"

[[namespaces.rules]]
path = "/tree"
mode = "rw"
target = "{graft}"

[[namespaces.rules]]
path = "/readonly"
mode = "ro"
target = "{graft}"

# The layering pair: the whole `user.` namespace is write-denied, and one
# longer literal prefix wins back its own name.
[[namespaces.xattr]]
match = "user.*"
write = "deny"

[[namespaces.xattr]]
match = "user.build.id"
write = "allow"

# A read denial, which must hide instead of announcing itself.
[[namespaces.xattr]]
match = "user.hidden.*"
read = "deny"

# The exact tie: two matches of equal literal prefix that both cover
# `user.secret-public`. Deny wins, whichever way round they are written.
[[namespaces.xattr]]
match = "user.*secret*"
read = "deny"

[[namespaces.xattr]]
match = "user.*public*"
read = "allow"

# Passthrough honesty: the attempt reaches the host, whose own answer comes
# back — an unprivileged server's `EPERM`, or the label landing where the
# suite runs privileged.
[[namespaces.xattr]]
match = "security.*"
read = "allow"
write = "allow"

# And an allow that the ACL guard overrules regardless.
[[namespaces.xattr]]
match = "system.*"
write = "allow"
"#,
        socket = socket.display(),
    )
}

/// Whether the filesystem under `path` supports `user.*` extended attributes.
///
/// tmpfs did not before Linux 6.6, and the suite has to run on both.
#[must_use]
pub fn supports_user_xattrs(path: &Path) -> bool {
    let probe = path.join(".xattr-probe");
    if fs::write(&probe, b"probe").is_err() {
        return false;
    }
    let supported =
        rustix::fs::setxattr(&probe, "user.probe", b"1", rustix::fs::XattrFlags::empty()).is_ok();
    let _ = fs::remove_file(&probe);
    supported
}
