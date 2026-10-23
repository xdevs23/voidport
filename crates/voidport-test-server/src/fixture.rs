use std::fs;
use std::path::{Path, PathBuf};

use voidport_control::{NamespaceName, Request, Rule, ShareMode};
use voidport_test_support::{create_directory, daemon_config};

use crate::wire::{ShareNotification, WireClient};
use crate::{RunningServer, TempDir};

const SHARE_EVENT_MARKER: &str = "share-event-marker";

#[derive(Debug)]
pub struct Fixture {
    pub directory: TempDir,
    pub server: RunningServer,
    /// Differs from `tree` when a test grafts a directory on a filesystem of its own.
    graft: PathBuf,
}

impl Fixture {
    #[must_use]
    pub fn start(label: &str) -> Self {
        Self::start_with(label, "")
    }

    /// `extra` goes before the listeners, so a bare key belongs to `[server]`.
    #[must_use]
    pub fn start_with(label: &str, extra: &str) -> Self {
        let directory = TempDir::new(label);
        let graft = directory.join("tree");
        Self::start_in(directory, extra, graft)
    }

    /// Grafts a directory chosen by the caller, so that the node identity tests
    /// can run on ext4, where inode reuse is immediate.
    #[must_use]
    pub fn start_with_graft(label: &str, extra: &str, graft: &Path) -> Self {
        Self::start_in(TempDir::new(label), extra, graft.to_path_buf())
    }

    fn start_in(directory: TempDir, extra: &str, graft: PathBuf) -> Self {
        build_tree(directory.path());
        let state = state_file(directory.path(), extra, &graft);
        let state_file = directory.write("state.toml", &state);

        // Only the identity of the server can be applied without CAP_CHOWN.
        let config = daemon_config(&state_file);
        let server = RunningServer::start(&config).expect("the server starts");
        Self {
            directory,
            server,
            graft,
        }
    }

    #[must_use]
    pub fn join(&self, name: &str) -> PathBuf {
        self.directory.join(name)
    }

    #[must_use]
    pub fn tree(&self, name: &str) -> PathBuf {
        self.graft.join(name)
    }

    #[must_use]
    pub fn graft_root(&self) -> &Path {
        &self.graft
    }

    /// The server writes the notifications of a connection in the order it
    /// published them, so what a client receives before the added rule is
    /// everything the earlier changes sent it.
    pub fn share_events_before(
        &self,
        namespace: &str,
        parent: &str,
        clients: &mut [&mut WireClient],
    ) -> Vec<Vec<ShareNotification>> {
        let namespace = NamespaceName::new(namespace).expect("a valid namespace name");
        let marker = format!("{parent}/{SHARE_EVENT_MARKER}");
        let mut control = self.server.connect();
        control.expect_ok(&Request::RuleAdd {
            namespace: namespace.clone(),
            rule: Rule::new(marker.clone(), ShareMode::Ro),
        });
        let events = clients
            .iter_mut()
            .map(|client| {
                let mut events = Vec::new();
                loop {
                    match client.share_event() {
                        ShareNotification::Added(line)
                            if line.path.ends_with(SHARE_EVENT_MARKER) =>
                        {
                            return events;
                        }
                        event => events.push(event),
                    }
                }
            })
            .collect();
        control.expect_ok(&Request::RuleRemove {
            namespace,
            path: marker,
            r#match: None,
        });
        for client in clients {
            let removed = client.share_event();
            assert!(
                matches!(&removed, ShareNotification::Removed(path) if path.ends_with(SHARE_EVENT_MARKER)),
                "the removal of the added rule follows it: {removed:?}"
            );
        }
        events
    }
}

fn build_tree(root: &Path) {
    let project = root.join("project");
    create_directory(&project.join("foo"));
    create_directory(&project.join("bar"));
    create_directory(&project.join("secret"));
    fs::write(project.join("file.txt"), b"worked example").expect("writable");
    fs::write(project.join("secret/key"), b"secret").expect("writable");
    create_directory(&root.join("external"));
    fs::write(root.join("external/note"), b"re-targeted").expect("writable");

    let tree = root.join("tree");
    create_directory(&tree.join("sub"));
    fs::write(tree.join("data.bin"), b"0123456789").expect("writable");
    fs::write(tree.join("sub/inner"), b"inner").expect("writable");
}

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

[[namespaces.xattr]]
match = "user.*"
write = "deny"

[[namespaces.xattr]]
match = "user.build.id"
write = "allow"

[[namespaces.xattr]]
match = "user.hidden.*"
read = "deny"

# Two matches of equal literal prefix cover `user.secret-public`. Deny wins.
[[namespaces.xattr]]
match = "user.*secret*"
read = "deny"

[[namespaces.xattr]]
match = "user.*public*"
read = "allow"

# The attempt reaches the host, whose answer comes back.
[[namespaces.xattr]]
match = "security.*"
read = "allow"
write = "allow"

[[namespaces.xattr]]
match = "system.*"
write = "allow"
"#,
        socket = socket.display(),
    )
}

/// Whether the filesystem under `path` supports `user.*` extended attributes.
///
/// tmpfs did not before Linux 6.6.
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
