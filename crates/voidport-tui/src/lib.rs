//! The voidport operator TUI: a full-screen manager for a running `voidportd`.
//!
//! Started as `voidportd --tui`, it is **presentation over the existing control
//! protocol**: it issues exactly the typed operations `voidport-ctl` issues,
//! never touches the state file, and adds no mutation the protocol does not
//! already have. `voidport-ctl` remains the scripting surface; this is the
//! surface for a person.
//!
//! # Layering
//!
//! ```text
//!   terminal (raw mode, panic/suspend/restore)  ─┐
//!   client worker thread (socket, reconnection) ─┤→  app loop  →  update  →  model
//!   the 1 s tick                                ─┘   (effects)   (reducer)   (value)
//!                                                                    ↓
//!                                                                 render
//! ```
//!
//! * [`model`] — a plain value: what the server last said, what the operator
//!   is doing, how the conversation is going. Never an optimistic result.
//! * [`update`] — the reducer: `(model, event) -> (model, effects)`. Pure. No
//!   I/O, no clock, no terminal. Every behaviour rule the design states is a
//!   unit test of this function.
//! * [`render`] — drawing, from the model and nothing else. Every screen is
//!   asserted against a `TestBackend` buffer with no terminal in sight.
//! * [`client`] — the shared control client, driven from a worker thread so
//!   the UI loop never blocks on a socket, with capped-backoff reconnection.
//! * [`tail`] — the one file reader: the Logs screen's window onto the
//!   server's log file, at the edge because the reducer is pure.
//! * [`terminal`] — raw mode, the panic hook, suspend/resume, input pumping.
//! * [`keys`] — the canonical binding table the reducer resolves through and
//!   the Help overlay renders.
//! * [`app`] — the loop that joins them, and the serve-and-present supervisor.
//! * [`harness`] — the same loop with the terminal removed, so the workspace's
//!   suites drive the real worker and the real reducer through one piece of
//!   plumbing instead of a copy each.
//!
//! # Field coverage
//!
//! Every field of every operation and reply in `voidport-control` is either
//! rendered or deliberately not offered. The mapping, so a reviewer can check
//! it against the types:
//!
//! | Field | Where |
//! |---|---|
//! | `server-info` → `version`, `state_file`, `control_socket`, `namespaces`, `listeners` | Overview (`version` also on the status line) |
//! | `server-info` → `log_file` | Logs — the file it tails, named on the screen whether or not it can be read |
//! | `session-list` → `id`, `namespace`, `subpath`, `transport`, `peer`, `nodes`, `handles` | Sessions; the count also on the Overview |
//! | `namespace-list` → `name`, `ownership`, `permission`, `auth`, `rules` | Namespaces |
//! | `namespace-show` → the whole [`NamespaceSpec`](voidport_control::NamespaceSpec) | Rules (its `rules`, with `path`, `match`, `mode`, `target` — a rule's row is keyed and shown by [`Rule::key`](voidport_control::Rule::key), the path-and-match pair), Ownership (its `ownership`, every per-mode field), Permission/Auth (`permission`, `auth`) |
//! | `namespace-create` → `name`, `permission`, `auth`, `ownership` | the create form |
//! | `namespace-delete` → `name` | the selected namespace, behind a confirmation |
//! | `rule-add` → `namespace`, `rule.path`, `rule.mode`, `rule.target` | the rule form |
//! | `rule-remove` → `namespace`, `path`, `match` | the selected rule, behind a confirmation; both halves of its key are sent, so a pattern rule and a literal rule on one directory remove separately |
//! | `ownership-set` → `mode`, `unmapped`, `squash_uid`, `squash_gid`, `uid_map`, `gid_map`, static `uid`/`gid` | the ownership editor, applied whole |
//! | `permission-set` / `auth-set` → `mode` | the Permission/Auth screen |
//! | error envelope → `code`, `message` | the status line, verbatim |
//!
//! Deliberately **not** offered:
//!
//! * `namespace-create`'s `rules`: a namespace is created empty and its rules
//!   are added on the Rules screen. Composing a whole rule table inside a
//!   create form would be a second, worse rule editor.
//! * The id tables, unmapped policy and squash ids of `namespace-create`'s
//!   ownership: the create form takes the mode (and the static ids the
//!   `static` mode requires); the rest is the Ownership editor's, which
//!   applies the policy whole exactly as the protocol does.
//! * `rule-add`'s `rule.match`: pattern rules are shown and removed here, but
//!   not composed. A match is a glob whose overlap with the namespace's other
//!   rules the server judges, and the form has nothing to add to
//!   `voidport-ctl rule add --match` beyond a second place to get it wrong.
//! * Listeners are shown but not editable. The protocol does have
//!   `listener-add` and `listener-remove` now, and the Overview follows them
//!   on its refresh cadence like every other reading; binding an endpoint is
//!   still `voidport-ctl listener add`, because a form here would be a second
//!   place to mistype an address the server then refuses.

#![deny(missing_docs)]

pub mod app;
pub mod client;
pub mod event;
pub mod harness;
pub mod keys;
pub mod model;
pub mod render;
pub mod tail;
pub mod terminal;
pub mod update;

pub use app::{Error, Options, Presentation, Serving, Stopper, run};
pub use model::{LaunchNotes, Model};
