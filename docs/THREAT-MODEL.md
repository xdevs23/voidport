# voidport threat model (v1)

This document states what voidport trusts, what it defends against, and —
just as deliberately — what it does not. Every tradeoff here is a decision,
dated, not an accident. The enforcement mechanisms referenced live in
`docs/DESIGN.md`.

## Trusted

- The host: kernel, filesystems, and the operator account.
- The `voidportd` process and the identity it runs as. voidport does not
  defend the host from its own operator or from other host processes.
- The hypervisor/VMM and the transports it provides.
- The state file and control socket, both owner-only (0600) and
  instance-locked. The control plane is a trusted-operator interface, not a
  hardened surface.

## Untrusted

- Everything guest-side: the guest kernel, guest root, and every guest
  process. Guest root is an attacker for enforcement purposes.
- Every byte arriving on a data-plane connection. The wire parser treats
  input as hostile: strict framing, no panics on arbitrary bytes (fuzzed),
  framing violations close the connection.
- With `auth.mode: none` (the only v1 mode), any peer that can reach a
  data-plane listener is equivalent to a guest. Reachability IS the v1
  authentication boundary — see the deliberate gaps below.

## What the boundary enforces

- **Deny by default.** A namespace starts empty; nothing resolves unless a
  rule grafts it. Hidden entries do not exist as far as any guest can tell.
- **Path containment.** Grafts are fd-pinned at build; all descent uses
  `openat2` with `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS`; final
  components pin with `O_NOFOLLOW`; the server never follows a symlink and
  rejects `..` components. A guest cannot cause the server to open
  anything outside a graft (kernel-probe-verified; symlink following
  happens only in the guest's own namespace, per FUSE semantics).
- **Server-side share-mode enforcement.** ro and hidden are enforced at the
  server on every write-class operation, regardless of anything the client
  displays or requests. Presented permission bits are presentation.
- **Presented attributes are the guest kernel's to act on.** The server
  presents; the guest kernel, in its own trust domain, decides what its
  processes may do with what it was told. That holds for the privileged mode
  bits as it holds for every other presented attribute: setuid and setgid the
  server *records* — because its own host backing must never carry a
  privileged bit an unprivileged process set — are presented to every mount of
  the namespace, and what exec does with them is the guest's decision, bounded
  by the guest's own `nosuid` and by whatever the guest kernel enforces. One
  line follows from the recording and is stated here so nobody has to
  discover it: a
  record presents its bits even where the host backing sits on a mount whose
  own kernel ignores them, because the bits were never the host file's. Two
  switches mask them instead — the per-namespace server switch and the client's
  own `--no-privileged-bits`, which is stronger than the classic `nosuid`.
- **Identity mapping.** Guest-supplied uids/gids are never applied raw:
  maps must be injective, reverse mapping is bounded by the server's actual
  privilege (an unprivileged server cannot chown arbitrarily; the
  documented fallback keeps the guest view consistent), and explicit
  chown to unattainable ids fails instead of lying.
- **Resource caps.** Per-session in-flight, node, handle, and listing caps
  plus a global session cap bound what one peer can consume (the v1
  denial-of-service posture under `auth: none`).

## Deliberate v1 gaps (accepted 2026-08-12, revisit with hardening)

- **No authentication.** Mitigations: unix sockets are owner-only; TCP
  listeners should bind VM-facing interfaces only; **AF_VSOCK is served**
  (2026-08-15) and is the recommended transport for VM guests, because it
  removes the network surface entirely; the handshake carries an auth blob
  so modes can be added without a protocol break.

  What a vsock listener changes, precisely: there is no interface, no
  route and no address anything off the machine can name, so the
  guest-to-host *network* surface disappears — a TCP listener's exposure is
  a firewall rule away from being wrong, and a vsock listener's is not.
  What it does not change: `auth: none` still means every peer that can
  reach the listener is a guest, and over vsock that set is exactly this
  machine's own VMs (plus the machine itself, where the kernel's loopback
  transport is loaded). Trusting a vsock listener is therefore trusting
  every VM the host runs — which is the v1 posture stated honestly, not an
  authentication mechanism. A `cid` bind narrows it to one context id;
  the default wildcard does not.
- **The live-mount hazard.** A writable graft means the guest can write
  content the HOST may later execute or interpret: git hooks, package
  manager scripts, Makefiles, editor config. This is the product working
  as designed — live sharing is the point — but operators must treat every
  writable share as guest-influence surface on the host. Share read-only
  or not at all when that influence is unacceptable.
- **Revocation vs open handles.** Policy binds at lookup: downgrading or
  hiding a path does not sever handles the guest already holds (local-
  filesystem chmod semantics); client TTLs bound how
  long a stale-mode node can still be opened. Forced revocation is a
  planned explicit operator action, not yet implemented.
- **No transport encryption or integrity.** v1 transports are assumed
  host-local (unix socket, VM-NAT TCP, vsock). Do not run the data plane
  across an untrusted network; vsock cannot leave the machine at all, which
  is why it is the preferred one.
- **Xattr policy.** Only `user.*` crosses the wire; `trusted.*`,
  `security.*`, and `system.*` return EOPNOTSUPP explicitly (unprivileged
  FUSE cannot serve `trusted.*`, and an explicit deny beats a confusing
  partial failure). Consequence: overlayfs upperdirs on a voidport mount
  are unsupported.
- **No cross-restart ino stability.** Tools keying on `(st_dev, st_ino)`
  across a server restart may see changed identities; within a server
  lifetime the synthetic ino table keeps them stable and collision-free
  across merged host filesystems.
