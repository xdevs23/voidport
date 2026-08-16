#!/usr/bin/env bash
# A mount manager driven by `voidport subscribe`.
#
# It keeps a directory of mountpoints in step with what a namespace shares: a
# share that appears is mounted, one that disappears is unmounted, and a
# snapshot reconciles the whole set at once. That is the point of the stream
# being level-triggered — this script never has to remember anything across a
# reconnect, because the server re-sends the truth.
#
# Usage:
#   mount-manager.sh <voidport-url> <mount-root>
#
# Example:
#   mount-manager.sh voidport://127.0.0.1:9000/@project /mnt/project
#
# Requirements: voidport and jq on PATH.
#
# Two deliberate choices to copy:
#
#   * it subscribes on a **session of its own**, not on a mount's. A
#     consumer that stops reading its socket stalls its own connection by
#     ordinary transport backpressure, as any dead peer does; keeping the
#     subscription off the mounts means a slow manager can never stall a
#     guest's file I/O.
#   * it treats `kind: "unknown"` as try-and-see. The server reports a kind only
#     where it already knows one without touching the host, and the mount
#     attempt is what meets reality.

set -uo pipefail

url=${1:?usage: mount-manager.sh <voidport-url> <mount-root>}
root=${2:?usage: mount-manager.sh <voidport-url> <mount-root>}

mkdir -p "$root"

# The mountpoint for a share path: the path with its separators flattened, so
# `/docs/notes` becomes `<root>/docs-notes` and cannot escape the root.
mountpoint_for() {
    local share=$1
    local name=${share#/}
    name=${name//\//-}
    [ -z "$name" ] && name=root
    printf '%s/%s\n' "$root" "$name"
}

# The mount URL of a share: the subscription's path appended to the namespace
# the subscription itself was opened on. The `/` entry — what a session mounted
# *inside* a share reports as its own root — is the namespace URL unchanged.
url_for() {
    local share=$1
    if [ "$share" = "/" ]; then
        printf '%s\n' "$url"
    else
        printf '%s%s\n' "${url%/}" "$share"
    fi
}

mount_share() {
    local share=$1 mode=$2
    local point
    point=$(mountpoint_for "$share")
    mountpoint -q "$point" && return 0
    mkdir -p "$point"
    local options=()
    [ "$mode" = "ro" ] && options+=(--read-only)
    echo "mount-manager: mounting $share at $point ($mode)" >&2
    # `voidport mount` stays in the foreground for the life of the mount, so each
    # one gets a process of its own. A share whose kind is unknown may not be a
    # directory at all, and a mount that fails logs and is skipped: the server
    # promised a rule, not a working directory.
    voidport mount "$(url_for "$share")" "$point" "${options[@]}" &
}

unmount_share() {
    local share=$1
    local point
    point=$(mountpoint_for "$share")
    mountpoint -q "$point" || return 0
    echo "mount-manager: unmounting $share from $point" >&2
    voidport umount "$point" >/dev/null 2>&1 || true
}

# Everything currently mounted under the root, as share paths.
mounted_shares() {
    local point
    for point in "$root"/*; do
        [ -d "$point" ] || continue
        mountpoint -q "$point" || continue
        basename "$point"
    done
}

reconcile() {
    # The snapshot is the whole truth: mount what it names, unmount what it
    # does not. Nothing this script remembered before it matters.
    local wanted=$1
    local name point
    while read -r name; do
        [ -z "$name" ] && continue
        point="$root/$name"
        if ! grep -qxF "$name" <<<"$wanted"; then
            echo "mount-manager: unmounting stale $point" >&2
            voidport umount "$point" >/dev/null 2>&1 || true
        fi
    done < <(mounted_shares)
}

echo "mount-manager: subscribing to $url" >&2

voidport subscribe "$url" | while IFS= read -r line; do
    event=$(jq -r '.event' <<<"$line")
    case "$event" in
        snapshot)
            wanted=""
            while read -r share; do
                [ -z "$share" ] && continue
                wanted+="$(basename "$(mountpoint_for "$share")")"$'\n'
            done < <(jq -r '.entries[] | .path' <<<"$line")
            reconcile "$wanted"
            while read -r share mode; do
                [ -z "$share" ] && continue
                mount_share "$share" "$mode"
            done < <(jq -r '.entries[] | "\(.path) \(.mode)"' <<<"$line")
            ;;
        added)
            mount_share "$(jq -r '.path' <<<"$line")" "$(jq -r '.mode' <<<"$line")"
            ;;
        changed)
            # A mode change is a remount: the kernel enforces the presented
            # bits, so a share that went read-only must be mounted again.
            share=$(jq -r '.path' <<<"$line")
            unmount_share "$share"
            mount_share "$share" "$(jq -r '.mode' <<<"$line")"
            ;;
        removed)
            unmount_share "$(jq -r '.path' <<<"$line")"
            ;;
        lapsed)
            echo "mount-manager: the server forced a resync; a snapshot follows" >&2
            ;;
        disconnected)
            echo "mount-manager: the server broke away; mounts stay up" >&2
            ;;
        resumed)
            echo "mount-manager: the server is back; a snapshot follows" >&2
            ;;
        ended)
            echo "mount-manager: the stream ended ($(jq -r '.reason' <<<"$line"))" >&2
            reconcile ""
            exit 0
            ;;
    esac
done
