#!/usr/bin/env bash
# Mounts every share of a namespace under a directory and unmounts it when the
# namespace stops sharing it, following the events of `voidport subscribe`.
#
# Usage: mount-manager.sh <voidport-url> <mount-root>
# Needs voidport and jq on PATH.
#
# The subscription uses a connection separate from the mounts, so a manager
# that stops reading cannot stall file I/O of the mounts.

set -uo pipefail

url=${1:?usage: mount-manager.sh <voidport-url> <mount-root>}
root=${2:?usage: mount-manager.sh <voidport-url> <mount-root>}

mkdir -p "$root"

# `/docs/notes` becomes `<root>/docs-notes`, which cannot escape the root.
mountpoint_for() {
    local share=$1
    local name=${share#/}
    name=${name//\//-}
    [ -z "$name" ] && name=root
    printf '%s/%s\n' "$root" "$name"
}

# A subscription opened inside a share reports that share as `/`.
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
    # A mount over FUSE runs in the foreground until it is unmounted. A share
    # of kind "unknown" may not be a directory, so a failed mount is only logged.
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

mounted_shares() {
    local point
    for point in "$root"/*; do
        [ -d "$point" ] || continue
        mountpoint -q "$point" || continue
        basename "$point"
    done
}

reconcile() {
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
            # A changed mode needs a new mount, because the guest kernel checks
            # the mount options before it allows writes.
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
