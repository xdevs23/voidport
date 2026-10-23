# shellcheck shell=bash
run_harness() {
  local mode=$1 runs=$2 namespace=$3
  shift 3
  local member=${VOIDPORT_KERNEL_MEMBER:-stable}
  local directory=${VOIDPORT_HARNESS_DIR:-$root/.cache/kernel-guests/$member/$mode}
  local slots=$root/slots/slots.py
  local attribute find_binaries keeper_binary=
  # `voidport_boot_parameters` is an array set by the caller.
  local parameter boot_arguments=()
  for parameter in "${voidport_boot_parameters[@]}"; do
    boot_arguments+=(--boot-parameter "$parameter")
  done
  case "$mode" in
    mount) attribute=mountGuest find_binaries=binaries_from_dev_shell ;;
    closure) attribute=closureGuest find_binaries=binaries_from_dev_shell ;;
    speed) attribute=speedGuest find_binaries=binaries_from_guest ;;
    *) printf 'unknown guest mode: %s\n' "$mode" >&2; exit 1 ;;
  esac
  [ -c /dev/kvm ] || { printf 'missing required device: /dev/kvm\n' >&2; exit 1; }
  case "${VOIDPORT_BAD_CHILD_OPEN:-0}" in
    0 | 1) ;;
    *) printf 'VOIDPORT_BAD_CHILD_OPEN must be 0 or 1\n' >&2; exit 1 ;;
  esac
  # shellcheck source=cache-args.sh
  source "$root/kernel/nix/cache-args.sh"
  # shellcheck source=processors.sh
  source "$root/kernel/nix/processors.sh"
  source_path=$("$slots" taskset -c "$voidport_cpus" bash "$root/kernel/nix/source-path")
  guest=$("$slots" taskset -c "$voidport_cpus" nix-build --max-jobs 1 --cores "$voidport_cores" --no-out-link "$source_path/kernel/nix" \
    "${voidport_cache_args[@]}" -A "$member.$attribute")
  tools=$("$slots" taskset -c "$voidport_cpus" nix-build --max-jobs 1 --cores "$voidport_cores" --no-out-link "$source_path/kernel/nix" -A harnessTools)
  "$find_binaries"
  exec "$slots" taskset -c "$voidport_cpus" "$tools/bin/python3" "$root/kernel/tests/run-guest.py" \
    --mode "$mode" --runs "$runs" --namespace "$namespace" \
    --guest "$guest" --server "$server_binary" --ctl "$ctl_binary" \
    ${keeper_binary:+--keeper "$keeper_binary"} \
    --qemu "$tools/bin/qemu-system-x86_64" --python "$tools/bin/python3" \
    --source "$source_path" --directory "$directory" \
    --focus "${VOIDPORT_FOCUS:-full}" --bad-child-open "${VOIDPORT_BAD_CHILD_OPEN:-0}" \
    "${boot_arguments[@]}" "$@"
}

binaries_from_dev_shell() {
  local binaries
  binaries=$("$slots" taskset -c "$voidport_cpus" nix develop --max-jobs 1 --cores "$voidport_cores" "path:$source_path" \
    -c bash -o pipefail -c '
      # A target directory of its own, so that this build never replaces a
      # debug/voidportd that a workspace build in the same directory runs.
      cargo build --manifest-path "$1/Cargo.toml" -p voidportd -p voidport-ctl -p voidport-keeper \
        --target-dir "${CARGO_TARGET_DIR:?the dev shell sets CARGO_TARGET_DIR}/guest-harness" \
        --message-format=json-render-diagnostics |
        "$2" -er -s '\''[.[] | select(.reason == "compiler-artifact"
          and .executable != null) | {key: .target.name, value: .executable}]
          | from_entries'\''
    ' _ "$root" "$tools/bin/jq")
  server_binary=$("$tools/bin/jq" -er '.voidportd' <<<"$binaries")
  ctl_binary=$("$tools/bin/jq" -er '.["voidport-ctl"]' <<<"$binaries")
  keeper_binary=$("$tools/bin/jq" -er '.["voidport-keeper"]' <<<"$binaries")
}

# The comparison measures release builds, so the server is the one built with
# the programs run by the guest.
binaries_from_guest() {
  server_binary=$guest/programs/bin/voidportd
  ctl_binary=$guest/programs/bin/voidport-ctl
}
