# shellcheck shell=bash
# extra-sandbox-paths requires an already-trusted Nix caller.
# VOIDPORT_CCACHE_KERNELS=1 changes the compiler identity and rebuilds the kernel.
voidport_cache_args=()
case "${VOIDPORT_CCACHE_KERNELS:-0}" in
0 | 1) ;;
*)
  printf '%s\n' 'VOIDPORT_CCACHE_KERNELS must be 0 or 1' >&2
  exit 1
  ;;
esac
if [ -n "${VOIDPORT_CCACHE_DIR:-}" ]; then
  # Nix's sandbox setting is a whitespace list with = mappings and ? suffixes,
  # not a shell argument list. Refuse paths it cannot represent literally.
  case "$VOIDPORT_CCACHE_DIR" in
  *[[:space:]=?]* | / | [!/]*)
    printf '%s\n' 'VOIDPORT_CCACHE_DIR must be an absolute dedicated directory without whitespace, = or ?' >&2
    exit 1
    ;;
  esac
  [ -d "$VOIDPORT_CCACHE_DIR" ] || {
    printf '%s\n' 'Create VOIDPORT_CCACHE_DIR privately as root:nixbld mode 0770 first' >&2
    exit 1
  }
  voidport_cache_metadata=$(stat -Lc '%u:%G:%a' -- "$VOIDPORT_CCACHE_DIR")
  if [ "$voidport_cache_metadata" != '0:nixbld:770' ]; then
    printf 'VOIDPORT_CCACHE_DIR requires root:nixbld mode 0770; observed uid:group:mode %s\n' \
      "$voidport_cache_metadata" >&2
    exit 1
  fi
  voidport_cache_args+=(--argstr ccacheDir "$VOIDPORT_CCACHE_DIR"
    --option extra-sandbox-paths "$VOIDPORT_CCACHE_DIR")
elif [ "${VOIDPORT_CCACHE_KERNELS:-0}" = 1 ]; then
  printf '%s\n' 'VOIDPORT_CCACHE_KERNELS=1 requires VOIDPORT_CCACHE_DIR' >&2
  exit 1
fi
if [ "${VOIDPORT_CCACHE_KERNELS:-0}" = 1 ]; then
  voidport_cache_args+=(--arg cacheKernel true)
fi
