# SPDX-License-Identifier: GPL-2.0

# The caller prints one verdict after this returns. A failed step does not skip
# the others.
fault_teardown() {
  if grep -q ' /mnt ' /proc/mounts; then
    umount /mnt || verdict=FAILED
  fi
  [ "$(counter requests_in_flight)" = 0 ] &&
    [ "$(counter replies_live)" = 0 ] &&
    [ "$(counter connections_live)" = 0 ] || verdict=FAILED
  rmmod voidport || verdict=FAILED
}
