#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
set -eu
. "$(dirname "$0")/fault-teardown.sh"

grep() { return 0; }
counter() {
  if [ "$mode" = live ] && [ "$1" = connections_live ]; then
    printf '1'
  else
    printf '0'
  fi
}
umount() { unmounted=yes; [ "$mode" != unmount-failure ]; }
rmmod() { unloaded=yes; [ "$mode" != unload-failure ]; }

for mode in healthy unmount-failure unload-failure live prior-failure; do
  verdict=ok
  [ "$mode" != prior-failure ] || verdict=FAILED
  unmounted=no
  unloaded=no
  fault_teardown
  [ "$unmounted" = yes ] && [ "$unloaded" = yes ]
  expected=FAILED
  [ "$mode" != healthy ] || expected=ok
  [ "$verdict" = "$expected" ]
  printf 'fault teardown control: %s %s\n' "$mode" "$verdict"
done
