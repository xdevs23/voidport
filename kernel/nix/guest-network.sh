# SPDX-License-Identifier: GPL-2.0

# QEMU user networking leads to the loopback of the host at VOIDPORT_ADDR. The
# kernel names the only network card eth0 before any renaming.
ip link set eth0 up
ip addr add "$VOIDPORT_GUEST_ADDRESS" dev eth0
