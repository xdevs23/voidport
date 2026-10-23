# SPDX-License-Identifier: GPL-2.0
rec {
  device = "/dev/hvc0";
  # Each write to the kernel log becomes one record, which the serial console
  # prints whole, so a module that does not load is reported without text cut
  # into a kernel line. Follows the mount of devtmpfs on /dev.
  toKernelLog = "exec >/dev/kmsg 2>&1";
  # The serial console then contains only kernel log records, so no line from a
  # program can cut into a kernel diagnostic. Follows the load of virtio_console.
  toConsole = "exec >${device} 2>&1";
}
