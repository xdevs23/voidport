/* SPDX-License-Identifier: GPL-2.0 */
#ifndef VOIDPORT_TRANSPORT_BINDINGS_H
#define VOIDPORT_TRANSPORT_BINDINGS_H

#include <linux/in.h>
#include <linux/inet.h>
#include <linux/mod_devicetable.h>
#include <linux/tcp.h>
#include <linux/un.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <net/sock.h>
#include <uapi/linux/virtio_fs.h>
#include <uapi/linux/virtio_ids.h>
#include "voidport_helpers.h"

/* bindgen cannot evaluate the GFP_NOIO macro, so a constant gives its value. */
const gfp_t VOIDPORT_GFP_NOIO = GFP_NOIO;

#endif /* VOIDPORT_TRANSPORT_BINDINGS_H */
