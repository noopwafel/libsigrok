/*
 * This file is part of the libsigrok project.
 *
 * Copyright (C) 2018 Alyssa Milburn <amilburn@zall.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LIBSIGROK_HARDWARE_OWON_VDS_TINY_PROTOCOL_H
#define LIBSIGROK_HARDWARE_OWON_VDS_TINY_PROTOCOL_H

#include <stdint.h>
#include <glib.h>
#include <libsigrok/libsigrok.h>
#include "libsigrok-internal.h"

#define LOG_PREFIX "owon-vds-tiny"

#define USB_INTERFACE 0
#define VDS_EP_IN 0x81
#define VDS_EP_OUT 0x03

enum calibrationtypes {
	GAIN = 0,
	AMPLITUDE = 1,
	COMPENSATION = 2
};

enum states {
	IDLE,
	NEW_CAPTURE,
	CAPTURE,
	FETCH_DATA,
	STOPPING,
};

struct vds_profile {
	uint16_t vid;
	uint16_t pid;
	uint32_t id;
	const char *vendor;
	const char *model;
};

struct dev_context {
	const struct vds_profile *profile;
	int dev_state;
	uint16_t calibration_data[3][2][10];
	int voltage[2];
};

SR_PRIV int vds_open(struct sr_dev_inst *sdi);
SR_PRIV void vds_close(struct sr_dev_inst *sdi);
SR_PRIV int vds_init(struct sr_dev_inst *sdi);
SR_PRIV int vds_capture_start(struct sr_dev_inst *sdi);
SR_PRIV int vds_receive_data(int fd, int revents, void *cb_data);
SR_PRIV int vds_get_data_ready(const struct sr_dev_inst *sdi);
SR_PRIV int vds_get_data(const struct sr_dev_inst *sdi, libusb_transfer_cb_fn cb);

#endif
