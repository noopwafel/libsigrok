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

#include <config.h>
#include "protocol.h"

#define VDS_USB_TIMEOUT 200

// #define VDS_DUMP_OUTPUT

#ifdef VDS_DUMP_OUTPUT
static void hexdump(uint8_t *buffer, int buflen) {
	for (int i = 0; i < buflen; ++i)
		printf("%02x ", buffer[i]);
}
#endif

static void make_int32(uint8_t *buffer, uint32_t val) {
	buffer[0] = val & 0xff;
	buffer[1] = (val >> 8) & 0xff;
	buffer[2] = (val >> 16) & 0xff;
	buffer[3] = (val >> 24) & 0xff;
}

static void make_int16(uint8_t *buffer, uint32_t val) {
	buffer[0] = val & 0xff;
	buffer[1] = (val >> 8) & 0xff;
}

static int send_bulkcmd(const struct sr_dev_inst *sdi, uint8_t *buffer, int buflen)
{
	struct sr_usb_dev_inst *usb;
	int ret, tmp;

	usb = sdi->conn;

#ifdef VDS_DUMP_OUTPUT
	printf("out: ");
	hexdump(buffer, buflen);
	printf("\n");
#endif

	if ((ret = libusb_bulk_transfer(usb->devhdl, VDS_EP_OUT, buffer, buflen, &tmp, VDS_USB_TIMEOUT)) != 0) {
		sr_err("Failed to send command: %s.",
		       libusb_error_name(ret));
		return SR_ERR;
	}

	return SR_OK;
}

static int recv_bulkcmd(const struct sr_dev_inst *sdi, uint8_t *buffer, int buflen)
{
	struct sr_usb_dev_inst *usb;
	int ret, tmp;

	usb = sdi->conn;

	if ((ret = libusb_bulk_transfer(usb->devhdl, VDS_EP_IN, buffer, buflen, &tmp, VDS_USB_TIMEOUT)) != 0) {
		sr_err("Failed to receive command: %s.",
		       libusb_error_name(ret));
		return SR_ERR;
	}

#ifdef VDS_DUMP_OUTPUT
	printf("in: ");
	hexdump(buffer, buflen);
	printf("\n");
#endif

	return SR_OK;
}

static int vds_packed_cmd(const struct sr_dev_inst *sdi, uint16_t cmd, uint8_t *cmddata, int cmdlen) {
	int ret;
	uint8_t buffer[32];

	if (cmdlen < 0 || cmdlen > 24)
		return SR_ERR;

	make_int32(buffer, cmd);
	buffer[4] = cmdlen;
	memcpy(buffer + 5, cmddata, cmdlen);
	
	if ((ret = send_bulkcmd(sdi, buffer, cmdlen + 5)) != SR_OK)
		return SR_ERR;

	return SR_OK;
}

static int vds_get_response(const struct sr_dev_inst *sdi, char respcode, uint32_t *response) {
	int ret;
	uint8_t buffer[5];

	if ((ret = recv_bulkcmd(sdi, buffer, 5)) != SR_OK)
		return SR_ERR;

	*response = buffer[1] | (buffer[2] << 8) | (buffer[3] << 16) | (buffer[4] << 24);

	if (buffer[0] != respcode) {
		sr_dbg("Expected response %02x (%c), but got %02x (%c) and data %08x\n", respcode, respcode, buffer[0], buffer[0], *response);
		return SR_ERR;
	}

	return SR_OK;
}

static int vds_packed_cmd_response(const struct sr_dev_inst *sdi, uint16_t cmd, uint8_t *cmddata, int cmdlen, char respcode, uint32_t *response) {
	int err;

	err = vds_packed_cmd(sdi, cmd, cmddata, cmdlen);
	if (err)
		return err;

	return vds_get_response(sdi, respcode, response);
}

static int vds_upload_firmware(struct sr_dev_inst *sdi)
{
	struct drv_context *drvc = sdi->driver->context;
	struct sr_usb_dev_inst *usb = sdi->conn;
	char *firmware;
	size_t fw_length;
	int err = SR_OK;
	uint8_t buffer[64];
	uint8_t *large_buffer = NULL;
	uint32_t response;
	uint32_t buffersize;
	uint32_t pos, length;
	unsigned int i;
	int tmp;

	firmware = sr_resource_load(drvc->sr_ctx, SR_RESOURCE_FIRMWARE, "VDS1022_FPGA_V3.5.bin", &fw_length, 0x100000);
	if (!firmware)
		return SR_ERR;

	make_int32(buffer, fw_length);
	err = vds_packed_cmd(sdi, 0x4000, buffer, 4);
	if (err)
		goto done;
	err = vds_get_response(sdi, 'D', &response);
	if (err)
		goto done;
	buffersize = response;
	sr_dbg("bitstream upload starting, buffer size is %d", buffersize);
	if (buffersize <= 4) {
		sr_err("buffer size %d is too small", buffersize);
		err = SR_ERR;
		goto done;
	}

	large_buffer = malloc(buffersize);
	for (i = 0; i < 1 + (fw_length / (buffersize - 4)); ++i) {
		// transfer ID
		make_int32(large_buffer, i);

		pos = i * (buffersize - 4);
		length = buffersize - 4;
		if (pos + length > fw_length)
			length = fw_length - pos;

		memcpy(large_buffer + 4, firmware + pos, length);

		if ((err = libusb_bulk_transfer(usb->devhdl, VDS_EP_OUT, large_buffer, length+4, &tmp, VDS_USB_TIMEOUT)) != 0)
			goto done;
		if ((err = vds_get_response(sdi, 'S', &response)) != 0)
			goto done;
		if (response != i) {
			sr_err("bitstream upload: bad response %d", response);
			err = SR_ERR;
			goto done;
		}
	}

	sr_dbg("bitstream upload done");

done:
	g_free(firmware);
	g_free(large_buffer);
	return err;
}

static int vds_parse_flash(struct sr_dev_inst *sdi, uint8_t *buffer)
{
	struct dev_context *devc = sdi->priv;
	uint32_t version;
	int err, i;

	if (buffer[0] != 0xaa || buffer[1] != 0x55) {
		sr_err("bad flash header");
		return SR_ERR;
	}

	version = buffer[2] | (buffer[3] << 8) | (buffer[4] << 16) | (buffer[5] << 24);
	if (version != 2) {
		sr_err("bad flash version %d", version);
		return SR_ERR;
	}

	memcpy(devc->calibration_data, buffer + 6, sizeof(devc->calibration_data));
	uint16_t *bb = buffer + 6;
	for (int z = 0; z < 3; z++) {
		for (int y = 0; y < 2; y++) {
			for (int x = 0; x < 10; x++) {
				printf("%02x ", *bb++);
			}
			printf("\n");
		}
	}

	return SR_OK;
}

SR_PRIV int vds_open(struct sr_dev_inst *sdi)
{
	struct dev_context *devc = sdi->priv;
	struct drv_context *drvc = sdi->driver->context;
	struct sr_usb_dev_inst *usb = sdi->conn;
	struct libusb_device_descriptor des;
	libusb_device **devlist;
	int err, i, tmp;
	char connection_id[64];
	uint8_t buffer[2];
	uint8_t *flash_buffer = NULL;
	uint32_t response;

	libusb_get_device_list(drvc->sr_ctx->libusb_ctx, &devlist);
	for (i = 0; devlist[i]; i++) {
		libusb_get_device_descriptor(devlist[i], &des);

		if (des.idVendor != devc->profile->vid
		    || des.idProduct != devc->profile->pid)
			continue;

		if ((sdi->status == SR_ST_INITIALIZING) ||
				(sdi->status == SR_ST_INACTIVE)) {
			/*
			 * Check device by its physical USB bus/port address.
			 */
			if (usb_get_port_path(devlist[i], connection_id, sizeof(connection_id)) < 0)
				continue;

			if (strcmp(sdi->connection_id, connection_id))
				/* This is not the one. */
				continue;
		}

		if (!(err = libusb_open(devlist[i], &usb->devhdl))) {
			buffer[0] = 0x56;
			err = vds_packed_cmd_response(sdi, 0x4001, buffer, 1, 'V', &response);
			if (response != 0x1) {
				// VDS 1022
				sr_err("Wrong machine type %08x", response);
				err = SR_ERR;
				break;
			}

			buffer[0] = 0x0;
			err = vds_packed_cmd_response(sdi, 0x223, buffer, 1, 'E', &response);

			if (err) {
				sr_err("Failure during initial handshake");
				break;
			}

			if (response == 0) {
				sr_dbg("Need to upload firmware");

				err = vds_upload_firmware(sdi);

				if (err) {
					sr_err("Failed to upload firmware");
					break;
				}
			}

			buffer[0] = 0x0;
			err = vds_packed_cmd(sdi, 0x1b0, buffer, 1);

			if (!err) {
				flash_buffer = g_malloc(2002);

				err = libusb_bulk_transfer(usb->devhdl, VDS_EP_IN, flash_buffer, 2002, &tmp, VDS_USB_TIMEOUT);
			}

			if (!err) {
				err = vds_parse_flash(sdi, flash_buffer);
			}

			g_free(flash_buffer);

			if (err) {
				sr_err("Failed to read flash contents");
				break;
			}

			sdi->status = SR_ST_ACTIVE;
			sr_info("Opened device on %d.%d (logical) / "
					"%s (physical) interface %d.",
				usb->bus, usb->address,
				sdi->connection_id, USB_INTERFACE);
		} else {
			sr_err("Failed to open device: %s.",
			       libusb_error_name(err));
		}

		/* If we made it here, we handled the device (somehow). */
		break;
	}
	libusb_free_device_list(devlist, 1);

	if (sdi->status != SR_ST_ACTIVE)
		return SR_ERR;

	return SR_OK;
}

SR_PRIV void vds_close(struct sr_dev_inst *sdi)
{
	struct sr_usb_dev_inst *usb;

	usb = sdi->conn;

	if (!usb->devhdl)
		return;

	sr_info("Closing device on %d.%d (logical) / %s (physical) interface %d.",
			usb->bus, usb->address, sdi->connection_id, USB_INTERFACE);
	libusb_release_interface(usb->devhdl, USB_INTERFACE);
	libusb_close(usb->devhdl);
	usb->devhdl = NULL;
	sdi->status = SR_ST_INACTIVE;
}

SR_PRIV int vds_init(struct sr_dev_inst *sdi)
{
	(void)sdi;

	return SR_OK;
}

SR_PRIV int vds_capture_start(struct sr_dev_inst *sdi)
{
	struct dev_context *devc = sdi->priv;
	int err = 0;
	uint8_t buffer[4];
	uint32_t response;
	uint16_t tmp;

	// phase_fine
	buffer[0] = 0;
	err |= vds_packed_cmd_response(sdi, 0x18, buffer, 1, 'S', &response);
	err |= vds_packed_cmd_response(sdi, 0x19, buffer, 1, 'S', &response);

	// trg
	make_int16(buffer, 0x0);
	err |= vds_packed_cmd_response(sdi, 0x24, buffer, 2, 'S', &response);

	// trg_holdoff_arg_ch1
	buffer[0] = 0;
	err |= vds_packed_cmd_response(sdi, 0x26, buffer, 1, 'S', &response);
	// trg_holdoff_index_ch1
	buffer[0] = 0x41;
	err |= vds_packed_cmd_response(sdi, 0x27, buffer, 1, 'S', &response);

	// edge_level_ch1
	buffer[0] = 0x32;
	err |= vds_packed_cmd_response(sdi, 0x2e, buffer, 1, 'S', &response);
	buffer[0] = 0x28;
	err |= vds_packed_cmd_response(sdi, 0x2f, buffer, 1, 'S', &response);

	// chl_on
	buffer[0] = 0x3;
	err |= vds_packed_cmd_response(sdi, 0xb, buffer, 1, 'S', &response);

	// channel_ch1
	buffer[0] = 0x80;
	err |= vds_packed_cmd_response(sdi, 0x111, buffer, 1, 'S', &response);

	// edge_level_ext?
	buffer[0] = 0;
	err |= vds_packed_cmd_response(sdi, 0x10c, buffer, 1, 'S', &response);

	// TODO: here?

	// volt_gain_ch1
	tmp = devc->calibration_data[GAIN][0][devc->voltage[0]];
        make_int16(buffer, tmp);
	err |= vds_packed_cmd_response(sdi, 0x116, buffer, 2, 'S', &response);

	// zero_off_ch1
	// TODO: 50 should be adjustable
	tmp = devc->calibration_data[COMPENSATION][0][devc->voltage[0]];
	tmp = tmp - (50 * devc->calibration_data[AMPLITUDE][0][devc->voltage[0]] / 100);
	make_int16(buffer, tmp);
	err |= vds_packed_cmd_response(sdi, 0x10a, buffer, 2, 'S', &response);

	// sample
	buffer[0] = 0;
	err |= vds_packed_cmd_response(sdi, 0x9, buffer, 1, 'S', &response);

	// dm (deep mem)
	make_int16(buffer, 0x13ec);
	err |= vds_packed_cmd_response(sdi, 0x5c, buffer, 2, 'S', &response);

	// sync output
	buffer[0] = 0;
	err |= vds_packed_cmd_response(sdi, 0x6, buffer, 1, 'S', &response);

	// timebase
	make_int32(buffer, 0x190);
	err |= vds_packed_cmd_response(sdi, 0x52, buffer, 4, 'S', &response);

	// slowmove
	buffer[0] = 0;
	err |= vds_packed_cmd_response(sdi, 0xa, buffer, 1, 'S', &response);

	// pre_trg
	buffer[0] = 0xf1;
	err |= vds_packed_cmd_response(sdi, 0x5a, buffer, 1, 'S', &response);
	buffer[0] = 0x09;
	err |= vds_packed_cmd_response(sdi, 0x5b, buffer, 1, 'S', &response);

	// suf_trg
	buffer[0] = 0xfb;
	err |= vds_packed_cmd_response(sdi, 0x56, buffer, 1, 'S', &response);
	buffer[0] = 0x09;
	err |= vds_packed_cmd_response(sdi, 0x57, buffer, 1, 'S', &response);
	buffer[0] = 0x0;
	err |= vds_packed_cmd_response(sdi, 0x58, buffer, 1, 'S', &response);
	buffer[0] = 0x0;
	err |= vds_packed_cmd_response(sdi, 0x59, buffer, 1, 'S', &response);

	// edge_level_ext (again)
	buffer[0] = 1;
	err |= vds_packed_cmd_response(sdi, 0x10c, buffer, 1, 'S', &response);

	if (err != SR_OK)
		sr_err("capture start failed");

	return err;
}

SR_PRIV int vds_get_data_ready(const struct sr_dev_inst *sdi)
{
	uint32_t response;
	uint8_t buffer[2];
	int err = 0;

	// trg_d
	buffer[0] = 0x0;
	if (!err)
		err = vds_packed_cmd_response(sdi, 0x1, buffer, 1, 'S', &response);

	// datafinished
	buffer[0] = 0x0;
	if (!err)
		err = vds_packed_cmd_response(sdi, 0x7a, buffer, 1, 'S', &response);

	if (err)
		return 0;
	return response;
}

SR_PRIV int vds_get_data(const struct sr_dev_inst *sdi, libusb_transfer_cb_fn cb)
{
	struct sr_usb_dev_inst *usb = sdi->conn;
	int err = 0;
	int i;
	uint8_t buffer[2];
	uint8_t *data_buf;
	struct libusb_transfer *transfer;

	make_int16(buffer, 0x0505);
	if (!err)
		err = vds_packed_cmd(sdi, 0x1000, buffer, 2);
	if (err)
		return SR_ERR;

	for (i = 0; i < 2; ++i) {
		data_buf = g_try_malloc(5200 + 11);
		transfer = libusb_alloc_transfer(0);
		// TODO: why this timeout
		libusb_fill_bulk_transfer(transfer, usb->devhdl, VDS_EP_IN, data_buf,
			5200 + 11, cb, (void *)sdi, 400);
		if ((err = libusb_submit_transfer(transfer)) != 0) {
			sr_err("Failed to submit transfer: %s.", libusb_error_name(err));
                        /* TODO: Free them all. */
                        libusb_free_transfer(transfer);
                        g_free(data_buf);
                        return SR_ERR;
		}
	}

	return SR_OK;
}

SR_PRIV int vds_receive_data(int fd, int revents, void *cb_data)
{
	const struct sr_dev_inst *sdi;
	struct dev_context *devc;

	(void)fd;

	if (!(sdi = cb_data))
		return TRUE;

	if (!(devc = sdi->priv))
		return TRUE;

	if (revents == G_IO_IN) {
		/* TODO */
	}

	return TRUE;
}
