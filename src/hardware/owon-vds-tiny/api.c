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

static const uint32_t scanopts[] = {
	SR_CONF_CONN,
};

static const uint32_t drvopts[] = {
	SR_CONF_OSCILLOSCOPE,
};

static const uint32_t devopts[] = {
	SR_CONF_CONTINUOUS,
};

static const char *channel_names[] = {
	"CH1", "CH2",
};

static const struct vds_profile dev_profiles[] = {
	{ 0x5345, 0x1234, 0x1, "Owon", "VDS1022" },
	ALL_ZERO
};

static struct sr_dev_inst *vds_dev_new(const struct vds_profile *prof)
{
	struct sr_dev_inst *sdi;
	struct sr_channel *ch;
	struct sr_channel_group *cg;
	struct dev_context *devc;
	unsigned int i;

	sdi = g_malloc0(sizeof(struct sr_dev_inst));
	sdi->status = SR_ST_INITIALIZING;
	sdi->vendor = g_strdup(prof->vendor);
	sdi->model = g_strdup(prof->model);

	/*
	 * Add only the real channels -- EXT isn't a source of data, only
	 * a trigger source internal to the device.
	 */
	for (i = 0; i < ARRAY_SIZE(channel_names); i++) {
		ch = sr_channel_new(sdi, i, SR_CHANNEL_ANALOG, TRUE, channel_names[i]);
		cg = g_malloc0(sizeof(struct sr_channel_group));
		cg->name = g_strdup(channel_names[i]);
		cg->channels = g_slist_append(cg->channels, ch);
		sdi->channel_groups = g_slist_append(sdi->channel_groups, cg);
	}

	devc = g_malloc0(sizeof(struct dev_context));
	devc->profile = prof;
	/*devc->dev_state = IDLE;
	devc->timebase = DEFAULT_TIMEBASE;
	devc->samplerate = DEFAULT_SAMPLERATE;
	devc->ch_enabled[0] = TRUE;
	devc->ch_enabled[1] = TRUE;
	devc->voltage[0] = DEFAULT_VOLTAGE;
	devc->voltage[1] = DEFAULT_VOLTAGE;
	devc->coupling[0] = DEFAULT_COUPLING;
	devc->coupling[1] = DEFAULT_COUPLING;
	devc->voffset_ch1 = DEFAULT_VERT_OFFSET;
	devc->voffset_ch2 = DEFAULT_VERT_OFFSET;
	devc->voffset_trigger = DEFAULT_VERT_TRIGGERPOS;
	devc->framesize = DEFAULT_FRAMESIZE;
	devc->triggerslope = SLOPE_POSITIVE;
	devc->triggersource = g_strdup(DEFAULT_TRIGGER_SOURCE);
	devc->capture_ratio = DEFAULT_CAPTURE_RATIO;*/
	sdi->priv = devc;

	return sdi;
}


static GSList *scan(struct sr_dev_driver *di, GSList *options)
{
	struct drv_context *drvc;
	struct dev_context *devc;
	struct sr_dev_inst *sdi;
	struct sr_usb_dev_inst *usb;
	struct sr_config *src;
	const struct vds_profile *prof;
	GSList *l, *devices, *conn_devices;
	struct libusb_device_descriptor des;
	libusb_device **devlist;
	int i, j;
	const char *conn;
	char connection_id[64];

	drvc = di->context;

	devices = 0;

	conn = NULL;
	for (l = options; l; l = l->next) {
		src = l->data;
		if (src->key == SR_CONF_CONN) {
			conn = g_variant_get_string(src->data, NULL);
			break;
		}
	}
	if (conn)
		conn_devices = sr_usb_find(drvc->sr_ctx->libusb_ctx, conn);
	else
		conn_devices = NULL;

	libusb_get_device_list(drvc->sr_ctx->libusb_ctx, &devlist);
	for (i = 0; devlist[i]; i++) {
		if (conn) {
			usb = NULL;
			for (l = conn_devices; l; l = l->next) {
				usb = l->data;
				if (usb->bus == libusb_get_bus_number(devlist[i])
					&& usb->address == libusb_get_device_address(devlist[i]))
					break;
			}
			if (!l)
				/* This device matched none of the ones that
				 * matched the conn specification. */
				continue;
		}

		libusb_get_device_descriptor(devlist[i], &des);

		if (usb_get_port_path(devlist[i], connection_id, sizeof(connection_id)) < 0)
			continue;

		prof = NULL;
		for (j = 0; dev_profiles[j].vid; j++) {
			if (!(des.idVendor == dev_profiles[j].vid
				&& des.idProduct == dev_profiles[j].pid)) {
				continue;
			}
			prof = &dev_profiles[j];
			sr_dbg("Found a %s %s.", prof->vendor, prof->model);
			sdi = vds_dev_new(prof);
			sdi->connection_id = g_strdup(connection_id);
			sdi->status = SR_ST_INACTIVE;
			devices = g_slist_append(devices, sdi);
			sdi->inst_type = SR_INST_USB;
			sdi->conn = sr_usb_dev_inst_new(
					libusb_get_bus_number(devlist[i]),
					libusb_get_device_address(devlist[i]), NULL);
			break;
		}
		if (!prof)
			/* not a supported VID/PID */
			continue;
	}
	libusb_free_device_list(devlist, 1);

	return std_scan_complete(di, devices);

}

static int dev_open(struct sr_dev_inst *sdi)
{
	struct dev_context *devc;
	struct sr_usb_dev_inst *usb;
	int err;

	devc = sdi->priv;
	usb = sdi->conn;

	err = vds_open(sdi);
	if (err != SR_OK) {
		sr_err("Unable to open device.");
		return SR_ERR;
	}

	err = libusb_claim_interface(usb->devhdl, USB_INTERFACE);
	if (err != 0) {
		sr_err("Unable to claim interface: %s.",
			libusb_error_name(err));
		return SR_ERR;
	}

	return SR_OK;
}

static int dev_close(struct sr_dev_inst *sdi)
{
	vds_close(sdi);

	return SR_OK;
}

static int config_get(uint32_t key, GVariant **data,
	const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	int ret;

	(void)sdi;
	(void)data;
	(void)cg;

	ret = SR_OK;
	switch (key) {
	/* TODO */
	default:
		return SR_ERR_NA;
	}

	return ret;
}

static int config_set(uint32_t key, GVariant *data,
	const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	int ret;

	(void)sdi;
	(void)data;
	(void)cg;

	ret = SR_OK;
	switch (key) {
	/* TODO */
	default:
		ret = SR_ERR_NA;
	}

	return ret;
}

static int config_list(uint32_t key, GVariant **data,
	const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	int ret;

	(void)sdi;
	(void)data;
	(void)cg;

	ret = SR_OK;
	switch (key) {
	case SR_CONF_SCAN_OPTIONS:
	case SR_CONF_DEVICE_OPTIONS:
		return STD_CONFIG_LIST(key, data, sdi, cg, scanopts, drvopts, devopts);
	/* TODO */
	default:
		return SR_ERR_NA;
	}

	return ret;
}

static void hexdump(uint8_t *buffer, int buflen) {
	for (int i = 0; i < buflen; ++i)
		printf("%02x ", buffer[i]);
}

static void LIBUSB_CALL receive_transfer(struct libusb_transfer *transfer)
{
	struct sr_datafeed_packet packet;
	struct sr_dev_inst *sdi;
	struct dev_context *devc;
	int num_samples, pre;
	int channel;

	sdi = transfer->user_data;
	devc = sdi->priv;
	sr_spew("receive_transfer(): status %s received %d bytes.",
		libusb_error_name(transfer->status), transfer->actual_length);

	if (transfer->actual_length == 0)
		/* Nothing to send to the bus. */
		return;

	if (transfer->actual_length != 5211) {
		// probably EBUSY
		sr_err("got incoming packet of size %d, that's bad: ", transfer->actual_length);
		hexdump(transfer->buffer, transfer->actual_length);
		printf("\n");

		// ouch
		packet.type = SR_DF_FRAME_END;
		sr_session_send(sdi, &packet);
		devc->dev_state = CAPTURE;
		return;
	}

	sr_dbg("got incoming packet");

	channel = transfer->buffer[0];
	if (channel < 0 || channel > 1) {
		sr_err("invalid channel %d", channel);
		return;
	}
	num_samples = 5100;

	//struct sr_datafeed_packet packet;
	struct sr_datafeed_analog analog;
	struct sr_analog_encoding encoding;
	struct sr_analog_meaning meaning;
	struct sr_analog_spec spec;
	//struct dev_context *devc = sdi->priv;
	//GSList *channels = devc->enabled_channels;

	packet.type = SR_DF_ANALOG;
	packet.payload = &analog;
	/* TODO: support for 5xxx series 9-bit samples */
	sr_analog_init(&analog, &encoding, &meaning, &spec, 0);
	analog.num_samples = num_samples;
	analog.meaning->mq = SR_MQ_VOLTAGE;
	analog.meaning->unit = SR_UNIT_VOLT;
	analog.meaning->mqflags = 0;

	/* TODO: Check malloc return value. */
	analog.data = g_try_malloc(num_samples * sizeof(float));
	//analog.meaning->channels = g_slist_append(NULL, channels->data);
	analog.meaning->channels = g_slist_append(NULL, g_slist_nth_data(sdi->channels, channel));

	uint8_t *data_in = transfer->buffer + 11 + 100;
	for (int i = 0; i < num_samples; i++) {
		//((float *)analog.data)[i] = range / 255 * *(data_in + i) - range / 2;
		((float *)analog.data)[i] = *(data_in + i);
	}

	sr_session_send(sdi, &packet);
	g_slist_free(analog.meaning->channels);
	g_free(analog.data);

	if (channel == 1) {
		packet.type = SR_DF_FRAME_END;
		sr_session_send(sdi, &packet);
		devc->dev_state = CAPTURE;
	}

#if 0
	for (int ch = 0; ch < NUM_CHANNELS; ch++) {
		if (!devc->ch_enabled[ch])
			continue;

		float range = ((float)vdivs[devc->voltage[ch]][0] / vdivs[devc->voltage[ch]][1]) * 8;
		float vdivlog = log10f(range / 255);
		int digits = -(int)vdivlog + (vdivlog < 0.0);
		analog.encoding->digits = digits;
		analog.spec->spec_digits = digits;
		analog.meaning->channels = g_slist_append(NULL, channels->data);

		for (int i = 0; i < num_samples; i++) {
			/*
			 * The device always sends data for both channels. If a channel
			 * is disabled, it contains a copy of the enabled channel's
			 * data. However, we only send the requested channels to
			 * the bus.
			 *
			 * Voltage values are encoded as a value 0-255 (0-512 on the
			 * DSO-5200*), where the value is a point in the range
			 * represented by the vdiv setting. There are 8 vertical divs,
			 * so e.g. 500mV/div represents 4V peak-to-peak where 0 = -2V
			 * and 255 = +2V.
			 */
			/* TODO: Support for DSO-5xxx series 9-bit samples. */
			((float *)analog.data)[i] = range / 255 * *(buf + i * 2 + 1 - ch) - range / 2;
		}
		sr_session_send(sdi, &packet);
		g_slist_free(analog.meaning->channels);

		channels = channels->next;
	}
#endif

/*	num_samples = transfer->actual_length / 2;

	sr_spew("Got %d-%d/%d samples in frame.", devc->samp_received + 1,
		devc->samp_received + num_samples, devc->framesize);*/

#if 0
	/*
	 * The device always sends a full frame, but the beginning of the frame
	 * doesn't represent the trigger point. The offset at which the trigger
	 * happened came in with the capture state, so we need to start sending
	 * from there up the session bus. The samples in the frame buffer
	 * before that trigger point came after the end of the device's frame
	 * buffer was reached, and it wrapped around to overwrite up until the
	 * trigger point.
	 */
	if (devc->samp_received < devc->trigger_offset) {
		/* Trigger point not yet reached. */
		if (devc->samp_received + num_samples < devc->trigger_offset) {
			/* The entire chunk is before the trigger point. */
			memcpy(devc->framebuf + devc->samp_buffered * 2,
					transfer->buffer, num_samples * 2);
			devc->samp_buffered += num_samples;
		} else {
			/*
			 * This chunk hits or overruns the trigger point.
			 * Store the part before the trigger fired, and
			 * send the rest up to the session bus.
			 */
			pre = devc->trigger_offset - devc->samp_received;
			memcpy(devc->framebuf + devc->samp_buffered * 2,
					transfer->buffer, pre * 2);
			devc->samp_buffered += pre;

			/* The rest of this chunk starts with the trigger point. */
			sr_dbg("Reached trigger point, %d samples buffered.",
				devc->samp_buffered);

			/* Avoid the corner case where the chunk ended at
			 * exactly the trigger point. */
			if (num_samples > pre)
				send_chunk(sdi, transfer->buffer + pre * 2,
						num_samples - pre);
		}
	} else {
		/* Already past the trigger point, just send it all out. */
		send_chunk(sdi, transfer->buffer, num_samples);
	}

	devc->samp_received += num_samples;

	/* Everything in this transfer was either copied to the buffer or
	 * sent to the session bus. */

	if (devc->samp_received >= devc->framesize) {
		/* That was the last chunk in this frame. Send the buffered
		 * pre-trigger samples out now, in one big chunk. */
		sr_dbg("End of frame, sending %d pre-trigger buffered samples.",
			devc->samp_buffered);
		send_chunk(sdi, devc->framebuf, devc->samp_buffered);
		g_free(devc->framebuf);
		devc->framebuf = NULL;

		/* Mark the end of this frame. */
		packet.type = SR_DF_FRAME_END;
		sr_session_send(sdi, &packet);

		if (devc->limit_frames && ++devc->num_frames >= devc->limit_frames) {
			/* Terminate session */
			devc->dev_state = STOPPING;
		} else {
			devc->dev_state = NEW_CAPTURE;
		}
	}
#endif

	g_free(transfer->buffer);
	libusb_free_transfer(transfer);
}


static int handle_event(int fd, int revents, void *cb_data)
{
	const struct sr_dev_inst *sdi = cb_data;
	struct sr_datafeed_packet packet;
	struct timeval tv;
	struct sr_dev_driver *di = sdi->driver;
	struct dev_context *devc = sdi->priv;
	struct drv_context *drvc = di->context;
	int num_channels;
	uint32_t trigger_offset;
	uint8_t capturestate;

	(void)fd;
	(void)revents;

	if (devc->dev_state == STOPPING) {
		/* We've been told to wind up the acquisition. */
		sr_dbg("Stopping acquisition.");
		/*
		 * TODO: Doesn't really cancel pending transfers so they might
		 * come in after SR_DF_END is sent.
		 */
		usb_source_remove(sdi->session, drvc->sr_ctx);

		std_session_send_df_end(sdi);

		devc->dev_state = IDLE;

		return TRUE;
	}

	/* Always handle pending libusb events. */
	tv.tv_sec = tv.tv_usec = 0;
	libusb_handle_events_timeout(drvc->sr_ctx->libusb_ctx, &tv);

	if (devc->dev_state != CAPTURE)
		return TRUE;

	if (!vds_get_data_ready(sdi))
		return TRUE;

	if (vds_get_data(sdi, receive_transfer) != SR_OK)
		return TRUE;

	devc->dev_state = FETCH_DATA;

	/* Tell the frontend a new frame is on the way. */
	packet.type = SR_DF_FRAME_BEGIN;
	sr_session_send(sdi, &packet);

#if 0
	if ((dso_get_capturestate(sdi, &capturestate, &trigger_offset)) != SR_OK)
		return TRUE;

	sr_dbg("Capturestate %d.", capturestate);
	sr_dbg("Trigger offset 0x%.6x.", trigger_offset);
	switch (capturestate) {
	case CAPTURE_EMPTY:
		if (++devc->capture_empty_count >= MAX_CAPTURE_EMPTY) {
			devc->capture_empty_count = 0;
			if (dso_capture_start(sdi) != SR_OK)
				break;
			if (dso_enable_trigger(sdi) != SR_OK)
				break;
//			if (dso_force_trigger(sdi) != SR_OK)
//				break;
			sr_dbg("Successfully requested next chunk.");
		}
		break;
	case CAPTURE_FILLING:
		/* No data yet. */
		break;
	case CAPTURE_READY_8BIT:
	case CAPTURE_READY_2250:
		/* Remember where in the captured frame the trigger is. */
		devc->trigger_offset = trigger_offset;

		num_channels = (devc->ch_enabled[0] && devc->ch_enabled[1]) ? 2 : 1;
		devc->framebuf = g_malloc(devc->framesize * num_channels * 2);
		devc->samp_buffered = devc->samp_received = 0;

		/* Tell the scope to send us the first frame. */
		if (dso_get_channeldata(sdi, receive_transfer) != SR_OK)
			break;

		/*
		 * Don't hit the state machine again until we're done fetching
		 * the data we just told the scope to send.
		 */
		devc->dev_state = FETCH_DATA;

		/* Tell the frontend a new frame is on the way. */
		packet.type = SR_DF_FRAME_BEGIN;
		sr_session_send(sdi, &packet);
		break;
	case CAPTURE_READY_9BIT:
		/* TODO */
		sr_err("Not yet supported.");
		break;
	case CAPTURE_TIMEOUT:
		/* Doesn't matter, we'll try again next time. */
		break;
	default:
		sr_dbg("Unknown capture state: %d.", capturestate);
		break;
	}
#endif

	return TRUE;
}

static int dev_acquisition_start(const struct sr_dev_inst *sdi)
{
	struct dev_context *devc = sdi->priv;
	struct sr_dev_driver *di = sdi->driver;
	struct drv_context *drvc = di->context;

/*	if (configure_channels(sdi) != SR_OK) {
		sr_err("Failed to configure channels.");
		return SR_ERR;
	}*/

	if (vds_init(sdi) != SR_OK)
		return SR_ERR;

	if (vds_capture_start(sdi) != SR_OK)
		return SR_ERR;
	devc->dev_state = CAPTURE;

	// TODO: why 1
	usb_source_add(sdi->session, drvc->sr_ctx, 1, handle_event, (void *)sdi);

	std_session_send_df_header(sdi);

	return SR_OK;
}

static int dev_acquisition_stop(struct sr_dev_inst *sdi)
{
	struct dev_context *devc;

	/* TODO: stop acquisition?? */

	devc = sdi->priv;
	devc->dev_state = STOPPING;
	//devc->num_frames = 0;

	return SR_OK;
}

SR_PRIV struct sr_dev_driver owon_vds_tiny_driver_info = {
	.name = "owon-vds-tiny",
	.longname = "OWON VDS1022/2052",
	.api_version = 1,
	.init = std_init,
	.cleanup = std_cleanup,
	.scan = scan,
	.dev_list = std_dev_list,
	.dev_clear = std_dev_clear,
	.config_get = config_get,
	.config_set = config_set,
	.config_list = config_list,
	.dev_open = dev_open,
	.dev_close = dev_close,
	.dev_acquisition_start = dev_acquisition_start,
	.dev_acquisition_stop = dev_acquisition_stop,
	.context = NULL,
};

SR_REGISTER_DEV_DRIVER(owon_vds_tiny_driver_info);
