/**
 * Copyright © 2016 Thincast Technologies Gmbh
 * Copyright © 2016 Hardening <contact@hardening-consulting.com>
 *
 * Permission to use, copy, modify, distribute, and sell this software and
 * its documentation for any purpose is hereby granted without fee, provided
 * that the above copyright notice appear in all copies and that both that
 * copyright notice and this permission notice appear in supporting
 * documentation, and that the name of the copyright holders not be used in
 * advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission.  The copyright holders make
 * no representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 *
 * THE COPYRIGHT HOLDERS DISCLAIM ALL WARRANTIES WITH REGARD TO THIS
 * SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS, IN NO EVENT SHALL THE COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER
 * RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF
 * CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "config.h"

#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/input.h>

#include <firerds/backend.h>
#include <firerds/dmgbuf.h>
#include <firerds/version.h>

#include <freerdp/freerdp.h>
#include <freerdp/update.h>
#include <freerdp/input.h>
#include <freerdp/locale/keyboard.h>
#include <freerdp/server/rdpei.h>

#include <winpr/input.h>
#include <winpr/stream.h>
#include <winpr/collections.h>

#include "../shared/helpers.h"
#include "pixman-renderer.h"
#include "compositor-firerds.h"


#define DEFAULT_AXIS_STEP_DISTANCE wl_fixed_from_int(10)
#define FIRERDS_COMMON_LENGTH 6
#define FIRERDS_MODE_FPS 60 * 1000

/* ======================== stolen from wayland-os.c  =======================*/
static int
set_cloexec_or_close(int fd)
{
	long flags;

	if (fd == -1)
		return -1;

	flags = fcntl(fd, F_GETFD);
	if (flags == -1)
		goto err;

	if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == -1)
		goto err;

	return fd;

err:
	close(fd);
	return -1;
}

static int
wl_os_socket_cloexec(int domain, int type, int protocol)
{
	int fd;

	fd = socket(domain, type | SOCK_CLOEXEC, protocol);
	if (fd >= 0)
		return fd;
	if (errno != EINVAL)
		return -1;

	fd = socket(domain, type, protocol);
	return set_cloexec_or_close(fd);
}

static int
wl_os_accept_cloexec(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	int fd;

#ifdef HAVE_ACCEPT4
	fd = accept4(sockfd, addr, addrlen, SOCK_CLOEXEC);
	if (fd >= 0)
		return fd;
	if (errno != ENOSYS)
		return -1;
#endif

	fd = accept(sockfd, addr, addrlen);
	return set_cloexec_or_close(fd);
}

/* =========================================================================== */

struct firerds_backend;
struct firerds_output;

/** @brief state of the module protocol automata */
enum StreamState {
	STREAM_WAITING_COMMON_HEADER,
	STREAM_WAITING_DATA
};

/** @brief a seat for firerds */
struct firerds_seat {
	struct weston_seat base;

	UINT32 keyboard_layout;
	UINT32 keyboard_type;

	RdpeiServerContext *rdpei_context;
	HANDLE rdpei_channel;
	struct wl_event_source *rdpei_event_source;
};

/** @brief firerds compositor */
struct firerds_backend {
	struct weston_backend base;
	struct weston_compositor *compositor;

	struct firerds_output *output;
	struct firerds_seat *seat;
	UINT32 mainSeatConnectionId;
	wHashTable *extra_seats;

	bool have_seat;
	int listening_fd;
	struct wl_event_source *server_event_source;
	int	client_fd;
	struct wl_event_source *client_event_source;
	enum StreamState streamState;
	wStream *in_stream;
	wStream *out_stream;
	UINT16 current_msg_type;
	UINT32 expected_bytes;
	xkb_mod_index_t capslock_mod_index;
	xkb_mod_index_t numlock_mod_index;
	xkb_mod_index_t scrolllock_mod_index;

	firerds_msg_framebuffer_info rds_fb_infos;
	firerds_msg_framebuffer_sync_reply rds_sync_reply;
	firerds_msg_set_system_pointer rds_set_system_pointer;
};

/** @brief a firerds output */
struct firerds_output {
	struct weston_output base;
	struct firerds_backend *compositor;
	struct wl_event_source *finish_frame_timer;

	int shmid;
	void *buffer;
	void *dmgBuf;
	int pendingShmId;
	int pendingFrame;
	pixman_image_t *shadow_surface;
	pixman_region32_t damagedRegion;
	bool outputActive;
};

static int
firerds_send_stream(struct firerds_backend *c, wStream *s) {
	int toWrite, written;
	const char *ptr;

	toWrite = Stream_Length(s);
	ptr = (const char *)Stream_Buffer(s);
	while (toWrite) {
		written = write(c->client_fd, ptr, toWrite);
		if (written <= 0)
			return -1;
		toWrite -= written;
		ptr += written;
	}
	return 0;
}

static int
backend_send_message(struct firerds_backend *b, UINT16 type, firerds_message *common) {
	Stream_SetPosition(b->out_stream, 0);
	firerds_message_send(b->out_stream, type, common);
	Stream_SealLength(b->out_stream);

	return firerds_send_stream(b, b->out_stream);
}


static void
firerds_update_framebuffer(struct firerds_backend *c, pixman_box32_t *rect) {
	struct firerds_output *output = c->output;
	unsigned char *src = (unsigned char *)pixman_image_get_data(output->shadow_surface) +
			(pixman_image_get_stride(output->shadow_surface) * rect->y1) +
			(rect->x1 * 4);
	unsigned char *dst = (unsigned char *)output->buffer +
			(c->rds_fb_infos.scanline * rect->y1) +
			(rect->x1 * 4);
	int widthBytes = (rect->x2 - rect->x1) * 4;
	int y;

	for (y = rect->y1; y < rect->y2; y++) {
		memcpy(dst, src, widthBytes);
		src += pixman_image_get_stride(output->shadow_surface);
		dst += c->rds_fb_infos.scanline;
	}
}

static int
firerds_refresh_region(struct firerds_backend *b, pixman_region32_t *region)
{
	int nrects, i;
	RDP_RECT *rdpRect;
	pixman_box32_t *rect;
	struct firerds_output *output = b->output;

	if (output->dmgBuf) {
		if (firerds_dmgbuf_get_id(output->dmgBuf) != output->pendingShmId) {
			firerds_dmgbuf_free(output->dmgBuf);
			output->dmgBuf = 0;
		}
	}

	if (!output->dmgBuf) {
		output->dmgBuf = firerds_dmgbuf_connect(output->pendingShmId);
		if (!output->dmgBuf) {
			weston_log("%s: unable to bind shmId=%d", __FUNCTION__, output->pendingShmId);
			return -1;
		}
		output->buffer = firerds_dmgbuf_get_data(output->dmgBuf);
	}

	rect = pixman_region32_rectangles(region, &nrects);
	rdpRect = firerds_dmgbuf_get_rects(output->dmgBuf, NULL);

	if (nrects > (int)firerds_dmgbuf_get_max_rects(output->dmgBuf)) {
		/* the region contains too many rectangles, so let's just use the extents
		 * as damaged region */
		pixman_box32_t *extents = pixman_region32_extents(region);
		firerds_dmgbuf_set_num_rects(output->dmgBuf, 1);
		rdpRect->x = extents->x1;
		rdpRect->y = extents->y1;
		rdpRect->width = extents->x2 - extents->x1;
		rdpRect->height = extents->y2 - extents->y1;
		firerds_update_framebuffer(b, extents);
	} else {
		firerds_dmgbuf_set_num_rects(output->dmgBuf, nrects);
		for (i = 0; i < nrects; i++, rect++, rdpRect++) {
			/*weston_log("refresh_rect id=0x%x (%d,%d,%d,%d)\n", output->pendingShmId, rect->x1, rect->y1, rect->x2, rect->y2);*/
			firerds_update_framebuffer(b, rect);

			rdpRect->x = rect->x1;
			rdpRect->y = rect->y1;
			rdpRect->width = rect->x2 - rect->x1;
			rdpRect->height = rect->y2 - rect->y1;
		}
	}

	pixman_region32_clear(region);

	b->rds_sync_reply.bufferId = output->pendingShmId;
	output->pendingFrame = 0;

	return backend_send_message(b, FIRERDS_SERVER_FRAMEBUFFER_SYNC_REPLY, (firerds_message *)&b->rds_sync_reply);
}


static void
firerds_output_start_repaint_loop(struct weston_output *output)
{
	struct timespec ts;

	clock_gettime(output->compositor->presentation_clock, &ts);
	weston_output_finish_frame(output, &ts, WP_PRESENTATION_FEEDBACK_INVALID);
}

static int
firerds_output_repaint(struct weston_output *output_base, pixman_region32_t *damage)
{
	struct firerds_output *output = container_of(output_base, struct firerds_output, base);
	struct weston_compositor *ec = output->base.compositor;

	pixman_region32_union(&output->damagedRegion, &output->damagedRegion, damage);

	pixman_renderer_output_set_buffer(output_base, output->shadow_surface);
	ec->renderer->repaint_output(&output->base, damage);

	if (output->compositor->client_event_source && output->pendingFrame)
		firerds_refresh_region(output->compositor, &output->damagedRegion);

	pixman_region32_subtract(&ec->primary_plane.damage, &ec->primary_plane.damage, damage);

	wl_event_source_timer_update(output->finish_frame_timer, 10);
	return 0;
}

static void
firerds_kill_client(struct firerds_backend *c) {
	wl_event_source_remove(c->client_event_source);
	c->client_event_source = 0;
	if (c->seat) {
		struct firerds_seat *seat = c->seat;
		seat->keyboard_layout = 0;
		seat->keyboard_type = 0;
		weston_seat_release_pointer(&seat->base);
		weston_seat_release_keyboard(&seat->base);
	}

	c->seat = NULL;
	close(c->client_fd);
	c->client_fd = -1;

	c->expected_bytes = FIRERDS_COMMON_LENGTH;
	c->streamState = STREAM_WAITING_COMMON_HEADER;
	c->have_seat = false;
	c->output->pendingShmId = -1;
}

static void
firerds_output_destroy(struct weston_output *output_base)
{
	struct firerds_output *output = container_of(output_base, struct firerds_output, base);

	pixman_image_unref(output->shadow_surface);
	wl_event_source_remove(output->finish_frame_timer);
	pixman_region32_fini(&output->damagedRegion);

	pixman_renderer_output_destroy(output_base);
	free(output);
}

static int
finish_frame_handler(void *data)
{
	firerds_output_start_repaint_loop(data);
	return 1;
}


static struct weston_mode *
firerds_insert_new_mode(struct weston_output *output, int width, int height, int rate) {
	struct weston_mode *ret;
	ret = zalloc(sizeof *ret);
	if(!ret)
		return ret;
	ret->width = width;
	ret->height = height;
	ret->refresh = rate;
	wl_list_insert(&output->mode_list, &ret->link);
	return ret;
}

static struct weston_mode *
ensure_matching_mode(struct weston_output *output, struct weston_mode *target) {
	struct weston_mode *local;

	wl_list_for_each(local, &output->mode_list, link) {
		if((local->width == target->width) && (local->height == target->height))
			return local;
	}

	return firerds_insert_new_mode(output, target->width, target->height, FIRERDS_MODE_FPS);
}


static int
firerds_send_shared_framebuffer(struct firerds_backend *b) {
	return backend_send_message(b, FIRERDS_SERVER_FRAMEBUFFER_INFO, (firerds_message *)&b->rds_fb_infos);
}



static int
firerds_switch_mode(struct weston_output *output, struct weston_mode *mode)
{
	struct weston_mode *localMode;
	pixman_image_t *new_shadow_buffer;
	struct firerds_output *rdsOutput = container_of(output, struct firerds_output, base);
	struct firerds_backend *c = rdsOutput->compositor;

	localMode = ensure_matching_mode(output, mode);
	if (!localMode) {
		weston_log("unable to ensure the requested mode\n");
		return -ENOMEM;
	}

	if(localMode == output->current_mode)
		return 0;

	output->current_mode->flags &= ~WL_OUTPUT_MODE_CURRENT;

	output->current_mode = localMode;
	output->current_mode->flags |= WL_OUTPUT_MODE_CURRENT;

	pixman_renderer_output_destroy(output);
	pixman_renderer_output_create(output);

	new_shadow_buffer = pixman_image_create_bits(PIXMAN_x8r8g8b8, mode->width,
			mode->height, 0, mode->width * 4);
	pixman_image_composite32(PIXMAN_OP_SRC, rdsOutput->shadow_surface, 0,
			new_shadow_buffer, 0, 0,
			0, 0,
			0, 0, mode->width, mode->height
	);

	pixman_image_unref(rdsOutput->shadow_surface);
	rdsOutput->shadow_surface = new_shadow_buffer;

	pixman_region32_clear(&rdsOutput->damagedRegion);
	pixman_region32_union_rect(&rdsOutput->damagedRegion, &rdsOutput->damagedRegion,
			0, 0, mode->width, mode->height);

	c->rds_fb_infos.width = mode->width;
	c->rds_fb_infos.height = mode->height;
	c->rds_fb_infos.scanline = mode->width * 4;

	if (c->client_fd >= 0) {
		// we have a connected peer so we have to inform it of the new configuration
		firerds_send_shared_framebuffer(c);
	}
	return 0;
}

struct firerds_simple_mode {
	int width;
	int height;
};
static struct firerds_simple_mode standard_modes[] = {
		{640, 480},
		{800, 600},
		{1024, 768},
		{1280, 1024},

		{0, 0}, /* /!\ the last one /!\ */
};


static int
firerds_compositor_create_output(struct firerds_backend *c, int width, int height)
{
	int i;
	struct firerds_output *output;
	struct wl_event_loop *loop;
	struct weston_mode *currentMode, *next, *extraMode;
	firerds_msg_framebuffer_info *fb_infos;
	firerds_msg_set_system_pointer *system_pointer;

	output = zalloc(sizeof *output);
	if (output == NULL)
		return -1;

	wl_list_init(&output->base.mode_list);

	currentMode = firerds_insert_new_mode(&output->base, width, height, FIRERDS_MODE_FPS);
	if(!currentMode)
		goto out_free_output;
	currentMode->flags = WL_OUTPUT_MODE_CURRENT | WL_OUTPUT_MODE_PREFERRED;

	for (i = 0; standard_modes[i].width; i++) {
		if (standard_modes[i].width == width && standard_modes[i].height == height)
			continue;

		extraMode = firerds_insert_new_mode(&output->base,
				standard_modes[i].width,
				standard_modes[i].height, FIRERDS_MODE_FPS
		);
		if(!extraMode)
			goto out_output;
	}

	output->base.current_mode = output->base.native_mode = currentMode;
	weston_output_init(&output->base, c->compositor, 0, 0, width, height,
			   WL_OUTPUT_TRANSFORM_NORMAL, 1);

	output->base.make = "weston";
	output->base.model = "firerds";

	output->shmid = -1;
	output->buffer = 0;
	output->outputActive = true;
	output->pendingShmId = -1;
	output->pendingFrame = false;

	fb_infos = &c->rds_fb_infos;
	fb_infos->width = width;
	fb_infos->height = height;
	fb_infos->bitsPerPixel = 32;
	fb_infos->bytesPerPixel = 4;
	fb_infos->userId = (UINT32)getuid();
	fb_infos->scanline = width * 4;

	system_pointer = &c->rds_set_system_pointer;
	system_pointer->ptrType = SYSPTR_NULL;

	pixman_region32_init(&output->damagedRegion);
	output->shadow_surface = pixman_image_create_bits(PIXMAN_a8r8g8b8,
			width, height,
		    NULL,
		    width * 4);
	if (output->shadow_surface == NULL) {
		weston_log("Failed to create surface for frame buffer.\n");
		goto out_output;
	}

	if (pixman_renderer_output_create(&output->base) < 0)
		goto out_shadow_surface;

	loop = wl_display_get_event_loop(c->compositor->wl_display);
	output->finish_frame_timer = wl_event_loop_add_timer(loop, finish_frame_handler, output);

	output->base.start_repaint_loop = firerds_output_start_repaint_loop;
	output->base.repaint = firerds_output_repaint;
	output->base.destroy = firerds_output_destroy;
	output->base.assign_planes = NULL;
	output->base.set_backlight = NULL;
	output->base.set_dpms = NULL;
	output->base.switch_mode = firerds_switch_mode;
	output->compositor = c;
	c->output = output;

	wl_list_insert(c->compositor->output_list.prev, &output->base.link);
	return 0;

out_shadow_surface:
	pixman_image_unref(output->shadow_surface);
out_output:
	weston_output_destroy(&output->base);

	wl_list_for_each_safe(currentMode, next, &output->base.mode_list, link)
		free(currentMode);
out_free_output:
	free(output);
	return -1;
}

static void
firerds_restore(struct weston_compositor *ec)
{
}

static void
firerds_destroy(struct weston_compositor *ec)
{
	struct firerds_backend *c = (struct firerds_backend *)ec->backend;

	wl_event_source_remove(c->server_event_source);
	c->server_event_source = 0;
	close(c->listening_fd);

	if (c->client_event_source)
		firerds_kill_client(c);

	Stream_Free(c->in_stream, TRUE);
	Stream_Free(c->out_stream, TRUE);
	weston_compositor_shutdown(ec);

	free(ec);
}


static void
firerds_mouse_event(struct firerds_backend *c, struct weston_seat *seat, DWORD x, DWORD y, DWORD flags) {
	uint32_t button = 0;
	bool need_frame = false;

	/*weston_log("mouse event: x=%d y=%d flags=0x%x\n", x, y, flags);*/
	if (flags & PTR_FLAGS_MOVE) {
		if((int)x < c->output->base.width && (int)y < c->output->base.height) {
			notify_motion_absolute(seat, weston_compositor_get_time(), x, y);
			need_frame = true;
		}
	}

	if (flags & PTR_FLAGS_BUTTON1)
		button = BTN_LEFT;
	else if (flags & PTR_FLAGS_BUTTON2)
		button = BTN_RIGHT;
	else if (flags & PTR_FLAGS_BUTTON3)
		button = BTN_MIDDLE;

	if(button) {
		notify_button(seat, weston_compositor_get_time(), button,
			(flags & PTR_FLAGS_DOWN) ? WL_POINTER_BUTTON_STATE_PRESSED : WL_POINTER_BUTTON_STATE_RELEASED
		);
		need_frame = true;
	}

	if (flags & PTR_FLAGS_WHEEL) {
		struct weston_pointer_axis_event event;
		double value;

		/* DEFAULT_AXIS_STEP_DISTANCE is stolen from compositor-x11.c
		 * The RDP specs says the lower bits of flags contains the "the number of rotation
		 * units the mouse wheel was rotated".
		 *
		 * http://blogs.msdn.com/b/oldnewthing/archive/2013/01/23/10387366.aspx explains the 120 value
		 */
		value = (flags & 0xff) / 120.0;
		if (flags & PTR_FLAGS_WHEEL_NEGATIVE)
			value = -value;

		event.axis = WL_POINTER_AXIS_VERTICAL_SCROLL;
		event.value = DEFAULT_AXIS_STEP_DISTANCE * value;
		event.discrete = (int)value;
		event.has_discrete = true;

		notify_axis(seat, weston_compositor_get_time(), &event);
		need_frame = true;
	}

	if (need_frame)
		notify_pointer_frame(seat);
}

static void
firerds_scancode_keyboard_event(struct firerds_backend *c, struct weston_seat *seat,
		UINT32 flags, UINT32 code, UINT32 keyboardType)
{
	uint32_t vk_code, full_code, key_code;
	enum wl_keyboard_key_state keyState;
	int notify = 0;

	/*weston_log("code=%d flags=0x%x keyb=%d\n", code, flags, keyboardType);*/
	if (flags & KBD_FLAGS_DOWN) {
		keyState = WL_KEYBOARD_KEY_STATE_PRESSED;
		notify = 1;
	} else if (flags & KBD_FLAGS_RELEASE) {
		keyState = WL_KEYBOARD_KEY_STATE_RELEASED;
		notify = 1;
	}

	if(notify) {
		full_code = code;
		if(flags & KBD_FLAGS_EXTENDED)
			full_code |= KBD_FLAGS_EXTENDED;

		vk_code = GetVirtualKeyCodeFromVirtualScanCode(full_code, keyboardType);
		if(flags & KBD_FLAGS_EXTENDED)
			vk_code |= KBDEXT;

		key_code = GetKeycodeFromVirtualKeyCode(vk_code, KEYCODE_TYPE_EVDEV);

		/*weston_log("code=%x ext=%d vk_code=%x scan_code=%x\n", code, (flags & KBD_FLAGS_EXTENDED) ? 1 : 0,
				vk_code, scan_code);*/
		notify_key(seat, weston_compositor_get_time(), key_code-8, keyState,
				STATE_UPDATE_AUTOMATIC);
	}
}

struct rdp_to_xkb_keyboard_layout {
	UINT32 rdpLayoutCode;
	const char *xkbLayout;
	const char *xkbVariant;
};


/* table reversed from
	https://github.com/awakecoding/FreeRDP/blob/master/libfreerdp/locale/xkb_layout_ids.c#L811 */
static
struct rdp_to_xkb_keyboard_layout rdp_keyboards[] = {
		{KBD_ARABIC_101, "ara", 0},
		{KBD_BULGARIAN, 0, 0},
		{KBD_CHINESE_TRADITIONAL_US, 0},
		{KBD_CZECH, "cz", 0},
		{KBD_CZECH_PROGRAMMERS, "cz", "bksl"},
		{KBD_CZECH_QWERTY, "cz", "qwerty"},
		{KBD_DANISH, "dk", 0},
		{KBD_GERMAN, "de", 0},
		{KBD_GERMAN_NEO, "de", "neo"},
		{KBD_GERMAN_IBM, "de", "qwerty"},
		{KBD_GREEK, "gr", 0},
		{KBD_GREEK_220, "gr", "simple"},
		{KBD_GREEK_319, "gr", "extended"},
		{KBD_GREEK_POLYTONIC, "gr", "polytonic"},
		{KBD_US, "us", 0},
		{KBD_US_ENGLISH_TABLE_FOR_IBM_ARABIC_238_L, "ara", "buckwalter"},
		{KBD_SPANISH, "es", 0},
		{KBD_SPANISH_VARIATION, "es", "nodeadkeys"},
		{KBD_FINNISH, "fi", 0},
		{KBD_FRENCH, "fr", 0},
		{KBD_HEBREW, "il", 0},
		{KBD_HUNGARIAN, "hu", 0},
		{KBD_HUNGARIAN_101_KEY, "hu", "standard"},
		{KBD_ICELANDIC, "is", 0},
		{KBD_ITALIAN, "it", 0},
		{KBD_ITALIAN_142, "it", "nodeadkeys"},
		{KBD_JAPANESE, "jp", 0},
		{KBD_JAPANESE_INPUT_SYSTEM_MS_IME2002, "jp", "kana"},
		{KBD_KOREAN, "kr", 0},
		{KBD_KOREAN_INPUT_SYSTEM_IME_2000, "kr", "kr104"},
		{KBD_DUTCH, "nl", 0},
		{KBD_NORWEGIAN, "no", 0},
		{KBD_POLISH_PROGRAMMERS, "pl", 0},
		{KBD_POLISH_214, "pl", "qwertz"},
//		{KBD_PORTUGUESE_BRAZILIAN_ABN0416, 0},
		{KBD_ROMANIAN, "ro", 0},
		{KBD_RUSSIAN, "ru", 0},
		{KBD_RUSSIAN_TYPEWRITER, "ru", "typewriter"},
		{KBD_CROATIAN, "hr", 0},
		{KBD_SLOVAK, "sk", 0},
		{KBD_SLOVAK_QWERTY, "sk", "qwerty"},
		{KBD_ALBANIAN, 0, 0},
		{KBD_SWEDISH, "se", 0},
		{KBD_THAI_KEDMANEE, "th", 0},
		{KBD_THAI_KEDMANEE_NON_SHIFTLOCK, "th", "tis"},
		{KBD_TURKISH_Q, "tr", 0},
		{KBD_TURKISH_F, "tr", "f"},
		{KBD_URDU, "in", "urd-phonetic3"},
		{KBD_UKRAINIAN, "ua", 0},
		{KBD_BELARUSIAN, "by", 0},
		{KBD_SLOVENIAN, "si", 0},
		{KBD_ESTONIAN, "ee", 0},
		{KBD_LATVIAN, "lv", 0},
		{KBD_LITHUANIAN_IBM, "lt", "ibm"},
		{KBD_FARSI, "af", 0},
		{KBD_VIETNAMESE, "vn", 0},
		{KBD_ARMENIAN_EASTERN, "am", 0},
		{KBD_AZERI_LATIN, 0, 0},
		{KBD_FYRO_MACEDONIAN, "mk", 0},
		{KBD_GEORGIAN, "ge", 0},
		{KBD_FAEROESE, 0, 0},
		{KBD_DEVANAGARI_INSCRIPT, 0, 0},
		{KBD_MALTESE_47_KEY, 0, 0},
		{KBD_NORWEGIAN_WITH_SAMI, "no", "smi"},
		{KBD_KAZAKH, "kz", 0},
		{KBD_KYRGYZ_CYRILLIC, "kg", "phonetic"},
		{KBD_TATAR, "ru", "tt"},
		{KBD_BENGALI, "bd", 0},
		{KBD_BENGALI_INSCRIPT, "bd", "probhat"},
		{KBD_PUNJABI, 0, 0},
		{KBD_GUJARATI, "in", "guj"},
		{KBD_TAMIL, "in", "tam"},
		{KBD_TELUGU, "in", "tel"},
		{KBD_KANNADA, "in", "kan"},
		{KBD_MALAYALAM, "in", "mal"},
		{KBD_HINDI_TRADITIONAL, "in", 0},
		{KBD_MARATHI, 0, 0},
		{KBD_MONGOLIAN_CYRILLIC, "mn", 0},
		{KBD_UNITED_KINGDOM_EXTENDED, "gb", "intl"},
		{KBD_SYRIAC, "syc", 0},
		{KBD_SYRIAC_PHONETIC, "syc", "syc_phonetic"},
		{KBD_NEPALI, "np", 0},
		{KBD_PASHTO, "af", "ps"},
		{KBD_DIVEHI_PHONETIC, 0, 0},
		{KBD_LUXEMBOURGISH, 0, 0},
		{KBD_MAORI, "mao", 0},
		{KBD_CHINESE_SIMPLIFIED_US, 0, 0},
		{KBD_SWISS_GERMAN, "ch", "de_nodeadkeys"},
		{KBD_UNITED_KINGDOM, "gb", 0},
		{KBD_LATIN_AMERICAN, "latam", 0},
		{KBD_BELGIAN_FRENCH, "be", 0},
		{KBD_BELGIAN_PERIOD, "be", "oss_sundeadkeys"},
		{KBD_PORTUGUESE, "pt", 0},
		{KBD_SERBIAN_LATIN, "rs", 0},
		{KBD_AZERI_CYRILLIC, "az", "cyrillic"},
		{KBD_SWEDISH_WITH_SAMI, "se", "smi"},
		{KBD_UZBEK_CYRILLIC, "af", "uz"},
		{KBD_INUKTITUT_LATIN, "ca", "ike"},
		{KBD_CANADIAN_FRENCH_LEGACY, "ca", "fr-legacy"},
		{KBD_SERBIAN_CYRILLIC, "rs", 0},
		{KBD_CANADIAN_FRENCH, "ca", "fr-legacy"},
		{KBD_SWISS_FRENCH, "ch", "fr"},
		{KBD_BOSNIAN, "ba", 0},
		{KBD_IRISH, 0, 0},
		{KBD_BOSNIAN_CYRILLIC, "ba", "us"},
		{KBD_UNITED_STATES_DVORAK, "us", "dvorak"},
		{KBD_PORTUGUESE_BRAZILIAN_ABNT2, "br", "nativo"},
		{KBD_CANADIAN_MULTILINGUAL_STANDARD, "ca", "multix"},
		{KBD_GAELIC, "ie", "CloGaelach"},

		{0x00000000, 0, 0},
};

/* taken from 2.2.7.1.6 Input Capability Set (TS_INPUT_CAPABILITYSET) */
static char *rdp_keyboard_types[] = {
	"",	/* 0: unused */
	"", /* 1: IBM PC/XT or compatible (83-key) keyboard */
	"", /* 2: Olivetti "ICO" (102-key) keyboard */
	"", /* 3: IBM PC/AT (84-key) or similar keyboard */
	"pc105",/* 4: IBM enhanced (101- or 102-key) keyboard */
	"", /* 5: Nokia 1050 and similar keyboards */
	"",	/* 6: Nokia 9140 and similar keyboards */
	"jp106"	/* 7: Japanese keyboard */
};

static struct xkb_keymap *
firerds_retrieve_keymap(UINT32 rdpKbLayout, UINT32 rdpKbType) {
	struct xkb_context *xkbContext;
	struct xkb_rule_names xkbRuleNames;
	struct xkb_keymap *keymap;
	int i;

	memset(&xkbRuleNames, 0, sizeof(xkbRuleNames));
	if(rdpKbType <= 7 && rdpKbType > 0)
		xkbRuleNames.model = rdp_keyboard_types[rdpKbType];
	else
		xkbRuleNames.model = "pc105";

	for(i = 0; rdp_keyboards[i].rdpLayoutCode; i++) {
		if(rdp_keyboards[i].rdpLayoutCode == rdpKbLayout) {
			xkbRuleNames.layout = rdp_keyboards[i].xkbLayout;
			xkbRuleNames.variant = rdp_keyboards[i].xkbVariant;
			break;
		}
	}

	keymap = NULL;
	if(xkbRuleNames.layout) {
		xkbContext = xkb_context_new(0);
		if(!xkbContext) {
			weston_log("unable to create a xkb_context\n");
			return NULL;
		}

		weston_log("looking for keymap %s\n", xkbRuleNames.layout);
		keymap = xkb_keymap_new_from_names(xkbContext, &xkbRuleNames, 0);
	}
	return keymap;
}

static void
firerds_configure_keyboard(struct firerds_backend *c, struct firerds_seat *seat, UINT32 layout, UINT32 keyboard_type) {
	//weston_log("%s: layout=0x%x keyboard_type=%d\n", __FUNCTION__, layout, keyboard_type);
	if (seat->keyboard_layout == layout && seat->keyboard_type == keyboard_type)
		return;

	weston_seat_init_keyboard(&seat->base,
			firerds_retrieve_keymap(layout, keyboard_type)
	);

	seat->keyboard_layout = layout;
	seat->keyboard_type = keyboard_type;
}

static void
firerds_update_keyboard_modifiers(struct firerds_backend *c, struct weston_seat *seat,
		bool capsLock, bool numLock, bool scrollLock, bool kanaLock)
{
	uint32_t mods_depressed, mods_latched, mods_locked, group;
	uint32_t serial;
	int numMask, capsMask, scrollMask;

	struct weston_keyboard *keyboard = seat->keyboard_state;
	struct xkb_state *state = keyboard->xkb_state.state;
	struct weston_xkb_info *xkb_info = keyboard->xkb_info;

	mods_depressed = xkb_state_serialize_mods(state, XKB_STATE_DEPRESSED);
	mods_latched = xkb_state_serialize_mods(state, XKB_STATE_LATCHED);
	mods_locked = xkb_state_serialize_mods(state, XKB_STATE_LOCKED);
	group = xkb_state_serialize_group(state, XKB_STATE_EFFECTIVE);

	numMask = (1 << xkb_info->mod2_mod);
	capsMask = (1 << xkb_info->caps_mod);
	scrollMask = (1 << xkb_info->scroll_led); // TODO: don't rely on the led status

	mods_locked = capsLock ? (mods_locked | capsMask) : (mods_locked & ~capsMask);
	mods_locked = numLock ? (mods_locked | numMask) : (mods_locked & ~numLock);
	mods_locked = scrollLock ? (mods_locked | scrollMask) : (mods_locked & ~scrollMask);

	xkb_state_update_mask(state, mods_depressed, mods_latched, mods_locked, 0, 0, group);

	serial = wl_display_next_serial(c->compositor->wl_display);
	notify_modifiers(seat, serial);
}

static int
firerds_send_disable_pointer(struct firerds_backend *b) {
	return backend_send_message(b, FIRERDS_SERVER_SET_SYSTEM_POINTER, (firerds_message *)&b->rds_set_system_pointer);
}

static struct weston_seat *
retrieve_seat(struct firerds_backend *c, UINT32 id) {
	struct weston_seat *ret;
	if (c->mainSeatConnectionId == id)
		return &c->seat->base;

	if (!HashTable_Contains(c->extra_seats, (void *)(size_t)id)) {
		weston_log("no seat registered for connection %d\n", (int)id);
		return NULL;
	}

	ret = (struct weston_seat *)HashTable_GetItemValue(c->extra_seats, (void *)(size_t)id);
	if (!ret)
		weston_log("no seat registered for connection %d(main=%d)\n", (int)id, (int)c->mainSeatConnectionId);
	return ret;
}

#define BUILD_MULTITOUCH
#ifdef BUILD_MULTITOUCH
static UINT
rdpei_onClientReady(RdpeiServerContext *context) {
	struct firerds_backend *c = (struct firerds_backend *)context->user_data;
	if ((context->clientVersion != RDPINPUT_PROTOCOL_V10) && (context->clientVersion != RDPINPUT_PROTOCOL_V101))
		weston_log("strange got an unexpected client version 0x%x", context->clientVersion);

	if (context->protocolFlags & READY_FLAGS_DISABLE_TIMESTAMP_INJECTION)
		weston_log("don't take in account the timestamps\n");

	weston_seat_init_touch(&c->seat->base);
	return CHANNEL_RC_OK;
}

static UINT
rdpei_onTouchEvent(RdpeiServerContext *context, RDPINPUT_TOUCH_EVENT *touchEvent) {
	struct firerds_backend *c = (struct firerds_backend *)context->user_data;
	UINT16 i;
	UINT32 j;

	for (i = 0; i < touchEvent->frameCount; i++) {
		RDPINPUT_TOUCH_FRAME *frame = &touchEvent->frames[i];

		notify_touch_frame(&c->seat->base);

		for (j = 0; j < frame->contactCount; j++) {
			RDPINPUT_CONTACT_DATA *data = &frame->contacts[j];
			int flags = 0;

			/*weston_log("%s: id=%d flags=0x%x up=%d down=%d update=%d\n", __FUNCTION__, data->contactId,
					data->contactFlags, data->contactFlags & CONTACT_FLAG_UP, data->contactFlags & CONTACT_FLAG_DOWN,
					data->contactFlags & CONTACT_FLAG_UPDATE);*/
			if (data->contactFlags & CONTACT_FLAG_UP)
				flags = WL_TOUCH_UP;
			else if (data->contactFlags & CONTACT_FLAG_DOWN) {
				flags = (data->contactFlags & CONTACT_FLAG_UPDATE) ? WL_TOUCH_MOTION : WL_TOUCH_DOWN;
			} else if (data->contactFlags & CONTACT_FLAG_UPDATE)
				flags = WL_TOUCH_MOTION;

			notify_touch(&c->seat->base, weston_compositor_get_time(), data->contactId,
					wl_fixed_from_int(data->x), wl_fixed_from_int(data->y), flags);
		}
	}

	return CHANNEL_RC_OK;
}

static int
firerds_multitouch_activity(int fd, uint32_t mask, void *data) {
	struct firerds_backend *c = (struct firerds_backend *)data;
	int ret;

	if (!c->seat)
		return 0;

	ret = rdpei_server_handle_messages(c->seat->rdpei_context);
	if (ret != CHANNEL_RC_OK) {
		weston_log("%s: disconnected !!!", __FUNCTION__);
		return -1;
	}

	return 0;
}

static int
firerds_configure_multitouch(struct firerds_backend *c, struct firerds_seat *seat) {
	struct wl_event_loop *loop;
	int fd;
	RdpeiServerContext *rdpei_context;

	seat->rdpei_context = rdpei_context = rdpei_server_context_new(WTS_CURRENT_SERVER_HANDLE);
	rdpei_context->user_data = c;
	rdpei_context->onClientReady = rdpei_onClientReady;
	rdpei_context->onTouchEvent = rdpei_onTouchEvent;
	if (rdpei_server_init(rdpei_context) != CHANNEL_RC_OK) {
		weston_log("no multitouch support\n");
		return 0;
	}

	if (rdpei_server_send_sc_ready(rdpei_context, RDPINPUT_PROTOCOL_V101) != CHANNEL_RC_OK) {
		weston_log("error sending first multitouch packet");
		return -1;
	}

	seat->rdpei_channel = rdpei_server_get_event_handle(rdpei_context);
	if (!seat->rdpei_channel || seat->rdpei_channel == INVALID_HANDLE_VALUE) {
		weston_log("error retrieving the RDPEI channel");
		return -1;
	}

	fd = GetEventFileDescriptor(seat->rdpei_channel);
	if (fd < 0) {
		weston_log("invalid RDPEI file descriptor");
		return -1;
	}

	loop = wl_display_get_event_loop(c->compositor->wl_display);
	seat->rdpei_event_source = wl_event_loop_add_fd(loop, fd, WL_EVENT_READABLE, firerds_multitouch_activity, c);

	return 0;
}

#endif

static int
firerds_treat_message(struct firerds_backend *b, UINT16 type, firerds_message *message) {
	firerds_msg_capabilities *capabilities;
	firerds_msg_mouse_event *mouse_event;
	firerds_msg_framebuffer_sync_request *sync_req;
	firerds_msg_scancode_keyboard_event *scancode_event;
	firerds_msg_synchronize_keyboard_event *sync_keyboard_event;
	firerds_msg_seat_new *seatNew;
	firerds_msg_seat_removed *seatRemoved;
	firerds_msg_version version;

	struct firerds_output *output;
	struct weston_mode *currentMode, targetMode;
	struct weston_seat *seat;
	struct firerds_seat *firerdsSeat;
	char seatName[50];

	/*weston_log("message type %d\n", type);*/
	switch (type) {
	case FIRERDS_CLIENT_CAPABILITIES:
		capabilities = &message->capabilities;
		if (!b->seat) {
			b->seat = zalloc(sizeof(*firerdsSeat));
			if (!b->seat) {
				weston_log("unable to allocate the seat");
				return 0;
			}
		}

		firerdsSeat = b->seat;
		weston_seat_init(&firerdsSeat->base, b->compositor, "firerds");
		weston_seat_init_pointer(&firerdsSeat->base);
		b->mainSeatConnectionId = capabilities->connectionId;

		firerds_configure_keyboard(b, firerdsSeat, capabilities->KeyboardLayout, capabilities->KeyboardType);
#ifdef BUILD_MULTITOUCH
		firerds_configure_multitouch(b, firerdsSeat);
#endif

		currentMode = b->output->base.current_mode;
		if (capabilities->DesktopWidth != (UINT32)currentMode->width || capabilities->DesktopHeight != (UINT32)currentMode->height) {
			// mode switching will send the shared framebuffer
			targetMode.width = capabilities->DesktopWidth;
			targetMode.height = capabilities->DesktopHeight;
			weston_output_mode_set_native(&b->output->base, &targetMode, 1);
		} else {
			if (firerds_send_shared_framebuffer(b) < 0)
				weston_log("unable to send shared framebuffer, errno=%d\n", errno);
		}

		if (firerds_send_disable_pointer(b) < 0)
			weston_log("unable to disable client-side pointer, errno=%d\n", errno);

		output = b->output;
		if (!pixman_region32_union_rect(&output->damagedRegion, &output->damagedRegion,
										0, 0, capabilities->DesktopWidth, capabilities->DesktopHeight)) {
			weston_log("unable to mark the full screen as damaged");
		}
		break;

	case FIRERDS_CLIENT_VERSION:
		version.VersionMajor = FIRERDS_PROTOCOL_VERSION_MAJOR;
		version.VersionMinor = FIRERDS_PROTOCOL_VERSION_MINOR;
		version.Cookie = getenv("BACKEND_COOKIE");

		if (backend_send_message(b, FIRERDS_SERVER_VERSION_REPLY, (firerds_message *)&version) < 0) {
			weston_log("unable to answer with client version");
		}
		break;


	case FIRERDS_CLIENT_MOUSE_EVENT:
		mouse_event = &message->mouse;
		seat = retrieve_seat(b, mouse_event->connectionId);
		if (!seat)
			return 0;
		firerds_mouse_event(b, seat, mouse_event->x, mouse_event->y, mouse_event->flags);
		break;

	case FIRERDS_CLIENT_SCANCODE_KEYBOARD_EVENT:
		scancode_event = &message->scancodeKeyboard;
		seat = retrieve_seat(b, scancode_event->connectionId);
		if (!seat)
			return 0;
		firerds_scancode_keyboard_event(b, seat, scancode_event->flags, scancode_event->code,
				scancode_event->keyboardType);
		break;

	case FIRERDS_CLIENT_FRAMEBUFFER_SYNC_REQUEST:
		sync_req = &message->framebufferSyncRequest;
		output = b->output;
		output->pendingShmId = sync_req->bufferId;
		output->pendingFrame = 1;
		if (pixman_region32_not_empty(&b->output->damagedRegion))
			firerds_refresh_region(b, &b->output->damagedRegion);
		break;

	case FIRERDS_CLIENT_IMMEDIATE_SYNC_REQUEST:
		sync_req = &message->immediateSyncRequest;
		output = b->output;
		output->pendingShmId = sync_req->bufferId;
		output->pendingFrame = 1;
		firerds_refresh_region(b, &b->output->damagedRegion);
		break;

	case FIRERDS_CLIENT_SYNCHRONIZE_KEYBOARD_EVENT:
		sync_keyboard_event = &message->synchronizeKeyboard;
		seat = retrieve_seat(b, sync_keyboard_event->connectionId);
		if (!seat)
			return 0;

		firerds_update_keyboard_modifiers(b, seat,
				sync_keyboard_event->flags & KBD_SYNC_CAPS_LOCK,
				sync_keyboard_event->flags & KBD_SYNC_NUM_LOCK,
				sync_keyboard_event->flags & KBD_SYNC_SCROLL_LOCK,
				sync_keyboard_event->flags & KBD_SYNC_KANA_LOCK
		);
		break;

	case FIRERDS_CLIENT_SEAT_NEW:
		seatNew = &message->seatNew;
		if (HashTable_Contains(b->extra_seats, (void *)(size_t)seatNew->connectionId)) {
			weston_log("seat for %d already registered\n", (int)seatNew->connectionId);
			return 0;
		}

		snprintf(seatName, sizeof(seatName), "firerds-%d", (int)seatNew->connectionId);
		firerdsSeat = (struct firerds_seat *)malloc( sizeof(*firerdsSeat) );
		if (!firerdsSeat) {
			weston_log("unable to allocate the new seat for %d\n", (int)seatNew->connectionId);
			return 0;
		}

		seat = &firerdsSeat->base;
		weston_seat_init(seat, b->compositor, seatName);
		weston_seat_init_pointer(seat);
		firerds_configure_keyboard(b, firerdsSeat, seatNew->keyboardLayout, seatNew->keyboardType);
		HashTable_Add(b->extra_seats, (void *)(size_t)seatNew->connectionId, seat);
		break;

	case FIRERDS_CLIENT_SEAT_REMOVED:
		seatRemoved = &message->seatRemoved;
		if (!HashTable_Contains(b->extra_seats, (void *)(size_t)seatRemoved->connectionId)) {
			weston_log("no seat for %d\n", (int)seatRemoved->connectionId);
			return 0;
		}

		firerdsSeat = (struct firerds_seat *)HashTable_GetItemValue(b->extra_seats, (void *)(size_t)seatRemoved->connectionId);
		seat = &firerdsSeat->base;
		weston_seat_release_keyboard(seat);
		weston_seat_release_pointer(seat);
		weston_seat_release(seat);
		free(firerdsSeat);
		HashTable_Remove(b->extra_seats, (void *)(size_t)seatRemoved->connectionId);
		break;

	case FIRERDS_CLIENT_UNICODE_KEYBOARD_EVENT:
	case FIRERDS_CLIENT_EXTENDED_MOUSE_EVENT:
	default:
		weston_log("not handled yet, %d\n", type);
		break;
	}
	return 0;
}


static int
firerds_client_activity(int fd, uint32_t mask, void *data) {
	struct firerds_backend *c = (struct firerds_backend *)data;
	int ret;
	firerds_message message;

	if (!(mask & WL_EVENT_READABLE))
		return 0;

	ret = read(fd, Stream_Pointer(c->in_stream), c->expected_bytes);
	if (ret <= 0) {
		weston_log("connection closed fd=%d client_fd=%d\n", fd, c->client_fd);
		firerds_kill_client(c);
		return 0;
	}

	Stream_Seek(c->in_stream, ret);
	c->expected_bytes -= ret;

	if (c->expected_bytes)
		return 0;

	if (c->streamState == STREAM_WAITING_COMMON_HEADER) {
		Stream_SetPosition(c->in_stream, 0);
		firerds_read_message_header(c->in_stream, &c->current_msg_type, &c->expected_bytes);

		if(c->expected_bytes) {
			Stream_SetPosition(c->in_stream, 0);
			Stream_EnsureCapacity(c->in_stream, c->expected_bytes);
			c->streamState = STREAM_WAITING_DATA;
			return 0;
		}
	}

	Stream_SealLength(c->in_stream);
	Stream_SetPosition(c->in_stream, 0);


	if (firerds_message_read(c->in_stream, c->current_msg_type, &message) < 0) {
		weston_log("invalid message\n");
		goto out_error;
	}

	if (firerds_treat_message(c, c->current_msg_type, &message) < 0) {
		weston_log("error treating message type %d\n", c->current_msg_type);
		goto out_error;
	}

	Stream_SetPosition(c->in_stream, 0);
	c->streamState = STREAM_WAITING_COMMON_HEADER;
	c->expected_bytes = FIRERDS_COMMON_LENGTH;
	return 0;

out_error:
	firerds_kill_client(c);
	return 0;
}

static int
firerds_named_pipe_activity(int fd, uint32_t mask, void *data) {
	struct firerds_backend *c = (struct firerds_backend *)data;
	struct wl_event_loop *loop;

	if (c->client_fd != -1) {
		weston_log("dropping existing client");
		firerds_kill_client(c);
	}

	c->client_fd = wl_os_accept_cloexec(c->listening_fd, 0, 0);
	if (c->client_fd >= 0) {
		loop = wl_display_get_event_loop(c->compositor->wl_display);
		c->client_event_source = wl_event_loop_add_fd(loop, c->client_fd, WL_EVENT_READABLE,
				firerds_client_activity, c);
	}
	return 0;
}


static struct firerds_backend *
firerds_backend_create(struct weston_compositor *compositor,
		struct weston_firerds_backend_config *config)
{
	struct firerds_backend *b;
	struct wl_event_loop *loop;
	struct sockaddr_un remote;
	int len;

	b = zalloc(sizeof *b);
	if (b == NULL)
		return NULL;

	b->compositor = compositor;
	b->base.destroy = firerds_destroy;
	b->base.restore = firerds_restore;
	b->client_fd = -1;

	b->extra_seats = HashTable_New(FALSE);
	if (!b->extra_seats)
		goto err_compositor;

	if (weston_compositor_set_presentation_clock_software(b->compositor) < 0)
		goto err_seats;

	if (pixman_renderer_init(b->compositor) < 0)
		goto err_seats;

	if (firerds_compositor_create_output(b, config->width, config->height) < 0)
		goto err_seats;

	compositor->capabilities |= WESTON_CAP_ARBITRARY_MODES;

	b->listening_fd = wl_os_socket_cloexec(AF_UNIX, SOCK_STREAM, 0);
	if (b->listening_fd < 0) {
		weston_log("unable to create the listening socket\n");
		goto err_output;
	}

	memset(&remote, 0, sizeof(remote));
	remote.sun_family = AF_UNIX;
	strcpy(remote.sun_path, config->named_pipe);
	len = strlen(remote.sun_path) + sizeof(remote.sun_family);
	if (bind(b->listening_fd, (struct sockaddr *)&remote, len) < 0) {
		weston_log("unable to bind the named pipe, error=%s path=%s\n",
				strerror(errno), config->named_pipe);
		goto err_socket;
	}

	if (!listen(b->listening_fd, 1) < 0) {
		weston_log("unable to listen on the named pipe, errno=%d path=%s\n",
				errno, config->named_pipe);
		goto err_socket;
	}

	b->in_stream = Stream_New(NULL, FIRERDS_COMMON_LENGTH);
	if (!b->in_stream) {
		weston_log("unable to allocate input stream");
		goto err_socket;
	}
	b->out_stream = Stream_New(NULL, 65536);
	if (!b->out_stream) {
		weston_log("unable to allocate input stream");
		goto err_out_stream;
	}
	b->expected_bytes = FIRERDS_COMMON_LENGTH;
	b->streamState = STREAM_WAITING_COMMON_HEADER;
	loop = wl_display_get_event_loop(b->compositor->wl_display);
	b->server_event_source = wl_event_loop_add_fd(loop, b->listening_fd, WL_EVENT_READABLE,
													firerds_named_pipe_activity, b);
	if (!b->server_event_source) {
		weston_log("unable to add fd to event loop");
		goto err_event_source;
	}
	return b;
err_event_source:
	Stream_Free(b->out_stream, TRUE);
err_out_stream:
	Stream_Free(b->in_stream, TRUE);
err_socket:
	close(b->listening_fd);
err_output:
	weston_output_destroy(&b->output->base);
err_seats:
	HashTable_Free(b->extra_seats);
err_compositor:
	weston_compositor_shutdown(b->compositor);
	free(b);
	return NULL;
}

static void
config_init_to_defaults(struct weston_firerds_backend_config *config)
{
	config->width = 640;
	config->height = 480;
	config->named_pipe = NULL;
}

WL_EXPORT int
backend_init(struct weston_compositor *compositor, int *argc, char *argv[],
	     struct weston_config *wconfig,
		 struct weston_backend_config *config_base)
{
	struct firerds_backend *b;
	struct weston_firerds_backend_config config = {{ 0, }};


	if (config_base == NULL ||
		config_base->struct_version != WESTON_FIRERDS_BACKEND_CONFIG_VERSION ||
		config_base->struct_size > sizeof(struct weston_firerds_backend_config)) {
		weston_log("fireRDS backend config structure is invalid\n");
		return -1;
	}

	config_init_to_defaults(&config);
	memcpy(&config, config_base, config_base->struct_size);

	if (!config.named_pipe) {
		weston_log("missing named pipe to listen on");
		return -1;
	}

	b = firerds_backend_create(compositor, &config);
	return b ? 0 : -1;
}
