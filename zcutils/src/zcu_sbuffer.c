/*
 *   This file is part of zcutils, ZEVENET Core Utils.
 *
 *   Copyright (C) ZEVENET SL.
 *   Author: Laura Garcia <laura.garcia@zevenet.com>
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU Affero General Public License as
 *   published by the Free Software Foundation, either version 3 of the
 *   License, or any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU Affero General Public License for more details.
 *
 *   You should have received a copy of the GNU Affero General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "zcu_sbuffer.h"
#include "zcu_log.h"

int zcu_buf_get_size(struct zcu_buffer *buf)
{
	return buf->size;
}

char *zcu_buf_get_next(struct zcu_buffer *buf)
{
	return buf->data + buf->next;
}

int zcu_buf_resize(struct zcu_buffer *buf, int times)
{
	char *pbuf;
	int newsize;

	if (times == 0)
		return 0;

	newsize = buf->size + (times * EXTRA_SIZE) + 1;

	if (!buf->data)
		return 1;

	pbuf = (char *)realloc(buf->data, newsize);
	if (!pbuf)
		return 1;

	buf->data = pbuf;
	buf->size = newsize;
	return 0;
}

int zcu_buf_create(struct zcu_buffer *buf)
{
	buf->size = 0;
	buf->next = 0;

	buf->data = (char *)calloc(1, ZCU_DEF_BUFFER_SIZE);
	if (!buf->data) {
		return 1;
	}

	*buf->data = '\0';
	buf->size = ZCU_DEF_BUFFER_SIZE;
	return 0;
}

int zcu_buf_isempty(struct zcu_buffer *buf)
{
	return (buf->data[0] == 0);
}

char *zcu_buf_get_data(struct zcu_buffer *buf)
{
	return buf->data;
}

int zcu_buf_clean(struct zcu_buffer *buf)
{
	if (buf->data)
		free(buf->data);
	buf->size = 0;
	buf->next = 0;
	return 0;
}

int zcu_buf_reset(struct zcu_buffer *buf)
{
	buf->data[0] = 0;
	buf->next = 0;
	return 0;
}

int zcu_buf_concat_va(struct zcu_buffer *buf, int len, char *fmt, va_list args)
{
	int times = 0;
	char *pnext;

	if (buf->next + len >= buf->size)
		times = ((buf->next + len - buf->size) / EXTRA_SIZE) + 1;

	if (zcu_buf_resize(buf, times)) {
		zcu_log_print(
			LOG_ERR,
			"Error resizing the buffer %d times from a size of %d!",
			times, buf->size);
		return 1;
	}

	pnext = zcu_buf_get_next(buf);
	vsnprintf(pnext, len + 1, fmt, args);
	buf->next += len;

	return 0;
}

int zcu_buf_concat(struct zcu_buffer *buf, char *fmt, ...)
{
	int len;
	va_list args;

	va_start(args, fmt);
	len = vsnprintf(0, 0, fmt, args);
	va_end(args);

	va_start(args, fmt);
	zcu_buf_concat_va(buf, len, fmt, args);
	va_end(args);

	return 0;
}
