/*
 *   This file is part of nftlb, nftables load balancer.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>

#include "sbuffer.h"

#define DEFAULT_BUFFER_SIZE		1024
#define EXTRA_SIZE				512

static char * get_buf_next(struct sbuffer *buf)
{
	return buf->data + buf->next;
}

static int resize_buf(struct sbuffer *buf, int times)
{
	char *pbuf;
	int newsize;
	syslog(LOG_DEBUG, "%s():%d: times %d", __FUNCTION__, __LINE__, times);

	if (times == 0)
		return 0;

	newsize = buf->size + (times * EXTRA_SIZE) + 1;

	if (!buf->data)
		return 1;

	pbuf = (char *) realloc(buf->data, newsize);
	if (!pbuf)
		return 1;

	buf->data = pbuf;
	buf->size = newsize;
	return 0;
}

int create_buf(struct sbuffer *buf)
{
	buf->size = 0;
	buf->next = 0;

	syslog(LOG_DEBUG, "%s():%d: allocating new buffer size %d", __FUNCTION__, __LINE__, DEFAULT_BUFFER_SIZE);

	buf->data = (char *) malloc(DEFAULT_BUFFER_SIZE + 1);
	if (!buf->data) {
		return 1;
	}

	*buf->data = '\0';
	buf->size = DEFAULT_BUFFER_SIZE + 1;
	return 0;
}

int isempty_buf(struct sbuffer *buf)
{
	return (buf->data[0] == 0);
}

char *get_buf_data(struct sbuffer *buf)
{
	return buf->data;
}

int clean_buf(struct sbuffer *buf)
{
	syslog(LOG_DEBUG, "%s():%d: cleaning buffer size %d", __FUNCTION__, __LINE__, buf->size);

	if (buf->data)
		free(buf->data);
	buf->size = 0;
	buf->next = 0;
	return 0;
}

int concat_buf(struct sbuffer *buf, char *fmt, ...)
{
	int times = 0;
	int len;
	va_list args;
	char *pnext;

	syslog(LOG_DEBUG, "%s():%d: format is %s and next %d", __FUNCTION__, __LINE__, fmt, buf->next);

	va_start(args, fmt);
	len = vsnprintf(0, 0, fmt, args);
	va_end(args);

	if (buf->next + len >= buf->size)
		times = ((buf->next + len - buf->size) / EXTRA_SIZE) + 1;

	if (resize_buf(buf, times)) {
		syslog(LOG_ERR, "Error resizing the buffer %d times from a size of %d!", times, buf->size);
		return 1;
	}

	pnext = get_buf_next(buf);

	va_start(args, fmt);
    vsnprintf(pnext, len + 1, fmt, args);
	va_end(args);

	buf->next += len;

	return 0;
}
