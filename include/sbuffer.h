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

#ifndef _SBUFFER_H_
#define _SBUFFER_H_

#include <stdarg.h>

#define DEFAULT_BUFFER_SIZE		4096
#define EXTRA_SIZE				1024

struct sbuffer {
	int		size;
	int		next;
	char	*data;
};

int get_buf_size(struct sbuffer *buf);
char * get_buf_next(struct sbuffer *buf);
char * get_buf_data(struct sbuffer *buf);
int resize_buf(struct sbuffer *buf, int times);
int create_buf(struct sbuffer *buf);
int clean_buf(struct sbuffer *buf);
int reset_buf(struct sbuffer *buf);
int isempty_buf(struct sbuffer *buf);
int concat_buf_va(struct sbuffer *buf, int len, char *fmt, va_list args);
int concat_buf(struct sbuffer *buf, char *fmt, ...);

#endif /* _SBUFFER_H_ */
