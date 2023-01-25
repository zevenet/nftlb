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

#ifndef _ZCU_SBUFFER_H_
#define _ZCU_SBUFFER_H_

#include <stdarg.h>
#include "zcu_common.h"

#define EXTRA_SIZE 1024

struct zcu_buffer {
	int size;
	int next;
	char *data;
};

#ifdef __cplusplus
extern "C" {
#endif

int zcu_buf_get_size(struct zcu_buffer *buf);
char *zcu_buf_get_next(struct zcu_buffer *buf);
int zcu_buf_resize(struct zcu_buffer *buf, int times);
int zcu_buf_create(struct zcu_buffer *buf);
int zcu_buf_isempty(struct zcu_buffer *buf);
char *zcu_buf_get_data(struct zcu_buffer *buf);
int zcu_buf_clean(struct zcu_buffer *buf);
int zcu_buf_reset(struct zcu_buffer *buf);
int zcu_buf_concat_va(struct zcu_buffer *buf, int len, char *fmt, va_list args);
int zcu_buf_concat(struct zcu_buffer *buf, char *fmt, ...);

#ifdef __cplusplus
}
#endif

#endif /* _ZCU_SBUFFER_H_ */
