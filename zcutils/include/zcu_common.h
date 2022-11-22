/*
 *    Zevenet zproxy Load Balancer Software License
 *    This file is part of the Zevenet zproxy Load Balancer software package.
 *
 *    Copyright (C) 2019-today ZEVENET SL, Sevilla (Spain)
 *
 *    This program is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU Affero General Public License as
 *    published by the Free Software Foundation, either version 3 of the
 *    License, or any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU Affero General Public License for more details.
 *
 *    You should have received a copy of the GNU Affero General Public License
 *    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef _ZCU_COMMON_H_
#define _ZCU_COMMON_H_

#define ZCU_DEF_BUFFER_SIZE 4096
#define MAXBUF 4096

#define LIKELY(x) __builtin_expect((x), 1)
#define UNLIKELY(x) __builtin_expect((x), 0)
#define UNIQUE_NAME_0(a, b) UNIQUE_NAME_I(a, b)
#define UNIQUE_NAME_I(a, b) UNIQUE_NAME_II(~, a##b)
#define UNIQUE_NAME_II(p, res) res
#define UNIQUE_NAME(base) UNIQUE_NAME_0(base, __COUNTER__)

// Maximum buffer data. The requet or response headers can't be bigger
// than this value
#ifndef MAX_DATA_SIZE
#define MAX_DATA_SIZE (1024 * 64)
#endif

#endif /* _ZCU_COMMON_H_ */
