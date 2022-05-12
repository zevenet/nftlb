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

#ifndef _TOOLS_H_
#define _TOOLS_H_

#include <syslog.h>

#define NFTLB_LOG_LEVEL_DEFAULT			LOG_NOTICE
#define NFTLB_LOG_OUTPUT_DEFAULT		VALUE_LOG_OUTPUT_SYSLOG

#define NFTLB_LOG_OUTPUT_SYSLOG			(1 << 0)
#define NFTLB_LOG_OUTPUT_STDOUT			(1 << 1)
#define NFTLB_LOG_OUTPUT_STDERR			(1 << 2)

enum log_output {
	VALUE_LOG_OUTPUT_SYSLOG,
	VALUE_LOG_OUTPUT_STDOUT,
	VALUE_LOG_OUTPUT_STDERR,
	VALUE_LOG_OUTPUT_SYSOUT,
	VALUE_LOG_OUTPUT_SYSERR,
};

void tools_snprintf(char *strdst, int size, char *strsrc);
void tools_log_set_level(int loglevel);
void tools_log_set_output(int output);
int tools_printlog(int loglevel, char *fmt, ...);
int tools_log_get_level(void);

#endif /* _TOOLS_H_ */
