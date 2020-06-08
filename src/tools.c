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
#include <stdarg.h>
#include "tools.h"

int log_output;
int log_level;

void tools_snprintf(char *strdst, int size, char *strsrc)
{
	for (int i = 0; i < size; i++) {
		strdst[i] = *(strsrc + i);
	}
	strdst[size] = '\0';
}

void tools_log_set_level(int loglevel)
{
	log_level = loglevel;
	setlogmask(LOG_UPTO(loglevel));
}

void tools_log_set_output(int output)
{
	switch (output) {
	case VALUE_LOG_OUTPUT_STDOUT:
		log_output = NFTLB_LOG_OUTPUT_STDOUT;
		break;
	case VALUE_LOG_OUTPUT_STDERR:
		log_output = NFTLB_LOG_OUTPUT_STDERR;
		break;
	case VALUE_LOG_OUTPUT_SYSOUT:
		log_output = NFTLB_LOG_OUTPUT_SYSLOG | NFTLB_LOG_OUTPUT_STDOUT;
		break;
	case VALUE_LOG_OUTPUT_SYSERR:
		log_output = NFTLB_LOG_OUTPUT_SYSLOG | NFTLB_LOG_OUTPUT_STDERR;
		break;
	case VALUE_LOG_OUTPUT_SYSLOG:
	default:
		log_output = NFTLB_LOG_OUTPUT_SYSLOG;
	}
	return;
}

int tools_printlog(int loglevel, char *fmt, ...)
{
	va_list args;

	if (log_output & NFTLB_LOG_OUTPUT_STDOUT && loglevel <= log_level) {
		va_start(args, fmt);
		vfprintf(stdout, fmt, args);
		fprintf(stdout, "\n");
		va_end(args);
	}

	if (log_output & NFTLB_LOG_OUTPUT_STDERR && loglevel <= log_level) {
		va_start(args, fmt);
		vfprintf(stderr, fmt, args);
		fprintf(stderr, "\n");
		va_end(args);
	}

	if (log_output & NFTLB_LOG_OUTPUT_SYSLOG) {
		va_start(args, fmt);
		vsyslog(loglevel, fmt, args);
		va_end(args);
	}

	return 0;
}

