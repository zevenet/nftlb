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

#include "zcu_log.h"

char zcu_log_prefix[LOG_PREFIX_BUFSIZE] = "";
int zcu_log_level = ZCUTILS_LOG_LEVEL_DEFAULT;
int zcu_log_output = ZCUTILS_LOG_OUTPUT_DEFAULT;


void zcu_log_set_prefix(const char *string)
{
    if (strlen(string) >= LOG_PREFIX_BUFSIZE)
        zcu_log_print(
            LOG_ERR,
            "The farm name is greater than the prefix log: %d >= %d",
            strlen(string), LOG_PREFIX_BUFSIZE);
    else
        memcpy(zcu_log_prefix, string, strlen(string) + 1);
}

void zcu_log_set_level(int loglevel)
{
    zcu_log_level = loglevel;
    setlogmask(LOG_UPTO(loglevel));
}

int zcu_log_get_level(void)
{
	return zcu_log_level;
}

void zcu_log_set_output(int output)
{
    switch (output) {
    case VALUE_LOG_OUTPUT_STDOUT:
        zcu_log_output = ZCUTILS_LOG_OUTPUT_STDOUT;
        break;
    case VALUE_LOG_OUTPUT_STDERR:
        zcu_log_output = ZCUTILS_LOG_OUTPUT_STDERR;
        break;
    case VALUE_LOG_OUTPUT_SYSOUT:
        zcu_log_output =
            ZCUTILS_LOG_OUTPUT_SYSLOG | ZCUTILS_LOG_OUTPUT_STDOUT;
        break;
    case VALUE_LOG_OUTPUT_SYSERR:
        zcu_log_output =
            ZCUTILS_LOG_OUTPUT_SYSLOG | ZCUTILS_LOG_OUTPUT_STDERR;
        break;
    case VALUE_LOG_OUTPUT_SYSLOG:
    default:
        zcu_log_output = ZCUTILS_LOG_OUTPUT_SYSLOG;
    }
    return;
}

int _zcu_log_print(int loglevel, const char *fmt, ...)
{
    va_list args;

    if (loglevel > zcu_log_level)
        return 0;

    if (zcu_log_output & ZCUTILS_LOG_OUTPUT_STDOUT) {
        va_start(args, fmt);
        vfprintf(stdout, fmt, args);
        fprintf(stdout, "\n");
        va_end(args);
    }

    if (zcu_log_output & ZCUTILS_LOG_OUTPUT_STDERR) {
        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        fprintf(stderr, "\n");
        va_end(args);
    }

    if (zcu_log_output & ZCUTILS_LOG_OUTPUT_SYSLOG) {
        va_start(args, fmt);
        vsyslog(loglevel, fmt, args);
        va_end(args);
    }

    return 0;
}
