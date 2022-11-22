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

#ifndef _ZCU_ENVIRONMENT_H_
#define _ZCU_ENVIRONMENT_H_

#include <csignal>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <string>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#include <iostream>

#ifdef __cplusplus
extern "C" {
#endif

/*
If a second paratemer is passed, it is added in the pid file in a new line
*/
static bool createPidFile(const std::string & pid_file_name,
			int pid = -1, int child_pid = -1)
{
	auto pid_file_hl = ::fopen(pid_file_name.c_str(), "wt");

	if (pid_file_hl != nullptr) {
		fprintf(pid_file_hl, "%d\n",
			pid != -1 ? pid : getpid());
		if (child_pid != -1)
			fprintf(pid_file_hl, "%d\n", child_pid);
		fclose(pid_file_hl);
		return true;
	} else
		zcu_log_print(LOG_ERR, "Create \"%s\": %s",
				  __func__, __LINE__,
				  pid_file_name.c_str(), strerror(errno));
	return false;
}

static bool removePidFile(const std::string & pid_file_name)
{
	struct stat info;

	if (lstat(pid_file_name.data(), &info) != 0)
		return false;
	if (!S_ISREG(info.st_mode))
		return false;
	if (info.st_uid != getuid())
		return false;
	if (info.st_size > static_cast < int > (sizeof("65535\r\n")))
		return false;
	unlink(pid_file_name.data());
	return true;
}

#ifdef __cplusplus
}
#endif

#endif /* _ZCU_ENVIRONMENT_H_ */
