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

#ifndef _ZCU_NETWORK_H_
#define _ZCU_NETWORK_H_

#include <netdb.h>
#include <sys/socket.h>
#include <sys/un.h>

#ifdef __cplusplus
extern "C" {
#endif

int zcu_soc_equal_sockaddr(struct sockaddr *addr1, struct sockaddr *addr2,
			int compare_port);

int zcu_net_get_host(const char *name, struct addrinfo *res, int ai_family,
		int port);

struct addrinfo *zcu_net_get_address(const char *address, int port);

#ifdef __cplusplus
}
#endif


#endif /* _ZCU_NETWORK_H_ */
