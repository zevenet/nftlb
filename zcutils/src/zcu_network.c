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

#include "zcu_network.h"
#include "zcu_log.h"
#include <stdlib.h>
#include <stdio.h>

#define ZCU_MAX_IDENT	100

int zcu_soc_equal_sockaddr(struct sockaddr *addr1, struct sockaddr *addr2, int compare_port)
{
	if (addr1->sa_family != addr2->sa_family)
		return 0;
	if (addr1->sa_family == AF_UNIX) {
		struct sockaddr_un *a1_un = (struct sockaddr_un *)addr1;
		struct sockaddr_un *a2_un = (struct sockaddr_un *)addr2;
		int r = strcmp(a1_un->sun_path, a2_un->sun_path);
		if (r != 0)
			return 1;
	} else if (addr1->sa_family == AF_INET) {
		struct sockaddr_in *a1_in = (struct sockaddr_in *)addr1;
		struct sockaddr_in *a2_in = (struct sockaddr_in *)addr2;
		if (ntohl(a1_in->sin_addr.s_addr) !=
		    ntohl(a2_in->sin_addr.s_addr))
			return 0;
		if (compare_port &&
		    ntohs(a1_in->sin_port) != ntohs(a2_in->sin_port))
			return 0;
	} else if (addr1->sa_family == AF_INET6) {
		struct sockaddr_in6 *a1_in6 = (struct sockaddr_in6 *)addr1;
		struct sockaddr_in6 *a2_in6 = (struct sockaddr_in6 *)addr2;
		int r = memcmp(a1_in6->sin6_addr.s6_addr,
			       a2_in6->sin6_addr.s6_addr,
			       sizeof(a1_in6->sin6_addr.s6_addr));
		if (r != 0)
			return r;
		if (compare_port &&
		    ntohs(a1_in6->sin6_port) != ntohs(a2_in6->sin6_port))
			return 0;
		if (a1_in6->sin6_flowinfo != a2_in6->sin6_flowinfo)
			return 0;
		if (a1_in6->sin6_scope_id != a2_in6->sin6_scope_id)
			return 0;
	} else {
		return 0;
	}
	return 1;
}

/*
 * Search for a host name, return the addrinfo for it
 */
int zcu_net_get_host(const char *name, struct addrinfo *res, int ai_family, int port)
{
	struct addrinfo *chain, *ap;
	struct addrinfo hints;
	int ret_val;
	char port_str[ZCU_MAX_IDENT] = { 0 };

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = ai_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_CANONNAME;

	if (port > 0)
		snprintf(port_str, ZCU_MAX_IDENT, "%d", port);

	if ((ret_val = getaddrinfo(name, port_str, &hints, &chain)) == 0) {
		for (ap = chain; ap != NULL; ap = ap->ai_next)
			if (ap->ai_socktype == SOCK_STREAM)
				break;
		if (ap == NULL) {
			freeaddrinfo(chain);
			return EAI_NONAME;
		}
		*res = *ap;
		if (((res->ai_addr = (struct sockaddr *)malloc(ap->ai_addrlen))) == NULL) {
			freeaddrinfo(chain);
			return EAI_MEMORY;
		}
		memcpy(res->ai_addr, ap->ai_addr, ap->ai_addrlen);
		freeaddrinfo(chain);
	}

	return ret_val;
}

struct addrinfo *zcu_net_get_address(const char *address, int port)
{
	struct addrinfo hints;
	struct addrinfo *result = NULL;
	int sfd;
	char port_str[ZCU_MAX_IDENT] = { 0 };

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC; /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM; /* Datagram socket */
	hints.ai_flags = AI_CANONNAME;
	hints.ai_protocol = 0; /* Any protocol */
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;
	if (port > 0)
		snprintf(port_str, ZCU_MAX_IDENT, "%d", port);

	sfd = getaddrinfo(address, port_str, &hints, &result);
	if (sfd != 0) {
		zcu_log_print(LOG_NOTICE, "%s():%d: getaddrinfo: %s",
			      __FUNCTION__, __LINE__, gai_strerror(sfd));
		return NULL;
	}

	return result;
}
