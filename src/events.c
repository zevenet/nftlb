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

#include "events.h"
#include "server.h"

#include <stdlib.h>
#include <ev.h>

struct events_stct {
	struct ev_loop *loop;
	struct ev_io *srv_accept;
	struct ev_io *net_ntlnk;
};

static struct events_stct st_ev;

int loop_init(void)
{
	st_ev.loop = ev_default_loop(0);

	return 0;
}

int loop_run(void)
{
	while (1)
		ev_loop(st_ev.loop, 0);

	return 0;
}

struct ev_loop *get_loop(void)
{
	return st_ev.loop;
}

struct ev_io *events_get_ntlnk(void)
{
	return st_ev.net_ntlnk;
}

struct ev_io *events_create_ntlnk(void)
{
	st_ev.net_ntlnk = (struct ev_io *)malloc(sizeof(struct ev_io));
	return st_ev.net_ntlnk;
}

void events_delete_ntlnk(void)
{
	if (st_ev.net_ntlnk)
		free(st_ev.net_ntlnk);
}

struct ev_io *events_get_srv(void)
{
	return st_ev.srv_accept;
}

struct ev_io *events_create_srv(void)
{
	st_ev.srv_accept = (struct ev_io *)malloc(sizeof(struct ev_io));
	return st_ev.srv_accept;
}

void events_delete_srv(void)
{
	if (st_ev.srv_accept)
		free(st_ev.srv_accept);
}
