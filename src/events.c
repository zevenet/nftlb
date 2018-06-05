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

int loop_init(struct events_stct *st_ev)
{
	st_ev->loop = ev_default_loop(0);

	return EXIT_SUCCESS;
}

int loop_run(struct events_stct *st_ev)
{
	while (1)
		ev_loop(st_ev->loop, 0);

	return EXIT_SUCCESS;
}

