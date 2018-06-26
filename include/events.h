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

#ifndef _EVENTS_H_
#define _EVENTS_H_

#include <ev.h>

int loop_init(void);
int loop_run(void);
struct ev_loop *get_loop(void);

struct ev_io *events_get_ntlnk(void);
struct ev_io *events_create_ntlnk(void);
void events_delete_ntlnk(void);

struct ev_io *events_get_srv(void);
struct ev_io *events_create_srv(void);
void events_delete_srv(void);


#endif /* _EVENTS_H_ */
