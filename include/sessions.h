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

#ifndef _SESSIONS_H_
#define _SESSIONS_H_

#include "farms.h"
#include "backends.h"

enum session_type {
	SESSION_TYPE_STATIC,
	SESSION_TYPE_TIMED,
};

struct session {
	struct list_head	list;
	struct farm			*f;
	char				*client;
	struct backend		*bck;
	char				*expiration;
	int					state;
	int					action;
};

int session_set_action(struct session *s, int type, int action);
struct session * session_lookup_by_key(struct farm *f, int type, int key, const char *name);
int session_s_set_action(struct farm *f, int action);
void session_s_print(struct farm *f);
int session_get_timed(struct farm *f);
void session_get_client(struct session *s, char **parsed);
int session_backend_action(struct farm *f, struct backend *b, int action);
int session_s_delete(struct farm *f, int type);
int session_set_attribute(struct config_pair *c);
int session_pre_actionable(struct config_pair *c);
int session_pos_actionable(struct config_pair *c);

#endif /* _SESSIONS_H_ */
