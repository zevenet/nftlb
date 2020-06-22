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

#ifndef _BACKENDS_H_
#define _BACKENDS_H_

#include "farms.h"

struct backend {
	struct list_head	list;
	struct farm		*parent;
	int			action;
	char			*name;
	char			*fqdn;
	char			*ipaddr;
	char			*ethaddr;
	int			ofidx;
	char			*oface;
	char			*port;
	char			*srcaddr;
	int			weight;
	int			priority;
	int			mark;
	int			estconnlimit;
	char		*estconnlimit_logprefix;
	int			state;
};

void backend_s_print(struct farm *f);
struct backend * backend_lookup_by_key(struct farm *f, int key, const char *name, int value);
int backend_validate(struct backend *b);
int backend_is_available(struct backend *b);

int backend_set_action(struct backend *b, int action);
int backend_s_set_action(struct farm *f, int action);

int backend_s_validate(struct farm *f);
int backend_s_delete(struct farm *f);

int backend_set_attribute(struct config_pair *c);
int backend_set_state(struct backend *b, int new_value);
int backend_s_set_ether_by_ipaddr(struct farm *f, const char *ip_bck, char *ether_bck);
int backend_s_find_ethers(struct farm *f);

struct backend * backend_get_first(struct farm *f);

int backend_is_usable(struct backend *b);
int backend_changed(struct config_pair *c);
int bck_pre_actionable(struct config_pair *c);
int bck_pos_actionable(struct config_pair *c, int action);

int backend_s_gen_priority(struct farm *f);
int backend_get_mark(struct backend *b);

#endif /* _BACKENDS_H_ */
