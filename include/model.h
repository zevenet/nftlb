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

#ifndef _MODEL_H_
#define _MODEL_H_

#include "../include/list.h"

enum levels {
	MODEL_LEVEL_INIT,
	MODEL_LEVEL_FARMS,
	MODEL_LEVEL_BCKS,
};

enum keys {
	MODEL_KEY_FARMS,
	MODEL_KEY_NAME,
	MODEL_KEY_FQDN,
	MODEL_KEY_IFACE,
	MODEL_KEY_OFACE,
	MODEL_KEY_FAMILY,
	MODEL_KEY_ETHADDR,
	MODEL_KEY_VIRTADDR,
	MODEL_KEY_VIRTPORTS,
	MODEL_KEY_IPADDR,
	MODEL_KEY_PORTS,
	MODEL_KEY_MODE,
	MODEL_KEY_PROTO,
	MODEL_KEY_SCHED,
	MODEL_KEY_STATE,
	MODEL_KEY_BCKS,
	MODEL_KEY_WEIGHT,
	MODEL_KEY_PRIORITY,
	MODEL_KEY_ACTION,
};

enum familys {
	MODEL_VALUE_FAMILY_IPV4,
	MODEL_VALUE_FAMILY_IPV6,
	MODEL_VALUE_FAMILY_INET,
};

enum modes {
	MODEL_VALUE_MODE_SNAT,
	MODEL_VALUE_MODE_DNAT,
	MODEL_VALUE_MODE_DSR,
};

enum protocols {
	MODEL_VALUE_PROTO_ALL,
	MODEL_VALUE_PROTO_TCP,
	MODEL_VALUE_PROTO_UDP,
	MODEL_VALUE_PROTO_SCTP,
};

enum schedulers {
	MODEL_VALUE_SCHED_RR,
	MODEL_VALUE_SCHED_WEIGHT,
	MODEL_VALUE_SCHED_HASH,
	MODEL_VALUE_SCHED_SYMHASH,
};

enum states {
	MODEL_VALUE_STATE_UP,
	MODEL_VALUE_STATE_DOWN,
	MODEL_VALUE_STATE_OFF,
};

enum actions {
	MODEL_ACTION_START,
	MODEL_ACTION_STOP,
	MODEL_ACTION_RELOAD,
	MODEL_ACTION_DELETE,
	MODEL_ACTION_NONE,
};

struct configpair {
	enum levels	level;
	enum keys	key;
	char		*str_value;
	int		int_value;
};

struct backend {
	struct list_head	list;
	int			action;
	char			*name;
	char			*fqdn;
	char			*ipaddr;
	char			*ethaddr;
	char			*ports;
	int			weight;
	int			priority;
	int			state;
};

struct farm {
	struct list_head	list;
	int			action;
	char			*name;
	char			*fqdn;
	char			*iface;
	char			*oface;
	char			*ethaddr;
	char			*virtaddr;
	char			*virtports;
	int			family;
	int			mode;
	int			protocol;
	int			scheduler;
	int			state;
	int			priority;
	int			total_weight;
	int			total_bcks;
	int			bcks_available;
	struct list_head	backends;
};

void model_init(void);
void model_print_farms(void);
struct farm * model_lookup_farm(const char *name);
struct backend * model_lookup_backend(struct farm *f, const char *name);
void print_pair(struct configpair *cfgp);
int model_set_obj_attribute(struct configpair *cfgp);
char * model_print_family(int family);
char * model_print_mode(int mode);
char * model_print_proto(int protocol);
char * model_print_sched(int scheduler);
char * model_print_state(int state);
struct list_head * model_get_farms(void);
int model_get_totalfarms(void);
int model_bck_is_available(struct farm *f, struct backend *b);
void model_print_int(char *buf, int value);
int farm_action_update(struct farm *f, int action);
int bck_action_update(struct backend *b, int action);
int farms_action_update(int action);
int backends_action_update(struct farm *f, int action);

#endif /* _MODEL_H_ */
