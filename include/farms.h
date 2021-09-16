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

#ifndef _FARMS_H_
#define _FARMS_H_

#include "list.h"
#include "config.h"

enum modes {
	VALUE_MODE_SNAT,
	VALUE_MODE_DNAT,
	VALUE_MODE_DSR,
	VALUE_MODE_STLSDNAT,
	VALUE_MODE_LOCAL,
};

enum protocols {
	VALUE_PROTO_ALL,
	VALUE_PROTO_TCP,
	VALUE_PROTO_UDP,
	VALUE_PROTO_SCTP,
};

enum schedulers {
	VALUE_SCHED_RR,
	VALUE_SCHED_WEIGHT,
	VALUE_SCHED_HASH,
	VALUE_SCHED_SYMHASH,
};

enum helpers {
	VALUE_HELPER_NONE,
	VALUE_HELPER_AMANDA,
	VALUE_HELPER_FTP,
	VALUE_HELPER_H323,
	VALUE_HELPER_IRC,
	VALUE_HELPER_NETBIOSNS,
	VALUE_HELPER_PPTP,
	VALUE_HELPER_SANE,
	VALUE_HELPER_SIP,
	VALUE_HELPER_SNMP,
	VALUE_HELPER_TFTP,
};

enum states {
	VALUE_STATE_UP,
	VALUE_STATE_DOWN,
	VALUE_STATE_OFF,
	VALUE_STATE_CONFERR,
};

 enum switches {
	VALUE_SWITCH_OFF,
	VALUE_SWITCH_ON,
};

#define VALUE_META_NONE		0
#define VALUE_META_SRCIP		(1 << 0)
#define VALUE_META_DSTIP		(1 << 1)
#define VALUE_META_SRCPORT	(1 << 2)
#define VALUE_META_DSTPORT	(1 << 3)
#define VALUE_META_SRCMAC		(1 << 4)
#define VALUE_META_DSTMAC		(1 << 5)
#define VALUE_META_MARK		(1 << 6)

#define VALUE_LOG_NONE			0
#define VALUE_LOG_INPUT			(1 << 0)
#define VALUE_LOG_FORWARD		(1 << 1)
#define VALUE_LOG_OUTPUT		(1 << 2)

#define VALUE_RLD_NONE						0

#define VALUE_RLD_NEWRTLIMIT_START			(1 << 0)
#define VALUE_RLD_RSTRTLIMIT_START			(1 << 1)
#define VALUE_RLD_ESTCONNLIMIT_START		(1 << 2)
#define VALUE_RLD_TCPSTRICT_START			(1 << 3)
#define VALUE_RLD_QUEUE_START				(1 << 4)

#define VALUE_RLD_NEWRTLIMIT_STOP			(1 << 5)
#define VALUE_RLD_RSTRTLIMIT_STOP			(1 << 6)
#define VALUE_RLD_ESTCONNLIMIT_STOP			(1 << 7)
#define VALUE_RLD_TCPSTRICT_STOP			(1 << 8)
#define VALUE_RLD_QUEUE_STOP				(1 << 9)

#define STATEFUL_RLD_START(x)				(x & VALUE_RLD_NEWRTLIMIT_START) || (x & VALUE_RLD_RSTRTLIMIT_START) || (x & VALUE_RLD_ESTCONNLIMIT_START) || (x & VALUE_RLD_TCPSTRICT_START) || (x & VALUE_RLD_QUEUE_START)
#define STATEFUL_RLD_STOP(x)				(x & VALUE_RLD_NEWRTLIMIT_STOP) || (x & VALUE_RLD_RSTRTLIMIT_STOP) || (x & VALUE_RLD_ESTCONNLIMIT_STOP) || (x & VALUE_RLD_TCPSTRICT_STOP) || (x & VALUE_RLD_QUEUE_STOP)

struct farm {
	struct list_head	list;
	int			action;
	int			reload_action;
	char			*name;
	char			*fqdn;
	char			*iface;
	char			*iethaddr;
	int			ifidx;
	char			*oface;
	char			*oethaddr;
	int			ofidx;
	char			*virtaddr;
	char			*virtports;
	char			*srcaddr;
	int			family;
	int			mode;
	int			responsettl;
	int			protocol;
	int			scheduler;
	int			schedparam;
	int			persistence;
	int			persistttl;
	int			helper;
	int			log;
	char		*logprefix;
	int			logrtlimit;
	int			logrtlimit_unit;
	int			mark;
	int			state;
	int			priority;
	int			limitsttl;
	int			newrtlimit;
	int			newrtlimitbst;
	char		*newrtlimit_logprefix;
	int			rstrtlimit;
	int			rstrtlimitbst;
	char		*rstrtlimit_logprefix;
	int			estconnlimit;
	char		*estconnlimit_logprefix;
	int			tcpstrict;
	char		*tcpstrict_logprefix;
	int			queue;
	int			verdict;
	int			flow_offload;
	int			total_weight;
	int			total_bcks;
	int			bcks_available;
	int			bcks_usable;
	int			bcks_are_marked;
	int			bcks_have_port;
	int			bcks_have_srcaddr;
	int			bcks_have_if;
	int			policies_action;
	int			policies_used;
	int			nft_chains;
	struct list_head	backends;
	struct list_head	policies;
	int					total_timed_sessions;
	struct list_head	timed_sessions;
	int					total_static_sessions;
	struct list_head	static_sessions;
	int					port_list[NFTLB_MAX_PORTS];
	int					nports;
};

struct list_head * farm_s_get_head(void);
int farm_set_priority(struct farm *f, int new_value);
void farm_s_print(void);
int farm_is_ingress_mode(struct farm *f);
int farm_needs_policies(struct farm *f);
int farm_needs_flowtable(struct farm *f);
int farm_set_ifinfo(struct farm *f, int key);
struct farm * farm_lookup_by_name(const char *name);

int farm_changed(struct config_pair *c);
int farm_pre_actionable(struct config_pair *c);
int farm_pos_actionable(struct config_pair *c);

int farm_set_attribute(struct config_pair *c);
int farm_set_action(struct farm *f, int action);
int farm_s_set_action(int action);
int farm_get_masquerade(struct farm *f);
void farm_s_set_backend_ether_by_oifidx(int interface_idx, const char * ip_bck, char * ether_bck);
int farm_s_lookup_policy_action(char *name, int action);

int farm_rulerize(struct farm *f);
int farm_s_rulerize(void);
int farm_get_mark(struct farm *f);

int farm_search_array_port(struct farm *f, int port);

#endif /* _FARMS_H_ */
