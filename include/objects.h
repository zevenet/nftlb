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

#ifndef _OBJECTS_H_
#define _OBJECTS_H_

#define DEFAULT_NAME		""
#define DEFAULT_FQDN		""
#define DEFAULT_IFNAME		NULL
#define DEFAULT_IFIDX		-1
#define DEFAULT_ETHADDR		NULL
#define DEFAULT_VIRTADDR	""
#define DEFAULT_VIRTPORTS	""
#define DEFAULT_IPADDR		NULL
#define DEFAULT_SRCADDR		NULL
#define DEFAULT_PORT		""
#define DEFAULT_FAMILY		VALUE_FAMILY_IPV4
#define DEFAULT_MODE		VALUE_MODE_SNAT
#define DEFAULT_RESPONSETTL	60
#define DEFAULT_PROTO		VALUE_PROTO_TCP
#define DEFAULT_SCHED		VALUE_SCHED_RR
#define DEFAULT_SCHEDPARAM	VALUE_META_NONE
#define DEFAULT_PERSIST		VALUE_META_NONE
#define DEFAULT_PERSISTTM	60
#define DEFAULT_HELPER		VALUE_HELPER_NONE
#define DEFAULT_LOG			VALUE_LOG_NONE
#define DEFAULT_LOG_LOGPREFIX	"TYPE-FNAME "
#define DEFAULT_LOGPREFIX	"KNAME-FNAME "
#define DEFAULT_MARK		0x0
#define DEFAULT_WEIGHT		1
#define DEFAULT_PRIORITY	1
#define DEFAULT_FARM_STATE	VALUE_STATE_UP
#define DEFAULT_BACKEND_STATE	VALUE_STATE_CONFERR
#define DEFAULT_ACTION		ACTION_START
#define DEFAULT_NEWRTLIMIT	0
#define DEFAULT_RTLIMITBURST	0
#define DEFAULT_RSTRTLIMIT	0
#define DEFAULT_ESTCONNLIMIT	0
#define DEFAULT_B_ESTCONNLIMIT_LOGPREFIX	"KNAME-FNAME-BNAME "
#define DEFAULT_TCPSTRICT	VALUE_SWITCH_OFF
#define DEFAULT_QUEUE		-1
#define DEFAULT_FLOWOFFLOAD		0

#define DEFAULT_POLICY_TYPE	VALUE_TYPE_BLACK
#define DEFAULT_POLICY_TIMEOUT	0
#define DEFAULT_POLICY_PRIORITY	1
#define DEFAULT_POLICY_LOGPREFIX	"KNAME-TYPE-PNAME-FNAME "
#define DEFAULT_ELEMENT_TIME			NULL
#define DEFAULT_SESSION_EXPIRATION		NULL

#define UNDEFINED_VALUE					"UNDEFINED"
#define IFACE_LOOPBACK					"lo"

enum obj_start {
	OBJ_START,
	OBJ_START_INV
};

enum levels {
	LEVEL_INIT,
	LEVEL_FARMS,
	LEVEL_BCKS,
	LEVEL_FARMPOLICY,
	LEVEL_POLICIES,
	LEVEL_ELEMENTS,
	LEVEL_SESSIONS,
};

enum actions {
	ACTION_START,
	ACTION_STOP,
	ACTION_FLUSH,
	ACTION_RELOAD,
	ACTION_DELETE,
	ACTION_NONE,
};

enum keys {
	KEY_FARMS,
	KEY_NAME,
	KEY_NEWNAME,
	KEY_FQDN,
	KEY_IFACE,
	KEY_OFACE,
	KEY_FAMILY,
	KEY_ETHADDR,
	KEY_VIRTADDR,
	KEY_VIRTPORTS,
	KEY_IPADDR,
	KEY_SRCADDR,
	KEY_PORT,
	KEY_MODE,
	KEY_PROTO,
	KEY_SCHED,
	KEY_SCHEDPARAM,
	KEY_PERSISTENCE,
	KEY_PERSISTTM,
	KEY_HELPER,
	KEY_LOG,
	KEY_MARK,
	KEY_STATE,
	KEY_BCKS,
	KEY_WEIGHT,
	KEY_PRIORITY,
	KEY_ACTION,
	KEY_NEWRTLIMIT,
	KEY_NEWRTLIMITBURST,
	KEY_RSTRTLIMIT,
	KEY_RSTRTLIMITBURST,
	KEY_ESTCONNLIMIT,
	KEY_TCPSTRICT,
	KEY_QUEUE,
	KEY_POLICIES,
	KEY_ELEMENTS,
	KEY_TYPE,
	KEY_TIMEOUT,
	KEY_DATA,
	KEY_TIME,
	KEY_LOGPREFIX,
	KEY_NEWRTLIMIT_LOGPREFIX,
	KEY_RSTRTLIMIT_LOGPREFIX,
	KEY_ESTCONNLIMIT_LOGPREFIX,
	KEY_TCPSTRICT_LOGPREFIX,
	KEY_RESPONSETTL,
	KEY_FLOWOFFLOAD,
	KEY_SESSIONS,
	KEY_CLIENT,
	KEY_BACKEND,
};

enum families {
	VALUE_FAMILY_IPV4,
	VALUE_FAMILY_IPV6,
	VALUE_FAMILY_INET,
	VALUE_FAMILY_NETDEV,
};

struct obj_config {
	struct farm		*fptr;
	struct backend		*bptr;
	struct policy		*pptr;
	struct element		*eptr;
	struct farmpolicy	*fpptr;
	struct session		*sptr;
	struct config_pair	*c;
};

void objects_init(void);
struct list_head * obj_get_farms(void);
int obj_get_total_farms(void);
void obj_set_total_farms(int new_value);
int obj_get_dsr_counter(void);
void obj_set_dsr_counter(int new_value);

struct obj_config * obj_get_current_object(void);

char * obj_print_key(int key);
char * obj_print_family(int family);
char * obj_print_mode(int mode);
char * obj_print_proto(int protocol);
char * obj_print_sched(int scheduler);
void obj_print_meta(int param, char* buf);
char * obj_print_helper(int helper);
void obj_print_log(int log, char *buf);
char * obj_print_state(int state);
char * obj_print_switch(int value);
int obj_set_attribute(struct config_pair *c, int actionable);
int obj_set_attribute_string(char *src, char **dst);
void obj_print(void);
int obj_rulerize(int mode);

struct list_head * obj_get_policies(void);
int obj_get_total_policies(void);
void obj_set_total_policies(int new_value);
char * obj_print_policy_type(int type);

#endif /* _OBJECTS_H_ */
