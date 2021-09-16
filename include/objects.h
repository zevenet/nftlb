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

#define NFTLB_MAX_PORTS				65535

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
#define DEFAULT_LOG_RTLIMIT	0
#define DEFAULT_LOG_RTLIMIT_UNIT	VALUE_UNIT_SECOND
#define DEFAULT_MARK		0x0
#define DEFAULT_WEIGHT		1
#define DEFAULT_PRIORITY	1
#define DEFAULT_FARM_STATE	VALUE_STATE_UP
#define DEFAULT_BACKEND_STATE	VALUE_STATE_CONFERR
#define DEFAULT_ACTION		ACTION_START
#define DEFAULT_LIMITSTTL		120
#define DEFAULT_NEWRTLIMIT	0
#define DEFAULT_RTLIMITBURST	0
#define DEFAULT_RSTRTLIMIT	0
#define DEFAULT_ESTCONNLIMIT	0
#define DEFAULT_B_ESTCONNLIMIT_LOGPREFIX	"KNAME-FNAME-BNAME "
#define DEFAULT_TCPSTRICT	VALUE_SWITCH_OFF
#define DEFAULT_QUEUE		-1
#define DEFAULT_FLOWOFFLOAD		0

#define DEFAULT_POLICY_TIMEOUT	0
#define DEFAULT_POLICY_TYPE				VALUE_TYPE_DENY
#define DEFAULT_VERDICT					VALUE_VERDICT_LOG | VALUE_VERDICT_DROP | VALUE_VERDICT_ACCEPT
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
	KEY_LIMITSTTL,
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
	KEY_USED,
	KEY_VERDICT,
 	KEY_LOG_RTLIMIT,
};

enum families {
	VALUE_FAMILY_IPV4,
	VALUE_FAMILY_IPV6,
	VALUE_FAMILY_INET,
	VALUE_FAMILY_NETDEV,
};


enum units {
	VALUE_UNIT_SECOND,
	VALUE_UNIT_MINUTE,
	VALUE_UNIT_HOUR,
	VALUE_UNIT_DAY,
	VALUE_UNIT_WEEK,
};

#define VALUE_VERDICT_NONE			0
#define VALUE_VERDICT_LOG			(1 << 0)
#define VALUE_VERDICT_DROP			(1 << 1)
#define VALUE_VERDICT_ACCEPT		(1 << 2)

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
struct farm * obj_get_current_farm(void);
struct backend * obj_get_current_backend(void);
struct policy * obj_get_current_policy(void);
struct farmpolicy * obj_get_current_farmpolicy(void);
struct element * obj_get_current_element(void);
struct session * obj_get_current_session(void);
void obj_set_current_farm(struct farm *f);
void obj_set_current_backend(struct backend *b);
void obj_set_current_policy(struct policy *p);
void obj_set_current_farmpolicy(struct farmpolicy *fp);
void obj_set_current_element(struct element *e);
void obj_set_current_session(struct session *s);

char * obj_print_key(int key);
char * obj_print_family(int family);
char * obj_print_mode(int mode);
char * obj_print_proto(int protocol);
int obj_print_rtlimit(char *buf, int value, int unit);
char * obj_print_sched(int scheduler);
void obj_print_meta(int param, char* buf);
char * obj_print_helper(int helper);
void obj_print_log(int log, char *buf);
char * obj_print_state(int state);
char * obj_print_switch(int value);
int obj_set_attribute(struct config_pair *c, int actionable);
int obj_set_attribute_string(char *src, char **dst);
int obj_equ_attribute_string(char *stra, char *strb);
void obj_set_attribute_int(int *src, int value);
int obj_equ_attribute_int(int valuea, int valueb);
void obj_print(void);
int obj_rulerize(int mode);
void obj_print_verdict(int verdict, char* buf);

struct list_head * obj_get_policies(void);
int obj_get_total_policies(void);
void obj_set_total_policies(int new_value);
char * obj_print_policy_type(int type);

#endif /* _OBJECTS_H_ */
