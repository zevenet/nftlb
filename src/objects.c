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

#include "objects.h"
#include "config.h"
#include "list.h"
#include "farms.h"
#include "farmpolicy.h"
#include "backends.h"
#include "policies.h"
#include "elements.h"
#include "sessions.h"
#include "tools.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#define MAX_OBJ_VALUE		50
#define MAX_OBJ_UNIT		20

struct obj_config	current_obj;

struct list_head	farms;
int			total_farms = 0;
int			dsr_counter = 0;
struct list_head	policies;
int			total_policies = 0;

void objects_init(void)
{
	init_list_head(&farms);
	init_list_head(&policies);
}

struct list_head * obj_get_farms(void)
{
	return &farms;
}

struct list_head * obj_get_policies(void)
{
	return &policies;
}

int obj_get_total_farms(void)
{
	return total_farms;
}

void obj_set_total_farms(int new_value)
{
	if (new_value >= 0)
		total_farms = new_value;
}

int obj_get_total_policies(void)
{
	return total_policies;
}

void obj_set_total_policies(int new_value)
{
	if (new_value >= 0)
		total_policies = new_value;
}

int obj_get_dsr_counter(void)
{
	syslog(LOG_DEBUG, "%s():%d: current dsr counter is %d", __FUNCTION__, __LINE__, dsr_counter);
	return dsr_counter;
}

void obj_set_dsr_counter(int new_value)
{
	syslog(LOG_DEBUG, "%s():%d: new dsr counter is %d", __FUNCTION__, __LINE__, new_value);

	if (new_value >= 0)
		dsr_counter = new_value;
}

static void obj_config_init(void)
{
	config_pair_init(current_obj.c);
	current_obj.fptr = NULL;
	current_obj.bptr = NULL;
	current_obj.fpptr = NULL;
	current_obj.pptr = NULL;
	current_obj.eptr = NULL;
}

struct obj_config * obj_get_current_object(void)
{
	return &current_obj;
}

struct farm * obj_get_current_farm(void)
{
	return current_obj.fptr;
}

struct backend * obj_get_current_backend(void)
{
	return current_obj.bptr;
}

struct policy * obj_get_current_policy(void)
{
	return current_obj.pptr;
}

struct farmpolicy * obj_get_current_farmpolicy(void)
{
	return current_obj.fpptr;
}

struct element * obj_get_current_element(void)
{
	return current_obj.eptr;
}

struct session * obj_get_current_session(void)
{
	return current_obj.sptr;
}

void obj_set_current_farm(struct farm *f)
{
	current_obj.fptr = f;
}

void obj_set_current_backend(struct backend *b)
{
	current_obj.bptr = b;
}

void obj_set_current_policy(struct policy *p)
{
	current_obj.pptr = p;
}

void obj_set_current_farmpolicy(struct farmpolicy *fp)
{
	current_obj.fpptr = fp;
}

void obj_set_current_element(struct element *e)
{
	current_obj.eptr = e;
}

void obj_set_current_session(struct session *s)
{
	current_obj.sptr = s;
}

char * obj_print_key(int key)
{
	switch (key) {
	case KEY_FARMS:
		return CONFIG_KEY_FARMS;
	case KEY_NAME:
		return CONFIG_KEY_NAME;
	case KEY_NEWNAME:
		return CONFIG_KEY_NEWNAME;
	case KEY_FQDN:
		return CONFIG_KEY_FQDN;
	case KEY_IFACE:
		return CONFIG_KEY_IFACE;
	case KEY_OFACE:
		return CONFIG_KEY_OFACE;
	case KEY_FAMILY:
		return CONFIG_KEY_FAMILY;
	case KEY_ETHADDR:
		return CONFIG_KEY_ETHADDR;
	case KEY_VIRTADDR:
		return CONFIG_KEY_VIRTADDR;
	case KEY_VIRTPORTS:
		return CONFIG_KEY_VIRTPORTS;
	case KEY_IPADDR:
		return CONFIG_KEY_IPADDR;
	case KEY_SRCADDR:
		return CONFIG_KEY_SRCADDR;
	case KEY_PORT:
		return CONFIG_KEY_PORT;
	case KEY_MODE:
		return CONFIG_KEY_MODE;
	case KEY_RESPONSETTL:
		return CONFIG_KEY_RESPONSETTL;
	case KEY_PROTO:
		return CONFIG_KEY_PROTO;
	case KEY_SCHED:
		return CONFIG_KEY_SCHED;
	case KEY_SCHEDPARAM:
		return CONFIG_KEY_SCHEDPARAM;
	case KEY_PERSISTENCE:
		return CONFIG_KEY_PERSIST;
	case KEY_PERSISTTM:
		return CONFIG_KEY_PERSISTTM;
	case KEY_HELPER:
		return CONFIG_KEY_HELPER;
	case KEY_LOG:
		return CONFIG_KEY_LOG;
	case KEY_LOGPREFIX:
		return CONFIG_KEY_LOGPREFIX;
	case KEY_LOG_RTLIMIT:
		return CONFIG_KEY_LOG_RTLIMIT;
	case KEY_MARK:
		return CONFIG_KEY_MARK;
	case KEY_STATE:
		return CONFIG_KEY_STATE;
	case KEY_BCKS:
		return CONFIG_KEY_BCKS;
	case KEY_WEIGHT:
		return CONFIG_KEY_WEIGHT;
	case KEY_PRIORITY:
		return CONFIG_KEY_PRIORITY;
	case KEY_ACTION:
		return CONFIG_KEY_ACTION;
	case KEY_LIMITSTTL:
		return CONFIG_KEY_LIMITSTTL;
	case KEY_NEWRTLIMIT:
		return CONFIG_KEY_NEWRTLIMIT;
	case KEY_NEWRTLIMITBURST:
		return CONFIG_KEY_NEWRTLIMITBURST;
	case KEY_NEWRTLIMIT_LOGPREFIX:
		return CONFIG_KEY_NEWRTLIMIT_LOGPREFIX;
	case KEY_RSTRTLIMIT:
		return CONFIG_KEY_RSTRTLIMIT;
	case KEY_RSTRTLIMITBURST:
		return CONFIG_KEY_RSTRTLIMITBURST;
	case KEY_RSTRTLIMIT_LOGPREFIX:
		return CONFIG_KEY_RSTRTLIMIT_LOGPREFIX;
	case KEY_ESTCONNLIMIT:
		return CONFIG_KEY_ESTCONNLIMIT;
	case KEY_ESTCONNLIMIT_LOGPREFIX:
		return CONFIG_KEY_ESTCONNLIMIT_LOGPREFIX;
	case KEY_TCPSTRICT:
		return CONFIG_KEY_TCPSTRICT;
	case KEY_TCPSTRICT_LOGPREFIX:
		return CONFIG_KEY_TCPSTRICT_LOGPREFIX;
	case KEY_QUEUE:
		return CONFIG_KEY_QUEUE;
	case KEY_FLOWOFFLOAD:
		return CONFIG_KEY_FLOWOFFLOAD;
	case KEY_POLICIES:
		return CONFIG_KEY_POLICIES;
	case KEY_TYPE:
		return CONFIG_KEY_TYPE;
	case KEY_TIMEOUT:
		return CONFIG_KEY_TIMEOUT;
	case KEY_ELEMENTS:
		return CONFIG_KEY_ELEMENTS;
	case KEY_DATA:
		return CONFIG_KEY_DATA;
	case KEY_TIME:
		return CONFIG_KEY_TIME;
	case KEY_SESSIONS:
		return CONFIG_KEY_SESSIONS;
	case KEY_CLIENT:
		return CONFIG_KEY_CLIENT;
	case KEY_BACKEND:
		return CONFIG_KEY_BACKEND;
	default:
		return NULL;
	}
}

char * obj_print_family(int family)
{
	switch (family) {
	case VALUE_FAMILY_IPV4:
		return CONFIG_VALUE_FAMILY_IPV4;
	case VALUE_FAMILY_IPV6:
		return CONFIG_VALUE_FAMILY_IPV6;
	case VALUE_FAMILY_INET:
		return CONFIG_VALUE_FAMILY_INET;
	default:
		return NULL;
	}
}

char * obj_print_mode(int mode)
{
	switch (mode) {
	case VALUE_MODE_SNAT:
		return CONFIG_VALUE_MODE_SNAT;
	case VALUE_MODE_DNAT:
		return CONFIG_VALUE_MODE_DNAT;
	case VALUE_MODE_DSR:
		return CONFIG_VALUE_MODE_DSR;
	case VALUE_MODE_STLSDNAT:
		return CONFIG_VALUE_MODE_STLSDNAT;
	case VALUE_MODE_LOCAL:
		return CONFIG_VALUE_MODE_LOCAL;
	default:
		return NULL;
	}
}

char * obj_print_proto(int protocol)
{
	switch (protocol) {
	case VALUE_PROTO_TCP:
		return CONFIG_VALUE_PROTO_TCP;
	case VALUE_PROTO_UDP:
		return CONFIG_VALUE_PROTO_UDP;
	case VALUE_PROTO_SCTP:
		return CONFIG_VALUE_PROTO_SCTP;
	case VALUE_PROTO_ALL:
		return CONFIG_VALUE_PROTO_ALL;
	default:
		return NULL;
	}
}

int obj_print_rtlimit(char *buf, int value, int unit)
{
	char *unit_str;

	buf[0] = '\0';

	switch (unit) {
	case VALUE_UNIT_MINUTE:
		unit_str = CONFIG_VALUE_UNIT_MINUTE;
		break;
	case VALUE_UNIT_HOUR:
		unit_str = CONFIG_VALUE_UNIT_HOUR;
		break;
	case VALUE_UNIT_DAY:
		unit_str = CONFIG_VALUE_UNIT_DAY;
		break;
	case VALUE_UNIT_WEEK:
		unit_str = CONFIG_VALUE_UNIT_WEEK;
		break;
	case VALUE_UNIT_SECOND:
	default:
		unit_str = CONFIG_VALUE_UNIT_SECOND;
	}

	snprintf(buf, MAX_OBJ_VALUE, "%d/%s", value, unit_str);
	return EXIT_SUCCESS;
}

char * obj_print_sched(int scheduler)
{
	switch (scheduler) {
	case VALUE_SCHED_RR:
		return CONFIG_VALUE_SCHED_RR;
	case VALUE_SCHED_WEIGHT:
		return CONFIG_VALUE_SCHED_WEIGHT;
	case VALUE_SCHED_HASH:
		return CONFIG_VALUE_SCHED_HASH;
	case VALUE_SCHED_SYMHASH:
		return CONFIG_VALUE_SCHED_SYMHASH;
	default:
		return NULL;
	}
}

void obj_print_meta(int param, char* buf)
{
	if (param == 0) {
		sprintf(buf, "%s", CONFIG_VALUE_META_NONE);
		return;
	}

	if (param & VALUE_META_SRCIP) {
		strcat(buf, CONFIG_VALUE_META_SRCIP);
		strcat(buf, " ");
	}

	if (param & VALUE_META_DSTIP) {
		strcat(buf, CONFIG_VALUE_META_DSTIP);
		strcat(buf, " ");
	}

	if (param & VALUE_META_SRCPORT) {
		strcat(buf, CONFIG_VALUE_META_SRCPORT);
		strcat(buf, " ");
	}

	if (param & VALUE_META_DSTPORT) {
		strcat(buf, CONFIG_VALUE_META_DSTPORT);
		strcat(buf, " ");
	}

	if (param & VALUE_META_SRCMAC) {
		strcat(buf, CONFIG_VALUE_META_SRCMAC);
		strcat(buf, " ");
	}

	if (param & VALUE_META_DSTMAC) {
		strcat(buf, CONFIG_VALUE_META_DSTMAC);
		strcat(buf, " ");
	}

	return;
}

char * obj_print_helper(int helper)
{
	switch (helper) {
	case VALUE_HELPER_NONE:
		return CONFIG_VALUE_HELPER_NONE;
	case VALUE_HELPER_AMANDA:
		return CONFIG_VALUE_HELPER_AMANDA;
	case VALUE_HELPER_FTP:
		return CONFIG_VALUE_HELPER_FTP;
	case VALUE_HELPER_H323:
		return CONFIG_VALUE_HELPER_H323;
	case VALUE_HELPER_IRC:
		return CONFIG_VALUE_HELPER_IRC;
	case VALUE_HELPER_NETBIOSNS:
		return CONFIG_VALUE_HELPER_NETBIOSNS;
	case VALUE_HELPER_PPTP:
		return CONFIG_VALUE_HELPER_PPTP;
	case VALUE_HELPER_SANE:
		return CONFIG_VALUE_HELPER_SANE;
	case VALUE_HELPER_SIP:
		return CONFIG_VALUE_HELPER_SIP;
	case VALUE_HELPER_SNMP:
		return CONFIG_VALUE_HELPER_SNMP;
	case VALUE_HELPER_TFTP:
		return CONFIG_VALUE_HELPER_TFTP;
	default:
		return NULL;
	}
}

void obj_print_log(int log, char* buf)
{
	if (log == 0) {
		sprintf(buf, "%s", CONFIG_VALUE_LOG_NONE);
		return;
	}

	if (log & VALUE_LOG_INPUT)
		sprintf(buf, "%s ", CONFIG_VALUE_LOG_INPUT);

	if (log & VALUE_LOG_FORWARD) {
		strcat(buf, CONFIG_VALUE_LOG_FORWARD);
		strcat(buf, " ");
	}

	if (log & VALUE_LOG_OUTPUT)
		strcat(buf, CONFIG_VALUE_LOG_OUTPUT);

	return;
}

char * obj_print_state(int state)
{
	switch (state) {
	case VALUE_STATE_UP:
		return CONFIG_VALUE_STATE_UP;
	case VALUE_STATE_DOWN:
		return CONFIG_VALUE_STATE_DOWN;
	case VALUE_STATE_OFF:
		return CONFIG_VALUE_STATE_OFF;
	case VALUE_STATE_CONFERR:
		return CONFIG_VALUE_STATE_CONFERR;
	default:
		return NULL;
	}
}

char * obj_print_switch(int state)
{
	switch (state) {
	case VALUE_SWITCH_ON:
		return CONFIG_VALUE_SWITCH_ON;
	case VALUE_SWITCH_OFF:
		return CONFIG_VALUE_SWITCH_OFF;
	default:
		return NULL;
	}
}

int obj_set_attribute(struct config_pair *c, int actionable)
{
	int ret = 0;
	int action = ACTION_NONE;
	syslog(LOG_DEBUG, "%s():%d: actionable is %d", __FUNCTION__, __LINE__, actionable);

	switch (c->level) {
	case LEVEL_FARMS:
		if (!farm_changed(c))
			return PARSER_OK;

		if (actionable)
			action = farm_pre_actionable(c);

		ret = farm_set_attribute(c);

		if (actionable && ret == PARSER_OK && action != ACTION_NONE)
			farm_pos_actionable(c);
		break;
	case LEVEL_BCKS:
		if (!backend_changed(c))
			return PARSER_OK;

		if (actionable)
			action = bck_pre_actionable(c);

		ret = backend_set_attribute(c);

		if (actionable && action != ACTION_NONE)
			bck_pos_actionable(c, action);
		break;
	case LEVEL_SESSIONS:
		if (actionable)
			session_pre_actionable(c);

		ret = session_set_attribute(c);

		if (actionable)
			session_pos_actionable(c);
		break;
	case LEVEL_FARMPOLICY:
		if (actionable)
			farmpolicy_pre_actionable(c);

		ret = farmpolicy_set_attribute(c);

		if (actionable)
			farmpolicy_pos_actionable(c);
		break;
	case LEVEL_POLICIES:
		if (!policy_changed(c))
			return PARSER_OK;

		if (actionable)
			policy_pre_actionable(c);

		ret = policy_set_attribute(c);

		if (actionable)
			policy_pos_actionable(c);
		break;
	case LEVEL_ELEMENTS:
		ret = element_set_attribute(c);

		if (actionable)
			element_pos_actionable(c);
		break;
	default:
		syslog(LOG_ERR, "%s():%d: unknown level %d", __FUNCTION__, __LINE__, c->level);
		return PARSER_FAILED;
	}

	return ret;
}

int obj_set_attribute_string(char *src, char **dst)
{
	int size = strlen(src)+1;
	*dst = (char *)malloc(size);

	if (!*dst) {
		syslog(LOG_ERR, "Attribute memory allocation error");
		return -1;
	}

	tools_snprintf(*dst, size-1, src);

	return 0;
}

int obj_equ_attribute_string(char *stra, char *strb)
{
	return (stra == strb ||
			(stra == NULL && strcmp(strb, "") == 0) ||
			(stra && strb && strcmp(stra, strb) == 0));
}

void obj_set_attribute_int(int *src, int value)
{
	*src = value;
}

int obj_equ_attribute_int(int valuea, int valueb)
{
	return valuea == valueb;
}

void obj_print(void)
{
	farm_s_print();
	policies_s_print();
}

int obj_rulerize(int mode)
{
	int out = 0;
	obj_config_init();
	if (mode == OBJ_START_INV) {
		out = farm_s_rulerize();
		out = out + policy_s_rulerize();
	} else {
		out = policy_s_rulerize();
		out = out + farm_s_rulerize();
	}
	return out;
}

char * obj_print_policy_type(int type)
{
	switch (type) {
	case VALUE_TYPE_DENY:
		return CONFIG_VALUE_POLICIES_TYPE_BL;
	case VALUE_TYPE_ALLOW:
		return CONFIG_VALUE_POLICIES_TYPE_WL;
	default:
		return NULL;
	}
}

void obj_print_verdict(int verdict, char* buf)
{
	if (verdict == VALUE_VERDICT_NONE) {
		strcat(buf, CONFIG_VALUE_VERDICT_NONE);
		return;
	}

	if (verdict & VALUE_VERDICT_LOG) {
		strcat(buf, CONFIG_VALUE_VERDICT_LOG);
		strcat(buf, " ");
	}

	if (verdict & VALUE_VERDICT_DROP) {
		strcat(buf, CONFIG_VALUE_VERDICT_DROP);
		strcat(buf, " ");
	}

	if (verdict & VALUE_VERDICT_ACCEPT)
		strcat(buf, CONFIG_VALUE_VERDICT_ACCEPT);

	return;
}
