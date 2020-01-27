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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

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
	int ret;
	int status;
	syslog(LOG_DEBUG, "%s():%d: actionable is %d", __FUNCTION__, __LINE__, actionable);

	switch (c->level) {
	case LEVEL_FARMS:
		if (actionable)
			farm_pre_actionable(c);

		ret = farm_set_attribute(c);

		if (actionable && ret == PARSER_OK)
			farm_pos_actionable(c);
		break;
	case LEVEL_BCKS:
		if (actionable)
			status = bck_pre_actionable(c);

		ret = backend_set_attribute(c);

		if (actionable && status == 0)
			bck_pos_actionable(c);
		break;
	case LEVEL_SESSIONS:
		if (actionable)
			status = session_pre_actionable(c);

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
	*dst = (char *)malloc(strlen(src)+1);

	if (!*dst) {
		syslog(LOG_ERR, "Attribute memory allocation error");
		return -1;
	}

	sprintf(*dst, "%s", src);

	return 0;
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
	case VALUE_TYPE_BLACK:
		return CONFIG_VALUE_POLICIES_TYPE_BL;
	case VALUE_TYPE_WHITE:
		return CONFIG_VALUE_POLICIES_TYPE_WL;
	default:
		return NULL;
	}
}

void obj_check_clean(void)
{
	if (nft_check_tables())
		nft_reset();
}
