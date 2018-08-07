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
#include "backends.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

struct obj_config	current_obj;

struct list_head	farms;
int			total_farms = 0;
int			dsr_counter = 0;


void objects_init(void)
{
	init_list_head(&farms);
}

struct list_head * obj_get_farms(void)
{
	return &farms;
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

int obj_set_attribute(struct config_pair *c, int actionable)
{
	syslog(LOG_DEBUG, "%s():%d: actionable is %d", __FUNCTION__, __LINE__, actionable);

	switch (c->level) {
	case LEVEL_FARMS:
		if (actionable)
			farm_pre_actionable(c);

		farm_set_attribute(c);

		if (actionable)
			farm_pos_actionable(c);
		break;
	case LEVEL_BCKS:
		backend_set_attribute(c);

		if (actionable)
			farm_pos_actionable(c);
		break;
	default:
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int obj_set_attribute_string(char *src, char **dst)
{
	*dst = (char *)malloc(strlen(src));

	if (!*dst) {
		syslog(LOG_ERR, "Attribute memory allocation error");
		return EXIT_FAILURE;
	}

	sprintf(*dst, "%s", src);

	return EXIT_SUCCESS;
}

void obj_print(void)
{
	farm_s_print();
}

