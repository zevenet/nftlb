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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "policies.h"
#include "elements.h"
#include "objects.h"
#include "config.h"
#include "nft.h"


static struct policy * policy_create(char *name)
{
	struct list_head *policies = obj_get_policies();

	struct policy *p = (struct policy *)malloc(sizeof(struct policy));
	if (!p) {
		syslog(LOG_ERR, "Policy memory allocation error");
		return NULL;
	}

	obj_set_attribute_string(name, &p->name);

	p->type = DEFAULT_POLICY_TYPE;
	p->timeout = DEFAULT_POLICY_TIMEOUT;
	p->priority = DEFAULT_POLICY_PRIORITY;
	p->used = 0;
	p->logprefix = DEFAULT_POLICY_LOGPREFIX;
	p->action = DEFAULT_ACTION;

	init_list_head(&p->elements);

	p->total_elem = 0;

	list_add_tail(&p->list, policies);
	obj_set_total_policies(obj_get_total_policies() + 1);

	return p;
}

static int policy_delete(struct policy *p)
{
	list_del(&p->list);

	if (p->name && strcmp(p->name, "") != 0)
		free(p->name);
	if (p->logprefix && strcmp(p->logprefix, DEFAULT_POLICY_LOGPREFIX) != 0)
		free(p->logprefix);

	free(p);
	obj_set_total_policies(obj_get_total_policies() - 1);

	return 0;
}

static void policy_print(struct policy *p)
{
	syslog(LOG_DEBUG," [policy] ");
	syslog(LOG_DEBUG,"    [%s] %s", CONFIG_KEY_NAME, p->name);
	syslog(LOG_DEBUG,"    [%s] %s", CONFIG_KEY_TYPE, obj_print_policy_type(p->type));
	syslog(LOG_DEBUG,"    [%s] %d", CONFIG_KEY_TIMEOUT, p->timeout);
	syslog(LOG_DEBUG,"    [%s] %d", CONFIG_KEY_PRIORITY, p->priority);
	if (p->logprefix)
		syslog(LOG_DEBUG,"    [%s] %s", CONFIG_KEY_LOGPREFIX, p->logprefix);

	syslog(LOG_DEBUG,"    *[used] %d", p->used);
	syslog(LOG_DEBUG,"    *[total_elem] %d", p->total_elem);
	syslog(LOG_DEBUG,"    *[%s] %d", CONFIG_KEY_ACTION, p->action);

	if (p->total_elem != 0)
		element_s_print(p);
}

void policies_s_print(void)
{
	struct list_head *policies = obj_get_policies();
	struct policy *p;

	list_for_each_entry(p, policies, list) {
		policy_print(p);
	}
}

struct policy * policy_lookup_by_name(const char *name)
{
	struct list_head *policies = obj_get_policies();
	struct policy *p;

	list_for_each_entry(p, policies, list) {
		if (strcmp(p->name, name) == 0)
			return p;
	}

	return NULL;
}

int policy_set_attribute(struct config_pair *c)
{
	struct obj_config *cur = obj_get_current_object();
	struct policy *p;

	if (c->key != KEY_NAME && !cur->pptr)
		return PARSER_OBJ_UNKNOWN;

	p = cur->pptr;

	switch (c->key) {
	case KEY_NAME:
		p = policy_lookup_by_name(c->str_value);
		if (!p) {
			p = policy_create(c->str_value);
			if (!p)
				return -1;
		}
		cur->pptr = p;
		break;
	case KEY_TYPE:
		p->type = c->int_value;
		break;
	case KEY_TIMEOUT:
		p->timeout = c->int_value;
		break;
	case KEY_PRIORITY:
		p->priority = c->int_value;
		break;
	case KEY_ACTION:
		policy_set_action(p, c->int_value);
		break;
	case KEY_LOGPREFIX:
		obj_set_attribute_string(c->str_value, &p->logprefix);
		break;
	default:
		return PARSER_STRUCT_FAILED;
	}

	return PARSER_OK;
}

int policy_set_action(struct policy *p, int action)
{
	syslog(LOG_DEBUG, "%s():%d: policy %s set action %d", __FUNCTION__, __LINE__, p->name, action);

	if (action == ACTION_DELETE) {
		farm_s_lookup_policy_action(p->name, action);
		policy_delete(p);
		return 1;
	}

	if (action == ACTION_STOP)
		farm_s_lookup_policy_action(p->name, action);

	if (p->action > action) {
		p->action = action;
		return 1;
	}

	return 0;
}

int policy_s_set_action(int action)
{
	struct list_head *policies = obj_get_policies();
	struct policy *p, *next;

	list_for_each_entry_safe(p, next, policies, list)
		policy_set_action(p, action);

	return 0;
}

int policy_pre_actionable(struct config_pair *c)
{
	struct obj_config *cur = obj_get_current_object();
	struct policy *p;

	if (!cur->pptr)
		return -1;

	p = cur->pptr;

	syslog(LOG_DEBUG, "%s():%d: pos actionable policy %s with param %d action is %d", __FUNCTION__, __LINE__, p->name, c->key, p->action);

	switch (c->key) {
	case KEY_NAME:
		break;
	case KEY_TYPE:
	case KEY_TIMEOUT:
		policy_set_action(p, ACTION_STOP);
		break;
	default:
		policy_set_action(p, ACTION_RELOAD);
		return 0;
	}

	return 0;
}

int policy_pos_actionable(struct config_pair *c)
{
	struct obj_config *cur = obj_get_current_object();
	struct policy *p;

	if (!cur->pptr)
		return -1;

	p = cur->pptr;

	syslog(LOG_DEBUG, "%s():%d: pos actionable policy %s with param %d action is %d", __FUNCTION__, __LINE__, p->name, c->key, p->action);

	switch (c->key) {
	case KEY_NAME:
		break;
	case KEY_TYPE:
	case KEY_TIMEOUT:
		policy_set_action(p, ACTION_START);
		break;
	default:
		policy_set_action(p, ACTION_RELOAD);
		return 0;
	}

	return 0;
}

int policy_rulerize(struct policy *p)
{
	syslog(LOG_DEBUG, "%s():%d: rulerize policy %s", __FUNCTION__, __LINE__, p->name);

	policy_print(p);

	if (p->action == ACTION_NONE) {
		syslog(LOG_INFO, "%s():%d: policy %s won't be rulerized", __FUNCTION__, __LINE__, p->name);
		return 0;
	}

	return nft_rulerize_policies(p);
}

int policy_s_rulerize(void)
{
	struct policy *p;
	int ret = 0;
	int output = 0;

	syslog(LOG_DEBUG, "%s():%d: rulerize all policies", __FUNCTION__, __LINE__);

	struct list_head *policies = obj_get_policies();

	list_for_each_entry(p, policies, list) {
		ret = policy_rulerize(p);
		output = output || ret;
	}

	return output;
}
