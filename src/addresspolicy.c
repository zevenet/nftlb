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

#include "addresspolicy.h"
#include "objects.h"
#include "network.h"
#include "tools.h"


static struct addresspolicy * addresspolicy_create(struct address *a, struct policy *p)
{
	struct addresspolicy *ap = (struct addresspolicy *)malloc(sizeof(struct addresspolicy));
	if (!ap) {
		tools_printlog(LOG_ERR, "address policy memory allocation error");
		return NULL;
	}

	tools_printlog(LOG_DEBUG, "%s():%d: address %s", __FUNCTION__, __LINE__, a->name);

	ap->address = a;
	ap->policy = p;
	ap->action = DEFAULT_ACTION;
	p->used++;

	a->policies_action = DEFAULT_ACTION;

	if (a->policies_used > 0 && a->action == ACTION_RELOAD)
		a->policies_action = ACTION_RELOAD;
	a->policies_used++;

	list_add_tail(&ap->list, &a->policies);

	return ap;
}

static int addresspolicy_delete(struct addresspolicy *ap)
{
	list_del(&ap->list);

	if (ap->address->policies_used > 0)
		ap->address->policies_used--;

	if (ap->policy->used > 0)
		ap->policy->used--;

	ap->address->policies_action = ACTION_STOP;

	free(ap);

	return 0;
}

void addresspolicy_s_print(struct address *a)
{
	struct addresspolicy *ap;

	list_for_each_entry(ap, &a->policies, list) {
		tools_printlog(LOG_DEBUG,"    [policy] ");
		tools_printlog(LOG_DEBUG,"       [%s] %s", CONFIG_KEY_NAME, ap->policy->name);
		tools_printlog(LOG_DEBUG,"       *[%s] %d", CONFIG_KEY_ACTION, ap->action);
	}
}

struct addresspolicy * addresspolicy_lookup_by_name(struct address *a, const char *name)
{
	struct addresspolicy *ap;

	list_for_each_entry(ap, &a->policies, list) {
		if (strcmp(ap->policy->name, name) == 0)
			return ap;
	}

	return NULL;
}

int addresspolicy_set_action(struct addresspolicy *ap, int action)
{
	if ((action == ACTION_DELETE) || (action == ACTION_STOP)) {
		addresspolicy_delete(ap);
		return 1;
	}

	if (ap->action != action) {
		ap->action = action;
		return 1;
	}

	return 0;
}

int addresspolicy_s_set_action(struct address *a, int action)
{
	struct addresspolicy *ap, *next;

	list_for_each_entry_safe(ap, next, &a->policies, list)
		addresspolicy_set_action(ap, action);

	return 0;
}

int addresspolicy_s_delete(struct address *a)
{
	struct addresspolicy *ap, *next;

	list_for_each_entry_safe(ap, next, &a->policies, list)
		addresspolicy_delete(ap);

	return 0;
}

int addresspolicy_s_lookup_policy_action(struct address *a, char *name, int action)
{
	struct addresspolicy *ap;
	int ret = 0;

	tools_printlog(LOG_DEBUG, "%s():%d: address %s action is %d - new action %d", __FUNCTION__, __LINE__, a->name, a->action, action);

	ap = addresspolicy_lookup_by_name(a, name);
	if (ap)
		ret = addresspolicy_set_action(ap, action);

	if (ret)
		address_set_action(a, ACTION_RELOAD);

	return 0;
}

int addresspolicy_set_attribute(struct config_pair *c)
{
	struct addresspolicy *ap = obj_get_current_addresspolicy();
	struct address *a = obj_get_current_address();
	struct policy *p;

	if (!a)
		return PARSER_OBJ_UNKNOWN;

	switch (c->key) {
	case KEY_NAME:
		p = policy_lookup_by_name(c->str_value);
		if (!p)
			return -1;
		ap = addresspolicy_lookup_by_name(a, c->str_value);
		if (ap)
			return 0;
		ap = addresspolicy_create(a, p);
		obj_set_current_addresspolicy(ap);
		break;
	default:
		return PARSER_STRUCT_FAILED;
	}

	return PARSER_OK;
}

int addresspolicy_pre_actionable(struct config_pair *c)
{
	struct address *a = obj_get_current_address();

	if (!a)
		return -1;

	tools_printlog(LOG_DEBUG, "%s():%d: pre actionable address policy for address %s", __FUNCTION__, __LINE__, a->name);

	address_set_action(a, ACTION_RELOAD);
	address_rulerize(a);

	return 0;
}

int addresspolicy_pos_actionable(struct config_pair *c)
{
	struct addresspolicy *ap = obj_get_current_addresspolicy();
	struct address *a = obj_get_current_address();

	if (!ap || !a)
		return -1;

	tools_printlog(LOG_DEBUG, "%s():%d: pos actionable address policy %s for address %s with param %d", __FUNCTION__, __LINE__, ap->policy->name, a->name, c->key);

	address_set_action(a, ACTION_RELOAD);

	return 0;
}
