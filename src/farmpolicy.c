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

#include "farmpolicy.h"
#include "farms.h"
#include "farmaddress.h"
#include "objects.h"
#include "network.h"
#include "tools.h"


static struct farmpolicy * farmpolicy_create(struct farm *f, struct policy *p)
{
	struct farmpolicy *fp = (struct farmpolicy *)malloc(sizeof(struct farmpolicy));
	if (!fp) {
		tools_printlog(LOG_ERR, "Farm Policy memory allocation error");
		return NULL;
	}

	fp->farm = f;
	fp->policy = p;
	fp->action = DEFAULT_ACTION;
	p->used++;

	f->policies_action = DEFAULT_ACTION;

	if (f->policies_used > 0 && f->action == ACTION_RELOAD)
		f->policies_action = ACTION_RELOAD;
	f->policies_used++;

	list_add_tail(&fp->list, &f->policies);

	return fp;
}

static int farmpolicy_delete(struct farmpolicy *fp)
{
	if (!fp)
		return 0;

	list_del(&fp->list);

	if (fp->farm->policies_used > 0)
		fp->farm->policies_used--;

	if (fp->policy->used > 0)
		fp->policy->used--;

	free(fp);

	return 0;
}

void farmpolicy_s_print(struct farm *f)
{
	struct farmpolicy *fp;

	list_for_each_entry(fp, &f->policies, list) {
		tools_printlog(LOG_DEBUG,"    [policy] ");
		tools_printlog(LOG_DEBUG,"       [%s] %s", CONFIG_KEY_NAME, fp->policy->name);
		tools_printlog(LOG_DEBUG,"       *[%s] %d", CONFIG_KEY_ACTION, fp->action);
	}
}

struct farmpolicy * farmpolicy_lookup_by_name(struct farm *f, const char *name)
{
	struct farmpolicy *fp;

	list_for_each_entry(fp, &f->policies, list) {
		if (strcmp(fp->policy->name, name) == 0)
			return fp;
	}

	return NULL;
}

int farmpolicy_set_action(struct farmpolicy *fp, int action)
{
	struct farm *f = fp->farm;

	if (action == ACTION_DELETE) {
		farmpolicy_delete(fp);
		farmaddress_s_set_action(f, ACTION_RELOAD);
		return 1;
	}

	if (fp->action > action) {
		fp->action = action;
		fp->policy->action = ACTION_RELOAD;
		// deactivate policies if it's the only one used
		if (f->policies_used == 1 && fp->action == ACTION_STOP)
			f->policies_action = action;
		else
			f->policies_action = ACTION_RELOAD;
		farmaddress_s_set_action(f, ACTION_RELOAD);
		return 1;
	}

	return 0;
}

int farmpolicy_s_set_action(struct farm *f, int action)
{
	struct farmpolicy *fp, *next;

	list_for_each_entry_safe(fp, next, &f->policies, list)
		farmpolicy_set_action(fp, action);

	f->policies_action = action;

	return 0;
}

int farmpolicy_s_delete(struct farm *f)
{
	struct farmpolicy *fp, *next;

	list_for_each_entry_safe(fp, next, &f->policies, list)
		farmpolicy_delete(fp);

	return 0;
}

int farmpolicy_s_lookup_policy_action(struct farm *f, char *name, int action)
{
	struct farmpolicy *fp;
	int ret = 0;

	fp = farmpolicy_lookup_by_name(f, name);
	if (fp)
		ret = farmpolicy_set_action(fp, action);

	if (ret) {
		farm_set_action(f, ACTION_RELOAD);
		farmaddress_s_set_action(f, ACTION_RELOAD);
	}

	return 0;
}

int farmpolicy_set_attribute(struct config_pair *c)
{
	struct farmpolicy *fp = obj_get_current_farmpolicy();
	struct farm *f = obj_get_current_farm();
	struct policy *p;

	if (!f)
		return PARSER_OBJ_UNKNOWN;

	switch (c->key) {
	case KEY_NAME:
		p = policy_lookup_by_name(c->str_value);
		if (!p)
			return -1;
		fp = farmpolicy_lookup_by_name(f, c->str_value);
		if (fp)
			return 0;
		fp = farmpolicy_create(f, p);
		obj_set_current_farmpolicy(fp);
		break;
	default:
		return PARSER_STRUCT_FAILED;
	}

	return PARSER_OK;
}

int farmpolicy_pre_actionable(struct config_pair *c)
{
	struct farm *f = obj_get_current_farm();

	if (!f)
		return -1;

	tools_printlog(LOG_DEBUG, "%s():%d: pre actionable farm policy for farm %s", __FUNCTION__, __LINE__, f->name);

	farm_set_action(f, ACTION_RELOAD);
	farmaddress_s_set_action(f, ACTION_RELOAD);
	farm_rulerize(f);

	return 0;
}

int farmpolicy_pos_actionable(struct config_pair *c)
{
	struct farmpolicy *fp = obj_get_current_farmpolicy();
	struct farm *f = obj_get_current_farm();

	if (!fp || !f)
		return -1;

	tools_printlog(LOG_DEBUG, "%s():%d: pos actionable farm policy %s for farm %s with param %d", __FUNCTION__, __LINE__, fp->policy->name, f->name, c->key);

	farm_set_action(f, ACTION_RELOAD);
	farmaddress_s_set_action(f, ACTION_RELOAD);

	return 0;
}
