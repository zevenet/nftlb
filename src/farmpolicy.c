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

#include "farmpolicy.h"
#include "farms.h"
#include "objects.h"
#include "network.h"


static struct farmpolicy * farmpolicy_create(struct farm *f, struct policy *p)
{
	struct farmpolicy *fp = (struct farmpolicy *)malloc(sizeof(struct farmpolicy));
	if (!fp) {
		syslog(LOG_ERR, "Farm Policy memory allocation error");
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
	list_del(&fp->list);

	if (fp->farm->policies_used > 0)
		fp->farm->policies_used--;

	if (fp->policy->used > 0)
		fp->policy->used--;

	fp->farm->policies_action = ACTION_STOP;

	if (fp->farm->policies_used > 0 && fp->farm->action == ACTION_RELOAD)
		fp->farm->policies_action = ACTION_RELOAD;

	free(fp);

	return 0;
}

void farmpolicy_s_print(struct farm *f)
{
	struct farmpolicy *fp;

	list_for_each_entry(fp, &f->policies, list) {
		syslog(LOG_DEBUG,"    [policy] ");
		syslog(LOG_DEBUG,"       [%s] %s", CONFIG_KEY_NAME, fp->policy->name);
		syslog(LOG_DEBUG,"       *[%s] %d", CONFIG_KEY_ACTION, fp->action);
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
	if ((action == ACTION_DELETE) || (action == ACTION_STOP)) {
		farmpolicy_delete(fp);
		return 1;
	}

	if (fp->action != action) {
		fp->action = action;
		fp->farm->policies_action = action;
		return 1;
	}

	return 0;
}

int farmpolicy_s_set_action(struct farm *f, int action)
{
	struct farmpolicy *fp, *next;

	list_for_each_entry_safe(fp, next, &f->policies, list)
		farmpolicy_set_action(fp, action);

	fp->farm->policies_action = action;

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

	fp = farmpolicy_lookup_by_name(f, name);
	if (fp)
		farmpolicy_set_action(fp, action);

	return 0;
}

int farmpolicy_set_attribute(struct config_pair *c)
{
	struct obj_config *cur = obj_get_current_object();
	struct farmpolicy *fp = cur->fpptr;
	struct policy *p;

	if (!cur->fptr)
		return PARSER_OBJ_UNKNOWN;

	switch (c->key) {
	case KEY_NAME:
		p = policy_lookup_by_name(c->str_value);
		if (!p)
			return -1;
		fp = farmpolicy_lookup_by_name(cur->fptr, c->str_value);
		if (fp)
			return 0;
		fp = farmpolicy_create(cur->fptr, p);
		cur->fpptr = fp;
		if (fp->farm->policies_used > 0 && fp->farm->iface == DEFAULT_IFNAME)
			farm_set_ifinfo(fp->farm, KEY_IFACE);
		break;
	default:
		return PARSER_STRUCT_FAILED;
	}

	return PARSER_OK;
}

int farmpolicy_pre_actionable(struct config_pair *c)
{
	struct obj_config *cur = obj_get_current_object();
	struct farm *f;

	if (!cur->fptr)
		return -1;

	f = cur->fptr;

	syslog(LOG_DEBUG, "%s():%d: pre actionable farm policy for farm %s", __FUNCTION__, __LINE__, f->name);

	farm_set_action(f, ACTION_RELOAD);

	return 0;
}

int farmpolicy_pos_actionable(struct config_pair *c)
{
	struct obj_config *cur = obj_get_current_object();
	struct farmpolicy *fp;
	struct farm *f;

	if (!cur->fpptr || !cur->fptr)
		return -1;

	fp = cur->fpptr;
	f = cur->fptr;

	syslog(LOG_DEBUG, "%s():%d: pos actionable farm policy %s for farm %s with param %d", __FUNCTION__, __LINE__, fp->policy->name, f->name, c->key);

	farm_set_action(f, ACTION_RELOAD);

	return 0;
}
