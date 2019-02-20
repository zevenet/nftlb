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

#include "elements.h"
#include "policies.h"
#include "objects.h"

static struct element * element_create(struct policy *p, char *data)
{
	struct element *e = (struct element *)malloc(sizeof(struct element));
	if (!e) {
		syslog(LOG_ERR, "Element memory allocation error");
		return NULL;
	}

	e->policy = p;
	obj_set_attribute_string(data, &e->data);

	e->time = DEFAULT_ELEMENT_TIME;
	e->action = DEFAULT_ACTION;

	list_add_tail(&e->list, &p->elements);
	p->total_elem++;

	return e;
}

static int element_delete_node(struct element *e)
{
	list_del(&e->list);
	if (e->data)
		free(e->data);
	if (e->time && strcmp(e->time, "") != 0)
		free(e->time);

	free(e);

	return 0;
}

static int element_delete(struct element *e)
{
	struct policy *p = e->policy;

	p->total_elem--;
	policy_set_action(p, ACTION_RELOAD);

	element_delete_node(e);

	return 0;
}

void element_s_print(struct policy *p)
{
	struct element *e;

	list_for_each_entry(e, &p->elements, list) {
		syslog(LOG_DEBUG,"    [element] ");
		syslog(LOG_DEBUG,"       [data] %s", e->data);
		if (p->timeout && e->time && strcmp(e->time, "") != 0)
			syslog(LOG_DEBUG,"       [time] %s", e->time);
		syslog(LOG_DEBUG,"       *[action] %d", e->action);
	}
}

struct element * element_lookup_by_name(struct policy *p, const char *data)
{
	struct element *e;

	list_for_each_entry(e, &p->elements, list) {
		if (strcmp(e->data, data) == 0)
			return e;
	}

	return NULL;
}

int element_set_action(struct element *e, int action)
{
	if (action == ACTION_DELETE) {
		element_delete(e);
		return 1;
	}

	if (e->action != action) {
		e->action = action;
		return 1;
	}

	return 0;
}

int element_s_set_action(struct policy *p, int action)
{
	struct element *e, *next;

	list_for_each_entry_safe(e, next, &p->elements, list)
		element_set_action(e, action);

	return 0;
}

int element_s_delete(struct policy *p)
{
	struct element *e, *next;

	list_for_each_entry_safe(e, next, &p->elements, list)
		element_delete(e);

	p->total_elem = 0;

	return 0;
}

int element_set_attribute(struct config_pair *c)
{
	struct obj_config *cur = obj_get_current_object();
	struct element *e = cur->eptr;

	if (!cur->pptr)
		return -1;

	switch (c->key) {
	case KEY_DATA:
		e = element_lookup_by_name(cur->pptr, c->str_value);
		if (!e) {
			e = element_create(cur->pptr, c->str_value);
			if (!e)
				return -1;
		}
		cur->eptr = e;
		break;
	case KEY_TIME:
		obj_set_attribute_string(c->str_value, &e->time);
		break;
	case KEY_ACTION:
		element_set_action(e, c->int_value);
		break;
	default:
		return -1;
	}

	return 0;
}

int element_pos_actionable(struct config_pair *c)
{
	struct obj_config *cur = obj_get_current_object();
	struct policy *p;
	struct element *e;

	if (!cur->pptr || !cur->eptr)
		return -1;

	p = cur->pptr;
	e = cur->eptr;

	syslog(LOG_DEBUG, "%s():%d: pos actionable element %s of policy %s with param %d", __FUNCTION__, __LINE__, e->data, p->name, c->key);

	//~ switch (c->key) {
	//~ case KEY_DATA:
		//~ break;
	//~ default:
		//~ break;
	//~ }

	policy_set_action(p, ACTION_RELOAD);

	return 0;
}
