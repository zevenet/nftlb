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
#include "nft.h"

static struct element * element_create(struct policy *p, char *data, char *time)
{
	struct element *e = (struct element *)malloc(sizeof(struct element));
	if (!e) {
		syslog(LOG_ERR, "element memory allocation error");
		return NULL;
	}

	e->policy = p;
	obj_set_attribute_string(data, &e->data);

	e->action = ACTION_NONE;
	e->time = DEFAULT_ELEMENT_TIME;
	if (time && strcmp(time, "") != 0)
		obj_set_attribute_string(time, &e->time);

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

static int nft_parse_elements(struct policy *p, const char *buf)
{
	char *ini_ptr = NULL;
	char *fin_ptr = NULL;
	char element1[2550] = {0};
	char element2[2550] = {0};
	char element3[2550] = {0};
	int next = 0;

	ini_ptr = strstr(buf, "elements = { ");
	if (ini_ptr == NULL)
		return 0;

	ini_ptr += 13;
new_element:
	next = 0;

	if (p->timeout) {
		if ((fin_ptr = strstr(ini_ptr, " expires ")) != NULL) {
			snprintf(element1, fin_ptr - ini_ptr + 1, "%s", ini_ptr);
			fin_ptr += 9;
			ini_ptr = fin_ptr;
		} else
			return 0;
	}

	if ((fin_ptr = strstr(ini_ptr + strlen(element2), ",")) != NULL) {
		next = 1;
	} else {
		if ((fin_ptr = strstr(ini_ptr, " ")) == NULL)
			return 0;
	}

	snprintf(element3, fin_ptr - ini_ptr + 1, "%s", ini_ptr);
	fin_ptr += 1;
	ini_ptr = fin_ptr;

	if (p->timeout)
		element_create(p, element3, element2);
	else
		element_create(p, element3, NULL);

	while (*fin_ptr == '\n' || *fin_ptr == '\t' || *fin_ptr == ' ') {
		fin_ptr++;
	}

	if (next && (*fin_ptr != '}' || *fin_ptr != '\0')) {
		ini_ptr = fin_ptr;
		goto new_element;
	}

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
	syslog(LOG_DEBUG, "%s():%d: element %s action is %d - new action %d", __FUNCTION__, __LINE__, e->data, e->action, action);

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

	if (action == ACTION_STOP) {
		policy_set_action(p, ACTION_FLUSH);
		return 0;
	}

	list_for_each_entry_safe(e, next, &p->elements, list)
		element_set_action(e, action);

	return 0;
}

int element_s_delete(struct policy *p)
{
	struct element *e, *next;

	list_for_each_entry_safe(e, next, &p->elements, list)
		element_delete(e);

	//~ p->total_elem = 0;

	return 0;
}

int element_set_attribute(struct config_pair *c)
{
	struct obj_config *cur = obj_get_current_object();
	struct element *e;

	if (!cur->pptr)
		return PARSER_OBJ_UNKNOWN;

	if (c->key != KEY_DATA && !cur->eptr)
		return PARSER_OBJ_UNKNOWN;

	e = cur->eptr;

	switch (c->key) {
	case KEY_DATA:
		e = element_lookup_by_name(cur->pptr, c->str_value);
		if (!e) {
			e = element_create(cur->pptr, c->str_value, NULL);
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

	policy_set_action(p, ACTION_RELOAD);

	return 0;
}

int element_get_list(struct policy *p)
{
	const char *buf;
	syslog(LOG_DEBUG, "%s():%d: policy %s", __FUNCTION__, __LINE__, p->name);

	nft_get_rules_buffer(&buf, KEY_POLICIES, p->name);
	p->total_elem = 0;
	nft_parse_elements(p, buf);
	nft_del_rules_buffer(buf);
	element_s_print(p);
	return 0;
}
