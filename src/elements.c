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

#include "elements.h"
#include "policies.h"
#include "objects.h"
#include "tools.h"
#include "nft.h"

static struct element * element_create(struct policy *p, char *data, char *time)
{
	struct element *e = (struct element *)malloc(sizeof(struct element));
	if (!e) {
		tools_printlog(LOG_ERR, "element memory allocation error");
		return NULL;
	}

	e->policy = p;
	obj_set_attribute_string(data, &e->data);

	e->action = ACTION_START;
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
	if (e->time)
		free(e->time);

	free(e);

	return 0;
}

static int element_delete(struct element *e)
{
	if (!e)
		return 0;

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
	char element1[100] = {0};
	char element2[100] = {0};
	char element3[100] = {0};
	int next = 0;

	ini_ptr = strstr(buf, "elements = { ");
	if (ini_ptr == NULL)
		return 0;

	ini_ptr += 13;
new_element:
	next = 0;

	if (p->timeout) {
		if ((fin_ptr = strstr(ini_ptr, " expires ")) != NULL) {
			tools_snprintf(element1, fin_ptr - ini_ptr, ini_ptr);
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

	tools_snprintf(element3, fin_ptr - ini_ptr, ini_ptr);
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
		tools_printlog(LOG_DEBUG,"    [element] ");
		tools_printlog(LOG_DEBUG,"       [data] %s", e->data);
		if (p->timeout && e->time && strcmp(e->time, "") != 0)
			tools_printlog(LOG_DEBUG,"       [time] %s", e->time);
		tools_printlog(LOG_DEBUG,"       *[action] %d", e->action);
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
	tools_printlog(LOG_DEBUG, "%s():%d: element %s action is %d - new action %d", __FUNCTION__, __LINE__, e->data, e->action, action);

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

	p->total_elem = 0;

	return 0;
}

int element_set_attribute(struct config_pair *c, int apply_action)
{
	struct policy *p = obj_get_current_policy();
	struct element *e = obj_get_current_element();

	if (!p || (c->key != KEY_DATA && !e))
		return PARSER_OBJ_UNKNOWN;

	switch (c->key) {
	case KEY_DATA:
		e = element_create(p, c->str_value, NULL);
		if (!e)
			return -1;
		obj_set_current_element(e);
		break;
	case KEY_TIME:
		if (e->time)
			free(e->time);
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

int element_pos_actionable(struct config_pair *c, int apply_action)
{
	struct policy *p = obj_get_current_policy();
	struct element *e = obj_get_current_element();

	if (!p || !e)
		return -1;

	tools_printlog(LOG_DEBUG, "%s():%d: pos actionable element %s of policy %s with param %d", __FUNCTION__, __LINE__, e->data, p->name, c->key);

	switch (c->key) {
	case KEY_DATA:
		if (apply_action != ACTION_START) {
			element_set_action(e, apply_action);
			policy_set_action(p, ACTION_RELOAD);
		}
		break;
	default:
		policy_set_action(p, ACTION_RELOAD);
		break;
	}

	return 0;
}

int element_get_list(struct policy *p)
{
	const char *buf;
	struct nftst *n = nftst_create_from_policy(p);

	tools_printlog(LOG_DEBUG, "%s():%d: policy %s", __FUNCTION__, __LINE__, p->name);

	nft_get_rules_buffer(&buf, KEY_POLICIES, n);
	p->total_elem = 0;
	nft_parse_elements(p, buf);
	nft_del_rules_buffer(buf);
	element_s_print(p);
	nftst_delete(n);
	return 0;
}
