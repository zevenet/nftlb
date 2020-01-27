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

#include "sessions.h"
#include "farms.h"
#include "objects.h"
#include "nft.h"

static struct session * session_create(struct farm *f, int type, char *client, char *bck, char *expiration)
{
	struct session *s;
	struct backend *b;

	if (!client || strcmp(client, "") == 0) {
		syslog(LOG_ERR, "%s():%d: missing data", __FUNCTION__, __LINE__);
		return NULL;
	}

	s = (struct session *)malloc(sizeof(struct session));
	if (!s) {
		syslog(LOG_ERR, "Session memory allocation error");
		return NULL;
	}

	s->f = f;
	obj_set_attribute_string(client, &s->client);
	s->state = VALUE_STATE_OFF;
	s->action = ACTION_NONE;

	s->bck = NULL;
	if (!bck || strcmp(bck, "") == 0 )
		goto cont;

	switch (f->mode) {
	case VALUE_MODE_DNAT:
	case VALUE_MODE_SNAT:
		if (strstr(bck, "0x") != NULL &&
			(b = backend_lookup_by_key(f, KEY_MARK, NULL, (int)strtol(bck, NULL, 16))) != NULL)
			s->bck = b;
		break;
	case VALUE_MODE_DSR:
	case VALUE_MODE_STLSDNAT:
		if ((b = backend_lookup_by_key(f, KEY_ETHADDR, bck, 0)) != NULL)
			s->bck = b;
		break;
	default:
		break;
	}

cont:
	s->expiration = DEFAULT_SESSION_EXPIRATION;

	if (type == SESSION_TYPE_TIMED) {
		list_add_tail(&s->list, &f->timed_sessions);
		f->total_timed_sessions++;
		obj_set_attribute_string(expiration, &s->expiration);
	} else {
		list_add_tail(&s->list, &f->static_sessions);
		f->total_static_sessions++;
	}

	return s;
}

static int nft_parse_sessions(struct farm *f, const char *buf)
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
new_session:
	next = 0;
	if ((fin_ptr = strstr(ini_ptr, " expires ")) != NULL) {
		snprintf(element1, fin_ptr - ini_ptr + 1, "%s", ini_ptr);
		fin_ptr += 9;
		ini_ptr = fin_ptr;
	} else
		return 0;

	if ((fin_ptr = strstr(ini_ptr, " : ")) != NULL) {
		snprintf(element2, fin_ptr - ini_ptr + 1, "%s", ini_ptr);
		fin_ptr += 3;
		ini_ptr = fin_ptr;
	} else
		return 0;

	if ((fin_ptr = strstr(ini_ptr + strlen(element2), ",")) != NULL) {
		next = 1;
	} else {
		if ((fin_ptr = strstr(ini_ptr, " ")) == NULL)
			return 0;
	}

	snprintf(element3, fin_ptr - ini_ptr + 1, "%s", ini_ptr);
	fin_ptr += 1;
	ini_ptr = fin_ptr;

	session_create(f, SESSION_TYPE_TIMED, element1, element3, element2);

	while (*fin_ptr == '\n' || *fin_ptr == '\t' || *fin_ptr == ' ') {
		fin_ptr++;
	}

	if (next && (*fin_ptr != '}' || *fin_ptr != '\0')) {
		ini_ptr = fin_ptr;
		goto new_session;
	}

	return 0;
}

static int session_delete_node(struct session *s, int type)
{
	syslog(LOG_DEBUG, "%s():%d: client %s", __FUNCTION__, __LINE__, s->client);

	list_del(&s->list);

	if (type == SESSION_TYPE_STATIC)
		s->f->total_static_sessions--;
	else
		s->f->total_timed_sessions--;

	if (s->client)
		free(s->client);
	if (s->expiration)
		free(s->expiration);

	free(s);

	return 0;
}

int session_set_action(struct session *s, int type, int action)
{
	syslog(LOG_DEBUG, "%s():%d: session %s action is %d - new action %d", __FUNCTION__, __LINE__, s->client, s->action, action);

	if (s->action == action)
		return 0;

	if (action == ACTION_DELETE) {
		session_delete_node(s, type);
		return 1;
	}

	if ((action == ACTION_STOP || action == ACTION_DELETE) && s->state == VALUE_STATE_UP) {
		s->action = action;
		s->state = VALUE_STATE_OFF;
		return 1;
	}

	if (action == ACTION_START && s->state != VALUE_STATE_UP && s->bck != NULL) {
		s->action = action;
		s->state = VALUE_STATE_UP;
		return 1;
	}

	return 0;
}

struct session * session_lookup_by_key(struct farm *f, int type, int key, const char *name)
{
	struct session *s;
	struct list_head *sessions;

	if (type == SESSION_TYPE_TIMED)
		sessions = &f->timed_sessions;
	else
		sessions = &f->static_sessions;

	list_for_each_entry(s, sessions, list) {
		switch (key) {
		case KEY_CLIENT:
			if (strcmp(s->client, name) == 0)
				return s;
			break;
		default:
			return NULL;
		}
	}

	return NULL;
}

int session_s_delete(struct farm *f, int type)
{
	struct list_head *sessions;
	struct session *s;
	struct session *next;

	syslog(LOG_DEBUG, "%s():%d: farm %s type %d", __FUNCTION__, __LINE__, f->name, type);

	if (type == SESSION_TYPE_TIMED)
		sessions = &f->timed_sessions;
	else
		sessions = &f->static_sessions;

	list_for_each_entry_safe(s, next, sessions, list)
		session_delete_node(s, type);

	return 0;
}

int session_s_set_action(struct farm *f, int action)
{
	struct session *s, *next;
	int ret = 0;

	if (f->total_static_sessions != 0)
		list_for_each_entry_safe(s, next, &f->static_sessions, list)
			ret += session_set_action(s, SESSION_TYPE_STATIC, action);
	if (f->total_timed_sessions != 0)
		list_for_each_entry_safe(s, next, &f->timed_sessions, list)
			ret += session_set_action(s, SESSION_TYPE_TIMED, action);

	return ret;
}

void session_s_print(struct farm *f)
{
	struct session *s;

	list_for_each_entry(s, &f->static_sessions, list) {
		syslog(LOG_DEBUG,"    [session] ");
		syslog(LOG_DEBUG,"       [client] %s", s->client);

		if (!s->bck)
			syslog(LOG_DEBUG,"       [backend] %s", UNDEFINED_VALUE);
		else
			syslog(LOG_DEBUG,"       [backend] %s", s->bck->name);

		syslog(LOG_DEBUG,"       *[state] %s", obj_print_state(s->state));
		syslog(LOG_DEBUG,"       *[action] %d", s->action);
	}

	list_for_each_entry(s, &f->timed_sessions, list) {
		syslog(LOG_DEBUG,"    [session] ");
		syslog(LOG_DEBUG,"       [client] %s", s->client);

		if (!s->bck)
			syslog(LOG_DEBUG,"       [backend] %s", UNDEFINED_VALUE);
		else
			syslog(LOG_DEBUG,"       [backend] %s", s->bck->name);

		syslog(LOG_DEBUG,"       [expiration] %s", s->expiration);
		syslog(LOG_DEBUG,"       *[state] %s", obj_print_state(s->state));
		syslog(LOG_DEBUG,"       *[action] %d", s->action);
	}
}

int session_get_timed(struct farm *f)
{
	const char *buf;
	syslog(LOG_DEBUG, "%s():%d: farm %s", __FUNCTION__, __LINE__, f->name);

	nft_get_rules_buffer(&buf, KEY_SESSIONS, f, NULL);
	f->total_timed_sessions = 0;
	nft_parse_sessions(f, buf);
	nft_del_rules_buffer(buf);
	session_s_print(f);
	return 0;
}

void session_get_client(struct session *s, char **parsed)
{
	struct farm *f = s->f;
	char *c;

	sprintf(*parsed, "%s", s->client);
	if ((f->persistence & VALUE_META_SRCIP) && (f->persistence & VALUE_META_SRCPORT)) {
		if (!(c = strstr(*parsed, " . ")))
			strcat(*parsed, " . 0");
	} else if (f->persistence & VALUE_META_SRCIP) {
		for (c = *parsed; (c = strchr(c, ' ')); ++c)
			*c = '\0';
	}
}

int session_backend_action(struct farm *f, struct backend *b, int action)
{
	struct session *s, *next;

	if (f->total_static_sessions != 0) {
		list_for_each_entry_safe(s, next, &f->static_sessions, list)
			if (!b ||
				((f->mode == VALUE_MODE_DNAT || f->mode == VALUE_MODE_SNAT || f->mode == VALUE_MODE_LOCAL) && b->mark == s->bck->mark) ||
				((f->mode == VALUE_MODE_DSR || f->mode == VALUE_MODE_STLSDNAT) && strcmp(b->ethaddr, s->bck->ethaddr) == 0))
				session_set_action(s, SESSION_TYPE_STATIC, action);
	}

	session_get_timed(f);
	if (f->total_static_sessions != 0) {
		list_for_each_entry_safe(s, next, &f->timed_sessions, list)
			if (!b ||
				((f->mode == VALUE_MODE_DNAT || f->mode == VALUE_MODE_SNAT || f->mode == VALUE_MODE_LOCAL) && b->mark == s->bck->mark) ||
				((f->mode == VALUE_MODE_DSR || f->mode == VALUE_MODE_STLSDNAT) && strcmp(b->ethaddr, s->bck->ethaddr) == 0))
				session_set_action(s, SESSION_TYPE_TIMED, action);
	}
	session_s_delete(f, SESSION_TYPE_TIMED);

	return 0;
}

int session_set_attribute(struct config_pair *c)
{
	struct obj_config *cur = obj_get_current_object();
	struct session *s;
	struct backend *b;
	struct farm *f;

	if (!cur->fptr)
		return PARSER_OBJ_UNKNOWN;
	f = cur->fptr;

	if (c->key != KEY_CLIENT && !cur->sptr)
		return PARSER_OBJ_UNKNOWN;

	s = cur->sptr;

	switch (c->key) {
	case KEY_CLIENT:
		s = session_lookup_by_key(f, SESSION_TYPE_STATIC, KEY_CLIENT, c->str_value);
		if (!s) {
			s = session_create(f, SESSION_TYPE_STATIC, c->str_value, NULL, NULL);
			if (!s)
				return PARSER_FAILED;
		}
		cur->sptr = s;
		break;
	case KEY_BACKEND:
		b = backend_lookup_by_key(f, KEY_NAME, c->str_value, 0);
		if (!b)
			return PARSER_OBJ_UNKNOWN;
		cur->sptr->bck = b;
		if (session_set_action(s, SESSION_TYPE_STATIC, ACTION_START))
			farm_set_action(f, ACTION_RELOAD);
		break;
	default:
		return -1;
	}

	return PARSER_OK;
}

int session_pre_actionable(struct config_pair *c)
{
	struct obj_config *cur = obj_get_current_object();
	struct farm *f;
	struct session *s;

	if (!cur->fptr || !cur->sptr)
		return -1;

	f = cur->fptr;
	s = cur->sptr;

	syslog(LOG_DEBUG, "%s():%d: pre actionable session farm %s", __FUNCTION__, __LINE__, f->name);

	switch (c->key) {
	case KEY_CLIENT:
		break;
	case KEY_BACKEND:
		if (session_set_action(s, SESSION_TYPE_STATIC, ACTION_STOP)) {
			farm_set_action(f, ACTION_RELOAD);
			farm_rulerize(f);
		}
		break;
	default:
		break;
	}

	return 0;
}

int session_pos_actionable(struct config_pair *c)
{
	struct obj_config *cur = obj_get_current_object();
	struct farm *f;
	struct session *s;

	if (!cur->fptr || !cur->sptr)
		return -1;

	f = cur->fptr;
	s = cur->sptr;

	syslog(LOG_DEBUG, "%s():%d: pos actionable session %s of farm %s with param %d", __FUNCTION__, __LINE__, s->client, f->name, c->key);

	switch (c->key) {
	case KEY_CLIENT:
		break;
	case KEY_BACKEND:
		if (session_set_action(s, SESSION_TYPE_STATIC, ACTION_START)) {
			farm_set_action(f, ACTION_RELOAD);
			farm_rulerize(f);
		}
		break;
	default:
		break;
	}

	return 0;
}
