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
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <jansson.h>
#include <syslog.h>

#include "config.h"
#include "farms.h"
#include "backends.h"
#include "farmpolicy.h"
#include "policies.h"
#include "elements.h"

#define CONFIG_MAXBUF			4096

static int config_json(json_t *element, int level, int source, int key);

struct config_pair c;

static void init_pair(struct config_pair *c)
{
	c->level = -1;
	c->key = -1;
	c->str_value = NULL;
	c->int_value = -1;
}

static void config_dump_int(char *buf, int value)
{
	sprintf(buf, "%d", value);
}

static void config_dump_hex(char *buf, int value)
{
	sprintf(buf, "0x%x", value);
}

static int config_value_family(const char *value)
{
	if (strcmp(value, CONFIG_VALUE_FAMILY_IPV4) == 0)
		return VALUE_FAMILY_IPV4;
	if (strcmp(value, CONFIG_VALUE_FAMILY_IPV6) == 0)
		return VALUE_FAMILY_IPV6;
	if (strcmp(value, CONFIG_VALUE_FAMILY_INET) == 0)
		return VALUE_FAMILY_INET;

	syslog(LOG_INFO, "%s():%d: parsing unknown value'%s', using defaults", __FUNCTION__, __LINE__, value);
	return VALUE_FAMILY_IPV4;
}

static int config_value_mode(const char *value)
{
	if (strcmp(value, CONFIG_VALUE_MODE_SNAT) == 0)
		return VALUE_MODE_SNAT;
	if (strcmp(value, CONFIG_VALUE_MODE_DNAT) == 0)
		return VALUE_MODE_DNAT;
	if (strcmp(value, CONFIG_VALUE_MODE_DSR) == 0)
		return VALUE_MODE_DSR;
	if (strcmp(value, CONFIG_VALUE_MODE_STLSDNAT) == 0)
		return VALUE_MODE_STLSDNAT;

	syslog(LOG_INFO, "%s():%d: parsing unknown value'%s', using defaults", __FUNCTION__, __LINE__, value);
	return VALUE_MODE_SNAT;
}

static int config_value_proto(const char *value)
{
	if (strcmp(value, CONFIG_VALUE_PROTO_TCP) == 0)
		return VALUE_PROTO_TCP;
	if (strcmp(value, CONFIG_VALUE_PROTO_UDP) == 0)
		return VALUE_PROTO_UDP;
	if (strcmp(value, CONFIG_VALUE_PROTO_SCTP) == 0)
		return VALUE_PROTO_SCTP;
	if (strcmp(value, CONFIG_VALUE_PROTO_ALL) == 0)
		return VALUE_PROTO_ALL;

	syslog(LOG_INFO, "%s():%d: parsing unknown value'%s', using defaults", __FUNCTION__, __LINE__, value);
	return VALUE_PROTO_TCP;
}

static int config_value_sched(const char *value)
{
	if (strcmp(value, CONFIG_VALUE_SCHED_RR) == 0)
		return VALUE_SCHED_RR;
	if (strcmp(value, CONFIG_VALUE_SCHED_WEIGHT) == 0)
		return VALUE_SCHED_WEIGHT;
	if (strcmp(value, CONFIG_VALUE_SCHED_HASH) == 0)
		return VALUE_SCHED_HASH;
	if (strcmp(value, CONFIG_VALUE_SCHED_SYMHASH) == 0)
		return VALUE_SCHED_SYMHASH;

	syslog(LOG_INFO, "%s():%d: parsing unknown value'%s', using defaults", __FUNCTION__, __LINE__, value);
	return VALUE_SCHED_RR;
}

static int config_value_meta(const char *value)
{
	int mask = 0;

	if (strstr(value, CONFIG_VALUE_META_NONE) != NULL) {
		mask = VALUE_META_NONE;
		return mask;
	}

	if (strstr(value, CONFIG_VALUE_META_SRCIP) != NULL)
		mask |= VALUE_META_SRCIP;
	if (strstr(value, CONFIG_VALUE_META_DSTIP) != NULL)
		mask |= VALUE_META_DSTIP;
	if (strstr(value, CONFIG_VALUE_META_SRCPORT) != NULL)
		mask |= VALUE_META_SRCPORT;
	if (strstr(value, CONFIG_VALUE_META_DSTPORT) != NULL)
		mask |= VALUE_META_DSTPORT;
	if (strstr(value, CONFIG_VALUE_META_SRCMAC) != NULL)
		mask |= VALUE_META_SRCMAC;
	if (strstr(value, CONFIG_VALUE_META_DSTMAC) != NULL)
		mask |= VALUE_META_DSTMAC;

	return mask;
}

static int config_value_helper(const char *value)
{
	if (strcmp(value, CONFIG_VALUE_HELPER_NONE) == 0)
		return VALUE_HELPER_NONE;
	if (strcmp(value, CONFIG_VALUE_HELPER_AMANDA) == 0)
		return VALUE_HELPER_AMANDA;
	if (strcmp(value, CONFIG_VALUE_HELPER_FTP) == 0)
		return VALUE_HELPER_FTP;
	if (strcmp(value, CONFIG_VALUE_HELPER_H323) == 0)
		return VALUE_HELPER_H323;
	if (strcmp(value, CONFIG_VALUE_HELPER_IRC) == 0)
		return VALUE_HELPER_IRC;
	if (strcmp(value, CONFIG_VALUE_HELPER_NETBIOSNS) == 0)
		return VALUE_HELPER_NETBIOSNS;
	if (strcmp(value, CONFIG_VALUE_HELPER_PPTP) == 0)
		return VALUE_HELPER_PPTP;
	if (strcmp(value, CONFIG_VALUE_HELPER_SANE) == 0)
		return VALUE_HELPER_SANE;
	if (strcmp(value, CONFIG_VALUE_HELPER_SIP) == 0)
		return VALUE_HELPER_SIP;
	if (strcmp(value, CONFIG_VALUE_HELPER_SNMP) == 0)
		return VALUE_HELPER_SNMP;
	if (strcmp(value, CONFIG_VALUE_HELPER_TFTP) == 0)
		return VALUE_HELPER_TFTP;

	syslog(LOG_INFO, "%s():%d: parsing unknown value'%s', using defaults", __FUNCTION__, __LINE__, value);
	return VALUE_HELPER_NONE;
}

static int config_value_log(const char *value)
{
	int logmask = 0;

	if (strstr(value, CONFIG_VALUE_LOG_NONE) != NULL) {
		logmask = VALUE_LOG_NONE;
		return logmask;
	}

	if (strstr(value, CONFIG_VALUE_LOG_INPUT) != NULL)
		logmask |= VALUE_LOG_INPUT;
	if (strstr(value, CONFIG_VALUE_LOG_FORWARD) != NULL)
		logmask |= VALUE_LOG_FORWARD;
	if (strstr(value, CONFIG_VALUE_LOG_OUTPUT) != NULL)
		logmask |= VALUE_LOG_OUTPUT;

	return logmask;
}

static int config_value_switch(const char *value)
{
	if (strcmp(value, CONFIG_VALUE_SWITCH_ON) == 0)
		return VALUE_SWITCH_ON;
	else
		return VALUE_SWITCH_OFF;

	syslog(LOG_INFO, "%s():%d: parsing unknown value'%s', using defaults", __FUNCTION__, __LINE__, value);
	return VALUE_SWITCH_OFF;
}

static int config_value_state(const char *value)
{
	if (strcmp(value, CONFIG_VALUE_STATE_UP) == 0)
		return VALUE_STATE_UP;
	if (strcmp(value, CONFIG_VALUE_STATE_DOWN) == 0)
		return VALUE_STATE_DOWN;
	if (strcmp(value, CONFIG_VALUE_STATE_OFF) == 0)
		return VALUE_STATE_OFF;
	if (strcmp(value, CONFIG_VALUE_STATE_CONFERR) == 0)
		return VALUE_STATE_CONFERR;

	syslog(LOG_INFO, "%s():%d: parsing unknown value'%s', using defaults", __FUNCTION__, __LINE__, value);
	return VALUE_STATE_UP;
}

static int config_value_action(const char *value)
{
	if (strcmp(value, CONFIG_VALUE_ACTION_STOP) == 0)
		return ACTION_STOP;
	if (strcmp(value, CONFIG_VALUE_ACTION_DELETE) == 0)
		return ACTION_DELETE;
	if (strcmp(value, CONFIG_VALUE_ACTION_START) == 0)
		return ACTION_START;
	if (strcmp(value, CONFIG_VALUE_ACTION_RELOAD) == 0)
		return ACTION_RELOAD;

	return ACTION_NONE;
}

static int config_value_type(const char *value)
{
	if (strcmp(value, CONFIG_VALUE_POLICIES_TYPE_BL) == 0)
		return VALUE_TYPE_BLACK;
	if (strcmp(value, CONFIG_VALUE_POLICIES_TYPE_WL) == 0)
		return VALUE_TYPE_WHITE;

	syslog(LOG_INFO, "%s():%d: parsing unknown value'%s', using defaults", __FUNCTION__, __LINE__, value);
	return VALUE_TYPE_BLACK;
}

static int config_value(const char *value)
{
	int ret = 0;

	switch(c.key) {
	case KEY_FAMILY:
		c.int_value = config_value_family(value);
		break;
	case KEY_MODE:
		c.int_value = config_value_mode(value);
		break;
	case KEY_PROTO:
		c.int_value = config_value_proto(value);
		break;
	case KEY_SCHED:
		c.int_value = config_value_sched(value);
		break;
	case KEY_SCHEDPARAM:
		c.int_value = config_value_meta(value);
		break;
	case KEY_PERSISTENCE:
		c.int_value = config_value_meta(value);
		break;
	case KEY_HELPER:
		c.int_value = config_value_helper(value);
		break;
	case KEY_LOG:
		c.int_value = config_value_log(value);
		break;
	case KEY_MARK:
		c.int_value = (int)strtol(value, NULL, 16);
		break;
	case KEY_STATE:
		c.int_value = config_value_state(value);
		break;
	case KEY_WEIGHT:
	case KEY_PRIORITY:
	case KEY_PERSISTTM:
	case KEY_NEWRTLIMIT:
	case KEY_NEWRTLIMITBURST:
	case KEY_RSTRTLIMIT:
	case KEY_RSTRTLIMITBURST:
	case KEY_ESTCONNLIMIT:
	case KEY_QUEUE:
	case KEY_TIMEOUT:
		c.int_value = atoi(value);
		break;
	case KEY_ACTION:
		c.int_value = config_value_action(value);
		break;
	case KEY_TCPSTRICT:
		c.int_value = config_value_switch(value);
		break;
	case KEY_TYPE:
		c.int_value = config_value_type(value);
		break;
	case KEY_NAME:
	case KEY_NEWNAME:
	case KEY_IFACE:
	case KEY_OFACE:
	case KEY_ETHADDR:
	case KEY_VIRTADDR:
	case KEY_VIRTPORTS:
	case KEY_IPADDR:
	case KEY_SRCADDR:
	case KEY_PORTS:
	case KEY_DATA:
		c.str_value = (char *)value;
		break;
	default:
		syslog(LOG_ERR, "%s():%d: unknown parsed key %d", __FUNCTION__, __LINE__, c.key);
		ret = -1;
		break;
	}

	return ret;
}

static int config_key(const char *key)
{
	if (strcmp(key, CONFIG_KEY_FARMS) == 0)
		return KEY_FARMS;
	if (strcmp(key, CONFIG_KEY_NAME) == 0)
		return KEY_NAME;
	if (strcmp(key, CONFIG_KEY_NEWNAME) == 0)
		return KEY_NEWNAME;
	if (strcmp(key, CONFIG_KEY_FQDN) == 0)
		return KEY_FQDN;
	if (strcmp(key, CONFIG_KEY_IFACE) == 0)
		return KEY_IFACE;
	if (strcmp(key, CONFIG_KEY_OFACE) == 0)
		return KEY_OFACE;
	if (strcmp(key, CONFIG_KEY_FAMILY) == 0)
		return KEY_FAMILY;
	if (strcmp(key, CONFIG_KEY_ETHADDR) == 0)
		return KEY_ETHADDR;
	if (strcmp(key, CONFIG_KEY_VIRTADDR) == 0)
		return KEY_VIRTADDR;
	if (strcmp(key, CONFIG_KEY_VIRTPORTS) == 0)
		return KEY_VIRTPORTS;
	if (strcmp(key, CONFIG_KEY_IPADDR) == 0)
		return KEY_IPADDR;
	if (strcmp(key, CONFIG_KEY_SRCADDR) == 0)
		return KEY_SRCADDR;
	if (strcmp(key, CONFIG_KEY_PORTS) == 0)
		return KEY_PORTS;
	if (strcmp(key, CONFIG_KEY_MODE) == 0)
		return KEY_MODE;
	if (strcmp(key, CONFIG_KEY_PROTO) == 0)
		return KEY_PROTO;
	if (strcmp(key, CONFIG_KEY_SCHED) == 0)
		return KEY_SCHED;
	if (strcmp(key, CONFIG_KEY_SCHEDPARAM) == 0)
		return KEY_SCHEDPARAM;
	if (strcmp(key, CONFIG_KEY_PERSIST) == 0)
		return KEY_PERSISTENCE;
	if (strcmp(key, CONFIG_KEY_PERSISTTM) == 0)
		return KEY_PERSISTTM;
	if (strcmp(key, CONFIG_KEY_HELPER) == 0)
		return KEY_HELPER;
	if (strcmp(key, CONFIG_KEY_LOG) == 0)
		return KEY_LOG;
	if (strcmp(key, CONFIG_KEY_MARK) == 0)
		return KEY_MARK;
	if (strcmp(key, CONFIG_KEY_STATE) == 0)
		return KEY_STATE;
	if (strcmp(key, CONFIG_KEY_BCKS) == 0)
		return KEY_BCKS;
	if (strcmp(key, CONFIG_KEY_WEIGHT) == 0)
		return KEY_WEIGHT;
	if (strcmp(key, CONFIG_KEY_PRIORITY) == 0)
		return KEY_PRIORITY;
	if (strcmp(key, CONFIG_KEY_ACTION) == 0)
		return KEY_ACTION;
	if (strcmp(key, CONFIG_KEY_NEWRTLIMIT) == 0)
		return KEY_NEWRTLIMIT;
	if (strcmp(key, CONFIG_KEY_NEWRTLIMITBURST) == 0)
		return KEY_NEWRTLIMITBURST;
	if (strcmp(key, CONFIG_KEY_RSTRTLIMIT) == 0)
		return KEY_RSTRTLIMIT;
	if (strcmp(key, CONFIG_KEY_RSTRTLIMITBURST) == 0)
		return KEY_RSTRTLIMITBURST;
	if (strcmp(key, CONFIG_KEY_ESTCONNLIMIT) == 0)
		return KEY_ESTCONNLIMIT;
	if (strcmp(key, CONFIG_KEY_TCPSTRICT) == 0)
		return KEY_TCPSTRICT;
	if (strcmp(key, CONFIG_KEY_QUEUE) == 0)
		return KEY_QUEUE;
	if (strcmp(key, CONFIG_KEY_POLICIES) == 0)
		return KEY_POLICIES;
	if (strcmp(key, CONFIG_KEY_TYPE) == 0)
		return KEY_TYPE;
	if (strcmp(key, CONFIG_KEY_TIMEOUT) == 0)
		return KEY_TIMEOUT;
	if (strcmp(key, CONFIG_KEY_ELEMENTS) == 0)
		return KEY_ELEMENTS;
	if (strcmp(key, CONFIG_KEY_DATA) == 0)
		return KEY_DATA;
	if (strcmp(key, CONFIG_KEY_TIME) == 0)
		return KEY_TIME;

	syslog(LOG_ERR, "%s():%d: unknown key '%s'", __FUNCTION__, __LINE__, key);
	return -1;
}

static int jump_config_value(int level, int key)
{
	if ((level == LEVEL_INIT && key != KEY_FARMS && key != KEY_POLICIES) ||
	    (key == KEY_BCKS && level != LEVEL_FARMS) ||
	    (key == KEY_POLICIES && level != LEVEL_FARMS && level != LEVEL_INIT) ||
	    (key == KEY_ELEMENTS && level != LEVEL_POLICIES))
			return -1;

	return 0;
}

static int config_json_object(json_t *element, int level, int source)
{
	const char *key;
	json_t *value;
	int ret = PARSER_OK;

	json_object_foreach(element, key, value) {
		c.level = level;
		c.key = config_key(key);

		if (ret)
			return ret;

		if (jump_config_value(level, c.key) == 0) {
			ret = config_json(value, level, source, c.key);
			if (ret) {
				syslog(LOG_ERR, "%s():%d: error parsing object in level %d", __FUNCTION__, __LINE__, c.level);
				return ret;
			}
		}
	}

	return ret;
}

static int config_json_array(json_t *element, int level, int source)
{
	size_t size = json_array_size(element);
	size_t i;
	int ret = PARSER_OK;

	for (i = 0; i < size && ret == PARSER_OK; i++) {
		ret = config_json(json_array_get(element, i), level, source, -1);
	}

	return ret;
}

static int config_json_string(json_t *element, int level, int source)
{
	int ret;

	ret = config_value(json_string_value(element));

	if (ret)
		return ret;

	syslog(LOG_DEBUG, "%s():%d: %d(level) %d(key) %s(value) %d(value)", __FUNCTION__, __LINE__, c.level, c.key, c.str_value, c.int_value);

	ret = obj_set_attribute(&c, source);
	init_pair(&c);

	return ret;
}

static int config_json(json_t *element, int level, int source, int key)
{
	int ret = PARSER_OK;

	syslog(LOG_DEBUG, "%s():%d: %d(level) %d(source)", __FUNCTION__, __LINE__, level, source);

	switch (json_typeof(element)) {
	case JSON_OBJECT:
		ret = config_json_object(element, level, source);
		break;
	case JSON_ARRAY:
		if (level == LEVEL_INIT && key == KEY_FARMS)
			level = LEVEL_FARMS;
		if (level == LEVEL_INIT && key == KEY_POLICIES)
			level = LEVEL_POLICIES;
		if (level == LEVEL_FARMS && key == KEY_BCKS)
			level = LEVEL_BCKS;
		if (level == LEVEL_FARMS && key == KEY_POLICIES)
			level = LEVEL_FARMPOLICY;
		if (level == LEVEL_POLICIES && key == KEY_ELEMENTS)
			level = LEVEL_ELEMENTS;

		ret = config_json_array(element, level, source);

		if (level == LEVEL_FARMS || level == LEVEL_POLICIES)
			level = LEVEL_INIT;
		if (level == LEVEL_BCKS || level == LEVEL_FARMPOLICY)
			level = LEVEL_FARMS;
		if (level == LEVEL_ELEMENTS)
			level = LEVEL_POLICIES;

		break;
	case JSON_STRING:
		ret = config_json_string(element, level, source);

		break;
	default:
		fprintf(stderr, "Configuration file unknown element type %d\n", json_typeof(element));
		syslog(LOG_ERR, "Configuration file unknown element type %d", json_typeof(element));
	}

	return ret;
}

void config_pair_init(struct config_pair *c)
{
	if (!c)
		return;

	c->level = -1;
	c->key = -1;
	c->str_value = NULL;
	c->int_value = -1;
}

int config_file(const char *file)
{
	FILE		*fd;
	json_error_t	error;
	json_t		*root;
	int		ret = PARSER_OK;

	fd = fopen(file, "r");
	if (fd == NULL) {
		fprintf(stderr, "Error open configuration file %s\n", file);
		syslog(LOG_ERR, "Error open configuration file %s", file);
		return PARSER_FAILED;
	}

	root = json_loadf(fd, JSON_ALLOW_NUL, &error);

	if (root) {
		ret = config_json(root, LEVEL_INIT, CONFIG_SRC_FILE, -1);
		json_decref(root);
	} else {
		fprintf(stderr, "Configuration file error '%s' on line %d: %s", file, error.line, error.text);
		syslog(LOG_ERR, "Configuration file error '%s' on line %d: %s", file, error.line, error.text);
		ret = PARSER_FAILED;
	}

	fclose(fd);
	return ret;
}

int config_buffer(const char *buf)
{
	json_error_t	error;
	json_t		*root;
	int		ret = PARSER_OK;

	syslog(LOG_DEBUG, "%s():%d: received buffer %d : %s", __FUNCTION__, __LINE__, (int)strlen(buf), buf);

	root = json_loadb(buf, strlen(buf), JSON_ALLOW_NUL, &error);

	if (root) {
		ret = config_json(root, LEVEL_INIT, CONFIG_SRC_BUFFER, -1);
		json_decref(root);
	} else {
		syslog(LOG_ERR, "Configuration error on line %d: %s", error.line, error.text);
		ret = PARSER_FAILED;
	}

	return ret;
}

static void add_dump_obj(json_t *obj, const char *name, char *value)
{
	if (value == NULL)
		return;

	json_object_set_new(obj, name, json_string(value));
}

static void add_dump_list(json_t *obj, const char *objname, int object,
			  struct list_head *head, char *name)
{
	struct farm *f;
	struct backend *b;
	struct farmpolicy *fp;
	struct policy *p;
	struct element *e;
	json_t *jarray = json_array();
	json_t *item;
	char value[10];
	char buf[100] = {};

	switch (object) {
	case LEVEL_FARMS:
		list_for_each_entry(f, head, list) {
			if (name != NULL && (strcmp(name, "") != 0) && (strcmp(f->name, name) != 0))
				continue;

			item = json_object();
			add_dump_obj(item, CONFIG_KEY_NAME, f->name);
			add_dump_obj(item, CONFIG_KEY_FAMILY, obj_print_family(f->family));
			add_dump_obj(item, CONFIG_KEY_VIRTADDR, f->virtaddr);
			add_dump_obj(item, CONFIG_KEY_VIRTPORTS, f->virtports);

			if (f->srcaddr)
				add_dump_obj(item, CONFIG_KEY_SRCADDR, f->srcaddr);
			else
				add_dump_obj(item, CONFIG_KEY_SRCADDR, "");

			add_dump_obj(item, CONFIG_KEY_MODE, obj_print_mode(f->mode));
			add_dump_obj(item, CONFIG_KEY_PROTO, obj_print_proto(f->protocol));
			add_dump_obj(item, CONFIG_KEY_SCHED, obj_print_sched(f->scheduler));

			obj_print_meta(f->schedparam, (char *)buf);
			add_dump_obj(item, CONFIG_KEY_SCHEDPARAM, buf);
			buf[0] = '\0';

			obj_print_meta(f->persistence, (char *)buf);
			add_dump_obj(item, CONFIG_KEY_PERSIST, buf);
			buf[0] = '\0';

			config_dump_int(value, f->persistttl);
			add_dump_obj(item, CONFIG_KEY_PERSISTTM, value);

			add_dump_obj(item, CONFIG_KEY_HELPER, obj_print_helper(f->helper));

			obj_print_log(f->log, (char *)buf);
			add_dump_obj(item, CONFIG_KEY_LOG, buf);

			config_dump_hex(value, f->mark);
			add_dump_obj(item, CONFIG_KEY_MARK, value);
			config_dump_int(value, f->priority);
			add_dump_obj(item, CONFIG_KEY_PRIORITY, value);
			add_dump_obj(item, CONFIG_KEY_STATE, obj_print_state(f->state));

			config_dump_int(value, f->newrtlimit);
			add_dump_obj(item, CONFIG_KEY_NEWRTLIMIT, value);
			config_dump_int(value, f->newrtlimitbst);
			add_dump_obj(item, CONFIG_KEY_NEWRTLIMITBURST, value);
			config_dump_int(value, f->rstrtlimit);
			add_dump_obj(item, CONFIG_KEY_RSTRTLIMIT, value);
			config_dump_int(value, f->rstrtlimitbst);
			add_dump_obj(item, CONFIG_KEY_RSTRTLIMITBURST, value);
			config_dump_int(value, f->estconnlimit);
			add_dump_obj(item, CONFIG_KEY_ESTCONNLIMIT, value);

			add_dump_obj(item, CONFIG_KEY_TCPSTRICT, obj_print_switch(f->tcpstrict));

			config_dump_int(value, f->queue);
			add_dump_obj(item, CONFIG_KEY_QUEUE, value);

			add_dump_list(item, CONFIG_KEY_BCKS, LEVEL_BCKS, &f->backends, NULL);
			add_dump_list(item, CONFIG_KEY_POLICIES, LEVEL_FARMPOLICY, &f->policies, NULL);

			json_array_append_new(jarray, item);
		}
		break;
	case LEVEL_BCKS:
		list_for_each_entry(b, head, list) {
			item = json_object();
			add_dump_obj(item, CONFIG_KEY_NAME, b->name);
			add_dump_obj(item, CONFIG_KEY_IPADDR, b->ipaddr);
			config_dump_int(value, b->weight);
			add_dump_obj(item, CONFIG_KEY_WEIGHT, value);
			config_dump_int(value, b->priority);
			add_dump_obj(item, CONFIG_KEY_PRIORITY, value);
			config_dump_hex(value, b->mark);
			add_dump_obj(item, CONFIG_KEY_MARK, value);
			add_dump_obj(item, CONFIG_KEY_STATE, obj_print_state(b->state));
			json_array_append_new(jarray, item);
		}
		break;
	case LEVEL_FARMPOLICY:
		list_for_each_entry(fp, head, list) {
			item = json_object();
			add_dump_obj(item, "name", fp->policy->name);
			json_array_append_new(jarray, item);
		}
		break;
	case LEVEL_POLICIES:
		list_for_each_entry(p, head, list) {
			if (name != NULL && (strcmp(name, "") != 0) && (strcmp(p->name, name) != 0))
				continue;

			item = json_object();
			add_dump_obj(item, "name", p->name);
			add_dump_obj(item, "type", obj_print_policy_type(p->type));
			config_dump_int(value, p->timeout);
			add_dump_obj(item, "timeout", value);
			config_dump_int(value, p->priority);
			add_dump_obj(item, "priority", value);
			config_dump_int(value, p->used);
			add_dump_obj(item, "used", value);
			add_dump_list(item, CONFIG_KEY_ELEMENTS, LEVEL_ELEMENTS, &p->elements, NULL);
			json_array_append_new(jarray, item);
		}
		break;
	case LEVEL_ELEMENTS:
		list_for_each_entry(e, head, list) {
			item = json_object();
			add_dump_obj(item, "data", e->data);
			add_dump_obj(item, "time", e->time);
			json_array_append_new(jarray, item);
		}
		break;
	default:
		return;
	}

	json_object_set_new(obj, objname, jarray);
	return;
}

int config_print_farms(char **buf, char *name)
{
	struct list_head *farms = obj_get_farms();
	json_t* jdata = json_object();

	add_dump_list(jdata, CONFIG_KEY_FARMS, LEVEL_FARMS, farms, name);

	*buf = json_dumps(jdata, JSON_INDENT(8));
	json_decref(jdata);

	if (*buf == NULL)
		return -1;

	return 0;
}

 int config_print_policies(char **buf, char *name)
{
	struct list_head *policies = obj_get_policies();
	json_t* jdata = json_object();

	add_dump_list(jdata, CONFIG_KEY_POLICIES, LEVEL_POLICIES, policies, name);

	*buf = json_dumps(jdata, JSON_INDENT(8));
	json_decref(jdata);

	if (*buf == NULL)
		return -1;

	return 0;
}

int config_set_farm_action(const char *name, const char *value)
{
	struct farm *f;

	if (!name || strcmp(name, "") == 0)
		return farm_s_set_action(config_value_action(value));

	f = farm_lookup_by_name(name);
	if (!f)
		return -1;

	farm_set_action(f, config_value_action(value));

	return 0;
}

int config_set_backend_action(const char *fname, const char *bname, const char *value)
{
	struct farm *f;
	struct backend *b;

	if (!fname || strcmp(fname, "") == 0)
		return -1;

	f = farm_lookup_by_name(fname);
	if (!f)
		return -1;

	if (!bname || strcmp(bname, "") == 0)
		return backend_s_set_action(f, config_value_action(value));

	b = backend_lookup_by_name(f, bname);
	if (!b)
		return -1;

	backend_set_action(b, config_value_action(value));

	return 0;
}

int config_set_fpolicy_action(const char *fname, const char *fpname, const char *value)
{
	struct farm *f;
	struct farmpolicy *fp;

	if (!fname || strcmp(fname, "") == 0)
		return -1;

	f = farm_lookup_by_name(fname);
	if (!f)
		return -1;

	if (!fpname || strcmp(fpname, "") == 0)
		return farmpolicy_s_set_action(f, config_value_action(value));

	fp = farmpolicy_lookup_by_name(f, fpname);
	if (!fp)
		return -1;

	farmpolicy_set_action(fp, config_value_action(value));

	return 0;
}

int config_set_policy_action(const char *name, const char *value)
{
	struct policy *p;

	if (!name || strcmp(name, "") == 0)
		return policy_s_set_action(config_value_action(value));

	p = policy_lookup_by_name(name);
	if (!p)
		return -1;

	policy_set_action(p, config_value_action(value));

	return 0;
}

int config_set_element_action(const char *pname, const char *edata, const char *value)
{
	struct policy *p;
	struct element *e;

	if (!pname || strcmp(pname, "") == 0)
		return -1;

	p = policy_lookup_by_name(pname);
	if (!p)
		return -1;

	if (!edata || strcmp(edata, "") == 0)
		return element_s_set_action(p, config_value_action(value));

	e = element_lookup_by_name(p, edata);
	if (!e)
		return -1;

	element_set_action(e, config_value_action(value));

	return 0;
}

void config_print_response(char **buf, const char *message)
{
	if (buf != NULL && *buf != NULL)
		sprintf(*buf, "{\"response\": \"%s\"}", message);
}
