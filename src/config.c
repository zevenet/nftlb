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

#include "../include/config.h"
#include "../include/model.h"

#define CONFIG_MAXBUF			4096

void config_json(json_t *element, int level);
void config_json_object(json_t *element, int level);
void config_json_array(json_t *element, int level);
void config_json_string(json_t *element, int level);
int config_key(const char *key);
int jump_config_value(int level, int key);
void init_pair(struct configpair *cfgp);
void config_value(const char *value);
int config_value_family(const char *value);
int config_value_mode(const char *value);
int config_value_proto(const char *value);
int config_value_sched(const char *value);
int config_value_state(const char *value);
int config_value_action(const char *value);


struct configpair cfgp;

int config_file(const char *file)
{
	FILE		*fd;
	json_error_t	error;
	json_t		*root;
	int		ret = EXIT_SUCCESS;

	fd = fopen(file, "r");
	if (fd == NULL) {
		fprintf(stderr, "Error open configuration file %s\n", file);
		syslog(LOG_ERR, "Error open configuration file %s", file);
		return EXIT_FAILURE;
	}

	root = json_loadf(fd, JSON_ALLOW_NUL, &error);

	if (root) {
		config_json(root, MODEL_LEVEL_INIT);
		json_decref(root);
	} else {
		syslog(LOG_ERR, "Configuration file error on line %d: %s", error.line, error.text);
		ret = EXIT_FAILURE;
	}

	fclose(fd);
	return ret;
}

int config_buffer(const char *buf)
{
	json_error_t	error;
	json_t		*root;
	int		ret = EXIT_SUCCESS;

	root = json_loadb(buf, strlen(buf), JSON_ALLOW_NUL, &error);

	if (root) {
		config_json(root, MODEL_LEVEL_INIT);
		json_decref(root);
	} else {
		syslog(LOG_ERR, "Configuration error on line %d: %s", error.line, error.text);
		ret = EXIT_FAILURE;
	}

	return ret;
}

void config_json(json_t *element, int level)
{
	switch (json_typeof(element)) {
	case JSON_OBJECT:
		config_json_object(element, level);
		break;
	case JSON_ARRAY:
		level++;
		config_json_array(element, level);
		break;
	case JSON_STRING:
		config_json_string(element, level);
		break;
	default:
		fprintf(stderr, "Configuration file unknown element type %d\n", json_typeof(element));
		syslog(LOG_ERR, "Configuration file unknown element type %d", json_typeof(element));
	}
}

void config_json_object(json_t *element, int level)
{
	const char *key;
	json_t *value;

	json_object_foreach(element, key, value) {
		cfgp.level = level;
		cfgp.key = config_key(key);

		if (jump_config_value(level, cfgp.key) == EXIT_SUCCESS)
			config_json(value, level);
	}
}

void config_json_array(json_t *element, int level)
{
	size_t i;
	size_t size = json_array_size(element);

	for (i = 0; i < size; i++)
		config_json(json_array_get(element, i), level);
}

void config_json_string(json_t *element, int level)
{
	config_value(json_string_value(element));
	model_set_obj_attribute(&cfgp);
	init_pair(&cfgp);
}

void init_pair(struct configpair *cfgp)
{
	cfgp->level = -1;
	cfgp->key = -1;
	cfgp->str_value = NULL;
	cfgp->int_value = -1;
}

int config_key(const char *key)
{
	if (strcmp(key, CONFIG_KEY_FARMS) == 0)
		return MODEL_KEY_FARMS;
	if (strcmp(key, CONFIG_KEY_NAME) == 0)
		return MODEL_KEY_NAME;
	if (strcmp(key, CONFIG_KEY_FQDN) == 0)
		return MODEL_KEY_FQDN;
	if (strcmp(key, CONFIG_KEY_IFACE) == 0)
		return MODEL_KEY_IFACE;
	if (strcmp(key, CONFIG_KEY_OFACE) == 0)
		return MODEL_KEY_OFACE;
	if (strcmp(key, CONFIG_KEY_FAMILY) == 0)
		return MODEL_KEY_FAMILY;
	if (strcmp(key, CONFIG_KEY_ETHADDR) == 0)
		return MODEL_KEY_ETHADDR;
	if (strcmp(key, CONFIG_KEY_VIRTADDR) == 0)
		return MODEL_KEY_VIRTADDR;
	if (strcmp(key, CONFIG_KEY_VIRTPORTS) == 0)
		return MODEL_KEY_VIRTPORTS;
	if (strcmp(key, CONFIG_KEY_IPADDR) == 0)
		return MODEL_KEY_IPADDR;
	if (strcmp(key, CONFIG_KEY_PORTS) == 0)
		return MODEL_KEY_PORTS;
	if (strcmp(key, CONFIG_KEY_MODE) == 0)
		return MODEL_KEY_MODE;
	if (strcmp(key, CONFIG_KEY_PROTO) == 0)
		return MODEL_KEY_PROTO;
	if (strcmp(key, CONFIG_KEY_SCHED) == 0)
		return MODEL_KEY_SCHED;
	if (strcmp(key, CONFIG_KEY_STATE) == 0)
		return MODEL_KEY_STATE;
	if (strcmp(key, CONFIG_KEY_BCKS) == 0)
		return MODEL_KEY_BCKS;
	if (strcmp(key, CONFIG_KEY_WEIGHT) == 0)
		return MODEL_KEY_WEIGHT;
	if (strcmp(key, CONFIG_KEY_PRIORITY) == 0)
		return MODEL_KEY_PRIORITY;
	if (strcmp(key, CONFIG_KEY_ACTION) == 0)
		return MODEL_KEY_ACTION;

	return EXIT_FAILURE;
}

int jump_config_value(int level, int key)
{
	if ((level == MODEL_LEVEL_INIT && key != MODEL_KEY_FARMS) ||
	    (key == MODEL_KEY_BCKS && level != MODEL_LEVEL_FARMS))
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}

void config_value(const char *value)
{
	switch(cfgp.key) {
	case MODEL_KEY_FAMILY:
		cfgp.int_value = config_value_family(value);
		break;
	case MODEL_KEY_MODE:
		cfgp.int_value = config_value_mode(value);
		break;
	case MODEL_KEY_PROTO:
		cfgp.int_value = config_value_proto(value);
		break;
	case MODEL_KEY_SCHED:
		cfgp.int_value = config_value_sched(value);
		break;
	case MODEL_KEY_STATE:
		cfgp.int_value = config_value_state(value);
		break;
	case MODEL_KEY_WEIGHT:
	case MODEL_KEY_PRIORITY:
		cfgp.int_value = atoi(value);
		break;
	case MODEL_KEY_ACTION:
		cfgp.int_value = config_value_action(value);
		break;
		break;
	default:
		cfgp.str_value = (char *)value;
	}
}

int config_value_family(const char *value)
{
	if (strcmp(value, CONFIG_VALUE_FAMILY_IPV4) == 0)
		return MODEL_VALUE_FAMILY_IPV4;
	if (strcmp(value, CONFIG_VALUE_FAMILY_IPV6) == 0)
		return MODEL_VALUE_FAMILY_IPV6;
	if (strcmp(value, CONFIG_VALUE_FAMILY_INET) == 0)
		return MODEL_VALUE_FAMILY_INET;

	return EXIT_FAILURE;
}

int config_value_mode(const char *value)
{
	if (strcmp(value, CONFIG_VALUE_MODE_SNAT) == 0)
		return MODEL_VALUE_MODE_SNAT;
	if (strcmp(value, CONFIG_VALUE_MODE_DNAT) == 0)
		return MODEL_VALUE_MODE_DNAT;
	if (strcmp(value, CONFIG_VALUE_MODE_DSR) == 0)
		return MODEL_VALUE_MODE_DSR;

	return EXIT_FAILURE;
}

int config_value_proto(const char *value)
{
	if (strcmp(value, CONFIG_VALUE_PROTO_TCP) == 0)
		return MODEL_VALUE_PROTO_TCP;
	if (strcmp(value, CONFIG_VALUE_PROTO_UDP) == 0)
		return MODEL_VALUE_PROTO_UDP;
	if (strcmp(value, CONFIG_VALUE_PROTO_SCTP) == 0)
		return MODEL_VALUE_PROTO_SCTP;
	if (strcmp(value, CONFIG_VALUE_PROTO_ALL) == 0)
		return MODEL_VALUE_PROTO_ALL;

	return EXIT_FAILURE;
}

int config_value_sched(const char *value)
{
	if (strcmp(value, CONFIG_VALUE_SCHED_RR) == 0)
		return MODEL_VALUE_SCHED_RR;
	if (strcmp(value, CONFIG_VALUE_SCHED_WEIGHT) == 0)
		return MODEL_VALUE_SCHED_WEIGHT;
	if (strcmp(value, CONFIG_VALUE_SCHED_HASH) == 0)
		return MODEL_VALUE_SCHED_HASH;
	if (strcmp(value, CONFIG_VALUE_SCHED_SYMHASH) == 0)
		return MODEL_VALUE_SCHED_SYMHASH;

	return EXIT_FAILURE;
}

int config_value_state(const char *value)
{
	if (strcmp(value, CONFIG_VALUE_STATE_UP) == 0)
		return MODEL_VALUE_STATE_UP;
	if (strcmp(value, CONFIG_VALUE_STATE_DOWN) == 0)
		return MODEL_VALUE_STATE_DOWN;
	if (strcmp(value, CONFIG_VALUE_STATE_OFF) == 0)
		return MODEL_VALUE_STATE_OFF;

	return EXIT_FAILURE;
}

void add_dump_obj(json_t *obj, const char *name, char *value)
{
	if (value == NULL)
		return;

	json_object_set_new(obj, name, json_string(value));
}

void add_dump_list(json_t *obj, const char *objname, int model, struct list_head *head, char *name)
{
	struct farm *f;
	struct backend *b;
	json_t *jarray = json_array();
	json_t *item;
	char value[10];

	switch (model) {
	case MODEL_LEVEL_FARMS:
		list_for_each_entry(f, head, list) {
			if (name != NULL && (strcmp(name, "") != 0) && (strcmp(f->name, name) != 0))
				continue;

			item = json_object();
			add_dump_obj(item, "name", f->name);
			add_dump_obj(item, "fqdn", f->fqdn);
			add_dump_obj(item, "iface", f->iface);
			add_dump_obj(item, "oface", f->oface);
			add_dump_obj(item, "family", model_print_family(f->family));
			add_dump_obj(item, "ether-addr", f->ethaddr);
			add_dump_obj(item, "virtual-addr", f->virtaddr);
			add_dump_obj(item, "virtual-ports", f->virtports);
			add_dump_obj(item, "mode", model_print_mode(f->mode));
			add_dump_obj(item, "protocol", model_print_proto(f->protocol));
			add_dump_obj(item, "scheduler", model_print_sched(f->scheduler));
			model_print_int(value, f->priority);
			add_dump_obj(item, "priority", value);
			add_dump_obj(item, "state", model_print_state(f->state));
			add_dump_list(item, CONFIG_KEY_BCKS, MODEL_LEVEL_BCKS, &f->backends, NULL);
			json_array_append_new(jarray, item);
		}
		break;
	case MODEL_LEVEL_BCKS:
		list_for_each_entry(b, head, list) {
			item = json_object();
			add_dump_obj(item, "name", b->name);
			add_dump_obj(item, "fqdn", b->fqdn);
			add_dump_obj(item, "ether-addr", b->ethaddr);
			add_dump_obj(item, "ip-addr", b->ipaddr);
			add_dump_obj(item, "ports", b->ports);
			model_print_int(value, b->weight);
			add_dump_obj(item, "weight", value);
			model_print_int(value, b->priority);
			add_dump_obj(item, "priority", value);
			add_dump_obj(item, "state", model_print_state(b->state));
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
	struct list_head *farms = model_get_farms();
	json_t* jdata = json_object();

	add_dump_list(jdata, CONFIG_KEY_FARMS, MODEL_LEVEL_FARMS, farms, name);

	*buf = json_dumps(jdata, 0);
	json_decref(jdata);

	if (*buf == NULL)
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}

int config_value_action(const char *value)
{
	if (strcmp(value, CONFIG_VALUE_ACTION_STOP) == 0)
		return MODEL_ACTION_STOP;
	if (strcmp(value, CONFIG_VALUE_ACTION_DELETE) == 0)
		return MODEL_ACTION_DELETE;
	if (strcmp(value, CONFIG_VALUE_ACTION_START) == 0)
		return MODEL_ACTION_START;
	if (strcmp(value, CONFIG_VALUE_ACTION_RELOAD) == 0)
		return MODEL_ACTION_RELOAD;

	return MODEL_ACTION_NONE;
}

int config_set_farm_action(const char *name, const char *value)
{
	struct farm *f;

	if (!name || strcmp(name, "") == 0)
		return farms_action_update(config_value_action(value));

	f = model_lookup_farm(name);

	if (!f)
		return EXIT_FAILURE;

	farm_action_update(f, config_value_action(value));

	return 0;
}

int config_set_backend_action(const char *fname, const char *bname, const char *value)
{
	struct farm *f;
	struct backend *b;

	if (!fname || strcmp(fname, "") == 0)
		return EXIT_FAILURE;

	f = model_lookup_farm(fname);

	if (!f)
		return EXIT_FAILURE;

	if (!bname || strcmp(bname, "") == 0)
		return backends_action_update(f, config_value_action(value));

	b = model_lookup_backend(f, bname);

	if (!b)
		return EXIT_FAILURE;

	bck_action_update(b, config_value_action(value));

	return 0;
}

void config_print_response(char **buf, const char *message)
{
	if (buf != NULL && *buf != NULL)
		sprintf(*buf, "{\"response\": \"%s\"}", message);
}

