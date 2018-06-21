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

#include "backends.h"
#include "farms.h"
#include "objects.h"
#include "network.h"


static struct backend * backend_create(struct farm *f, char *name)
{
	struct backend *b = (struct backend *)malloc(sizeof(struct backend));
	if (!b) {
		syslog(LOG_ERR, "Backend memory allocation error");
		return NULL;
	}

	list_add_tail(&b->list, &f->backends);
	f->total_bcks++;

	b->parent = f;
	obj_set_attribute_string(name, &b->name);

	b->fqdn = DEFAULT_FQDN;
	b->ethaddr = DEFAULT_ETHADDR;
	b->ipaddr = DEFAULT_IPADDR;
	b->ports = DEFAULT_PORTS;
	b->weight = DEFAULT_WEIGHT;
	b->priority = DEFAULT_PRIORITY;
	b->state = DEFAULT_BACKEND_STATE;
	b->action = DEFAULT_ACTION;

	f->total_weight += DEFAULT_WEIGHT;
	f->bcks_available++;

	return b;
}

static int backend_delete_node(struct backend *b)
{
	list_del(&b->list);
	if (b->name)
		free(b->name);
	if (b->fqdn && strcmp(b->fqdn, "") != 0)
		free(b->fqdn);
	if (b->ipaddr && strcmp(b->ipaddr, "") != 0)
		free(b->ipaddr);
	if (b->ethaddr && strcmp(b->ethaddr, "") != 0)
		free(b->ethaddr);
	if (b->ports && strcmp(b->ports, "") != 0)
		free(b->ports);

	free(b);

	return EXIT_SUCCESS;
}

static int backend_delete(struct backend *b)
{
	struct farm *f = b->parent;

	if (backend_is_available(b)) {
		f->bcks_available--;
		f->total_weight -= b->weight;
	}
	f->total_bcks--;
	farm_set_action(f, ACTION_RELOAD);

	backend_delete_node(b);

	return EXIT_SUCCESS;
}

void backend_s_print(struct farm *f)
{
	struct backend *b;

	list_for_each_entry(b, &f->backends, list) {
		syslog(LOG_DEBUG,"Model dump    [backend] ");
		syslog(LOG_DEBUG,"Model dump       [name] %s", b->name);

		if (b->fqdn)
			syslog(LOG_DEBUG,"Model dump       [fqdn] %s", b->fqdn);

		if (b->ipaddr)
			syslog(LOG_DEBUG,"Model dump       [ipaddr] %s", b->ipaddr);

		if (b->ethaddr)
			syslog(LOG_DEBUG,"Model dump       [ethaddr] %s", b->ethaddr);

		if (b->ports)
			syslog(LOG_DEBUG,"Model dump       [ports] %s", b->ports);

		syslog(LOG_DEBUG,"Model dump       [weight] %d", b->weight);
		syslog(LOG_DEBUG,"Model dump       [priority] %d", b->priority);
		syslog(LOG_DEBUG,"Model dump       [state] %s", obj_print_state(b->state));
	}
}

struct backend * backend_lookup_by_name(struct farm *f, const char *name)
{
	struct backend *b;

	list_for_each_entry(b, &f->backends, list) {
		if (strcmp(b->name, name) == 0)
			return b;
	}

	return NULL;
}

static int backend_set_ipaddr_from_ether(struct backend *b)
{
	struct farm *f = b->parent;
	int ret = EXIT_SUCCESS;
	unsigned char dst_ethaddr[ETH_HW_ADDR_LEN];
	unsigned char src_ethaddr[ETH_HW_ADDR_LEN];
	char streth[ETH_HW_STR_LEN] = {};

	if (f->mode == VALUE_MODE_DSR) {
		sscanf(f->iethaddr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &src_ethaddr[0], &src_ethaddr[1], &src_ethaddr[2], &src_ethaddr[3], &src_ethaddr[4], &src_ethaddr[5]);

		ret = net_get_neigh_ether((unsigned char **) &dst_ethaddr, src_ethaddr, f->family, f->virtaddr, b->ipaddr, f->ofidx);
		if (ret == EXIT_SUCCESS) {
			sprintf(streth, "%02x:%02x:%02x:%02x:%02x:%02x", dst_ethaddr[0],
				dst_ethaddr[1], dst_ethaddr[2], dst_ethaddr[3], dst_ethaddr[4], dst_ethaddr[5]);

			syslog(LOG_DEBUG, "%s():%d: discovered ether address for %s is %s", __FUNCTION__, __LINE__, b->name, streth);

			obj_set_attribute_string(streth, &b->ethaddr);
		} else {
			syslog(LOG_DEBUG, "%s():%d: backend %s comes to OFF", __FUNCTION__, __LINE__, b->name);
			backend_set_state(b, VALUE_STATE_OFF);
		}
	}

	return ret;
}

static int backend_set_weight(struct backend *b, int new_value)
{
	struct farm *f = b->parent;
	int old_value = b->weight;

	syslog(LOG_DEBUG, "%s():%d: current value is %d, but new value will be %d",
	       __FUNCTION__, __LINE__, old_value, new_value);

	b->weight = new_value;

	if (backend_is_available(b))
		f->total_weight += (b->weight-old_value);

	return EXIT_SUCCESS;
}

static int backend_set_priority(struct backend *b, int new_value)
{
	struct farm *f = b->parent;
	int old_value = b->priority;

	syslog(LOG_DEBUG, "%s():%d: current value is %d, but new value will be %d",
	       __FUNCTION__, __LINE__, old_value, new_value);

	if (backend_is_available(b) &&
	    new_value > f->priority) {
		f->bcks_available--;
		f->total_weight -= b->weight;
	}

	else if (old_value > f->priority &&
		 backend_is_available(b)) {
		f->bcks_available++;
		f->total_weight += b->weight;
	}

	b->priority = new_value;

	return EXIT_SUCCESS;
}

int backend_is_available(struct backend *b)
{
	struct farm *f = b->parent;

	syslog(LOG_DEBUG, "%s():%d: backend %s state is %d and priority %d",
	       __FUNCTION__, __LINE__, b->name, b->state, b->priority);

	return (b->state == VALUE_STATE_UP) && (b->priority <= f->priority);
}

int backend_set_action(struct backend *b, int action)
{
	if (action == ACTION_DELETE) {
		backend_delete(b);
		return 1;
	}

	if (b->action > action) {
		b->action = action;
		return 1;
	}

	return 0;
}

int backend_s_set_action(struct farm *f, int action)
{
	struct backend *b, *next;

	list_for_each_entry_safe(b, next, &f->backends, list)
		backend_set_action(b, action);

	return EXIT_SUCCESS;
}

int backend_s_delete(struct farm *f)
{
	struct backend *b, *next;

	list_for_each_entry_safe(b, next, &f->backends, list)
		backend_delete(b);

	f->total_bcks = 0;
	f->bcks_available = 0;
	f->total_weight = 0;

	return EXIT_SUCCESS;
}

int backend_set_attribute(struct config_pair *c)
{
	struct obj_config *cur = obj_get_current_object();
	struct backend *b = cur->bptr;

	if (!cur->fptr)
		return EXIT_FAILURE;

	switch (c->key) {
	case KEY_NAME:
		b = backend_lookup_by_name(cur->fptr, c->str_value);
		if (!b) {
			b = backend_create(cur->fptr, c->str_value);
			if (!b)
				return EXIT_FAILURE;
		}
		cur->bptr = b;
		break;
	case KEY_FQDN:
		obj_set_attribute_string(c->str_value, &b->fqdn);
		break;
	case KEY_IPADDR:
		obj_set_attribute_string(c->str_value, &b->ipaddr);
		backend_set_ipaddr_from_ether(b);
		break;
	case KEY_ETHADDR:
		obj_set_attribute_string(c->str_value, &b->ethaddr);
		break;
	case KEY_PORTS:
		obj_set_attribute_string(c->str_value, &b->ports);
		break;
	case KEY_WEIGHT:
		backend_set_weight(b, c->int_value);
		break;
	case KEY_PRIORITY:
		backend_set_priority(b, c->int_value);
		break;
	case KEY_STATE:
		backend_set_state(b, c->int_value);
		break;
	case KEY_ACTION:
		backend_set_action(b, c->int_value);
		break;
	default:
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int backend_set_state(struct backend *b, int new_value)
{
	struct farm *f = b->parent;
	int old_value = b->state;

	syslog(LOG_DEBUG, "%s():%d: current value is %d, but new value will be %d",
	       __FUNCTION__, __LINE__, old_value, new_value);

	if (backend_is_available(b) &&
	    new_value != VALUE_STATE_UP) {
		b->state = new_value;
		f->total_weight -= b->weight;
		f->bcks_available--;
	}

	else if (old_value != VALUE_STATE_UP &&
		 new_value == VALUE_STATE_UP) {
		b->state = new_value;

		if (backend_is_available(b)) {
			f->total_weight += b->weight;
			f->bcks_available++;
		}
	}

	return EXIT_SUCCESS;
}

int backend_s_set_ether_by_ipaddr(struct farm *f, const char *ip_bck, char *ether_bck)
{
	struct backend *b;
	int changed = 0;

	list_for_each_entry(b, &f->backends, list) {

		if (strcmp(b->ipaddr, ip_bck) != 0)
			continue;

		syslog(LOG_DEBUG, "%s():%d: backend with ip address %s found", __FUNCTION__, __LINE__, ip_bck);

		if (strcmp(b->ethaddr, ether_bck) != 0) {
			obj_set_attribute_string(ether_bck, &b->ethaddr);
			backend_set_state(b, VALUE_STATE_UP);
			changed = 1;
			syslog(LOG_INFO, "%s():%d: ether address changed for backend %s with %s", __FUNCTION__, __LINE__, b->name, ether_bck);
		}
	}

	return changed;
}

