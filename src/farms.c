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

#include "farms.h"
#include "backends.h"
#include "objects.h"
#include "config.h"
#include "nft.h"
#include "network.h"


static struct farm * farm_create(char *name)
{
	struct list_head *farms = obj_get_farms();

	struct farm *pfarm = (struct farm *)malloc(sizeof(struct farm));
	if (!pfarm) {
		syslog(LOG_ERR, "Farm memory allocation error");
		return NULL;
	}

	list_add_tail(&pfarm->list, farms);
	obj_set_total_farms(obj_get_total_farms() + 1);

	obj_set_attribute_string(name, &pfarm->name);

	pfarm->fqdn = DEFAULT_FQDN;
	pfarm->iface = DEFAULT_IFACE;
	pfarm->oface = DEFAULT_OFACE;
	pfarm->iethaddr = DEFAULT_ETHADDR;
	pfarm->oethaddr = DEFAULT_ETHADDR;
	pfarm->ifidx = DEFAULT_IFIDX;
	pfarm->ofidx = DEFAULT_IFIDX;
	pfarm->virtaddr = DEFAULT_VIRTADDR;
	pfarm->virtports = DEFAULT_VIRTPORTS;
	pfarm->family = DEFAULT_FAMILY;
	pfarm->mode = DEFAULT_MODE;
	pfarm->protocol = DEFAULT_PROTO;
	pfarm->scheduler = DEFAULT_SCHED;
	pfarm->state = DEFAULT_FARM_STATE;
	pfarm->action = DEFAULT_ACTION;

	init_list_head(&pfarm->backends);

	pfarm->total_weight = 0;
	pfarm->priority = DEFAULT_PRIORITY;
	pfarm->total_bcks = 0;
	pfarm->bcks_available = 0;

	return pfarm;
}

static int farm_delete(struct farm *pfarm)
{
	backend_s_delete(pfarm);
	list_del(&pfarm->list);

	if (pfarm->name && strcmp(pfarm->name, "") != 0)
		free(pfarm->name);
	if (pfarm->fqdn && strcmp(pfarm->fqdn, "") != 0)
		free(pfarm->fqdn);
	if (pfarm->iface && strcmp(pfarm->iface, "") != 0)
		free(pfarm->iface);
	if (pfarm->oface && strcmp(pfarm->oface, "") != 0)
		free(pfarm->oface);
	if (pfarm->iethaddr && strcmp(pfarm->iethaddr, "") != 0)
		free(pfarm->iethaddr);
	if (pfarm->oethaddr && strcmp(pfarm->oethaddr, "") != 0)
		free(pfarm->oethaddr);
	if (pfarm->virtaddr && strcmp(pfarm->virtaddr, "") != 0)
		free(pfarm->virtaddr);
	if (pfarm->virtports && strcmp(pfarm->virtports, "") != 0)
		free(pfarm->virtports);

	free(pfarm);
	obj_set_total_farms(obj_get_total_farms() - 1);

	return EXIT_SUCCESS;
}


void farm_s_print(void)
{
	struct list_head *farms = obj_get_farms();
	struct farm *f;

	list_for_each_entry(f, farms, list) {

		syslog(LOG_DEBUG,"Model dump [farm] ");
		syslog(LOG_DEBUG,"Model dump    [name] %s", f->name);

		if (f->fqdn)
			syslog(LOG_DEBUG,"Model dump    [fqdn] %s", f->fqdn);

		if (f->iface)
			syslog(LOG_DEBUG,"Model dump    [iface] %s", f->iface);

		if (f->iethaddr)
			syslog(LOG_DEBUG,"Model dump    [iethaddr] %s", f->iethaddr);

		syslog(LOG_DEBUG,"Model dump    *[ifidx] %d", f->ifidx);

		if (f->oface)
			syslog(LOG_DEBUG,"Model dump    [oface] %s", f->oface);

		if (f->oethaddr)
			syslog(LOG_DEBUG,"Model dump    [oethaddr] %s", f->oethaddr);

		syslog(LOG_DEBUG,"Model dump    *[ofidx] %d", f->ofidx);

		if (f->virtaddr)
			syslog(LOG_DEBUG,"Model dump    [virtaddr] %s", f->virtaddr);

		if (f->virtports)
			syslog(LOG_DEBUG,"Model dump    [virtports] %s", f->virtports);

		syslog(LOG_DEBUG,"Model dump    [family] %s", obj_print_family(f->family));
		syslog(LOG_DEBUG,"Model dump    [mode] %s", obj_print_mode(f->mode));
		syslog(LOG_DEBUG,"Model dump    [protocol] %s", obj_print_proto(f->protocol));
		syslog(LOG_DEBUG,"Model dump    [scheduler] %s", obj_print_sched(f->scheduler));
		syslog(LOG_DEBUG,"Model dump    [state] %s", obj_print_state(f->state));
		syslog(LOG_DEBUG,"Model dump    [priority] %d", f->priority);
		syslog(LOG_DEBUG,"Model dump    *[total_weight] %d", f->total_weight);
		syslog(LOG_DEBUG,"Model dump    *[total_bcks] %d", f->total_bcks);
		syslog(LOG_DEBUG,"Model dump    *[bcks_available] %d", f->bcks_available);
		syslog(LOG_DEBUG,"Model dump    *[action] %d", f->action);

		if (f->total_bcks != 0)
			backend_s_print(f);
	}
}

struct farm * farm_lookup_by_name(const char *name)
{
	struct list_head *farms = obj_get_farms();
	struct farm *f;

	list_for_each_entry(f, farms, list) {
		if (strcmp(f->name, name) == 0)
			return f;
	}

	return NULL;
}

static int farm_set_ifinfo(struct farm *f, int key)
{
	unsigned char ether[ETH_HW_ADDR_LEN];
	char streth[ETH_HW_STR_LEN] = {};
	int *if_index;
	char **if_str;
	char **ether_addr;

	if (f->mode != VALUE_MODE_DSR) {
		syslog(LOG_DEBUG, "%s():%d: farm %s is not in DSR mode", __FUNCTION__, __LINE__, f->name);
		return EXIT_FAILURE;
	}

	if (key == KEY_IFACE) {
		if_index = &f->ifidx;
		ether_addr = &f->iethaddr;
		if_str = &f->iface;
	} else if (key == KEY_OFACE) {
		if_index = &f->ofidx;
		ether_addr = &f->oethaddr;
		if_str = &f->oface;
	}

	if (strcmp(*if_str, "") == 0) {
		syslog(LOG_INFO, "%s():%d: interface not set yet in farm %s", __FUNCTION__, __LINE__, f->name);
		return EXIT_FAILURE;
	}

	if (net_get_local_ifinfo((unsigned char **)&ether, if_index, *if_str) != EXIT_SUCCESS)
		return EXIT_FAILURE;

	sprintf(streth, "%02x:%02x:%02x:%02x:%02x:%02x", ether[0],
		ether[1], ether[2], ether[3], ether[4], ether[5]);

	obj_set_attribute_string(streth, ether_addr);

	return EXIT_SUCCESS;
}

static int farm_set_mode(struct farm *f, int new_value)
{
	int old_value = f->mode;

	if (old_value != new_value) {
		farm_set_ifinfo(f, KEY_IFACE);
		farm_set_ifinfo(f, KEY_OFACE);
	}

	f->mode = new_value;

	return EXIT_SUCCESS;
}

static int farm_set_state(struct farm *f, int new_value)
{
	int old_value = f->state;

	if (old_value != VALUE_STATE_UP &&
	    new_value == VALUE_STATE_UP) {
		farm_set_action(f, ACTION_START);
	}

	if (old_value == VALUE_STATE_UP &&
	    new_value != VALUE_STATE_UP) {
		farm_set_action(f, ACTION_STOP);
	}

	f->state = new_value;

	return EXIT_SUCCESS;
}

int farm_pre_actionable(struct config_pair *c)
{
	struct obj_config *cur = obj_get_current_object();
	struct farm *f;

	if (!cur->fptr)
		return EXIT_FAILURE;

	f = cur->fptr;

	switch (c->key) {
	case KEY_PROTO:
		if (farm_set_action(f, ACTION_STOP))
			nft_rulerize();
		break;
	default:
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int farm_pos_actionable(struct config_pair *c)
{
	struct obj_config *cur = obj_get_current_object();
	struct farm *f;

	if (!cur->fptr)
		return EXIT_FAILURE;

	f = cur->fptr;

	switch (c->key) {
	case KEY_PROTO:
		farm_set_action(f, ACTION_START);
		break;
	default:
		farm_set_action(f, ACTION_RELOAD);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int farm_set_attribute(struct config_pair *c)
{
	struct obj_config *cur = obj_get_current_object();
	struct farm *f = cur->fptr;

	switch (c->key) {
	case KEY_NAME:
		f = farm_lookup_by_name(c->str_value);
		if (!f) {
			f = farm_create(c->str_value);
			if (!f)
				return EXIT_FAILURE;
		}
		cur->fptr = f;
		break;
	case KEY_FQDN:
		obj_set_attribute_string(c->str_value, &f->fqdn);
		break;
	case KEY_IFACE:
		obj_set_attribute_string(c->str_value, &f->iface);
		break;
	case KEY_OFACE:
		obj_set_attribute_string(c->str_value, &f->oface);
		break;
	case KEY_FAMILY:
		f->family = c->int_value;
		break;
	case KEY_ETHADDR:
		obj_set_attribute_string(c->str_value, &f->iethaddr);
		break;
	case KEY_VIRTADDR:
		obj_set_attribute_string(c->str_value, &f->virtaddr);
		break;
	case KEY_VIRTPORTS:
		obj_set_attribute_string(c->str_value, &f->virtports);
		break;
	case KEY_MODE:
		farm_set_mode(f, c->int_value);
		break;
	case KEY_PROTO:
		f->protocol = c->int_value;
		break;
	case KEY_SCHED:
		f->scheduler = c->int_value;
		break;
	case KEY_STATE:
		farm_set_state(f, c->int_value);
		break;
	case KEY_ACTION:
		farm_set_action(f, c->int_value);
		break;
	default:
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int farm_set_action(struct farm *f, int action)
{
	if (action == ACTION_DELETE) {
		farm_delete(f);
		return 1;
	}

	if (f->action > action) {
		f->action = action;
		return 1;
	}

	return 0;
}

int farm_s_set_action(int action)
{
	struct list_head *farms = obj_get_farms();
	struct farm *f, *next;

	list_for_each_entry_safe(f, next, farms, list)
		farm_set_action(f, action);

	return EXIT_SUCCESS;
}

void farm_s_set_backend_ether_by_oifidx(int interface_idx, const char * ip_bck, char * ether_bck)
{
	struct list_head *farms = obj_get_farms();
	struct farm *f;
	int changed = 0;

	syslog(LOG_DEBUG, "%s():%d: updating farms with oifidx %d and backends with ip address %s and ether address %s", __FUNCTION__, __LINE__, interface_idx, ip_bck, ether_bck);

	list_for_each_entry(f, farms, list) {

		if (f->ofidx != interface_idx)
			continue;

		syslog(LOG_DEBUG, "%s():%d: farm with oifidx %d found", __FUNCTION__, __LINE__, interface_idx);

		if (backend_s_set_ether_by_ipaddr(f, ip_bck, ether_bck)) {
			farm_set_action(f, ACTION_RELOAD);
			changed = 1;
		}
	}

	if (changed)
		nft_rulerize();
}

