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
#include <net/if.h>

#include "addresses.h"
#include "farms.h"
#include "backends.h"
#include "policies.h"
#include "addresspolicy.h"
#include "objects.h"
#include "network.h"
#include "config.h"
#include "nft.h"
#include "tools.h"


struct address * address_create(char *name)
{
	struct list_head *addresses = obj_get_addresses();

	struct address *paddress = (struct address *)malloc(sizeof(struct address));
	if (!paddress) {
		tools_printlog(LOG_ERR, "Address memory allocation error");
		return NULL;
	}

	obj_set_attribute_string(name, &paddress->name);

	paddress->fqdn = DEFAULT_FQDN;
	paddress->iface = DEFAULT_IFNAME;
	paddress->iethaddr = DEFAULT_ETHADDR;
	paddress->ifidx = DEFAULT_IFIDX;
	paddress->ipaddr = DEFAULT_VIRTADDR;
	paddress->ports = DEFAULT_VIRTPORTS;
	paddress->family = DEFAULT_FAMILY;
	paddress->protocol = DEFAULT_PROTO;
	paddress->action = DEFAULT_ACTION;
	paddress->verdict = DEFAULT_VERDICT;
	paddress->logprefix = DEFAULT_LOG_LOGPREFIX_ADDRESS;
	paddress->logrtlimit = DEFAULT_LOG_RTLIMIT;
	paddress->logrtlimit_unit = DEFAULT_LOG_RTLIMIT_UNIT;
	paddress->policies_action = ACTION_NONE;

	init_list_head(&paddress->policies);

	paddress->policies_used = 0;
	paddress->used = 0;
	paddress->nft_chains = 0;
	paddress->nports = 0;

	list_add_tail(&paddress->list, addresses);
	obj_set_total_addresses(obj_get_total_addresses() + 1);

	return paddress;
}

int address_delete(struct address *paddress)
{
	if (!paddress)
		return 0;

	tools_printlog(LOG_DEBUG, "%s():%d: deleting address %s",
				   __FUNCTION__, __LINE__, paddress->name);

	list_del(&paddress->list);

	if (paddress->name && strcmp(paddress->name, "") != 0)
		free(paddress->name);
	if (paddress->fqdn && strcmp(paddress->fqdn, "") != 0)
		free(paddress->fqdn);
	if (paddress->iface && strcmp(paddress->iface, "") != 0)
		free(paddress->iface);
	if (paddress->iethaddr && strcmp(paddress->iethaddr, "") != 0)
		free(paddress->iethaddr);
	if (paddress->ipaddr && strcmp(paddress->ipaddr, "") != 0)
		free(paddress->ipaddr);
	if (paddress->ports && strcmp(paddress->ports, "") != 0)
		free(paddress->ports);
	if (paddress->logprefix && strcmp(paddress->logprefix, DEFAULT_LOG_LOGPREFIX_ADDRESS) != 0)
		free(paddress->logprefix);

	free(paddress);
	obj_set_total_addresses(obj_get_total_addresses() - 1);

	return 0;
}

static void address_get_range_ports(const char *ptr, int *first, int *last)
{
	sscanf(ptr, "%d-%d[^,]", first, last);
}

int address_search_array_port(struct address *a, int port)
{
	if (a->port_list[port-1])
		return 1;

	return 0;
}

static void address_add_array_port(struct address *a, int port)
{
	if (!a->port_list[port-1]) {
		a->nports++;
		a->port_list[port-1] = 1;
	}
}

static int address_get_array_ports(struct address *a)
{
	int index = 0;
	char *ptr;
	int iport, new;
	int last = 0;

	a->nports = 0;
	memset(a->port_list, 0, NFTLB_MAX_PORTS * sizeof(int));
	ptr = a->ports;
	while (ptr != NULL && *ptr != '\0') {
		last = new = 0;
		address_get_range_ports(ptr, &new, &last);
		if (last == 0)
			last = new;
		if (new > last)
			goto next;

		for (iport = new; iport <= last; iport++)
			address_add_array_port(a, iport);

next:
		ptr = strchr(ptr, ',');
		if (ptr != NULL)
			ptr++;
	}

	return index;
}

int address_set_ports(struct address *a, char *new_value)
{
	if (strcmp(new_value, "0") != 0) {
		if (strcmp(a->ports, DEFAULT_VIRTPORTS) != 0)
			free(a->ports);
		obj_set_attribute_string(new_value, &a->ports);
	}

	if (strcmp(new_value, "") == 0)
		a->protocol = VALUE_PROTO_ALL;

	address_get_array_ports(a);

	return 0;
}

void address_print(struct address *a)
{
	char buf[100] = {};

	tools_printlog(LOG_DEBUG," [address] ");
	tools_printlog(LOG_DEBUG,"    [%s] %s", CONFIG_KEY_NAME, a->name);

	if (a->fqdn)
		tools_printlog(LOG_DEBUG,"    [%s] %s", CONFIG_KEY_FQDN, a->fqdn);

	if (a->iface)
		tools_printlog(LOG_DEBUG,"    [%s] %s", CONFIG_KEY_IFACE, a->iface);

	if (a->iethaddr)
		tools_printlog(LOG_DEBUG,"    [%s] %s", CONFIG_KEY_IETHADDR, a->iethaddr);

	tools_printlog(LOG_DEBUG,"   *[ifidx] %d", a->ifidx);

	if (a->ipaddr)
		tools_printlog(LOG_DEBUG,"    [%s] %s", CONFIG_KEY_IPADDR, a->ipaddr);

	if (a->ports)
		tools_printlog(LOG_DEBUG,"    [%s] %s", CONFIG_KEY_PORTS, a->ports);

	tools_printlog(LOG_DEBUG,"    [%s] %s", CONFIG_KEY_FAMILY, obj_print_family(a->family));
	tools_printlog(LOG_DEBUG,"    [%s] %s", CONFIG_KEY_PROTO, obj_print_proto(a->protocol));

	obj_print_verdict(a->verdict, (char *)buf);
	tools_printlog(LOG_DEBUG,"    [%s] %s", CONFIG_KEY_VERDICT, buf);

	if (a->logprefix)
		tools_printlog(LOG_DEBUG,"    [%s] %s", CONFIG_KEY_LOGPREFIX, a->logprefix);
	obj_print_rtlimit(buf, a->logrtlimit, a->logrtlimit_unit);
	tools_printlog(LOG_DEBUG,"    [%s] %s", CONFIG_KEY_LOG_RTLIMIT, buf);

	tools_printlog(LOG_DEBUG,"   *[used] %d", a->used);
	tools_printlog(LOG_DEBUG,"   *[%s] %d", CONFIG_KEY_ACTION, a->action);
	tools_printlog(LOG_DEBUG,"   *[policies_action] %d", a->policies_action);
	tools_printlog(LOG_DEBUG,"   *[nft_chains] %x", a->nft_chains);

	if (a->policies_used > 0)
		addresspolicy_s_print(a);
}

static int address_set_iface_info(struct address *a)
{
	unsigned char ether[ETH_HW_ADDR_LEN];
	char streth[ETH_HW_STR_LEN] = {};
	char if_str[IFNAMSIZ];
	int if_index;
	int ret = 0;

	tools_printlog(LOG_DEBUG, "%s():%d: address %s set interface info for interface", __FUNCTION__, __LINE__, a->name);

	if (a->iface && strcmp(a->iface, IFACE_LOOPBACK) == 0) {
		tools_printlog(LOG_DEBUG, "%s():%d: address %s doesn't require input netinfo, loopback interface", __FUNCTION__, __LINE__, a->name);
		a->ifidx = 0;
		return 0;
	}

	ret = net_get_local_ifname_per_vip(a->ipaddr, if_str);

	if (ret != 0) {
		tools_printlog(LOG_ERR, "%s():%d: inbound interface not found with IP %s by address %s", __FUNCTION__, __LINE__, a->ipaddr, a->name);
		return -1;
	}

	if (a->iface)
		free(a->iface);
	obj_set_attribute_string(if_str, &a->iface);
	net_strim_netface(a->iface);

	if_index = if_nametoindex(a->iface);

	if (if_index == 0) {
		tools_printlog(LOG_ERR, "%s():%d: index of the inbound interface %s in address %s not found", __FUNCTION__, __LINE__, a->iface, a->name);
		return -1;
	}

	a->ifidx = if_index;

	net_get_local_ifinfo((unsigned char **)&ether, a->iface);
	net_strim_netface(a->iface);

	sprintf(streth, "%02x:%02x:%02x:%02x:%02x:%02x", ether[0],
		ether[1], ether[2], ether[3], ether[4], ether[5]);

	if (a->iethaddr)
		free(a->iethaddr);
	obj_set_attribute_string(streth, &a->iethaddr);

	return 0;
}

int address_set_protocol(struct address *a, int new_value)
{
	int old_value = a->protocol;

	syslog(LOG_DEBUG, "%s():%d: address %s old protocol %d new protocol %d", __FUNCTION__, __LINE__, a->name, old_value, new_value);

	a->protocol = new_value;
	return PARSER_OK;
}

static int address_set_verdict(struct address *a, int new_value)
{
	int old_value = a->verdict;

	tools_printlog(LOG_DEBUG, "%s():%d: address %s old verdict %d new verdict %d", __FUNCTION__, __LINE__, a->name, old_value, new_value);

	if (new_value == VALUE_VERDICT_NONE)
		return 1;

	a->verdict = new_value;

	return 0;
}

int address_set_netinfo(struct address *a)
{
	tools_printlog(LOG_DEBUG, "%s():%d: address %s", __FUNCTION__, __LINE__, a->name);

	address_set_iface_info(a);
	farm_s_set_oface_info(a);

	return 0;
}

int address_changed(struct config_pair *c)
{
	struct address *a = obj_get_current_address();

	if (!a)
		return -1;

	tools_printlog(LOG_DEBUG, "%s():%d: address %s with param %d", __FUNCTION__, __LINE__, a->name, c->key);

	switch (c->key) {
	case KEY_NAME:
		return 1;
		break;
	case KEY_FQDN:
		return !obj_equ_attribute_string(a->fqdn, c->str_value);
		break;
	case KEY_IFACE:
		return !obj_equ_attribute_string(a->iface, c->str_value);
		break;
	case KEY_IETHADDR:
		return !obj_equ_attribute_string(a->iethaddr, c->str_value);
		break;
	case KEY_FAMILY:
		return !obj_equ_attribute_int(a->family, c->int_value);
		break;
	case KEY_IPADDR:
		return !obj_equ_attribute_string(a->ipaddr, c->str_value);
		break;
	case KEY_PORTS:
		return !obj_equ_attribute_string(a->ports, c->str_value);
		break;
	case KEY_PROTO:
		return !obj_equ_attribute_int(a->protocol, c->int_value);
		break;
	case KEY_VERDICT:
		return !obj_equ_attribute_int(a->verdict, c->int_value);
		break;
	case KEY_LOGPREFIX:
		return !obj_equ_attribute_string(a->logprefix, c->str_value);
		break;
	case KEY_ACTION:
		return !obj_equ_attribute_int(a->action, c->int_value);
		break;
	default:
		break;
	}

	return 0;
}

void address_s_print(void)
{
	struct list_head *addresses = obj_get_addresses();
	struct address *a;

	list_for_each_entry(a, addresses, list)
		address_print(a);
}

struct address * address_lookup_by_name(const char *name)
{
	struct list_head *addresses = obj_get_addresses();
	struct address *a;

	list_for_each_entry(a, addresses, list) {
		if (strcmp(a->name, name) == 0)
			return a;
	}

	return NULL;
}

int address_pre_actionable(struct config_pair *c)
{
	struct address *a = obj_get_current_address();

	if (!a)
		return -1;

	return ACTION_START;
}

int address_pos_actionable(struct config_pair *c)
{
	struct address *a = obj_get_current_address();

	if (!a)
		return -1;

	return 0;
}

int address_set_attribute(struct config_pair *c)
{
	struct address *a = obj_get_current_address();
	int ret = PARSER_FAILED;

	if (c->key != KEY_NAME && !a) {
		tools_printlog(LOG_INFO, "%s():%d: address UNKNOWN", __FUNCTION__, __LINE__);
		return PARSER_OBJ_UNKNOWN;
	}

	switch (c->key) {
	case KEY_NAME:
		a = address_lookup_by_name(c->str_value);
		if (!a) {
			a = address_create(c->str_value);
			if (!a)
				return PARSER_FAILED;
		}
		obj_set_current_address(a);
		ret = PARSER_OK;
		break;
	case KEY_FQDN:
		if (strcmp(a->fqdn, DEFAULT_FQDN) != 0)
			free(a->fqdn);
		ret = obj_set_attribute_string(c->str_value, &a->fqdn);
		break;
	case KEY_IFACE:
		if (a->iface)
			free(a->iface);
		ret = obj_set_attribute_string(c->str_value, &a->iface);
		net_strim_netface(a->iface);
		break;
	case KEY_FAMILY:
		a->family = c->int_value;
		ret = PARSER_OK;
		break;
	case KEY_ETHADDR:
		if (a->iethaddr)
			free(a->iethaddr);
		ret = obj_set_attribute_string(c->str_value, &a->iethaddr);
		break;
	case KEY_IETHADDR:
		if (a->iethaddr)
			free(a->iethaddr);
		ret = obj_set_attribute_string(c->str_value, &a->iethaddr);
		address_set_netinfo(a);
		break;
	case KEY_IPADDR:
		if (strcmp(a->ipaddr, DEFAULT_VIRTADDR) != 0)
			free(a->ipaddr);
		ret = obj_set_attribute_string(c->str_value, &a->ipaddr);
		address_set_netinfo(a);
		break;
	case KEY_PORTS:
		ret = address_set_ports(a, c->str_value);
		break;
	case KEY_PROTO:
		ret = address_set_protocol(a, c->int_value);
		break;
	case KEY_VERDICT:
		if (!address_set_verdict(a, c->int_value))
			return PARSER_OK;
		break;
	case KEY_LOGPREFIX:
		if (strcmp(a->logprefix, DEFAULT_LOG_LOGPREFIX) != 0)
			free(a->logprefix);
		ret = obj_set_attribute_string(c->str_value, &a->logprefix);
		break;
	case KEY_ACTION:
		ret = address_set_action(a, c->int_value);
		break;
	case KEY_USED:
		ret = PARSER_OK;
		break;
	default:
		return PARSER_STRUCT_FAILED;
	}

	return ret;
}

int address_not_used(struct address *a)
{
	return (!a->policies_used && !a->used);
}

int address_set_action(struct address *a, int action)
{
	tools_printlog(LOG_DEBUG, "%s():%d: address %s action is %d - new action %d", __FUNCTION__, __LINE__, a->name, a->action, action);

	if (a->action == action)
		return 0;

	if (action == ACTION_DELETE) {
		if (!farm_s_lookup_address_action(a->name, action))
			address_delete(a);
		return 1;
	}

	if (action == ACTION_STOP)
		farm_s_lookup_address_action(a->name, action);

	if (a->action > action)
		a->action = action;
	return 1;
}

int address_s_set_action(int action)
{
	struct list_head *addresses = obj_get_addresses();
	struct address *a, *next;

	list_for_each_entry_safe(a, next, addresses, list)
		address_set_action(a, action);

	return 0;
}

int address_no_port(struct address *a)
{
	if (obj_equ_attribute_string(a->ports, DEFAULT_VIRTPORTS))
		return 1;
	return 0;
}

int address_no_ipaddr(struct address *a)
{
	if (obj_equ_attribute_string(a->ipaddr, DEFAULT_VIRTADDR))
		return 1;
	return 0;
}

int address_rulerize(struct address *a)
{
	tools_printlog(LOG_DEBUG, "%s():%d: rulerize address %s", __FUNCTION__, __LINE__, a->name);

	address_print(a);

	if (a->used) {
		tools_printlog(LOG_INFO, "%s():%d: address %s won't be rulerized", __FUNCTION__, __LINE__, a->name);
		return 0;
	}

	return nft_rulerize_address(a);
}

int address_s_rulerize(void)
{
	struct list_head *addresses = obj_get_addresses();
	struct address *a, *next;
	int ret = 0;
	int output = 0;

	tools_printlog(LOG_DEBUG, "%s():%d: rulerize addresses", __FUNCTION__, __LINE__);

	list_for_each_entry_safe(a, next, addresses, list) {
		ret = address_rulerize(a);
		output = output || ret;
	}

	return output;
}

int address_needs_policies(struct address *a)
{
	return (a->policies_used > 0) || (a->policies_action != ACTION_NONE);
}

int address_s_lookup_policy_action(char *name, int action)
{
	struct list_head *addresses = obj_get_addresses();
	struct address *a, *next;

	tools_printlog(LOG_DEBUG, "%s():%d: name %s action %d", __FUNCTION__, __LINE__, name, action);

	list_for_each_entry_safe(a, next, addresses, list)
		addresspolicy_s_lookup_policy_action(a, name, action);

	return 0;
}

int address_validate_iface(struct address *a)
{
	tools_printlog(LOG_DEBUG, "%s():%d: validating inbound address interface of %s", __FUNCTION__, __LINE__, a->name);
	if (!a || !a->iface || obj_equ_attribute_string(a->iface, ""))
		return 1;
	return 0;
}

int address_validate_iether(struct address *a)
{
	tools_printlog(LOG_DEBUG, "%s():%d: validating inbound address ether of %s", __FUNCTION__, __LINE__, a->name);
	if (!a || !a->iethaddr || obj_equ_attribute_string(a->iethaddr, ""))
		return 1;
	return 0;
}
