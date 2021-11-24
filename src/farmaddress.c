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

#include "farmaddress.h"
#include "addresses.h"
#include "farms.h"
#include "objects.h"
#include "network.h"
#include "tools.h"


static struct farmaddress * farmaddress_create(struct farm *f, struct address *a)
{
	struct farmaddress *fa = (struct farmaddress *)malloc(sizeof(struct farmaddress));
	if (!fa) {
		tools_printlog(LOG_ERR, "Farm address memory allocation error");
		return NULL;
	}

	fa->farm = f;
	fa->address = a;
	fa->action = DEFAULT_ACTION;
	f->addresses_used++;

	list_add_tail(&fa->list, &f->addresses);
	a->used++;

	if (f->policies_used)
		f->policies_action = ACTION_START;

	return fa;
}

static int farmaddress_delete(struct farmaddress *fa)
{
	if (!fa)
		return 0;

	list_del(&fa->list);

	if (fa->farm->addresses_used > 0)
		fa->farm->addresses_used--;

	if (fa->address->used > 0)
		fa->address->used--;

	free(fa);

	return 0;
}

void farmaddress_s_print(struct farm *f)
{
	struct farmaddress *fa;
	struct address *a;

	list_for_each_entry(fa, &f->addresses, list) {
		a = fa->address;

		tools_printlog(LOG_DEBUG,"    [address] ");
		tools_printlog(LOG_DEBUG,"       [%s] %s", CONFIG_KEY_NAME, fa->address->name);
		tools_printlog(LOG_DEBUG,"      *[%s] %d", CONFIG_KEY_ACTION, fa->action);

		if (a->iface)
			tools_printlog(LOG_DEBUG,"       [%s] %s", CONFIG_KEY_IFACE, a->iface);

		if (a->iethaddr)
			tools_printlog(LOG_DEBUG,"       [%s] %s", CONFIG_KEY_IETHADDR, a->iethaddr);

		tools_printlog(LOG_DEBUG,"      *[ifidx] %d", a->ifidx);

		if (a->ipaddr)
			tools_printlog(LOG_DEBUG,"       [%s] %s", CONFIG_KEY_IPADDR, a->ipaddr);

		if (a->ports)
			tools_printlog(LOG_DEBUG,"       [%s] %s", CONFIG_KEY_PORTS, a->ports);

		tools_printlog(LOG_DEBUG,"       [%s] %s", CONFIG_KEY_FAMILY, obj_print_family(a->family));
		tools_printlog(LOG_DEBUG,"       [%s] %s", CONFIG_KEY_PROTO, obj_print_proto(a->protocol));
		tools_printlog(LOG_DEBUG,"      *[policies_action] %d", a->policies_action);
	}
}

struct farmaddress * farmaddress_lookup_by_name(struct farm *f, const char *name)
{
	struct farmaddress *fa;

	list_for_each_entry(fa, &f->addresses, list) {
		if (strcmp(fa->address->name, name) == 0)
			return fa;
	}

	return NULL;
}

int farmaddress_set_action(struct farmaddress *fa, int action)
{
	struct farm *f = fa->farm;
	struct address *a = fa->address;
	tools_printlog(LOG_DEBUG, "%s():%d: farm %s address %s action %d", __FUNCTION__, __LINE__, fa->farm->name, fa->address->ipaddr, action);

	if (action == ACTION_DELETE) {
		farmaddress_delete(fa);
		if (address_not_used(a))
			address_delete(a);
		return 1;
	}

	if (fa->action != action) {
		fa->action = action;

		if (action != ACTION_RELOAD && f->policies_used) {
			f->policies_action = action;
			fa->address->policies_action = action;
		}

		return 1;
	}

	return 0;
}

int farmaddress_s_set_action(struct farm *f, int action)
{
	struct farmaddress *fa, *next;

	tools_printlog(LOG_DEBUG, "%s():%d: farm %s", __FUNCTION__, __LINE__, f->name);

	list_for_each_entry_safe(fa, next, &f->addresses, list)
		if (fa->action > action)
			farmaddress_set_action(fa, action);

	return 0;
}

int farmaddress_s_delete(struct farm *f)
{
	struct farmaddress *fa, *next;

	list_for_each_entry_safe(fa, next, &f->addresses, list)
		farmaddress_delete(fa);

	return 0;
}

int farmaddress_s_lookup_address_action(struct farm *f, char *name, int action)
{
	struct farmaddress *fa;
	int ret = 0;

	fa = farmaddress_lookup_by_name(f, name);
	if (fa)
		ret = farmaddress_set_action(fa, action);

	if (ret)
		f->action = ACTION_RELOAD;

	return ret;
}

int farmaddress_create_default(struct config_pair *c)
{
	char fa_name[300];

	struct farm *f = obj_get_current_farm();
	struct farmaddress *fa;
	struct address *a;

	if (!f)
		return 1;

	sprintf(fa_name, "%s-addr", f->name);
	a = address_lookup_by_name(fa_name);
	if (!a) {
		a = address_create(fa_name);
		if (!a)
			return -1;
		obj_set_current_address(a);
	}
	fa = farmaddress_lookup_by_name(f, fa_name);
	if (!fa)
		fa = farmaddress_create(f, a);
	obj_set_current_farmaddress(fa);

	return 0;
}

int farmaddress_set_attribute(struct config_pair *c)
{
	struct farmaddress *fa = obj_get_current_farmaddress();
	struct farm *f = obj_get_current_farm();
	struct address *a;

	if (!f) {
		tools_printlog(LOG_INFO, "%s():%d: farm UNKNOWN", __FUNCTION__, __LINE__);
		return PARSER_OBJ_UNKNOWN;
	}

	switch (c->key) {
	case KEY_NAME:
		a = address_lookup_by_name(c->str_value);
		if (!a) {
			a = address_create(c->str_value);
			if (!a)
				return -1;
		}
		obj_set_current_address(a);
		fa = farmaddress_lookup_by_name(f, c->str_value);
		if (fa)
			return 0;
		fa = farmaddress_create(f, a);
		obj_set_current_farmaddress(fa);
		return PARSER_OK;
		break;
	default:
		return address_set_attribute(c);
	}

	return PARSER_OK;
}

int farmaddress_pre_actionable(struct config_pair *c)
{
	struct farm *f = obj_get_current_farm();

	if (!f)
		return -1;

	tools_printlog(LOG_DEBUG, "%s():%d: pre actionable farm address for farm %s action %d", __FUNCTION__, __LINE__, f->name, f->action);

	return farm_set_action(f, ACTION_RELOAD);
}

int farmaddress_pos_actionable(struct config_pair *c)
{
	struct farmaddress *fa = obj_get_current_farmaddress();
	struct farm *f = obj_get_current_farm();

	if (!fa || !f)
		return -1;

	tools_printlog(LOG_DEBUG, "%s():%d: pos actionable farm address %s for farm %s with param %d", __FUNCTION__, __LINE__, fa->address->name, f->name, c->key);

	return farm_set_action(f, ACTION_RELOAD);
}

int farmaddress_s_validate_iface(struct farm *f)
{
	struct farmaddress *fa;
	int anyvalid = 0;

	tools_printlog(LOG_DEBUG, "%s():%d: validating input farm addresses interface of %s", __FUNCTION__, __LINE__, f->name);

	list_for_each_entry(fa, &f->addresses, list) {
		if (!fa->address || !fa->address->iface || obj_equ_attribute_string(fa->address->iface, "") ||
			!fa->address->iethaddr || obj_equ_attribute_string(fa->address->iethaddr, "")) {
			fa->action = ACTION_NONE;
			continue;
		}
		anyvalid |= 1;
	}

	return anyvalid;
}

int farmaddress_s_validate_helper(struct farm *f, int new_value)
{
	struct farmaddress *fa;

	tools_printlog(LOG_DEBUG, "%s():%d: validating input farm address proto for new helper of %s", __FUNCTION__, __LINE__, f->name);

	if (new_value == VALUE_HELPER_NONE)
		return PARSER_OK;

	list_for_each_entry(fa, &f->addresses, list) {
		if ((new_value == VALUE_HELPER_FTP || new_value == VALUE_HELPER_PPTP) && (fa->address->protocol != VALUE_PROTO_TCP))
			return PARSER_FAILED;

		if ((new_value == VALUE_HELPER_TFTP || new_value == VALUE_HELPER_SNMP) && (fa->address->protocol != VALUE_PROTO_UDP))
			return PARSER_FAILED;

		if (new_value == VALUE_HELPER_SIP && fa->address->protocol == VALUE_PROTO_SCTP)
			return PARSER_FAILED;
	}

	return PARSER_OK;
}

int farmaddress_s_set_attribute(struct farm *f, struct config_pair *c)
{
	struct farmaddress *fa;

	list_for_each_entry(fa, &f->addresses, list)
		farmaddress_set_attribute(c);

	return 1;
}

struct farmaddress * farmaddress_get_first(struct farm *f)
{
	if (list_empty(&f->addresses))
		return NULL;

	return list_first_entry(&f->addresses, struct farmaddress, list);
}

int farmaddress_rename_default(struct config_pair *c)
{
	char fa_name[300];

	struct farm *f = obj_get_current_farm();
	struct farmaddress *fa;
	struct address *a;

	if (!f)
		return 1;

	sprintf(fa_name, "%s-addr", f->name);
	a = address_lookup_by_name(fa_name);
	if (!a)
		return 1;

	fa = farmaddress_lookup_by_name(f, fa_name);
	if (!fa)
		return 1;

	free(a->name);
	sprintf(fa_name, "%s-addr", c->str_value);
	obj_set_attribute_string(fa_name, &a->name);

	return 0;
}
