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

#ifndef _ADDRESSES_H_
#define _ADDRESSES_H_

#include "list.h"
#include "config.h"

struct address {
	struct list_head	list;
	int					action;
	char				*name;
	char				*fqdn;
	char				*iface;
	char				*iethaddr;
	int					ifidx;
	char				*ipaddr;
	char				*ports;
	int					family;
	int					protocol;
	int					verdict;
	char				*logprefix;
	struct list_head	policies;
	int					policies_used;
	int					policies_action;
	int					used;
	int					nft_chains;
};

struct address * address_create(char *name);
int address_changed(struct config_pair *c);
void address_s_print(void);
void address_s_farm_print(struct farm *f);
struct address * address_lookup_by_name(const char *name);
int address_pre_actionable(struct config_pair *c);
int address_pos_actionable(struct config_pair *c);
int address_set_attribute(struct config_pair *c);
int address_set_action(struct address *a, int action);
int address_s_set_action(int action);
int address_s_lookup_policy_action(char *name, int action);
int address_no_port(struct address *a);
int address_no_ipaddr(struct address *a);
void address_print(struct address *a);
int address_set_netinfo(struct address *a);
int address_set_ports(struct address *a, char *new_value);
int address_rulerize(struct address *a);
int address_s_rulerize(void);
int address_needs_policies(struct address *a);
int address_set_protocol(struct address *a, int new_value);
int address_not_used(struct address *a);
int address_delete(struct address *paddress);


#endif /* _ADDRESSES_H_ */
