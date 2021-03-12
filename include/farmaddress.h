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

#ifndef _FARMADDRESS_H_
#define _FARMADDRESS_H_

#include "farms.h"
#include "addresses.h"

struct farmaddress {
	struct list_head	list;
	struct farm			*farm;
	struct address		*address;
	int					action;
};

void farmaddress_s_print(struct farm *f);
struct farmaddress * farmaddress_lookup_by_name(struct farm *f, const char *name);
int farmaddress_s_lookup_address_action(struct farm *f, char *name, int action);
int farmaddress_set_attribute(struct config_pair *c);
int farmaddress_set_action(struct farmaddress *fa, int action);
int farmaddress_s_set_action(struct farm *f, int action);
int farmaddress_s_delete(struct farm *f);
int farmaddress_pre_actionable(struct config_pair *c);
int farmaddress_pos_actionable(struct config_pair *c);
int farmaddress_s_validate_iface(struct farm *f);
int farmaddress_s_validate_oface(struct farm *f);
int farmaddress_s_set_attribute(struct farm *f, struct config_pair *c);
int farmaddress_create_default(struct config_pair *c);
struct farmaddress * farmaddress_get_first(struct farm *f);
int farmaddress_s_validate_helper(struct farm *f, int new_value);
int farmaddress_rename_default(struct config_pair *c);

#endif /* _FARMADDRESS_H_ */
