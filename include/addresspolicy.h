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

#ifndef _ADDRESSPOLICY_H_
#define _ADDRESSPOLICY_H_

#include "addresses.h"
#include "policies.h"

struct addresspolicy {
	struct list_head	list;
	struct address		*address;
	struct policy		*policy;
	int					action;
};


void addresspolicy_s_print(struct address *a);
struct addresspolicy * addresspolicy_lookup_by_name(struct address *a, const char *name);
int addresspolicy_set_attribute(struct config_pair *c);
int addresspolicy_set_action(struct addresspolicy *ap, int action);
int addresspolicy_s_set_action(struct address *a, int action);
int addresspolicy_s_delete(struct address *a);
int addresspolicy_s_lookup_policy_action(struct address *a, char *name, int action);
int addresspolicy_pre_actionable(struct config_pair *c);
int addresspolicy_pos_actionable(struct config_pair *c);

#endif /* _ADDRESSPOLICY_H_ */
