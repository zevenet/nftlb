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

#ifndef _ELEMENTS_H_
#define _ELEMENTS_H_

#include "policies.h"


struct element {
	struct list_head	list;
	struct policy		*policy;
	char				*data;
	char				*time;
	int					action;
};

void element_s_print(struct policy *p);
struct element * element_lookup_by_name(struct policy *p, const char *data);
int element_set_action(struct element *e, int action);
int element_s_set_action(struct policy *p, int action);
int element_s_delete(struct policy *p);
int element_set_attribute(struct config_pair *c);
int element_pos_actionable(struct config_pair *c);
int element_get_list(struct policy *p);

#endif /* _ELEMENTS_H_ */
