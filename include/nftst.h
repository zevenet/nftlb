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

#ifndef _NFTST_H_
#define _NFTST_H_

#include "farms.h"
#include "addresses.h"
#include "farmaddress.h"
#include "backends.h"
#include "policies.h"

struct nftst {
	struct farm *farm;
	struct address *address;
	struct backend *backend;
	struct policy *policy;
	int action;
};

struct nftst *nftst_create_from_farm(struct farm *f);
struct nftst *nftst_create_from_farmaddress(struct farmaddress *fa);
struct nftst *nftst_create_from_address(struct address *a);
struct nftst *nftst_create_from_policy(struct policy *p);
void nftst_delete(struct nftst *n);
void nftst_set_farm(struct nftst *n, struct farm *f);
struct farm *nftst_get_farm(struct nftst *n);
void nftst_set_address(struct nftst *n, struct address *a);
struct address *nftst_get_address(struct nftst *n);
void nftst_set_backend(struct nftst *n, struct backend *b);
struct backend *nftst_get_backend(struct nftst *n);
void nftst_set_action(struct nftst *n, int action);
int nftst_get_action(struct nftst *n);
void nftst_set_policy(struct nftst *n, struct policy *p);
struct policy *nftst_get_policy(struct nftst *n);
char *nftst_get_name(struct nftst *n);
int nftst_get_family(struct nftst *n);
int nftst_get_proto(struct nftst *n);
int nftst_get_chains(struct nftst *n);
void nftst_set_chains(struct nftst *n, int chains);
int nftst_actions_done(struct nftst *n);
int nftst_has_farm(struct nftst *n);
int nftst_has_address(struct nftst *n);
int nftst_has_backend(struct nftst *n);

#endif /* _NFTST_H_ */
