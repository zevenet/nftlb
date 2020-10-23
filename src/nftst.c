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

#include <stdlib.h>

#include "nftst.h"
#include "backends.h"
#include "tools.h"
#include "list.h"

static struct nftst *nftst_create(void)
{
	struct nftst *n = (struct nftst *)malloc(sizeof(struct nftst));
	if (!n) {
		tools_printlog(LOG_ERR, "nft struct memory allocation error");
		return NULL;
	}
	return n;
}

struct nftst *nftst_create_from_farm(struct farm *f)
{
	struct nftst *n = nftst_create();

	if (!n)
		return NULL;

	n->farm = f;
	n->address = NULL;
	n->backend = NULL;
	n->policy = NULL;
	n->action = f->action;
	return n;
}

struct nftst *nftst_create_from_farmaddress(struct farmaddress *fa)
{
	struct nftst *n = nftst_create();

	if (!n)
		return NULL;

	n->farm = fa->farm;
	n->address = fa->address;
	n->backend = NULL;
	n->policy = NULL;
	n->action = fa->action;
	return n;
}

struct nftst *nftst_create_from_address(struct address *a)
{
	struct nftst *n = nftst_create();

	if (!n)
		return NULL;

	n->farm = NULL;
	n->address = a;
	n->backend = NULL;
	n->policy = NULL;
	n->action = a->action;
	return n;
}

struct nftst *nftst_create_from_policy(struct policy *p)
{
	struct nftst *n = nftst_create();

	if (!n)
		return NULL;

	n->farm = NULL;
	n->address = NULL;
	n->backend = NULL;
	n->policy = p;
	n->action = p->action;
	return n;
}

void nftst_delete(struct nftst *n)
{
	if (n)
		free(n);
}

void nftst_set_farm(struct nftst *n, struct farm *f)
{
	n->farm = f;
}

struct farm *nftst_get_farm(struct nftst *n)
{
	return n->farm;
}

void nftst_set_address(struct nftst *n, struct address *a)
{
	n->address = a;
}

struct address *nftst_get_address(struct nftst *n)
{
	return n->address;
}

void nftst_set_backend(struct nftst *n, struct backend *b)
{
	n->backend = b;
}

struct backend *nftst_get_backend(struct nftst *n)
{
	return n->backend;
}

void nftst_set_action(struct nftst *n, int action)
{
	n->action = action;
}

int nftst_get_action(struct nftst *n)
{
	return n->action;
}

void nftst_set_policy(struct nftst *n, struct policy *p)
{
	n->policy = p;
}

struct policy *nftst_get_policy(struct nftst *n)
{
	return n->policy;
}

int nftst_get_family(struct nftst *n)
{
	if (n->address)
		return n->address->family;

	return -1;
}

int nftst_get_proto(struct nftst *n)
{
	if (n->address)
		return n->address->protocol;

	return -1;
}

char *nftst_get_name(struct nftst *n)
{
	if (n->farm)
		return n->farm->name;

	if (n->address)
		return n->address->name;

	return NULL;
}

int nftst_get_chains(struct nftst *n)
{
	if (n->farm)
		return n->farm->nft_chains;

	if (n->address)
		return n->address->nft_chains;

	return -1;
}

void nftst_set_chains(struct nftst *n, int chains)
{
	if (n->farm)
		n->farm->nft_chains = chains;

	if (n->address)
		n->address->nft_chains = chains;

	return;
}

int nftst_actions_done(struct nftst *n)
{
	struct farm *f = n->farm;
	struct address *a = n->address;
	struct backend *b;
	struct farmaddress *fa;

	if (f) {
		list_for_each_entry(b, &f->backends, list)
			b->action = ACTION_NONE;

		list_for_each_entry(fa, &f->addresses, list)
			fa->action = ACTION_NONE;

		f->action = ACTION_NONE;
		f->reload_action = VALUE_RLD_NONE;
		f->policies_action = ACTION_NONE;
	}

	if (a) {
		a->action = ACTION_NONE;
		a->policies_action = ACTION_NONE;
	}

	return 0;
}

int nftst_has_farm(struct nftst *n)
{
	if (n->farm)
		return 1;

	return 0;
}

int nftst_has_address(struct nftst *n)
{
	if (n->address)
		return 1;

	return 0;
}

int nftst_has_backend(struct nftst *n)
{
	if (n->backend)
		return 1;

	return 0;
}

