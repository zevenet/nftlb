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

#include "../include/model.h"
#include "../include/config.h"
#include "../include/nft.h"

#define MODEL_NAME_DEF		""
#define MODEL_FQDN_DEF		""
#define MODEL_IFACE_DEF		""
#define MODEL_OFACE_DEF		""
#define MODEL_ETHADDR_DEF	""
#define MODEL_VIRTADDR_DEF	""
#define MODEL_VIRTPORTS_DEF	""
#define MODEL_IPADDR_DEF	""
#define MODEL_PORTS_DEF		""
#define MODEL_FAMILY_DEF	MODEL_VALUE_FAMILY_IPV4
#define MODEL_MODE_DEF		MODEL_VALUE_MODE_SNAT
#define MODEL_PROTO_DEF		MODEL_VALUE_PROTO_TCP
#define MODEL_SCHED_DEF		MODEL_VALUE_SCHED_RR
#define MODEL_WEIGHT_DEF	1
#define MODEL_PRIORITY_DEF	1
#define MODEL_STATE_DEF		MODEL_VALUE_STATE_UP
#define MODEL_ACTION_DEF	MODEL_ACTION_NONE

enum obj_types {
	OBJ_TYPE_FARM,
	OBJ_TYPE_BCK,
};

struct model_obj {
	struct farm		*fptr;
	struct backend		*bptr;
	struct configpair	*cfgp;
};

struct model_obj current_obj;

struct list_head		farms;
int				total_farms = 0;

void model_init(void)
{
	init_list_head(&farms);
}

struct list_head * model_get_farms(void)
{
	return &farms;
}

int model_get_totalfarms(void)
{
	return total_farms;
}

static int set_attr_string(char *src, char **dst)
{
	*dst = (char *)malloc(strlen(src));

	if (!*dst) {
		syslog(LOG_ERR, "Attribute memory allocation error");
		return EXIT_FAILURE;
	}

	sprintf(*dst, "%s", src);

	return EXIT_SUCCESS;
}

static struct farm * model_create_farm(char *name)
{
	struct farm *pfarm = (struct farm *)malloc(sizeof(struct farm));
	if (!pfarm) {
		syslog(LOG_ERR, "Farm memory allocation error");
		return NULL;
	}

	list_add_tail(&pfarm->list, &farms);
	total_farms++;

	set_attr_string(name, &pfarm->name);

	pfarm->fqdn = MODEL_FQDN_DEF;
	pfarm->iface = MODEL_IFACE_DEF;
	pfarm->oface = MODEL_OFACE_DEF;
	pfarm->ethaddr = MODEL_ETHADDR_DEF;
	pfarm->virtaddr = MODEL_VIRTADDR_DEF;
	pfarm->virtports = MODEL_VIRTPORTS_DEF;
	pfarm->family = MODEL_FAMILY_DEF;
	pfarm->mode = MODEL_MODE_DEF;
	pfarm->protocol = MODEL_PROTO_DEF;
	pfarm->scheduler = MODEL_SCHED_DEF;
	pfarm->state = MODEL_STATE_DEF;
	pfarm->action = MODEL_ACTION_START;

	init_list_head(&pfarm->backends);

	pfarm->total_weight = 0;
	pfarm->priority = MODEL_PRIORITY_DEF;
	pfarm->total_bcks = 0;
	pfarm->bcks_available = 0;

	return pfarm;
}

static struct backend * model_create_backend(struct farm *f, char *name)
{
	struct backend *pbck = (struct backend *)malloc(sizeof(struct backend));
	if (!pbck) {
		syslog(LOG_ERR, "Backend memory allocation error");
		return NULL;
	}

	list_add_tail(&pbck->list, &f->backends);
	f->total_bcks++;

	set_attr_string(name, &pbck->name);

	pbck->fqdn = MODEL_FQDN_DEF;
	pbck->ethaddr = MODEL_ETHADDR_DEF;
	pbck->ipaddr = MODEL_IPADDR_DEF;
	pbck->ports = MODEL_PORTS_DEF;
	pbck->weight = MODEL_WEIGHT_DEF;
	pbck->priority = MODEL_PRIORITY_DEF;
	pbck->state = MODEL_STATE_DEF;
	pbck->action = MODEL_ACTION_DEF;

	f->total_weight += MODEL_WEIGHT_DEF;
	f->bcks_available++;

	return pbck;
}

static int del_bck(struct backend *b)
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

static int delete_backends(struct farm *f)
{
	struct backend *pbck, *next;

	list_for_each_entry_safe(pbck, next, &f->backends, list)
		del_bck(pbck);

	f->total_bcks = 0;
	f->bcks_available = 0;
	f->total_weight = 0;

	return EXIT_SUCCESS;
}

static int delete_farm(struct farm *pfarm)
{
	delete_backends(pfarm);
	list_del(&pfarm->list);

	if (pfarm->name && strcmp(pfarm->name, "") != 0)
		free(pfarm->name);
	if (pfarm->fqdn && strcmp(pfarm->fqdn, "") != 0)
		free(pfarm->fqdn);
	if (pfarm->iface && strcmp(pfarm->iface, "") != 0)
		free(pfarm->iface);
	if (pfarm->oface && strcmp(pfarm->oface, "") != 0)
		free(pfarm->oface);
	if (pfarm->ethaddr && strcmp(pfarm->ethaddr, "") != 0)
		free(pfarm->ethaddr);
	if (pfarm->virtaddr && strcmp(pfarm->virtaddr, "") != 0)
		free(pfarm->virtaddr);
	if (pfarm->virtports && strcmp(pfarm->virtports, "") != 0)
		free(pfarm->virtports);

	free(pfarm);
	total_farms--;

	return EXIT_SUCCESS;
}

static int delete_backend(struct farm *f, struct backend *pbck)
{
	if (model_bck_is_available(f, pbck)) {
		f->bcks_available--;
		f->total_weight -= pbck->weight;
	}
	f->total_bcks--;
	farm_action_update(f, MODEL_ACTION_RELOAD);

	del_bck(pbck);

	return EXIT_SUCCESS;
}

static void model_print_backends(struct farm *f)
{
	struct backend *b;

	list_for_each_entry(b, &f->backends, list) {
		syslog(LOG_DEBUG,"Model dump    [backend] ");
		syslog(LOG_DEBUG,"Model dump       [name] %s", b->name);

		if (b->fqdn)
			syslog(LOG_DEBUG,"Model dump       [fqdn] %s", b->fqdn);

		if (b->ipaddr)
			syslog(LOG_DEBUG,"Model dump       [iface] %s", b->ipaddr);

		if (b->ethaddr)
			syslog(LOG_DEBUG,"Model dump       [ethaddr] %s", b->ethaddr);

		if (b->ports)
			syslog(LOG_DEBUG,"Model dump       [ports] %s", b->ports);

		syslog(LOG_DEBUG,"Model dump       [weight] %d", b->weight);
		syslog(LOG_DEBUG,"Model dump       [priority] %d", b->priority);
		syslog(LOG_DEBUG,"Model dump       [state] %s", model_print_state(b->state));
	}
}

void model_print_farms(void)
{
	struct farm *f;

	list_for_each_entry(f, &farms, list) {

		syslog(LOG_DEBUG,"Model dump [farm] ");
		syslog(LOG_DEBUG,"Model dump    [name] %s", f->name);

		if (f->fqdn)
			syslog(LOG_DEBUG,"Model dump    [fqdn] %s", f->fqdn);

		if (f->iface)
			syslog(LOG_DEBUG,"Model dump    [iface] %s", f->iface);

		if (f->oface)
			syslog(LOG_DEBUG,"Model dump    [oface] %s", f->oface);

		if (f->ethaddr)
			syslog(LOG_DEBUG,"Model dump    [ethaddr] %s", f->ethaddr);

		if (f->virtaddr)
			syslog(LOG_DEBUG,"Model dump    [virtaddr] %s", f->virtaddr);

		if (f->virtports)
			syslog(LOG_DEBUG,"Model dump    [virtports] %s", f->virtports);

		syslog(LOG_DEBUG,"Model dump    [family] %s", model_print_family(f->family));
		syslog(LOG_DEBUG,"Model dump    [mode] %s", model_print_mode(f->mode));
		syslog(LOG_DEBUG,"Model dump    [protocol] %s", model_print_proto(f->protocol));
		syslog(LOG_DEBUG,"Model dump    [scheduler] %s", model_print_sched(f->scheduler));
		syslog(LOG_DEBUG,"Model dump    [state] %s", model_print_state(f->state));
		syslog(LOG_DEBUG,"Model dump    [priority] %d", f->priority);
		syslog(LOG_DEBUG,"Model dump    *[total_weight] %d", f->total_weight);
		syslog(LOG_DEBUG,"Model dump    *[total_bcks] %d", f->total_bcks);
		syslog(LOG_DEBUG,"Model dump    *[bcks_available] %d", f->bcks_available);
		syslog(LOG_DEBUG,"Model dump    *[action] %d", f->action);

		if (f->total_bcks != 0)
			model_print_backends(f);
	}
}

struct farm * model_lookup_farm(const char *name)
{
	struct farm *f;

	list_for_each_entry(f, &farms, list) {
		if (strcmp(f->name, name) == 0)
			return f;
	}

	return NULL;
}

struct backend * model_lookup_backend(struct farm *f, const char *name)
{
	struct backend *b;

	list_for_each_entry(b, &f->backends, list) {
		if (strcmp(b->name, name) == 0)
			return b;
	}

	return NULL;
}

void print_pair(struct configpair *cfgp)
{
	syslog(LOG_DEBUG,"pair: %d(level) %d(key) %s(value) %d(value)", cfgp->level, cfgp->key, cfgp->str_value, cfgp->int_value);
}

static int bck_weight_update(struct configpair *cfgp, struct backend *b)
{
	int oldw = b->weight;

	b->weight = cfgp->int_value;

	if (model_bck_is_available(current_obj.fptr, b))
		current_obj.fptr->total_weight += (b->weight-oldw);

	return EXIT_SUCCESS;
}

static int bck_priority_update(struct configpair *cfgp, struct backend *b)
{
	int oldp = b->priority;

	if (model_bck_is_available(current_obj.fptr, b) &&
	    cfgp->int_value > current_obj.fptr->priority) {
		current_obj.fptr->bcks_available--;
		current_obj.fptr->total_weight -= b->weight;
	}

	else if (oldp > current_obj.fptr->priority &&
		 model_bck_is_available(current_obj.fptr, b)) {
		current_obj.fptr->bcks_available++;
		current_obj.fptr->total_weight += b->weight;
	}

	b->priority = cfgp->int_value;

	return EXIT_SUCCESS;
}

static int bck_state_update(struct configpair *cfgp, struct backend *b)
{
	int oldst = b->state;

	if (model_bck_is_available(current_obj.fptr, b) &&
	    cfgp->int_value != MODEL_VALUE_STATE_UP) {
		current_obj.fptr->total_weight -= b->weight;
		current_obj.fptr->bcks_available--;
	}

	else if (oldst != MODEL_VALUE_STATE_UP &&
		 model_bck_is_available(current_obj.fptr, b)) {
		current_obj.fptr->total_weight += b->weight;
		current_obj.fptr->bcks_available++;
	}

	b->state = cfgp->int_value;

	return EXIT_SUCCESS;
}

static int set_b_attribute(struct configpair *cfgp, struct backend *pb)
{
	switch (cfgp->key) {
	case MODEL_KEY_FQDN:
		set_attr_string(cfgp->str_value, &pb->fqdn);
		break;
	case MODEL_KEY_IPADDR:
		set_attr_string(cfgp->str_value, &pb->ipaddr);
		break;
	case MODEL_KEY_ETHADDR:
		set_attr_string(cfgp->str_value, &pb->ethaddr);
		break;
	case MODEL_KEY_PORTS:
		set_attr_string(cfgp->str_value, &pb->ports);
		break;
	case MODEL_KEY_WEIGHT:
		bck_weight_update(cfgp, pb);
		break;
	case MODEL_KEY_PRIORITY:
		bck_priority_update(cfgp, pb);
		break;
	case MODEL_KEY_STATE:
		bck_state_update(cfgp, pb);
		break;
	case MODEL_KEY_ACTION:
		bck_action_update(pb, cfgp->int_value);
		break;
	default:
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int set_backend_attribute(struct configpair *cfgp)
{
	struct backend *pb;

	if (!current_obj.fptr)
		return EXIT_FAILURE;

	switch (cfgp->key) {
	case MODEL_KEY_NAME:
		pb = model_lookup_backend(current_obj.fptr, cfgp->str_value);
		if (!pb) {
			pb = model_create_backend(current_obj.fptr, cfgp->str_value);
			if (!pb)
				return EXIT_FAILURE;
		}
		current_obj.bptr = pb;
		break;
	default:
		if (!current_obj.bptr)
			return EXIT_FAILURE;

		set_b_attribute(cfgp, current_obj.bptr);
	}

	return EXIT_SUCCESS;
}

static int is_srv_change(struct configpair *cfgp)
{
	int key = cfgp->key;

	switch (key) {
	case MODEL_KEY_IFACE:
	case MODEL_KEY_OFACE:
	case MODEL_KEY_FAMILY:
	case MODEL_KEY_ETHADDR:
	case MODEL_KEY_VIRTADDR:
	case MODEL_KEY_VIRTPORTS:
	case MODEL_KEY_PROTO:
	case MODEL_KEY_STATE:
		return 1;
	default:
		return 0;
	}
}

static int farm_state_update(struct configpair *cfgp, struct farm *f)
{
	int oldst = f->state;

	if (oldst != MODEL_VALUE_STATE_UP &&
	    cfgp->int_value == MODEL_VALUE_STATE_UP) {
		farm_action_update(current_obj.fptr, MODEL_ACTION_START);
	}

	if (oldst == MODEL_VALUE_STATE_UP &&
	    cfgp->int_value != MODEL_VALUE_STATE_UP) {
		farm_action_update(current_obj.fptr, MODEL_ACTION_STOP);
	}

	f->state = cfgp->int_value;

	return EXIT_SUCCESS;
}

static int set_f_attribute(struct configpair *cfgp, struct farm *pf)
{
	switch (cfgp->key) {
	case MODEL_KEY_FQDN:
		set_attr_string(cfgp->str_value, &pf->fqdn);
		break;
	case MODEL_KEY_IFACE:
		set_attr_string(cfgp->str_value, &pf->iface);
		break;
	case MODEL_KEY_OFACE:
		set_attr_string(cfgp->str_value, &pf->oface);
		break;
	case MODEL_KEY_FAMILY:
		pf->family = cfgp->int_value;
		break;
	case MODEL_KEY_ETHADDR:
		set_attr_string(cfgp->str_value, &pf->ethaddr);
		break;
	case MODEL_KEY_VIRTADDR:
		set_attr_string(cfgp->str_value, &pf->virtaddr);
		break;
	case MODEL_KEY_VIRTPORTS:
		set_attr_string(cfgp->str_value, &pf->virtports);
		break;
	case MODEL_KEY_MODE:
		pf->mode = cfgp->int_value;
		break;
	case MODEL_KEY_PROTO:
		pf->protocol = cfgp->int_value;
		break;
	case MODEL_KEY_SCHED:
		pf->scheduler = cfgp->int_value;
		break;
	case MODEL_KEY_STATE:
		farm_state_update(cfgp, pf);
		break;
	case MODEL_KEY_ACTION:
		farm_action_update(pf, cfgp->int_value);
		break;
	default:
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int set_farm_attribute(struct configpair *cfgp)
{
	struct farm *pf;
	int restart;

	switch (cfgp->key) {
	case MODEL_KEY_NAME:
		pf = model_lookup_farm(cfgp->str_value);
		if (!pf) {
			pf = model_create_farm(cfgp->str_value);
			if (!pf)
				return EXIT_FAILURE;
		}
		current_obj.fptr = pf;
		break;
	default:
		if (!current_obj.fptr)
			return EXIT_FAILURE;

		restart = is_srv_change(cfgp);
		if (restart && farm_action_update(current_obj.fptr, MODEL_ACTION_STOP))
			nft_rulerize();

		set_f_attribute(cfgp, current_obj.fptr);

		if (restart)
			farm_action_update(current_obj.fptr, MODEL_ACTION_START);
		else
			farm_action_update(current_obj.fptr, MODEL_ACTION_RELOAD);
	}

	return EXIT_SUCCESS;
}

int model_set_obj_attribute(struct configpair *cfgp)
{
	print_pair(cfgp);

	switch (cfgp->level) {
	case MODEL_LEVEL_FARMS:
		set_farm_attribute(cfgp);
		break;
	case MODEL_LEVEL_BCKS:
		set_backend_attribute(cfgp);
		farm_action_update(current_obj.fptr, MODEL_ACTION_RELOAD);
		break;
	default:
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

void model_print_int(char *buf, int value)
{
	sprintf(buf, "%d", value);
}

char * model_print_family(int family)
{
	switch (family) {
	case MODEL_VALUE_FAMILY_IPV4:
		return CONFIG_VALUE_FAMILY_IPV4;
	case MODEL_VALUE_FAMILY_IPV6:
		return CONFIG_VALUE_FAMILY_IPV6;
	case MODEL_VALUE_FAMILY_INET:
		return CONFIG_VALUE_FAMILY_INET;
	default:
		return NULL;
	}
}

char * model_print_mode(int mode)
{
	switch (mode) {
	case MODEL_VALUE_MODE_SNAT:
		return CONFIG_VALUE_MODE_SNAT;
	case MODEL_VALUE_MODE_DNAT:
		return CONFIG_VALUE_MODE_DNAT;
	case MODEL_VALUE_MODE_DSR:
		return CONFIG_VALUE_MODE_DSR;
	default:
		return NULL;
	}
}

char * model_print_proto(int protocol)
{
	switch (protocol) {
	case MODEL_VALUE_PROTO_TCP:
		return CONFIG_VALUE_PROTO_TCP;
	case MODEL_VALUE_PROTO_UDP:
		return CONFIG_VALUE_PROTO_UDP;
	case MODEL_VALUE_PROTO_SCTP:
		return CONFIG_VALUE_PROTO_SCTP;
	case MODEL_VALUE_PROTO_ALL:
		return CONFIG_VALUE_PROTO_ALL;
	default:
		return NULL;
	}
}

char * model_print_sched(int scheduler)
{
	switch (scheduler) {
	case MODEL_VALUE_SCHED_RR:
		return CONFIG_VALUE_SCHED_RR;
	case MODEL_VALUE_SCHED_WEIGHT:
		return CONFIG_VALUE_SCHED_WEIGHT;
	case MODEL_VALUE_SCHED_HASH:
		return CONFIG_VALUE_SCHED_HASH;
	case MODEL_VALUE_SCHED_SYMHASH:
		return CONFIG_VALUE_SCHED_SYMHASH;
	default:
		return NULL;
	}
}

char * model_print_state(int state)
{
	switch (state) {
	case MODEL_VALUE_STATE_UP:
		return CONFIG_VALUE_STATE_UP;
	case MODEL_VALUE_STATE_DOWN:
		return CONFIG_VALUE_STATE_DOWN;
	case MODEL_VALUE_STATE_OFF:
		return CONFIG_VALUE_STATE_OFF;
	default:
		return NULL;
	}
}

int model_bck_is_available(struct farm *f, struct backend *b)
{
	return (b->state == MODEL_VALUE_STATE_UP) && (b->priority <= f->priority);
}

int farm_action_update(struct farm *f, int action)
{
	if (action == MODEL_ACTION_DELETE) {
		delete_farm(f);
		return 1;
	}

	if (f->action > action) {
		f->action = action;
		return 1;
	}

	return 0;
}

int bck_action_update(struct backend *b, int action)
{
	if (action == MODEL_ACTION_DELETE) {
		delete_backend(current_obj.fptr, b);
		return 1;
	}

	if (b->action > action) {
		b->action = action;
		return 1;
	}

	return 0;
}

int farms_action_update(int action)
{
	struct farm *f, *next;

	list_for_each_entry_safe(f, next, &farms, list)
		farm_action_update(f, action);

	return EXIT_SUCCESS;
}

int backends_action_update(struct farm *f, int action)
{
	struct backend *b, *next;
	list_for_each_entry_safe(b, next, &f->backends, list)
		bck_action_update(b, action);

	return EXIT_SUCCESS;
}
