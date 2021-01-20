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

#include "farms.h"
#include "backends.h"
#include "sessions.h"
#include "farmpolicy.h"
#include "farmaddress.h"
#include "objects.h"
#include "config.h"
#include "nft.h"
#include "network.h"
#include "tools.h"
#include "nftst.h"


static struct farm * farm_create(char *name)
{
	struct list_head *farms = obj_get_farms();

	struct farm *pfarm = (struct farm *)malloc(sizeof(struct farm));
	if (!pfarm) {
		tools_printlog(LOG_ERR, "Farm memory allocation error");
		return NULL;
	}

	obj_set_attribute_string(name, &pfarm->name);

	pfarm->fqdn = DEFAULT_FQDN;
	pfarm->oface = DEFAULT_IFNAME;
	pfarm->oethaddr = DEFAULT_ETHADDR;
	pfarm->ofidx = DEFAULT_IFIDX;
	pfarm->srcaddr = DEFAULT_SRCADDR;
	pfarm->mode = DEFAULT_MODE;
	pfarm->responsettl = DEFAULT_RESPONSETTL;
	pfarm->scheduler = DEFAULT_SCHED;
	pfarm->schedparam = DEFAULT_SCHEDPARAM;
	pfarm->persistence = DEFAULT_PERSIST;
	pfarm->persistttl = DEFAULT_PERSISTTM;
	pfarm->helper = DEFAULT_HELPER;
	pfarm->log = DEFAULT_LOG;
	pfarm->logprefix = DEFAULT_LOG_LOGPREFIX;
	pfarm->mark = DEFAULT_MARK;
	pfarm->state = DEFAULT_FARM_STATE;
	pfarm->action = DEFAULT_ACTION;
	pfarm->reload_action = VALUE_RLD_NONE;

	init_list_head(&pfarm->backends);
	init_list_head(&pfarm->policies);

	pfarm->total_weight = 0;
	pfarm->priority = DEFAULT_PRIORITY;
	pfarm->newrtlimit = DEFAULT_NEWRTLIMIT;
	pfarm->newrtlimitbst = DEFAULT_RTLIMITBURST;
	pfarm->newrtlimit_logprefix = DEFAULT_LOGPREFIX;
	pfarm->rstrtlimit = DEFAULT_RSTRTLIMIT;
	pfarm->rstrtlimitbst = DEFAULT_RTLIMITBURST;
	pfarm->rstrtlimit_logprefix = DEFAULT_LOGPREFIX;
	pfarm->estconnlimit = DEFAULT_ESTCONNLIMIT;
	pfarm->estconnlimit_logprefix = DEFAULT_LOGPREFIX;
	pfarm->tcpstrict = DEFAULT_TCPSTRICT;
	pfarm->tcpstrict_logprefix = DEFAULT_LOGPREFIX;
	pfarm->queue = DEFAULT_QUEUE;
	pfarm->flow_offload = DEFAULT_FLOWOFFLOAD;
	pfarm->intra_connect = DEFAULT_INTRACONNECT;

	pfarm->total_bcks = 0;
	pfarm->bcks_available = 0;
	pfarm->bcks_usable = 0;
	pfarm->bcks_have_port = 0;
	pfarm->bcks_have_srcaddr = 0;
	pfarm->bcks_have_if = 0;
	pfarm->policies_used = 0;
	pfarm->policies_action = ACTION_NONE;
	pfarm->nft_chains = 0;

	init_list_head(&pfarm->static_sessions);
	pfarm->total_static_sessions = 0;
	init_list_head(&pfarm->timed_sessions);
	pfarm->total_timed_sessions = 0;

	list_add_tail(&pfarm->list, farms);
	obj_set_total_farms(obj_get_total_farms() + 1);

	init_list_head(&pfarm->addresses);
	pfarm->addresses_used = 0;

	return pfarm;
}

static int farm_delete(struct farm *pfarm)
{
	tools_printlog(LOG_DEBUG, "%s():%d: deleting farm %s", __FUNCTION__, __LINE__, pfarm->name);

	backend_s_delete(pfarm);
	farmpolicy_s_delete(pfarm);
	farmaddress_s_delete(pfarm);
	list_del(&pfarm->list);

	if (pfarm->name && strcmp(pfarm->name, "") != 0)
		free(pfarm->name);
	if (pfarm->fqdn && strcmp(pfarm->fqdn, "") != 0)
		free(pfarm->fqdn);
	if (pfarm->oface && strcmp(pfarm->oface, "") != 0)
		free(pfarm->oface);
	if (pfarm->oethaddr && strcmp(pfarm->oethaddr, "") != 0)
		free(pfarm->oethaddr);
	if (pfarm->logprefix && strcmp(pfarm->logprefix, DEFAULT_LOG_LOGPREFIX) != 0)
		free(pfarm->logprefix);
	if (pfarm->newrtlimit_logprefix && strcmp(pfarm->newrtlimit_logprefix, DEFAULT_LOGPREFIX) != 0)
		free(pfarm->newrtlimit_logprefix);
	if (pfarm->rstrtlimit_logprefix && strcmp(pfarm->rstrtlimit_logprefix, DEFAULT_LOGPREFIX) != 0)
		free(pfarm->rstrtlimit_logprefix);
	if (pfarm->estconnlimit_logprefix && strcmp(pfarm->estconnlimit_logprefix, DEFAULT_LOGPREFIX) != 0)
		free(pfarm->estconnlimit_logprefix);
	if (pfarm->tcpstrict_logprefix && strcmp(pfarm->tcpstrict_logprefix, DEFAULT_LOGPREFIX) != 0)
		free(pfarm->tcpstrict_logprefix);

	free(pfarm);
	obj_set_total_farms(obj_get_total_farms() - 1);

	return 0;
}

static int farm_validate_oface(struct farm *f)
{
	tools_printlog(LOG_DEBUG, "%s():%d: validating output farm interface of %s", __FUNCTION__, __LINE__, f->name);

	if (!f->oface || obj_equ_attribute_string(f->oface, "") ||
		!f->oethaddr || obj_equ_attribute_string(f->oethaddr, ""))
		return 0;

	return 1;
}

static int farm_validate(struct farm *f)
{
	tools_printlog(LOG_DEBUG, "%s():%d: validating farm %s", __FUNCTION__, __LINE__, f->name);

	if (farm_needs_policies(f) && !farmaddress_s_validate_iface(f))
		return 0;

	if ((farm_is_ingress_mode(f) || farm_needs_flowtable(f)) &&
		(!farmaddress_s_validate_iface(f) ||
		!farm_validate_oface(f)))
		return 0;

	return 1;
}

static int farm_is_available(struct farm *f)
{
	tools_printlog(LOG_DEBUG, "%s():%d: farm %s state is %s",
				   __FUNCTION__, __LINE__, f->name, obj_print_state(f->state));

	return (f->state == VALUE_STATE_UP) && farm_validate(f);
}

static int farm_s_update_dsr_counter(void)
{
	struct list_head *farms = obj_get_farms();
	struct farm *f;
	int dsrcount = 0;
	int curcount = obj_get_dsr_counter();

	tools_printlog(LOG_DEBUG, "%s():%d: updating dsr counter", __FUNCTION__, __LINE__);

	list_for_each_entry(f, farms, list) {
		if (farm_is_ingress_mode(f))
			dsrcount++;
	}

	if (dsrcount != curcount)
		tools_printlog(LOG_DEBUG, "%s():%d: farm dsr counter becomes %d", __FUNCTION__, __LINE__, dsrcount);

	obj_set_dsr_counter(dsrcount);

	return dsrcount;
}

static void farm_manage_eventd(void)
{
	farm_s_update_dsr_counter();

	if (obj_get_dsr_counter() && !net_get_event_enabled()) {
		net_eventd_init();
	}

	if (!obj_get_dsr_counter() && net_get_event_enabled()) {
		net_eventd_stop();
	}
}

int farm_needs_flowtable(struct farm *f)
{
	return f->flow_offload;
}

int farm_needs_intraconnect(struct farm *f)
{
	return f->intra_connect;
}

static int farm_set_netinfo(struct farm *f)
{
	tools_printlog(LOG_DEBUG, "%s():%d: farm %s", __FUNCTION__, __LINE__, f->name);

	if (f->state != VALUE_STATE_UP) {
		tools_printlog(LOG_INFO, "%s():%d: farm %s doesn't require low level network info", __FUNCTION__, __LINE__, f->name);
		return -1;
	}

	if (farm_is_ingress_mode(f) &&
		farm_set_oface_info(f) == 0 ) {
		f->bcks_have_if = backend_s_check_have_iface(f);
		farm_manage_eventd();
		backend_s_find_ethers(f);
	}

	if (farm_needs_flowtable(f)) {
		farm_set_oface_info(f);
		f->bcks_have_if = backend_s_check_have_iface(f);
	}

	return 0;
}

extern int masquerade_mark;

static int farm_set_mark(struct farm *f, int new_value)
{
	int old_value = f->mark;

	tools_printlog(LOG_DEBUG, "%s():%d: farm %s old mark %d new mark %d", __FUNCTION__, __LINE__, f->name, old_value, new_value);

	if (f->mode != VALUE_MODE_DNAT && f->mode != VALUE_MODE_SNAT) {
		tools_printlog(LOG_INFO, "%s():%d: mark for farm %s not available for the current mode %d", __FUNCTION__, __LINE__, f->name, f->mode);
		return 0;
	}

	if (new_value & masquerade_mark) {
		tools_printlog(LOG_ERR, "%s():%d: mark 0x%x for farm %s conflicts with the POSTROUTING mark 0x%x", __FUNCTION__, __LINE__, f->mark, f->name, masquerade_mark);
		return 0;
	}

	f->mark = new_value;

	return 0;
}

static int farm_set_state(struct farm *f, int new_value)
{
	int old_value = f->state;

	tools_printlog(LOG_DEBUG, "%s():%d: farm %s old state %d new state %d", __FUNCTION__, __LINE__, f->name, old_value, new_value);

	if (old_value != VALUE_STATE_UP &&
	    new_value == VALUE_STATE_UP) {

		farm_set_action(f, ACTION_START);
		f->state = new_value;
		farm_set_netinfo(f);
		return 0;
	}

	if (old_value == VALUE_STATE_UP &&
	    new_value != VALUE_STATE_UP) {

		farm_set_action(f, ACTION_STOP);
		farm_manage_eventd();
	}

	f->state = new_value;

	return 0;
}

static int farm_set_mode(struct farm *f, int new_value)
{
	int old_value = f->mode;

	tools_printlog(LOG_DEBUG, "%s():%d: farm %s old mode %d new mode %d", __FUNCTION__, __LINE__, f->name, old_value, new_value);

	if (old_value != new_value) {
		f->mode = new_value;
		farm_set_netinfo(f);
		backend_s_validate(f);
	}

	return 0;
}

static int farm_set_sched(struct farm *f, int new_value)
{
	int old_value = f->scheduler;

	tools_printlog(LOG_DEBUG, "%s():%d: farm %s old scheduler %d new scheduler %d", __FUNCTION__, __LINE__, f->name, old_value, new_value);

	f->scheduler = new_value;

	if (f->scheduler == VALUE_SCHED_HASH && f->schedparam == VALUE_META_NONE) {
		f->schedparam = VALUE_META_SRCIP;
	}

	if (f->scheduler != VALUE_SCHED_HASH) {
		f->schedparam = VALUE_META_NONE;
	}

	return 0;
}

static int farm_set_persistence(struct farm *f, int new_value)
{
	int old_value = f->persistence;

	tools_printlog(LOG_DEBUG, "%s():%d: farm %s old persistence %d new persistence %d", __FUNCTION__, __LINE__, f->name, old_value, new_value);

	session_s_delete(f, SESSION_TYPE_STATIC);

	f->persistence = new_value;

	return 0;
}

static void farm_print(struct farm *f)
{
	char buf[100] = {};
	struct farmaddress *fa = farmaddress_get_first(f);
	struct address *a = NULL;

	if (fa)
		a = fa->address;

	tools_printlog(LOG_DEBUG," [farm] ");
	tools_printlog(LOG_DEBUG,"    [%s] %s", CONFIG_KEY_NAME, f->name);

	if (f->fqdn)
		tools_printlog(LOG_DEBUG,"    [%s] %s", CONFIG_KEY_FQDN, f->fqdn);

	if (f->oface)
		tools_printlog(LOG_DEBUG,"    [%s] %s", CONFIG_KEY_OFACE, f->oface);

	if (f->oethaddr)
		tools_printlog(LOG_DEBUG,"    [%s] %s", CONFIG_KEY_OETHADDR, f->oethaddr);

	tools_printlog(LOG_DEBUG,"   *[ofidx] %d", f->ofidx);

	if (a) {
		if (a->iface)
			tools_printlog(LOG_DEBUG,"    [%s] %s", CONFIG_KEY_IFACE, a->iface);

		if (a->iethaddr)
			tools_printlog(LOG_DEBUG,"    [%s] %s", CONFIG_KEY_IETHADDR, a->iethaddr);

		tools_printlog(LOG_DEBUG,"   *[ifidx] %d", a->ifidx);

		if (a->ipaddr)
			tools_printlog(LOG_DEBUG,"    [%s] %s", CONFIG_KEY_VIRTADDR, a->ipaddr);

		if (a->ports)
			tools_printlog(LOG_DEBUG,"    [%s] %s", CONFIG_KEY_VIRTPORTS, a->ports);

		tools_printlog(LOG_DEBUG,"    [%s] %s", CONFIG_KEY_FAMILY, obj_print_family(a->family));
		tools_printlog(LOG_DEBUG,"    [%s] %s", CONFIG_KEY_PROTO, obj_print_proto(a->protocol));
	}

	if (f->srcaddr)
		tools_printlog(LOG_DEBUG,"    [%s] %s", CONFIG_KEY_SRCADDR, f->srcaddr);

	tools_printlog(LOG_DEBUG,"    [%s] %s", CONFIG_KEY_MODE, obj_print_mode(f->mode));

	if (f->mode == VALUE_MODE_STLSDNAT)
		tools_printlog(LOG_DEBUG,"    [%s] %d", CONFIG_KEY_RESPONSETTL, f->responsettl);

	tools_printlog(LOG_DEBUG,"    [%s] %s", CONFIG_KEY_SCHED, obj_print_sched(f->scheduler));

	obj_print_meta(f->schedparam, (char *)buf);
	tools_printlog(LOG_DEBUG,"    [%s] %s", CONFIG_KEY_SCHEDPARAM, buf);
	buf[0] = '\0';

	obj_print_meta(f->persistence, (char *)buf);
	tools_printlog(LOG_DEBUG,"    [%s] %s", CONFIG_KEY_PERSIST, buf);
	buf[0] = '\0';
	tools_printlog(LOG_DEBUG,"    [%s] %d", CONFIG_KEY_PERSISTTM, f->persistttl);

	tools_printlog(LOG_DEBUG,"    [%s] %s", CONFIG_KEY_HELPER, obj_print_helper(f->helper));

	obj_print_log(f->log, (char *)buf);
	tools_printlog(LOG_DEBUG,"    [%s] %s", CONFIG_KEY_LOG, buf);
	if (f->logprefix)
		tools_printlog(LOG_DEBUG,"    [%s] %s", CONFIG_KEY_LOGPREFIX, f->logprefix);

	tools_printlog(LOG_DEBUG,"    [%s] 0x%x", CONFIG_KEY_MARK, f->mark);
	tools_printlog(LOG_DEBUG,"    [%s] %s", CONFIG_KEY_STATE, obj_print_state(f->state));
	tools_printlog(LOG_DEBUG,"    [%s] %d", CONFIG_KEY_PRIORITY, f->priority);

	tools_printlog(LOG_DEBUG,"    [%s] %d", CONFIG_KEY_NEWRTLIMIT, f->newrtlimit);
	tools_printlog(LOG_DEBUG,"    [%s] %d", CONFIG_KEY_NEWRTLIMITBURST, f->newrtlimitbst);
	if (f->newrtlimit_logprefix)
		tools_printlog(LOG_DEBUG,"    [%s] %s", CONFIG_KEY_NEWRTLIMIT_LOGPREFIX, f->newrtlimit_logprefix);

	tools_printlog(LOG_DEBUG,"    [%s] %d", CONFIG_KEY_RSTRTLIMIT, f->rstrtlimit);
	tools_printlog(LOG_DEBUG,"    [%s] %d", CONFIG_KEY_RSTRTLIMITBURST, f->rstrtlimitbst);
	if (f->rstrtlimit_logprefix)
		tools_printlog(LOG_DEBUG,"    [%s] %s", CONFIG_KEY_RSTRTLIMIT_LOGPREFIX, f->rstrtlimit_logprefix);

	tools_printlog(LOG_DEBUG,"    [%s] %d", CONFIG_KEY_ESTCONNLIMIT, f->estconnlimit);
	if (f->estconnlimit_logprefix)
		tools_printlog(LOG_DEBUG,"    [%s] %s", CONFIG_KEY_ESTCONNLIMIT_LOGPREFIX, f->estconnlimit_logprefix);

	tools_printlog(LOG_DEBUG,"    [%s] %s", CONFIG_KEY_TCPSTRICT, obj_print_switch(f->tcpstrict));
	if (f->tcpstrict_logprefix)
		tools_printlog(LOG_DEBUG,"    [%s] %s", CONFIG_KEY_TCPSTRICT_LOGPREFIX, f->tcpstrict_logprefix);

	tools_printlog(LOG_DEBUG,"    [%s] %d", CONFIG_KEY_QUEUE, f->queue);
	tools_printlog(LOG_DEBUG,"    [%s] %s", CONFIG_KEY_FLOWOFFLOAD, obj_print_switch(f->flow_offload));
	tools_printlog(LOG_DEBUG,"    [%s] %s", CONFIG_KEY_INTRACONNECT, obj_print_switch(f->intra_connect));

	tools_printlog(LOG_DEBUG,"   *[total_weight] %d", f->total_weight);
	tools_printlog(LOG_DEBUG,"   *[total_bcks] %d", f->total_bcks);
	tools_printlog(LOG_DEBUG,"   *[bcks_available] %d", f->bcks_available);
	tools_printlog(LOG_DEBUG,"   *[bcks_usable] %d", f->bcks_usable);
	tools_printlog(LOG_DEBUG,"   *[bcks_have_port] %d", f->bcks_have_port);
	tools_printlog(LOG_DEBUG,"   *[bcks_have_srcaddr] %d", f->bcks_have_srcaddr);
	tools_printlog(LOG_DEBUG,"   *[bcks_have_if] %d", f->bcks_have_if);
	tools_printlog(LOG_DEBUG,"   *[policies_action] %d", f->policies_action);
	tools_printlog(LOG_DEBUG,"   *[policies_used] %d", f->policies_used);
	tools_printlog(LOG_DEBUG,"   *[total_static_sessions] %d", f->total_static_sessions);
	tools_printlog(LOG_DEBUG,"   *[total_timed_sessions] %d", f->total_timed_sessions);
	tools_printlog(LOG_DEBUG,"   *[nft_chains] %x", f->nft_chains);
	tools_printlog(LOG_DEBUG,"   *[addresses_used] %d", f->addresses_used);
	tools_printlog(LOG_DEBUG,"   *[reload_action] %x", f->reload_action);
	tools_printlog(LOG_DEBUG,"   *[%s] %d", CONFIG_KEY_ACTION, f->action);

	if (f->addresses_used > 0)
		farmaddress_s_print(f);

	if (f->total_bcks > 0)
		backend_s_print(f);

	if (f->policies_used > 0)
		farmpolicy_s_print(f);

	if (f->total_static_sessions || f->total_timed_sessions)
		session_s_print(f);
}

static int farm_set_newrtlimit(struct farm *f, int new_value)
{
	if (f->newrtlimit == new_value)
		return PARSER_OK;

	if (new_value == 0)
		f->reload_action |= VALUE_RLD_NEWRTLIMIT_STOP;
	else
		f->reload_action |= VALUE_RLD_NEWRTLIMIT_START;

	f->newrtlimit = new_value;
	return PARSER_OK;
}

static int farm_set_rstrtlimit(struct farm *f, int new_value)
{
	if (f->rstrtlimit == new_value)
		return PARSER_OK;

	if (new_value == 0)
		f->reload_action |= VALUE_RLD_RSTRTLIMIT_STOP;
	else
		f->reload_action |= VALUE_RLD_RSTRTLIMIT_START;

	f->rstrtlimit = new_value;
	return PARSER_OK;
}

static int farm_set_estconnlimit(struct farm *f, int new_value)
{
	if (f->estconnlimit == new_value)
		return PARSER_OK;

	if (new_value == 0)
		f->reload_action |= VALUE_RLD_ESTCONNLIMIT_STOP;
	else
		f->reload_action |= VALUE_RLD_ESTCONNLIMIT_START;

	f->estconnlimit = new_value;
	return PARSER_OK;
}

static int farm_set_tcpstrict(struct farm *f, int new_value)
{
	if (new_value == VALUE_SWITCH_OFF)
		f->reload_action |= VALUE_RLD_TCPSTRICT_STOP;
	else
		f->reload_action |= VALUE_RLD_TCPSTRICT_START;

	f->tcpstrict = new_value;
	return PARSER_OK;
}

static int farm_set_queue(struct farm *f, int new_value)
{
	if (new_value == -1)
		f->reload_action |= VALUE_RLD_QUEUE_STOP;
	else
		f->reload_action |= VALUE_RLD_QUEUE_START;

	f->queue = new_value;
	return PARSER_OK;
}

static int farm_set_helper(struct farm *f, int new_value)
{
	int old_value = f->helper;

	syslog(LOG_DEBUG, "%s():%d: farm %s old helper %d new helper %d", __FUNCTION__, __LINE__, f->name, old_value, new_value);

	if (farmaddress_s_validate_helper(f, new_value))
		return PARSER_FAILED;

	f->helper = new_value;
	return PARSER_OK;
}

int farm_changed(struct config_pair *c)
{
	struct farm *f = obj_get_current_farm();

	if (!f)
		return -1;

	tools_printlog(LOG_DEBUG, "%s():%d: farm %s with param %d", __FUNCTION__, __LINE__, f->name, c->key);

	switch (c->key) {
	case KEY_NAME:
		return 1;
		break;
	case KEY_NEWNAME:
		return !obj_equ_attribute_string(f->name, c->str_value);
		break;
	case KEY_FQDN:
		return !obj_equ_attribute_string(f->fqdn, c->str_value);
		break;
	case KEY_ETHADDR:
	case KEY_IETHADDR:
	case KEY_IFACE:
	case KEY_FAMILY:
	case KEY_VIRTADDR:
	case KEY_VIRTPORTS:
	case KEY_PROTO:
		return 1;
		break;
	case KEY_OETHADDR:
		return !obj_equ_attribute_string(f->oethaddr, c->str_value);
		break;
	case KEY_OFACE:
		return !obj_equ_attribute_string(f->oface, c->str_value);
		break;
	case KEY_SRCADDR:
		return !obj_equ_attribute_string(f->srcaddr, c->str_value);
		break;
	case KEY_MODE:
		return !obj_equ_attribute_int(f->mode, c->int_value);
		break;
	case KEY_RESPONSETTL:
		return !obj_equ_attribute_int(f->responsettl, c->int_value);
		break;
	case KEY_SCHED:
		return !obj_equ_attribute_int(f->scheduler, c->int_value);
		break;
	case KEY_SCHEDPARAM:
		return !obj_equ_attribute_int(f->schedparam, c->int_value);
		break;
	case KEY_PERSISTENCE:
		return !obj_equ_attribute_int(f->persistence, c->int_value);
		break;
	case KEY_PERSISTTM:
		return !obj_equ_attribute_int(f->persistttl, c->int_value);
		break;
	case KEY_HELPER:
		return !obj_equ_attribute_int(f->helper, c->int_value);
		break;
	case KEY_LOG:
		return !obj_equ_attribute_int(f->log, c->int_value);
		break;
	case KEY_LOGPREFIX:
		return !obj_equ_attribute_string(f->logprefix, c->str_value);
		break;
	case KEY_MARK:
		return !obj_equ_attribute_int(f->mark, c->int_value);
		break;
	case KEY_STATE:
		return !obj_equ_attribute_int(f->state, c->int_value);
		break;
	case KEY_ACTION:
		return !obj_equ_attribute_int(f->action, c->int_value);
		break;
	case KEY_NEWRTLIMIT:
		return !obj_equ_attribute_int(f->newrtlimit, c->int_value);
		break;
	case KEY_NEWRTLIMITBURST:
		return !obj_equ_attribute_int(f->newrtlimitbst, c->int_value);
		break;
	case KEY_RSTRTLIMIT:
		return !obj_equ_attribute_int(f->rstrtlimit, c->int_value);
		break;
	case KEY_RSTRTLIMITBURST:
		return !obj_equ_attribute_int(f->rstrtlimitbst, c->int_value);
		break;
	case KEY_ESTCONNLIMIT:
		return !obj_equ_attribute_int(f->estconnlimit, c->int_value);
		break;
	case KEY_TCPSTRICT:
		return !obj_equ_attribute_int(f->tcpstrict, c->int_value);
		break;
	case KEY_QUEUE:
		return !obj_equ_attribute_int(f->queue, c->int_value);
		break;
	case KEY_FLOWOFFLOAD:
		return !obj_equ_attribute_int(f->flow_offload, c->int_value);
		break;
	case KEY_NEWRTLIMIT_LOGPREFIX:
		return !obj_equ_attribute_string(f->newrtlimit_logprefix, c->str_value);
		break;
	case KEY_RSTRTLIMIT_LOGPREFIX:
		return !obj_equ_attribute_string(f->rstrtlimit_logprefix, c->str_value);
		break;
	case KEY_ESTCONNLIMIT_LOGPREFIX:
		return !obj_equ_attribute_string(f->estconnlimit_logprefix, c->str_value);
		break;
	case KEY_TCPSTRICT_LOGPREFIX:
		return !obj_equ_attribute_string(f->tcpstrict_logprefix, c->str_value);
		break;
	case KEY_INTRACONNECT:
		return !obj_equ_attribute_int(f->intra_connect, c->int_value);
		break;
	default:
		break;
	}

	return 0;
}

int farm_set_priority(struct farm *f, int new_value)
{
	int old_value = f->priority;

	tools_printlog(LOG_DEBUG, "%s():%d: current value is %d, but new value will be %d",
				   __FUNCTION__, __LINE__, old_value, new_value);

	if (new_value <= 0)
		return -1;

	f->priority = new_value;

	return 0;
}

void farm_s_print(void)
{
	struct list_head *farms = obj_get_farms();
	struct farm *f;

	list_for_each_entry(f, farms, list)
		farm_print(f);
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

int farm_is_ingress_mode(struct farm *f)
{
	return (f->mode == VALUE_MODE_DSR || f->mode == VALUE_MODE_STLSDNAT);
}

int farm_needs_policies(struct farm *f)
{
	return (f->policies_used > 0) || (f->policies_action != ACTION_NONE);
}

struct farm * farm_get_first(void)
{
	struct list_head *farms = obj_get_farms();
	return list_first_entry(farms, struct farm, list);
}

int farm_set_oface_info(struct farm *f)
{
	unsigned char ether[ETH_HW_ADDR_LEN];
	char streth[ETH_HW_STR_LEN] = {};
	char if_str[IFNAMSIZ];
	struct backend *b;
	char **ether_addr;
	int if_index;
	int ret = 0;

	tools_printlog(LOG_DEBUG, "%s():%d: farm %s set interface info for interface", __FUNCTION__, __LINE__, f->name);

	if (!(farm_is_ingress_mode(f) ||
		farm_needs_flowtable(f))) {
		tools_printlog(LOG_DEBUG, "%s():%d: farm %s doesn't require netinfo", __FUNCTION__, __LINE__, f->name);
		return 0;
	}

	if (f->oface && strcmp(f->oface, IFACE_LOOPBACK) == 0) {
		tools_printlog(LOG_DEBUG, "%s():%d: farm %s doesn't require output netinfo, loopback interface", __FUNCTION__, __LINE__, f->name);
		f->ofidx = 0;
		return 0;
	}

	ether_addr = &f->oethaddr;

	b = backend_get_first(f);
	if (!b || b->ipaddr == DEFAULT_IPADDR) {
		tools_printlog(LOG_DEBUG, "%s():%d: there is no backend yet in the farm %s", __FUNCTION__, __LINE__, f->name);
		return 0;
	}

	ret = net_get_local_ifidx_per_remote_host(b->ipaddr, &if_index);
	if (ret == -1) {
		tools_printlog(LOG_ERR, "%s():%d: unable to get the outbound interface to %s for the farm %s", __FUNCTION__, __LINE__, b->ipaddr, f->name);
		return -1;
	}

	f->ofidx = if_index;

	if (if_indextoname(if_index, if_str) == NULL) {
		tools_printlog(LOG_ERR, "%s():%d: unable to get the outbound interface name with index %d required by the farm %s", __FUNCTION__, __LINE__, if_index, f->name);
		return -1;
	}

	if (f->oface)
		free(f->oface);
	obj_set_attribute_string(if_str, &f->oface);
	net_strim_netface(f->oface);

	net_get_local_ifinfo((unsigned char **)&ether, f->oface);
	sprintf(streth, "%02x:%02x:%02x:%02x:%02x:%02x", ether[0],
		ether[1], ether[2], ether[3], ether[4], ether[5]);

	if (f->oethaddr)
		free(f->oethaddr);
	obj_set_attribute_string(streth, ether_addr);

	return 0;
}

int farm_pre_actionable(struct config_pair *c)
{
	struct farm *f = obj_get_current_farm();

	if (!f)
		return -1;

	tools_printlog(LOG_DEBUG, "%s():%d: pre actionable farm %s with param %d", __FUNCTION__, __LINE__, f->name, c->key);

	switch (c->key) {
	case KEY_NAME:
		break;
	case KEY_NEWNAME:
	case KEY_FAMILY:
	case KEY_VIRTADDR:
	case KEY_VIRTPORTS:
	case KEY_SRCADDR:
	case KEY_MODE:
	case KEY_RESPONSETTL:
	case KEY_PROTO:
	case KEY_PERSISTENCE:
	case KEY_PERSISTTM:
	case KEY_FLOWOFFLOAD:
	case KEY_LOG:
	case KEY_HELPER:
	case KEY_INTRACONNECT:
		if (farm_set_action(f, ACTION_STOP))
			farm_rulerize(f);
		break;
	default:
		break;
	}

	return ACTION_START;
}

int farm_pos_actionable(struct config_pair *c)
{
	struct farm *f = obj_get_current_farm();

	if (!f)
		return -1;

	tools_printlog(LOG_DEBUG, "%s():%d: pos actionable farm %s with param %d", __FUNCTION__, __LINE__, f->name, c->key);

	switch (c->key) {
	case KEY_NAME:
		break;
	case KEY_NEWNAME:
	case KEY_FAMILY:
	case KEY_VIRTADDR:
	case KEY_VIRTPORTS:
	case KEY_SRCADDR:
	case KEY_MODE:
	case KEY_RESPONSETTL:
	case KEY_PROTO:
	case KEY_PERSISTENCE:
	case KEY_PERSISTTM:
	case KEY_FLOWOFFLOAD:
	case KEY_LOG:
	case KEY_HELPER:
	case KEY_INTRACONNECT:
		farm_set_action(f, ACTION_START);
		break;
	case KEY_STATE:
		break;
	default:
		farm_set_action(f, ACTION_RELOAD);
		return 0;
	}

	return 0;
}

int farm_set_attribute(struct config_pair *c)
{
	struct farm *f = obj_get_current_farm();
	struct farmaddress *fa;
	struct address *a;
	struct farm *nf;
	int ret = PARSER_FAILED;

	if (c->key != KEY_NAME && !f)
		return PARSER_OBJ_UNKNOWN;

	switch (c->key) {
	case KEY_NAME:
		f = farm_lookup_by_name(c->str_value);
		if (!f) {
			f = farm_create(c->str_value);
			if (!f)
				return -1;
		}
		obj_set_current_farm(f);
		ret = PARSER_OK;
		break;
	case KEY_NEWNAME:
		nf = farm_lookup_by_name(c->str_value);
		if (!nf) {
			free(f->name);
			obj_set_attribute_string(c->str_value, &f->name);
		}
		ret = PARSER_OK;
		break;
	case KEY_FQDN:
		if (strcmp(f->fqdn, DEFAULT_FQDN) != 0)
			free(f->fqdn);
		ret = obj_set_attribute_string(c->str_value, &f->fqdn);
		break;
	case KEY_IFACE:
		farmaddress_create_default(c);
		fa = obj_get_current_farmaddress();
		a = fa->address;
		if (a->iface)
			free(a->iface);
		ret = obj_set_attribute_string(c->str_value, &a->iface);
		net_strim_netface(a->iface);
		address_set_netinfo(a);
		break;
	case KEY_OFACE:
		if (f->oface)
			free(f->oface);
		ret = obj_set_attribute_string(c->str_value, &f->oface);
		net_strim_netface(f->oface);
		farm_set_netinfo(f);
		break;
	case KEY_FAMILY:
		farmaddress_create_default(c);
		fa = obj_get_current_farmaddress();
		a = fa->address;
		a->family = c->int_value;
		ret = PARSER_OK;
		break;
	case KEY_ETHADDR:
		farmaddress_create_default(c);
		fa = obj_get_current_farmaddress();
		a = fa->address;
		if (a->iethaddr)
			free(a->iethaddr);
		if (f->oethaddr)
			free(f->oethaddr);
		ret = obj_set_attribute_string(c->str_value, &a->iethaddr) ||
			obj_set_attribute_string(c->str_value, &f->oethaddr);
		break;
	case KEY_IETHADDR:
		farmaddress_create_default(c);
		fa = obj_get_current_farmaddress();
		a = fa->address;
		if (a->iethaddr)
			free(a->iethaddr);
		ret = obj_set_attribute_string(c->str_value, &a->iethaddr);
		break;
	case KEY_OETHADDR:
		if (f->oethaddr)
			free(f->oethaddr);
		ret = obj_set_attribute_string(c->str_value, &f->oethaddr);
		break;
	case KEY_VIRTADDR:
		farmaddress_create_default(c);
		fa = obj_get_current_farmaddress();
		a = fa->address;
		if (strcmp(a->ipaddr, DEFAULT_VIRTADDR) != 0)
			free(a->ipaddr);
		ret = obj_set_attribute_string(c->str_value, &a->ipaddr);
		address_set_netinfo(a);
		break;
	case KEY_VIRTPORTS:
		farmaddress_create_default(c);
		fa = obj_get_current_farmaddress();
		a = fa->address;
		ret = address_set_ports(a, c->str_value);
		break;
	case KEY_SRCADDR:
		if (f->srcaddr)
			free(f->srcaddr);
		ret = obj_set_attribute_string(c->str_value, &f->srcaddr);
		break;
	case KEY_MODE:
		ret = farm_set_mode(f, c->int_value);
		break;
	case KEY_RESPONSETTL:
		f->responsettl = c->int_value;
		ret = PARSER_OK;
		break;
	case KEY_PROTO:
		farmaddress_create_default(c);
		fa = obj_get_current_farmaddress();
		a = fa->address;
		ret = address_set_protocol(a, c->int_value);
		break;
	case KEY_SCHED:
		ret = farm_set_sched(f, c->int_value);
		break;
	case KEY_SCHEDPARAM:
		f->schedparam = c->int_value;
		ret = PARSER_OK;
		break;
	case KEY_PERSISTENCE:
		ret = farm_set_persistence(f, c->int_value);
		break;
	case KEY_PERSISTTM:
		f->persistttl = c->int_value;
		ret = PARSER_OK;
		break;
	case KEY_PRIORITY:
		farm_set_priority(f, c->int_value);
		ret = PARSER_OK;
		break;
	case KEY_HELPER:
		ret = farm_set_helper(f, c->int_value);
		break;
	case KEY_LOG:
		f->log = c->int_value;
		ret = PARSER_OK;
		break;
	case KEY_MARK:
		ret = farm_set_mark(f, c->int_value);
		break;
	case KEY_STATE:
		if (c->int_value != VALUE_STATE_CONFERR)
			ret = farm_set_state(f, c->int_value);
		else
			ret = PARSER_OK;
		break;
	case KEY_ACTION:
		ret = farm_set_action(f, c->int_value);
		break;
	case KEY_NEWRTLIMIT:
		ret = farm_set_newrtlimit(f, c->int_value);
		break;
	case KEY_NEWRTLIMITBURST:
		f->newrtlimitbst = c->int_value;
		ret = PARSER_OK;
		break;
	case KEY_RSTRTLIMIT:
		ret = farm_set_rstrtlimit(f, c->int_value);
		break;
	case KEY_RSTRTLIMITBURST:
		f->rstrtlimitbst = c->int_value;
		ret = PARSER_OK;
		break;
	case KEY_ESTCONNLIMIT:
		ret = farm_set_estconnlimit(f, c->int_value);
		break;
	case KEY_TCPSTRICT:
		ret = farm_set_tcpstrict(f, c->int_value);
		ret = PARSER_OK;
		break;
	case KEY_QUEUE:
		ret = farm_set_queue(f, c->int_value);
		ret = PARSER_OK;
		break;
	case KEY_FLOWOFFLOAD:
		f->flow_offload = c->int_value;
		farm_set_netinfo(f);
		ret = PARSER_OK;
		break;
	case KEY_LOGPREFIX:
		if (strcmp(f->logprefix, DEFAULT_LOG_LOGPREFIX) != 0)
			free(f->logprefix);
		ret = obj_set_attribute_string(c->str_value, &f->logprefix);
		break;
	case KEY_NEWRTLIMIT_LOGPREFIX:
		if (strcmp(f->newrtlimit_logprefix, DEFAULT_LOGPREFIX) != 0)
			free(f->newrtlimit_logprefix);
		ret = obj_set_attribute_string(c->str_value, &f->newrtlimit_logprefix);
		break;
	case KEY_RSTRTLIMIT_LOGPREFIX:
		if (strcmp(f->rstrtlimit_logprefix, DEFAULT_LOGPREFIX) != 0)
			free(f->rstrtlimit_logprefix);
		ret = obj_set_attribute_string(c->str_value, &f->rstrtlimit_logprefix);
		break;
	case KEY_ESTCONNLIMIT_LOGPREFIX:
		if (strcmp(f->estconnlimit_logprefix, DEFAULT_LOGPREFIX) != 0)
			free(f->estconnlimit_logprefix);
		ret = obj_set_attribute_string(c->str_value, &f->estconnlimit_logprefix);
		break;
	case KEY_TCPSTRICT_LOGPREFIX:
		if (strcmp(f->tcpstrict_logprefix, DEFAULT_LOGPREFIX) != 0)
			free(f->tcpstrict_logprefix);
		ret = obj_set_attribute_string(c->str_value, &f->tcpstrict_logprefix);
		break;
	case KEY_INTRACONNECT:
		f->intra_connect = c->int_value;
		ret = PARSER_OK;
		break;
	default:
		return PARSER_STRUCT_FAILED;
	}

	return ret;
}

int farm_set_action(struct farm *f, int action)
{
	tools_printlog(LOG_DEBUG, "%s():%d: farm %s action is %d - new action %d", __FUNCTION__, __LINE__, f->name, f->action, action);

	if (action == ACTION_STOP && f->state != VALUE_STATE_UP)
		return 0;

	if (action == ACTION_RELOAD && f->state != VALUE_STATE_UP)
		action = ACTION_START;

	if (action != ACTION_NONE && action != ACTION_RELOAD && f->policies_used != 0)
		f->policies_action = action;

	if (action == ACTION_DELETE) {
		farm_delete(f);
		return 1;
	}

	if (f->action > action) {
		backend_s_gen_priority(f);
		farm_manage_eventd();
		f->action = action;
		farm_set_netinfo(f);
		backend_s_validate(f);
		if (action == ACTION_STOP || action == ACTION_START)
			farmaddress_s_set_action(f, action);

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

	return 0;
}

int farm_get_masquerade(struct farm *f)
{
	int masq = (f->mode == VALUE_MODE_SNAT && (f->srcaddr == DEFAULT_SRCADDR || strcmp(f->srcaddr, "") == 0));

	tools_printlog(LOG_DEBUG, "%s():%d: farm %s masquerade %d", __FUNCTION__, __LINE__, f->name, masq);

	return masq;
}

void farm_s_set_backend_ether_by_oifidx(int interface_idx, const char * ip_bck, char * ether_bck)
{
	struct list_head *farms = obj_get_farms();
	struct farm *f;

	tools_printlog(LOG_DEBUG, "%s():%d: updating farms with backends ip address %s and ether address %s", __FUNCTION__, __LINE__, ip_bck, ether_bck);

	list_for_each_entry(f, farms, list) {

		tools_printlog(LOG_DEBUG, "%s():%d: farm with oifidx %d found", __FUNCTION__, __LINE__, interface_idx);

		if (!farm_validate(f)) {
			tools_printlog(LOG_INFO, "%s():%d: farm %s doesn't validate", __FUNCTION__, __LINE__, f->name);
			farm_set_state(f, VALUE_STATE_CONFERR);
			continue;
		}

		if (backend_s_set_ether_by_ipaddr(f, ip_bck, ether_bck)) {
			f->ofidx = interface_idx;
			farm_set_action(f, ACTION_RELOAD);
			farm_rulerize(f);
		}
	}
}

int farm_s_lookup_policy_action(char *name, int action)
{
	struct list_head *farms = obj_get_farms();
	struct farm *f, *next;

	list_for_each_entry_safe(f, next, farms, list)
		farmpolicy_s_lookup_policy_action(f, name, action);

	return 0;
}

int farm_s_lookup_address_action(char *name, int action)
{
	struct list_head *farms = obj_get_farms();
	struct farm *f, *next;

	list_for_each_entry_safe(f, next, farms, list)
		farmaddress_s_lookup_address_action(f, name, action);

	return 0;
}

int farm_rulerize(struct farm *f)
{
	tools_printlog(LOG_DEBUG, "%s():%d: rulerize farm %s", __FUNCTION__, __LINE__, f->name);

	farm_print(f);

	if ((f->action == ACTION_START || f->action == ACTION_RELOAD) &&
		!farm_is_available(f)) {
		tools_printlog(LOG_INFO, "%s():%d: farm %s won't be rulerized", __FUNCTION__, __LINE__, f->name);
		if (f->state == VALUE_STATE_UP)
			farm_set_state(f, VALUE_STATE_CONFERR);
		return 0;
	}

	return nft_rulerize_farms(f);
}

int farm_s_rulerize(void)
{
	struct list_head *farms = obj_get_farms();
	struct farm *f, *next;
	int ret = 0;
	int output = 0;

	tools_printlog(LOG_DEBUG, "%s():%d: rulerize everything", __FUNCTION__, __LINE__);

	list_for_each_entry_safe(f, next, farms, list) {
		ret = farm_rulerize(f);
		output = output || ret;
	}

	return output;
}

int farm_get_mark(struct farm *f)
{
	int mark = f->mark;

	if (farm_get_masquerade(f))
		mark |= masquerade_mark;

	return mark;
}

void farm_s_set_oface_info(struct address *a)
{
	struct list_head *farms = obj_get_farms();
	struct farm *f, *next;
	struct farmaddress *fa;

	if (!a->iface)
		return;

	list_for_each_entry_safe(f, next, farms, list) {
		if (f->ofidx != DEFAULT_IFIDX)
			continue;

		fa = farmaddress_lookup_by_name(f, a->name);
		if (fa) {
			if (a->iface)
				obj_set_attribute_string(a->iface, &f->oface);
			if (a->iethaddr)
				obj_set_attribute_string(a->iethaddr, &f->oethaddr);
			f->ofidx = a->ifidx;
		}
	}
}

int farm_s_validate_helper_proto(struct address *a, int new_value)
{
	struct list_head *farms = obj_get_farms();
	struct farm *f, *next;
	struct farmaddress *fa;

	list_for_each_entry_safe(f, next, farms, list) {
		fa = farmaddress_lookup_by_name(f, a->name);
		if (fa) {
			if (new_value == VALUE_PROTO_ALL) {
				if ((f->helper != VALUE_HELPER_NONE && f->helper != VALUE_HELPER_SIP)){
					return PARSER_FAILED; }
				continue;
			}

			if (new_value == VALUE_PROTO_TCP) {
				if ((f->helper != VALUE_HELPER_NONE && f->helper != VALUE_HELPER_FTP && f->helper != VALUE_HELPER_PPTP && f->helper != VALUE_HELPER_SIP)){
					return PARSER_FAILED;}
				continue;
			}

			if (new_value == VALUE_PROTO_UDP) {
				if ((f->helper != VALUE_HELPER_NONE && f->helper != VALUE_HELPER_TFTP && f->helper != VALUE_HELPER_SNMP && f->helper != VALUE_HELPER_SIP)){
					return PARSER_FAILED;}
				continue;
			}
		}
	}

	return PARSER_OK;
}
