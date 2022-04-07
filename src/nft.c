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

#include "nft.h"
#include "objects.h"
#include "farms.h"
#include "backends.h"
#include "sessions.h"
#include "farmpolicy.h"
#include "policies.h"
#include "elements.h"
#include "addresses.h"
#include "farmaddress.h"
#include "addresspolicy.h"
#include "config.h"
#include "list.h"
#include "sbuffer.h"
#include "tools.h"

#include <stdlib.h>
#include <nftables/libnftables.h>
#include <string.h>
#include <stdarg.h>

#define NFTLB_MAX_CMD				2048
#define NFTLB_MAX_IFACES			100
#define NFTLB_MAX_PORTS				65535
#define NFTLB_MAX_OBJ_NAME			256
#define NFTLB_MAX_OBJ_DEVICE		16
#define NFTLB_MAX_OBJ_PROTO			11

#define NFTLB_TABLE_NAME			"nftlb"
#define NFTLB_TABLE_PREROUTING		"prerouting"
#define NFTLB_TABLE_POSTROUTING		"postrouting"
#define NFTLB_TABLE_INGRESS			"ingress"
#define NFTLB_TABLE_INGRESS_DNAT	"ingress-dnat"
#define NFTLB_TABLE_FILTER			"filter"
#define NFTLB_TABLE_FORWARD			"forward"
#define NFTLB_TABLE_OUT_FILTER		"output-filter"
#define NFTLB_TABLE_OUT_NAT			"output-nat"

#define NFTLB_TYPE_NONE				""
#define NFTLB_TYPE_NAT				"nat"
#define NFTLB_TYPE_FILTER			"filter"
#define NFTLB_TYPE_NETDEV			"netdev"
#define NFTLB_TYPE_FWD				"forward"

#define NFTLB_HOOK_PREROUTING		"prerouting"
#define NFTLB_HOOK_POSTROUTING		"postrouting"
#define NFTLB_HOOK_INGRESS			"ingress"
#define NFTLB_HOOK_FORWARD			"forward"
#define NFTLB_HOOK_OUTPUT			"output"

#define NFTLB_PREROUTING_PRIO		-100
#define NFTLB_POSTROUTING_PRIO		100
#define NFTLB_FLOWTABLE_BASE_PRIO	50
#define NFTLB_INGRESS_PRIO			101
#define NFTLB_INGRESS_DNAT_PRIO		100
#define NFTLB_FILTER_PRIO			-150
#define NFTLB_RAW_PRIO				-300

#define NFTLB_IPV4_PROTOCOL			"protocol"
#define NFTLB_IPV6_PROTOCOL			"nexthdr"

#define NFTLB_UDP_PROTO				"udp"
#define NFTLB_TCP_PROTO				"tcp"
#define NFTLB_SCTP_PROTO			"sctp"

#define NFTLB_UDP_SERVICES_MAP		"udp-services"
#define NFTLB_TCP_SERVICES_MAP		"tcp-services"
#define NFTLB_SCTP_SERVICES_MAP		"sctp-services"
#define NFTLB_IP_SERVICES_MAP		"services"
#define NFTLB_PROTO_SERVICES_MAP	"proto-services"
#define NFTLB_PORT_SERVICES_MAP		"port-services"

#define NFTLB_UDP_SERVICES6_MAP		"udp-services6"
#define NFTLB_TCP_SERVICES6_MAP		"tcp-services6"
#define NFTLB_SCTP_SERVICES6_MAP	"sctp-services6"
#define NFTLB_IP_SERVICES6_MAP		"services6"
#define NFTLB_PROTO_SERVICES6_MAP	"proto-services6"
#define NFTLB_PORT_SERVICES6_MAP	"port-services6"

#define NFTLB_MAP_KEY_TYPE			0
#define NFTLB_MAP_KEY_RULE			1

#define NFTLB_MAP_TYPE_IPV4			"ipv4_addr"
#define NFTLB_MAP_TYPE_IPV6			"ipv6_addr"
#define NFTLB_MAP_TYPE_INETSRV		"inet_service"
#define NFTLB_MAP_TYPE_MAC			"ether_addr"
#define NFTLB_MAP_TYPE_MARK			"mark"
#define NFTLB_MAP_TYPE_PROTO		"inet_proto"

#define NFTLB_IPV4_FAMILY			0
#define NFTLB_IPV6_FAMILY			1
#define NFTLB_NETDEV_FAMILY			2

#define NFTLB_IPV4_FAMILY_STR		"ip"
#define NFTLB_IPV6_FAMILY_STR		"ip6"
#define NFTLB_NETDEV_FAMILY_STR		"netdev"

#define NFTLB_IP_ACTIVE				(1 << 0)
#define NFTLB_PROTO_IP_PORT_ACTIVE	(1 << 1)
#define NFTLB_PROTO_IP_ACTIVE		(1 << 2)
#define NFTLB_PROTO_PORT_ACTIVE		(1 << 3)
#define NFTLB_MARK_ACTIVE			(1 << 4)
#define NFTLB_TABLE_IP_ACTIVE		(1 << 5)
#define NFTLB_TABLE_IP6_ACTIVE		(1 << 6)
#define NFTLB_TABLE_NETDEV_ACTIVE	(1 << 7)

#define NFTLB_NFT_DADDR				"daddr"
#define NFTLB_NFT_DPORT				"dport"
#define NFTLB_NFT_SADDR				"saddr"
#define NFTLB_NFT_SPORT				"sport"

#define NFTLB_NFT_VERDICT_NONE		""
#define NFTLB_NFT_VERDICT_DROP		"drop"
#define NFTLB_NFT_VERDICT_ACCEPT	"accept"
#define NFTLB_NFT_PREFIX_POLICY_BL	"BL"
#define NFTLB_NFT_PREFIX_POLICY_WL	"WL"

#define NFTLB_NFT_ACTION_ADD		"add"
#define NFTLB_NFT_ACTION_DEL		"delete"
#define NFTLB_NFT_ACTION_FLUSH		"flush"

#define NFTLB_F_CHAIN_ING_FILTER	(1 << 0)
#define NFTLB_F_CHAIN_ING_DNAT		(1 << 1)
#define NFTLB_F_CHAIN_PRE_FILTER	(1 << 2)
#define NFTLB_F_CHAIN_PRE_DNAT		(1 << 3)
#define NFTLB_F_CHAIN_FWD_FILTER	(1 << 4)
#define NFTLB_F_CHAIN_POS_SNAT		(1 << 5)
#define NFTLB_F_CHAIN_OUT_FILTER	(1 << 6)
#define NFTLB_F_CHAIN_OUT_DNAT		(1 << 7)

#define NFTLB_CHECK_AVAIL			0
#define NFTLB_CHECK_USABLE			1

extern unsigned int serialize;
extern int masquerade_mark;
struct nft_ctx *ctx = NULL;

int nftlb_flowtable_prio = NFTLB_FLOWTABLE_BASE_PRIO;

enum chain_counter_position {
	NFTLB_F_CHAIN_ING_FILTER_POS,
	NFTLB_F_CHAIN_ING_DNAT_POS,
	NFTLB_F_CHAIN_PRE_FILTER_POS,
	NFTLB_F_CHAIN_PRE_DNAT_POS,
	NFTLB_F_CHAIN_FWD_FILTER_POS,
	NFTLB_F_CHAIN_POS_SNAT_POS,
	NFTLB_F_CHAIN_OUT_FILTER_POS,
	NFTLB_F_CHAIN_OUT_DNAT_POS,
	NFTLB_F_CHAIN_MAX,
};

enum map_modes {
	BCK_MAP_NONE,
	BCK_MAP_IPADDR,
	BCK_MAP_ETHADDR,
	BCK_MAP_WEIGHT,
	BCK_MAP_MARK,
	BCK_MAP_IPADDR_PORT,
	BCK_MAP_NAME,
	BCK_MAP_SRCIPADDR,
	BCK_MAP_BCK_IPADDR,
	BCK_MAP_BCK_MARK,
	BCK_MAP_BCK_IPADDR_F_PORT,
	BCK_MAP_BCK_BF_SRCIPADDR,
	BCK_MAP_BCK_ID,
	BCK_MAP_OFACE,
	BCK_MAP_PROTO_IPADDR_PORT,
	BCK_MAP_BCK_PROTO_IPADDR_F_PORT,
	BCK_MAP_PROTO_IPADDR,
	BCK_MAP_PROTO_PORT,
	BCK_MAP_PORT,
};

struct if_base_rule {
	char				*ifname;
	unsigned int		rules_v4;
	unsigned int		rules_v6;
};

struct if_base_rule_list {
	struct if_base_rule	*interfaces[NFTLB_MAX_IFACES];
	int					n_interfaces;
};

struct nft_chain_srv_family_counters {
	unsigned int proto_ip_port_cnt;
	unsigned int proto_port_cnt;
	unsigned int proto_ip_cnt;
	unsigned int bckmark_cnt;
};

struct nft_chain_srv_counters {
	struct nft_chain_srv_family_counters ipv4_counters;
	struct nft_chain_srv_family_counters ipv6_counters;
};

struct nft_chain_srv_counters service_counters[NFTLB_F_CHAIN_MAX];

static int get_chain_pos_counter(int type)
{
	if (type & NFTLB_F_CHAIN_ING_FILTER)
		return NFTLB_F_CHAIN_ING_FILTER_POS;
	else if (type & NFTLB_F_CHAIN_PRE_FILTER)
		return NFTLB_F_CHAIN_PRE_FILTER_POS;
	else if (type & NFTLB_F_CHAIN_PRE_DNAT)
		return NFTLB_F_CHAIN_PRE_DNAT_POS;
	else if (type & NFTLB_F_CHAIN_FWD_FILTER)
		return NFTLB_F_CHAIN_FWD_FILTER_POS;
	else if (type & NFTLB_F_CHAIN_POS_SNAT)
		return NFTLB_F_CHAIN_POS_SNAT_POS;
	else if (type & NFTLB_F_CHAIN_ING_DNAT)
		return NFTLB_F_CHAIN_ING_DNAT_POS;
	else if (type & NFTLB_F_CHAIN_OUT_FILTER)
		return NFTLB_F_CHAIN_OUT_FILTER_POS;
	else if (type & NFTLB_F_CHAIN_OUT_DNAT)
		return NFTLB_F_CHAIN_OUT_DNAT_POS;
	else
		return -1;
}

static unsigned int *get_service_counter(int type, unsigned int structure, int family)
{
	struct nft_chain_srv_family_counters *service_cnt;
	unsigned int *counter;

	if (family == VALUE_FAMILY_IPV6)
		service_cnt = &service_counters[get_chain_pos_counter(type)].ipv6_counters;
	else
		service_cnt = &service_counters[get_chain_pos_counter(type)].ipv4_counters;

	if (structure & NFTLB_PROTO_PORT_ACTIVE)
		counter = &(service_cnt->proto_port_cnt);
	else if (structure & NFTLB_PROTO_IP_ACTIVE)
		counter = &(service_cnt->proto_ip_cnt);
	else if (structure & NFTLB_PROTO_IP_PORT_ACTIVE)
		counter = &(service_cnt->proto_ip_port_cnt);
	else
		counter = &(service_cnt->bckmark_cnt);

	return counter;
}

static unsigned int get_rules_needed(struct address *a)
{
	unsigned int ret = 0;

	if (address_no_port(a))
		ret |= NFTLB_IP_ACTIVE | NFTLB_PROTO_IP_ACTIVE;
	else if (address_no_ipaddr(a))
		ret |= NFTLB_IP_ACTIVE | NFTLB_PROTO_PORT_ACTIVE;
	else if (!address_no_port(a) && !address_no_ipaddr(a))
		ret |= NFTLB_IP_ACTIVE | NFTLB_PROTO_IP_PORT_ACTIVE;

	return ret;
}

static void update_service_counters(struct address *a, int type, int structure, int family, int qty, int action)
{
	unsigned int *counter;

	if ((type & NFTLB_F_CHAIN_POS_SNAT) && structure)
		counter = get_service_counter(type, NFTLB_IP_ACTIVE | NFTLB_MARK_ACTIVE, family);
	else
		counter = get_service_counter(type, get_rules_needed(a), family);

	if (action == ACTION_START || action == ACTION_RELOAD) {
		*counter += qty;
	} else if ((action == ACTION_STOP || action == ACTION_DELETE) && ((int)*counter >= qty)) {
		*counter -= qty;
	}
}

static char * get_chain_print_pos(int pos)
{
	if (pos == NFTLB_F_CHAIN_ING_FILTER_POS)
		return "NFTLB_F_CHAIN_ING_FILTER";
	if (pos == NFTLB_F_CHAIN_PRE_FILTER_POS)
		return "NFTLB_F_CHAIN_PRE_FILTER";
	if (pos == NFTLB_F_CHAIN_PRE_DNAT_POS)
		return "NFTLB_F_CHAIN_PRE_DNAT";
	if (pos == NFTLB_F_CHAIN_FWD_FILTER_POS)
		return "NFTLB_F_CHAIN_FWD_FILTER";
	if (pos == NFTLB_F_CHAIN_POS_SNAT_POS)
		return "NFTLB_F_CHAIN_POS_SNAT";
	if (pos == NFTLB_F_CHAIN_ING_DNAT_POS)
		return "NFTLB_F_CHAIN_ING_DNAT";
	if (pos == NFTLB_F_CHAIN_OUT_FILTER_POS)
		return "NFTLB_F_CHAIN_OUT_FILTER";
	if (pos == NFTLB_F_CHAIN_OUT_DNAT_POS)
		return "NFTLB_F_CHAIN_OUT_DNAT";
	else
		return "UNKNOWN";
}

static void print_service_counters(void)
{
	int i;
	for (i = 0; i < NFTLB_F_CHAIN_MAX; i++) {
		tools_printlog(LOG_DEBUG, "%s(): [%s]", __FUNCTION__, get_chain_print_pos(i));
		tools_printlog(LOG_DEBUG, "%s():    ipv4_counters.proto_ip_port_cnt = %d", __FUNCTION__, service_counters[i].ipv4_counters.proto_ip_port_cnt);
		tools_printlog(LOG_DEBUG, "%s():    ipv4_counters.proto_port_cnt = %d", __FUNCTION__, service_counters[i].ipv4_counters.proto_port_cnt);
		tools_printlog(LOG_DEBUG, "%s():    ipv4_counters.proto_ip_cnt = %d", __FUNCTION__, service_counters[i].ipv4_counters.proto_ip_cnt);
		tools_printlog(LOG_DEBUG, "%s():    ipv4_counters.bckmark_cnt = %d", __FUNCTION__, service_counters[i].ipv4_counters.bckmark_cnt);
		tools_printlog(LOG_DEBUG, "%s():    ipv6_counters.proto_ip_port_cnt = %d", __FUNCTION__, service_counters[i].ipv6_counters.proto_ip_port_cnt);
		tools_printlog(LOG_DEBUG, "%s():    ipv6_counters.proto_port_cnt = %d", __FUNCTION__, service_counters[i].ipv6_counters.proto_port_cnt);
		tools_printlog(LOG_DEBUG, "%s():    ipv6_counters.proto_ip_cnt = %d", __FUNCTION__, service_counters[i].ipv6_counters.proto_ip_cnt);
		tools_printlog(LOG_DEBUG, "%s():    ipv6_counters.bckmark_cnt = %d", __FUNCTION__, service_counters[i].ipv6_counters.bckmark_cnt);
	}
}

struct nft_base_rules {
	unsigned int tables;
	unsigned int dnat_rules_v4;
	unsigned int dnat_rules_v6;
	unsigned int snat_rules_v4;
	unsigned int snat_rules_v6;
	unsigned int filter_rules_v4;
	unsigned int filter_rules_v6;
	unsigned int fwd_rules_v4;
	unsigned int fwd_rules_v6;
	unsigned int out_filter_rules_v4;
	unsigned int out_filter_rules_v6;
	unsigned int out_nat_rules_v4;
	unsigned int out_nat_rules_v6;
	unsigned int ndv_ingress_policies;
	struct if_base_rule_list ndv_ingress_rules;
	struct if_base_rule_list ndv_ingress_dnat_rules;
};

struct nft_base_rules nft_base_rules;

static void print_nft_base_rules(void)
{
	tools_printlog(LOG_DEBUG, "%s():    table ip = %d", __FUNCTION__, nft_base_rules.tables & NFTLB_TABLE_IP_ACTIVE);
	tools_printlog(LOG_DEBUG, "%s():    table ip6 = %d", __FUNCTION__, nft_base_rules.tables & NFTLB_TABLE_IP6_ACTIVE);
	tools_printlog(LOG_DEBUG, "%s():    table netdev = %d", __FUNCTION__, nft_base_rules.tables & NFTLB_TABLE_NETDEV_ACTIVE);
	tools_printlog(LOG_DEBUG, "%s():    dnat_rules_v4 = %d", __FUNCTION__, nft_base_rules.dnat_rules_v4);
	tools_printlog(LOG_DEBUG, "%s():    snat_rules_v4 = %d", __FUNCTION__, nft_base_rules.snat_rules_v4);
	tools_printlog(LOG_DEBUG, "%s():    filter_rules_v4 = %d", __FUNCTION__, nft_base_rules.filter_rules_v4);
	tools_printlog(LOG_DEBUG, "%s():    fwd_rules_v4 = %d", __FUNCTION__, nft_base_rules.fwd_rules_v4);
	tools_printlog(LOG_DEBUG, "%s():    out_filter_rules_v4 = %d", __FUNCTION__, nft_base_rules.out_filter_rules_v4);
	tools_printlog(LOG_DEBUG, "%s():    out_nat_rules_v4 = %d", __FUNCTION__, nft_base_rules.out_nat_rules_v4);

	tools_printlog(LOG_DEBUG, "%s():    dnat_rules_v6 = %d", __FUNCTION__, nft_base_rules.dnat_rules_v6);
	tools_printlog(LOG_DEBUG, "%s():    snat_rules_v6 = %d", __FUNCTION__, nft_base_rules.snat_rules_v6);
	tools_printlog(LOG_DEBUG, "%s():    filter_rules_v6 = %d", __FUNCTION__, nft_base_rules.filter_rules_v6);
	tools_printlog(LOG_DEBUG, "%s():    fwd_rules_v6 = %d", __FUNCTION__, nft_base_rules.fwd_rules_v6);
	tools_printlog(LOG_DEBUG, "%s():    out_filter_rules_v6 = %d", __FUNCTION__, nft_base_rules.out_filter_rules_v6);
	tools_printlog(LOG_DEBUG, "%s():    out_nat_rules_v6 = %d", __FUNCTION__, nft_base_rules.out_nat_rules_v6);

	tools_printlog(LOG_DEBUG, "%s():    ndv_ingress_policies = %d", __FUNCTION__, nft_base_rules.ndv_ingress_policies);
	tools_printlog(LOG_DEBUG, "%s():    ndv_ingress_rules = %d", __FUNCTION__, nft_base_rules.ndv_ingress_rules.n_interfaces);
	tools_printlog(LOG_DEBUG, "%s():    ndv_ingress_dnat_rules = %d", __FUNCTION__, nft_base_rules.ndv_ingress_dnat_rules.n_interfaces);
}

static int reset_ndv_base(struct if_base_rule_list *ndv_if_rules)
{
	int i;

	for (i = 0; i < ndv_if_rules->n_interfaces; i++) {
		if (!ndv_if_rules->interfaces[i])
			break;
		if (ndv_if_rules->interfaces[i]->ifname)
			free(ndv_if_rules->interfaces[i]->ifname);
		if (ndv_if_rules->interfaces[i])
			free(ndv_if_rules->interfaces[i]);
	}

	ndv_if_rules->n_interfaces = 0;

	return 0;
}

static void clean_rules_counters(void)
{
	reset_ndv_base(&nft_base_rules.ndv_ingress_rules);
	reset_ndv_base(&nft_base_rules.ndv_ingress_dnat_rules);
	nft_base_rules.dnat_rules_v4 = 0;
	nft_base_rules.dnat_rules_v6 = 0;
	nft_base_rules.filter_rules_v4 = 0;
	nft_base_rules.filter_rules_v6 = 0;
	nft_base_rules.fwd_rules_v4 = 0;
	nft_base_rules.fwd_rules_v6 = 0;
	nft_base_rules.snat_rules_v4 = 0;
	nft_base_rules.snat_rules_v6 = 0;
	nft_base_rules.out_filter_rules_v4 = 0;
	nft_base_rules.out_filter_rules_v6 = 0;
	nft_base_rules.out_nat_rules_v4 = 0;
	nft_base_rules.out_nat_rules_v6 = 0;
}

static struct if_base_rule * get_ndv_base(struct if_base_rule_list *ndv_if_rules, char *ifname)
{
	int i;

	for (i = 0; i < ndv_if_rules->n_interfaces; i++) {
		if (strcmp(ndv_if_rules->interfaces[i]->ifname, ifname) == 0)
			return ndv_if_rules->interfaces[i];
	}

	return NULL;
}

static struct if_base_rule * add_ndv_base(struct if_base_rule_list *ndv_if_rules, char *ifname)
{
	struct if_base_rule *ifentry;

	if (ndv_if_rules->n_interfaces == NFTLB_MAX_IFACES) {
		tools_printlog(LOG_ERR, "%s():%d: maximum number of interfaces reached", __FUNCTION__, __LINE__);
		return NULL;
	}

	ifentry = (struct if_base_rule *)malloc(sizeof(struct if_base_rule));
	if (!ifentry) {
		tools_printlog(LOG_ERR, "%s():%d: unable to allocate interface struct for %s", __FUNCTION__, __LINE__, ifname);
		return NULL;
	}

	ndv_if_rules->interfaces[ndv_if_rules->n_interfaces] = ifentry;
	ndv_if_rules->n_interfaces++;

	ifentry->ifname = (char *)malloc(strlen(ifname));
	if (!ifentry->ifname) {
		tools_printlog(LOG_ERR, "%s():%d: unable to allocate interface name for %s", __FUNCTION__, __LINE__, ifname);
		return NULL;
	}

	sprintf(ifentry->ifname, "%s", ifname);
	ifentry->rules_v4 = 0;
	ifentry->rules_v6 = 0;

	return ifentry;
}

static int del_ndv_base(struct if_base_rule_list *ndv_if_rules, char *ifname)
{
	struct if_base_rule *ifentry;

	ifentry = get_ndv_base(ndv_if_rules, ifname);
	if (!ifentry)
		return 1;

	free(ifentry->ifname);
	free(ifentry);

	if (ndv_if_rules->n_interfaces > 0)
		return ndv_if_rules->n_interfaces--;

	return 0;
}

static int exec_cmd_open(char *cmd, const char **out, int error_output)
{
	int error;

	if (strlen(cmd) == 0 || strcmp(cmd, "") == 0)
		return 0;

	tools_printlog(LOG_NOTICE, "nft command exec : %s", cmd);

	ctx = nft_ctx_new(0);
	nft_ctx_buffer_error(ctx);

	if (out != NULL)
		nft_ctx_buffer_output(ctx);

	error = nft_run_cmd_from_buffer(ctx, cmd);

	if (error && error_output)
		tools_printlog(LOG_ERR, "nft command error : %s", nft_ctx_get_error_buffer(ctx));

	if (out != NULL)
		*out = nft_ctx_get_output_buffer(ctx);

	return error;
}

static void exec_cmd_close(const char *out)
{
	if (ctx == NULL)
		return;

	if (out != NULL)
		nft_ctx_unbuffer_output(ctx);

	nft_ctx_unbuffer_error(ctx);
	nft_ctx_free(ctx);
	ctx = NULL;
}

static int exec_cmd(char *cmd)
{
	int error;

	error = exec_cmd_open(cmd, NULL, 1);
	exec_cmd_close(NULL);

	return error;
}

static int exec_cmd_unbuffered(struct sbuffer *buf)
{
	int error;
	error = exec_cmd(get_buf_data(buf));
	reset_buf(buf);

	return error;
}

static void concat_exec_cmd(struct sbuffer *buf, char *fmt, ...)
{
	int len;
	va_list args;

	va_start(args, fmt);
	len = vsnprintf(0, 0, fmt, args);
	va_end(args);

	va_start(args, fmt);
	concat_buf_va(buf, len, fmt, args);
	va_end(args);

	if (serialize)
		exec_cmd_unbuffered(buf);
}

static char * print_nft_mode_service(int mode, int family)
{
	if (family == VALUE_FAMILY_IPV6) {
		if (mode & NFTLB_PROTO_IP_ACTIVE)
			return NFTLB_IP_SERVICES6_MAP;
		else if (mode & NFTLB_PROTO_PORT_ACTIVE)
			return NFTLB_PORT_SERVICES6_MAP;
		else
			return NFTLB_PROTO_SERVICES6_MAP;
	} else {
		if (mode & NFTLB_PROTO_IP_ACTIVE)
			return NFTLB_IP_SERVICES_MAP;
		else if (mode & NFTLB_PROTO_PORT_ACTIVE)
			return NFTLB_PORT_SERVICES_MAP;
		else
			return NFTLB_PROTO_SERVICES_MAP;
	}
}

static int get_address_service_mode(struct address *a)
{
	if (address_no_port(a))
		return NFTLB_PROTO_IP_ACTIVE;
	else if (address_no_ipaddr(a))
		return NFTLB_PROTO_PORT_ACTIVE;
	else
		return NFTLB_PROTO_IP_PORT_ACTIVE;
}

static char * print_nft_family_type(int family)
{
	switch (family) {
	case VALUE_FAMILY_IPV6:
		return NFTLB_MAP_TYPE_IPV6;
	default:
		return NFTLB_MAP_TYPE_IPV4;
	}
}

static char * print_nft_family(int family)
{
	switch (family) {
	case VALUE_FAMILY_NETDEV:
		return NFTLB_NETDEV_FAMILY_STR;
	case VALUE_FAMILY_IPV6:
		return NFTLB_IPV6_FAMILY_STR;
	default:
		return NFTLB_IPV4_FAMILY_STR;
	}
}

static char * print_nft_family_protocol(int family)
{
	switch (family) {
	case VALUE_FAMILY_IPV6:
		return NFTLB_IPV6_PROTOCOL;
	default:
		return NFTLB_IPV4_PROTOCOL;
	}
}

static char * print_nft_table_family(int family, unsigned int type)
{
	if (family == VALUE_FAMILY_NETDEV || type & NFTLB_F_CHAIN_ING_FILTER || type & NFTLB_F_CHAIN_ING_DNAT)
		return NFTLB_NETDEV_FAMILY_STR;
	else if (family == VALUE_FAMILY_IPV6)
		return NFTLB_IPV6_FAMILY_STR;
	else
		return NFTLB_IPV4_FAMILY_STR;
}

static char * print_nft_protocol(int protocol)
{
	switch (protocol) {
	case VALUE_PROTO_UDP:
		return NFTLB_UDP_PROTO;
	case VALUE_PROTO_SCTP:
		return NFTLB_SCTP_PROTO;
	default:
		return NFTLB_TCP_PROTO;
	}
}

static char * print_nft_verdict(int verdict, int type)
{
	if (type == VALUE_TYPE_ALLOW && verdict & VALUE_VERDICT_ACCEPT)
		return NFTLB_NFT_VERDICT_ACCEPT;
	else
		if (type == VALUE_TYPE_DENY && verdict & VALUE_VERDICT_DROP)
			return NFTLB_NFT_VERDICT_DROP;
	return NFTLB_NFT_VERDICT_NONE;
}

static char * print_nft_prefix_policy(enum type type)
{
	if (type == VALUE_TYPE_ALLOW)
		return NFTLB_NFT_PREFIX_POLICY_WL;
	else
		return NFTLB_NFT_PREFIX_POLICY_BL;
}

static unsigned int * get_rules_applied(int type, int family, char *iface)
{
	unsigned int * ret = NULL;
	struct if_base_rule *if_base;

	if (type & NFTLB_F_CHAIN_ING_FILTER) {
		if_base = get_ndv_base(&nft_base_rules.ndv_ingress_rules, iface);
		if (!if_base)
			if_base = add_ndv_base(&nft_base_rules.ndv_ingress_rules, iface);
		if (!if_base)
			return ret;
		if (family == VALUE_FAMILY_IPV4)
			ret = &if_base->rules_v4;
		if (family == VALUE_FAMILY_IPV6)
			ret = &if_base->rules_v6;

	} else if (type & NFTLB_F_CHAIN_ING_DNAT) {
		if_base = get_ndv_base(&nft_base_rules.ndv_ingress_dnat_rules, iface);
		if (!if_base)
			if_base = add_ndv_base(&nft_base_rules.ndv_ingress_dnat_rules, iface);
		if (!if_base)
			return ret;
		if (family == VALUE_FAMILY_IPV4)
			ret = &if_base->rules_v4;
		if (family == VALUE_FAMILY_IPV6)
			ret = &if_base->rules_v6;

	} else if (type & NFTLB_F_CHAIN_PRE_DNAT) {
		if (family == VALUE_FAMILY_IPV4)
			ret = &nft_base_rules.dnat_rules_v4;
		if (family == VALUE_FAMILY_IPV6)
			ret = &nft_base_rules.dnat_rules_v6;

	} else if (type & NFTLB_F_CHAIN_PRE_FILTER) {
		if (family == VALUE_FAMILY_IPV4)
			ret = &nft_base_rules.filter_rules_v4;
		if (family == VALUE_FAMILY_IPV6)
			ret = &nft_base_rules.filter_rules_v6;

	} else if (type & NFTLB_F_CHAIN_FWD_FILTER) {
		if (family == VALUE_FAMILY_IPV4)
			ret = &nft_base_rules.fwd_rules_v4;
		if (family == VALUE_FAMILY_IPV6)
			ret = &nft_base_rules.fwd_rules_v6;

	} else if (type & NFTLB_F_CHAIN_POS_SNAT) {
		if (family == VALUE_FAMILY_IPV4)
			ret = &nft_base_rules.snat_rules_v4;
		if (family == VALUE_FAMILY_IPV6)
			ret = &nft_base_rules.snat_rules_v6;

	} else if (type & NFTLB_F_CHAIN_OUT_FILTER) {
		if (family == VALUE_FAMILY_IPV4)
			ret = &nft_base_rules.out_filter_rules_v4;
		if (family == VALUE_FAMILY_IPV6)
			ret = &nft_base_rules.out_filter_rules_v6;

	} else if (type & NFTLB_F_CHAIN_OUT_DNAT) {
		if (family == VALUE_FAMILY_IPV4)
			ret = &nft_base_rules.out_nat_rules_v4;
		if (family == VALUE_FAMILY_IPV6)
			ret = &nft_base_rules.out_nat_rules_v6;
	}

	return ret;
}

static void logprefix_replace(char *buf, char *token, char *value)
{
	char tmp[NFTLB_MAX_OBJ_NAME] = { 0 };
	char *ptr = buf;
	char *tmpptr = tmp;

	while (*ptr != '\0') {
		if (strncmp(token, ptr, strlen(token)) == 0) {
			strcat(tmpptr, value);
			ptr += strlen(token);
			tmpptr += strlen(value);
		}
		*tmpptr = *ptr;
		ptr++;
		tmpptr++;
	}

	*tmpptr = '\0';
	sprintf(buf, "%s", tmp);
}

static void print_log_format(char *buf, int key, int type, struct nftst *n)
{
	struct farm *f = nftst_get_farm(n);
	struct address *a = nftst_get_address(n);
	struct backend *b = nftst_get_backend(n);
	struct policy *p = nftst_get_policy(n);

	if (!f && !a)
		return;

	switch (key) {
	case KEY_LOGPREFIX:
		if (p) {
			sprintf(buf, "%s", p->logprefix);
			logprefix_replace(buf, "KNAME", "policy");
			if (f)
				logprefix_replace(buf, "FNAME", f->name);
			if (a)
				logprefix_replace(buf, "ANAME", a->name);
			logprefix_replace(buf, "PNAME", p->name);
			logprefix_replace(buf, "TYPE", print_nft_prefix_policy(p->type));
			return;
		}
		if (f) {
			sprintf(buf, "%s", f->logprefix);
			logprefix_replace(buf, "FNAME", f->name);
		}
		if (a) {
			sprintf(buf, "%s", a->logprefix);
			logprefix_replace(buf, "ANAME", a->name);
		}
		logprefix_replace(buf, "KNAME", CONFIG_KEY_LOG);
		if ((a || (f->log & VALUE_LOG_INPUT)) && ((type & NFTLB_F_CHAIN_ING_FILTER) || (type & NFTLB_F_CHAIN_PRE_FILTER) || (type & NFTLB_F_CHAIN_PRE_DNAT)))
			logprefix_replace(buf, "TYPE", "IN");
		else if ((f->log & VALUE_LOG_FORWARD) && (type & NFTLB_F_CHAIN_FWD_FILTER))
			logprefix_replace(buf, "TYPE", "FWD");
		else if ((f->log & VALUE_LOG_OUTPUT) && ((type & NFTLB_F_CHAIN_POS_SNAT) || (type & NFTLB_F_CHAIN_ING_DNAT)))
			logprefix_replace(buf, "TYPE", "OUT");
		break;
	case KEY_NEWRTLIMIT_LOGPREFIX:
		sprintf(buf, "%s", f->newrtlimit_logprefix);
		logprefix_replace(buf, "KNAME", CONFIG_KEY_NEWRTLIMIT);
		if (f)
			logprefix_replace(buf, "FNAME", f->name);
		if (a)
			logprefix_replace(buf, "ANAME", a->name);
		break;
	case KEY_RSTRTLIMIT_LOGPREFIX:
		sprintf(buf, "%s", f->rstrtlimit_logprefix);
		logprefix_replace(buf, "KNAME", CONFIG_KEY_RSTRTLIMIT);
		if (f)
			logprefix_replace(buf, "FNAME", f->name);
		if (a)
			logprefix_replace(buf, "ANAME", a->name);
		break;
	case KEY_ESTCONNLIMIT_LOGPREFIX:
		if (b) {
			sprintf(buf, "%s", b->estconnlimit_logprefix);
			logprefix_replace(buf, "KNAME", CONFIG_KEY_ESTCONNLIMIT);
			logprefix_replace(buf, "BNAME", b->name);
			if (f)
				logprefix_replace(buf, "FNAME", f->name);
			if (a)
				logprefix_replace(buf, "ANAME", a->name);
			return;
		}
		sprintf(buf, "%s", f->estconnlimit_logprefix);
		logprefix_replace(buf, "KNAME", CONFIG_KEY_ESTCONNLIMIT);
		if (f)
			logprefix_replace(buf, "FNAME", f->name);
		if (a)
			logprefix_replace(buf, "ANAME", a->name);
		break;
	case KEY_TCPSTRICT_LOGPREFIX:
		sprintf(buf, "%s", f->tcpstrict_logprefix);
		logprefix_replace(buf, "KNAME", CONFIG_KEY_TCPSTRICT);
		if (f)
			logprefix_replace(buf, "FNAME", f->name);
		if (a)
			logprefix_replace(buf, "ANAME", a->name);
		break;
	default:
		break;
	}
}

static int need_filter(struct farm *f)
{
	return (!farm_is_ingress_mode(f));
}

static int need_forward(struct farm *f)
{
	return ((f->log & VALUE_LOG_FORWARD) || farm_needs_flowtable(f));
}

static int need_output(struct farm *f)
{
	return farm_needs_intraconnect(f);
}

static unsigned int get_stage_by_farm_mode(struct farm *f)
{
	if (f->mode == VALUE_MODE_DSR)
		return NFTLB_F_CHAIN_ING_FILTER;
	else if (f->mode == VALUE_MODE_STLSDNAT)
		return NFTLB_F_CHAIN_ING_DNAT;
	else
		return NFTLB_F_CHAIN_PRE_FILTER;
}

static void get_chain_name(char *chain, char *name, int type)
{
	if (type & NFTLB_F_CHAIN_ING_FILTER)
		snprintf(chain, NFTLB_MAX_OBJ_NAME, "%s", name);
	else if (type & NFTLB_F_CHAIN_PRE_FILTER)
		snprintf(chain, NFTLB_MAX_OBJ_NAME, "%s-%s", NFTLB_TYPE_FILTER, name);
	else if (type & NFTLB_F_CHAIN_PRE_DNAT)
		snprintf(chain, NFTLB_MAX_OBJ_NAME, "%s-%s", NFTLB_TYPE_NAT, name);
	else if (type & NFTLB_F_CHAIN_FWD_FILTER)
		snprintf(chain, NFTLB_MAX_OBJ_NAME, "%s-%s", NFTLB_TYPE_FWD, name);
	else if (type & NFTLB_F_CHAIN_ING_DNAT)
		snprintf(chain, NFTLB_MAX_OBJ_NAME, "%s-back", name);
	else if (type & NFTLB_F_CHAIN_OUT_FILTER)
		snprintf(chain, NFTLB_MAX_OBJ_NAME, "%s-%s", NFTLB_TYPE_FILTER, name);
	else if (type & NFTLB_F_CHAIN_OUT_DNAT)
		snprintf(chain, NFTLB_MAX_OBJ_NAME, "%s-%s", NFTLB_TYPE_NAT, name);
}

static void get_flowtable_name(char *name, struct farm *f)
{
	snprintf(name, NFTLB_MAX_OBJ_NAME, "ft-%s", f->name);
}

static void get_nft_name_service(char *name, int srv_mode, char *trailing, int type, int family)
{
	if (type & NFTLB_F_CHAIN_ING_FILTER)
		sprintf(name, "%s%s", print_nft_mode_service(srv_mode, family), trailing);
	else if (type & NFTLB_F_CHAIN_PRE_FILTER)
		sprintf(name, "%s-%s%s", NFTLB_TYPE_FILTER, print_nft_mode_service(srv_mode, family), trailing);
	else if (type & NFTLB_F_CHAIN_PRE_DNAT)
		sprintf(name, "%s-%s%s", NFTLB_TYPE_NAT, print_nft_mode_service(srv_mode, family), trailing);
	else if (type & NFTLB_F_CHAIN_FWD_FILTER)
		sprintf(name, "%s-%s%s", NFTLB_TYPE_FWD, print_nft_mode_service(srv_mode, family), trailing);
	else if (type & NFTLB_F_CHAIN_POS_SNAT)
		sprintf(name, "%s-back%s", print_nft_mode_service(NFTLB_PROTO_IP_ACTIVE, family), trailing);
	else if (type & NFTLB_F_CHAIN_ING_DNAT)
		sprintf(name, "%s-dnat%s", print_nft_mode_service(srv_mode, family), trailing);
	else if (type & NFTLB_F_CHAIN_OUT_FILTER)
		sprintf(name, "%s-%s%s", NFTLB_TABLE_OUT_FILTER, print_nft_mode_service(srv_mode, family), trailing);
	else if (type & NFTLB_F_CHAIN_OUT_DNAT)
		sprintf(name, "%s-%s%s", NFTLB_TABLE_OUT_NAT, print_nft_mode_service(srv_mode, family), trailing);
}

static void get_address_service(char *name, struct address *a, int type, int family, int key_mode)
{
	char trailing[NFTLB_MAX_OBJ_NAME];

	if (type & NFTLB_F_CHAIN_ING_FILTER || type & NFTLB_F_CHAIN_ING_DNAT) {
		sprintf(trailing, "-%s", a->iface);
		get_nft_name_service(name, get_address_service_mode(a), trailing, type, family);
	}

	else if (type & NFTLB_F_CHAIN_POS_SNAT && (key_mode == BCK_MAP_BCK_ID || key_mode == BCK_MAP_BCK_MARK))
		get_nft_name_service(name, get_address_service_mode(a), "-m", type, family);
	else
		get_nft_name_service(name, get_address_service_mode(a), "", type, family);
}

static int nft_table_handler(struct sbuffer *buf, char *str_family, int action)
{
	switch (action) {
	case ACTION_RELOAD:
		concat_exec_cmd(buf, " ; flush table %s %s", str_family, NFTLB_TABLE_NAME);
		break;
	case ACTION_START:
		concat_exec_cmd(buf, " ; add table %s %s", str_family, NFTLB_TABLE_NAME);
		break;
	case ACTION_STOP:
	case ACTION_DELETE:
		concat_exec_cmd(buf, " ; delete table %s %s", str_family, NFTLB_TABLE_NAME);
		break;
	default:
		break;
	}

	return 0;
}

static int nft_chain_handler(struct sbuffer *buf, char *str_family, char *chain, char *str_type, char *hook, char *str_device, int priority, int action)
{
	switch (action) {
	case ACTION_RELOAD:
		concat_exec_cmd(buf, " ; flush chain %s %s %s", str_family, NFTLB_TABLE_NAME, chain);
		break;
	case ACTION_START:
		concat_buf(buf, " ; add chain %s %s %s", str_family, NFTLB_TABLE_NAME, chain);
		if (!obj_equ_attribute_string(str_type, "") && !obj_equ_attribute_string(hook, "")) {
			concat_buf(buf, " { type %s hook %s", str_type, hook);
			if (!obj_equ_attribute_string(str_device, ""))
				concat_buf(buf, " device %s", str_device);
			concat_buf(buf, " priority %d ;}", priority);
		}
		concat_exec_cmd(buf, "");
		break;
	case ACTION_STOP:
	case ACTION_DELETE:
		concat_exec_cmd(buf, " ; delete chain %s %s %s", str_family, NFTLB_TABLE_NAME, chain);
		break;
	default:
		break;
	}

	return 0;
}

static int run_nftst_rules_gen_chain(struct sbuffer *buf, struct nftst *n, int family, int type, int action)
{
	struct farm *f = nftst_get_farm(n);
	struct address *a = nftst_get_address(n);
	char chain[NFTLB_MAX_OBJ_NAME] = { 0 };

	get_chain_name(chain, nftst_get_name(n), type);

	switch (action) {
	case ACTION_RELOAD:
		if ((nftst_get_chains(n) & type) == 0)
			action = ACTION_START;
		break;
	case ACTION_START:
		if (nftst_get_chains(n) & type)
			action = ACTION_RELOAD;
		break;
	case ACTION_DELETE:
	case ACTION_STOP:
		if ((nftst_get_chains(n) & type) == 0)
			action = ACTION_NONE;
		break;
	default:
		break;
	}

	// output uses the same farm chains than prerouting-filter and prerouting-nat
	if (type == NFTLB_F_CHAIN_OUT_FILTER || type == NFTLB_F_CHAIN_OUT_DNAT)
		return 0;

	switch (action) {
	case ACTION_RELOAD:
	case ACTION_START:
		nft_chain_handler(buf, print_nft_table_family(family, type), chain, NULL, NULL, NULL, 0, action);
		nftst_set_chains(n, nftst_get_chains(n) | type);
		break;
	case ACTION_DELETE:
	case ACTION_STOP:
		if ((f && f->addresses_used == 1) ||
			(!f && a)){
			nft_chain_handler(buf, print_nft_table_family(family, type), chain, NULL, NULL, NULL, 0, action);
			nftst_set_chains(n, nftst_get_chains(n) & ~type);
		}
		break;
	default:
		break;
	}

	return 0;
}

static int run_base_chain_filter_ctmark(struct sbuffer *buf, int type, char *chain_family, char *base_chain)
{
	if (type & NFTLB_F_CHAIN_PRE_FILTER)
		concat_exec_cmd(buf, " ; add rule %s %s %s mark set ct mark", chain_family, NFTLB_TABLE_NAME, base_chain);

	return 0;
}

static int run_base_chain_postrouting_masquerade(struct sbuffer *buf, int type, char *chain_family)
{
	if (type & NFTLB_F_CHAIN_POS_SNAT) {
		concat_exec_cmd(buf, " ; add rule %s %s %s ct mark 0x0 ct mark set meta mark", chain_family, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING);
		concat_exec_cmd(buf, " ; add rule %s %s %s ct mark and 0x%x == 0x%x masquerade", chain_family, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, masquerade_mark, masquerade_mark);
	}

	return 0;
}

static int run_base_chain_postrouting_bckmark(struct sbuffer *buf, char *service, int type, int family)
{
	if (~type & NFTLB_F_CHAIN_POS_SNAT)
		return 0;

	concat_exec_cmd(buf, " ; add map %s %s %s { type %s : %s ;}", print_nft_family(family), NFTLB_TABLE_NAME, service, NFTLB_MAP_TYPE_MARK, print_nft_family_type(family));
	concat_exec_cmd(buf, " ; add rule %s %s %s snat to ct mark map @%s", print_nft_family(family), NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, service);

	return 1;
}

static int run_farm_rules_gen_meta_param(struct sbuffer *buf, int protocol, int family, int param, int type)
{
	int items = 0;

	if ((param & VALUE_META_NONE) ||
		(param & VALUE_META_SRCIP)) {
		(type == NFTLB_MAP_KEY_TYPE) ? concat_buf(buf, " %s", print_nft_family_type(family)) : concat_buf(buf, " %s saddr", print_nft_family(family));
		items++;
	}

	if (param & VALUE_META_DSTIP) {
		if (items)
			concat_buf(buf, " .");
		(type == NFTLB_MAP_KEY_TYPE) ? concat_buf(buf, " %s", print_nft_family_type(family)) : concat_buf(buf, " %s daddr", print_nft_family(family));
		items++;
	}

	if (param & VALUE_META_SRCPORT) {
		if (items)
			concat_buf(buf, " .");
		(type == NFTLB_MAP_KEY_TYPE) ? concat_buf(buf, " inet_service") : concat_buf(buf, " %s sport", print_nft_protocol(protocol));
		items++;
	}

	if (param & VALUE_META_DSTPORT) {
		if (items)
			concat_buf(buf, " .");
		(type == NFTLB_MAP_KEY_TYPE) ? concat_buf(buf, " inet_service") : concat_buf(buf, " %s dport", print_nft_protocol(protocol));
		items++;
	}

	if (param & VALUE_META_SRCMAC) {
		if (items)
			concat_buf(buf, " .");
		(type == NFTLB_MAP_KEY_TYPE) ? concat_buf(buf, " ether_addr") : concat_buf(buf, " ether saddr");
		items++;
	}

	if (param & VALUE_META_DSTMAC) {
		if (items)
			concat_buf(buf, " .");
		(type == NFTLB_MAP_KEY_TYPE) ? concat_buf(buf, " ether_addr") : concat_buf(buf, " ether daddr");
	}

	if (param & VALUE_META_MARK) {
		if (items)
			concat_buf(buf, " .");
		concat_buf(buf, " mark");
	}

	return 0;
}

static void run_farm_map(struct sbuffer *buf, struct address *a, int family, unsigned int stage, char *mapname, int key, int data, int timeout, int action)
{
	switch (action) {
	case ACTION_START:
		concat_buf(buf, " ; add map %s %s %s { type ", print_nft_table_family(family, stage), NFTLB_TABLE_NAME, mapname);
		run_farm_rules_gen_meta_param(buf, a->protocol, family, key, NFTLB_MAP_KEY_TYPE);
		concat_buf(buf, " :");
		run_farm_rules_gen_meta_param(buf, a->protocol, family, data, NFTLB_MAP_KEY_TYPE);
		concat_buf(buf, ";");
		if (timeout != -1)
			concat_buf(buf, " timeout %ds;", timeout);
		concat_exec_cmd(buf, " }");
		break;
	case ACTION_DELETE:
	case ACTION_STOP:
		concat_exec_cmd(buf, " ; delete map %s %s %s", print_nft_table_family(family, stage), NFTLB_TABLE_NAME, mapname);
		break;
	case ACTION_RELOAD:
	default:
		break;
	}
}

static int run_base_table(struct sbuffer *buf, int type, int family, int action)
{
	char *chain_family = print_nft_table_family(family, type);

	if (action == ACTION_STOP || action == ACTION_DELETE) {
		// delete ip and ip6 based nftlb tables
		if ((type & NFTLB_F_CHAIN_PRE_DNAT || type & NFTLB_F_CHAIN_PRE_FILTER) &&
			((nft_base_rules.tables & NFTLB_TABLE_IP_ACTIVE && family == VALUE_FAMILY_IPV4 && (nft_base_rules.dnat_rules_v4 == 0 && nft_base_rules.filter_rules_v4 == 0)) ||
				(nft_base_rules.tables & NFTLB_TABLE_IP6_ACTIVE && family == VALUE_FAMILY_IPV6 && (nft_base_rules.dnat_rules_v6 == 0 && nft_base_rules.filter_rules_v6 == 0)))) {
			if (family == VALUE_FAMILY_IPV4)
				nft_base_rules.tables &= ~NFTLB_TABLE_IP_ACTIVE;
			if (family == VALUE_FAMILY_IPV6)
				nft_base_rules.tables &= ~NFTLB_TABLE_IP6_ACTIVE;
			nft_table_handler(buf, chain_family, ACTION_DELETE);
		}

		if (type & NFTLB_F_CHAIN_ING_FILTER && (nft_base_rules.tables & NFTLB_TABLE_NETDEV_ACTIVE) &&
			nft_base_rules.ndv_ingress_policies == 0 && nft_base_rules.ndv_ingress_rules.n_interfaces == 0 && nft_base_rules.ndv_ingress_dnat_rules.n_interfaces == 0) {
			nft_base_rules.tables &= ~NFTLB_TABLE_NETDEV_ACTIVE;
			nft_table_handler(buf, chain_family, ACTION_DELETE);
		}
	}

	if (action == ACTION_RELOAD || action == ACTION_START) {
		if ((type & NFTLB_F_CHAIN_PRE_DNAT || type & NFTLB_F_CHAIN_PRE_FILTER) &&
			((~nft_base_rules.tables & NFTLB_TABLE_IP_ACTIVE && family == VALUE_FAMILY_IPV4 && (nft_base_rules.dnat_rules_v4 == 0 && nft_base_rules.filter_rules_v4 == 0)) ||
			(~nft_base_rules.tables & NFTLB_TABLE_IP6_ACTIVE && family == VALUE_FAMILY_IPV6 && (nft_base_rules.dnat_rules_v6 == 0 && nft_base_rules.filter_rules_v6 == 0)))) {
			if (family == VALUE_FAMILY_IPV4)
				nft_base_rules.tables |= NFTLB_TABLE_IP_ACTIVE;
			if (family == VALUE_FAMILY_IPV6)
				nft_base_rules.tables |= NFTLB_TABLE_IP6_ACTIVE;
			nft_table_handler(buf, chain_family, ACTION_START);
		}

		if (type & NFTLB_F_CHAIN_ING_FILTER && ~nft_base_rules.tables & NFTLB_TABLE_NETDEV_ACTIVE &&
			nft_base_rules.ndv_ingress_rules.n_interfaces == 0 &&
			nft_base_rules.ndv_ingress_dnat_rules.n_interfaces == 0) {
			nft_base_rules.tables |= NFTLB_TABLE_NETDEV_ACTIVE;
			nft_table_handler(buf, chain_family, ACTION_START);
		}
	}

	return 0;
}

static int run_base_chain(struct sbuffer *buf, struct nftst *n, int type, int family, unsigned int rules_needed, int action)
{
	char service[NFTLB_MAX_OBJ_NAME-2] = { 0 };
	char servicem[NFTLB_MAX_OBJ_NAME] = { 0 };
	char base_chain[NFTLB_MAX_OBJ_NAME] = { 0 };
	char chain_device[NFTLB_MAX_OBJ_DEVICE] = { 0 };
	char trailing[NFTLB_MAX_OBJ_NAME] = { 0 };
	char *chain_type;
	char *chain_hook;
	char *chain_family;
	int chain_prio;
	unsigned int *base_rules;
	unsigned int *base_rules_t;
	struct if_base_rule_list *if_base_list = &nft_base_rules.ndv_ingress_rules;
	struct address *a = nftst_get_address(n);
	struct farm *f = nftst_get_farm(n);

	tools_printlog(LOG_DEBUG, "%s():%d: chain %s - action %d", __FUNCTION__, __LINE__, get_chain_print_pos(get_chain_pos_counter(type)), action);

	get_address_service(service, a, type, family, BCK_MAP_NONE);
	get_address_service(servicem, a, NFTLB_F_CHAIN_POS_SNAT, family, BCK_MAP_BCK_MARK);
	chain_family = print_nft_table_family(family, type);

	if (type & NFTLB_F_CHAIN_ING_FILTER) {
		base_rules = get_rules_applied(type, family, a->iface);
		if (!base_rules)
			return 1;
		chain_prio = NFTLB_INGRESS_PRIO;
		chain_type = NFTLB_TYPE_FILTER;
		chain_hook = NFTLB_HOOK_INGRESS;
		snprintf(chain_device, NFTLB_MAX_OBJ_DEVICE, "%s", a->iface);
		snprintf(base_chain, NFTLB_MAX_OBJ_NAME, "%s-%s", NFTLB_TABLE_INGRESS, a->iface);
		snprintf(trailing, NFTLB_MAX_OBJ_NAME, "-%s", a->iface);

	} else if (type & NFTLB_F_CHAIN_ING_DNAT) {
		if (!f)
			return 0;
		base_rules = get_rules_applied(type, family, f->oface);
		if (!base_rules)
			return 1;
		if_base_list = &nft_base_rules.ndv_ingress_dnat_rules;
		chain_prio = NFTLB_INGRESS_DNAT_PRIO;
		chain_type = NFTLB_TYPE_FILTER;
		chain_hook = NFTLB_HOOK_INGRESS;
		snprintf(chain_device, NFTLB_MAX_OBJ_DEVICE, "%s", f->oface);
		snprintf(base_chain, NFTLB_MAX_OBJ_NAME, "%s-dnat-%s", NFTLB_TABLE_INGRESS, chain_device);
		snprintf(trailing, NFTLB_MAX_OBJ_NAME, "-%s", f->oface);

	} else if (type & NFTLB_F_CHAIN_PRE_FILTER) {
		base_rules = get_rules_applied(type, family, "");
		chain_prio = NFTLB_FILTER_PRIO;
		snprintf(base_chain, NFTLB_MAX_OBJ_NAME, "%s", NFTLB_TABLE_FILTER);
		chain_type = NFTLB_TYPE_FILTER;
		chain_hook = NFTLB_HOOK_PREROUTING;

	} else if (type & NFTLB_F_CHAIN_PRE_DNAT) {
		base_rules = get_rules_applied(type, family, "");
		chain_prio = NFTLB_PREROUTING_PRIO;
		snprintf(base_chain, NFTLB_MAX_OBJ_NAME, "%s", NFTLB_TABLE_PREROUTING);
		chain_type = NFTLB_TYPE_NAT;
		chain_hook = NFTLB_HOOK_PREROUTING;

	} else if (type & NFTLB_F_CHAIN_POS_SNAT) {
		base_rules = get_rules_applied(type, family, "");
		chain_prio = NFTLB_POSTROUTING_PRIO;
		snprintf(base_chain, NFTLB_MAX_OBJ_NAME, "%s", NFTLB_TABLE_POSTROUTING);
		chain_type = NFTLB_TYPE_NAT;
		chain_hook = NFTLB_HOOK_POSTROUTING;

	} else if (type & NFTLB_F_CHAIN_FWD_FILTER) {
		base_rules = get_rules_applied(type, family, "");
		chain_prio = NFTLB_PREROUTING_PRIO;
		snprintf(base_chain, NFTLB_MAX_OBJ_NAME, "%s", NFTLB_TABLE_FORWARD);
		chain_type = NFTLB_TYPE_FILTER;
		chain_hook = NFTLB_HOOK_FORWARD;

	} else if (type & NFTLB_F_CHAIN_OUT_FILTER) {
		base_rules = get_rules_applied(type, family, "");
		chain_prio = NFTLB_FILTER_PRIO;
		snprintf(base_chain, NFTLB_MAX_OBJ_NAME, "%s", NFTLB_TABLE_OUT_FILTER);
		chain_type = NFTLB_TYPE_FILTER;
		chain_hook = NFTLB_HOOK_OUTPUT;

	} else if (type & NFTLB_F_CHAIN_OUT_DNAT) {
		base_rules = get_rules_applied(type, family, "");
		chain_prio = NFTLB_PREROUTING_PRIO;
		snprintf(base_chain, NFTLB_MAX_OBJ_NAME, "%s", NFTLB_TABLE_OUT_NAT);
		chain_type = NFTLB_TYPE_NAT;
		chain_hook = NFTLB_HOOK_OUTPUT;

	} else
		return 1;

	if (action == ACTION_STOP || action == ACTION_DELETE) {

		// If any chain type counter is 0, then reload chain rules and deactivate the usage flag
		if (((*base_rules & NFTLB_PROTO_IP_PORT_ACTIVE) && *get_service_counter(type, NFTLB_PROTO_IP_PORT_ACTIVE, family) == 0) ||
			((*base_rules & NFTLB_PROTO_PORT_ACTIVE) && *get_service_counter(type, NFTLB_PROTO_PORT_ACTIVE, family) == 0) ||
			((*base_rules & NFTLB_PROTO_IP_ACTIVE) && *get_service_counter(type, NFTLB_PROTO_IP_ACTIVE, family) == 0) ||
			((*base_rules & NFTLB_MARK_ACTIVE) && *get_service_counter(type, NFTLB_MARK_ACTIVE, family) == 0)) {

			nft_chain_handler(buf, chain_family, base_chain, NULL, NULL, NULL, 0, ACTION_RELOAD);
			run_base_chain_filter_ctmark(buf, type, chain_family, base_chain);
			run_farm_map(buf, a, family, type, service, 0, 0, 0, ACTION_DELETE);
			*base_rules &= ~NFTLB_PROTO_IP_PORT_ACTIVE & ~NFTLB_PROTO_PORT_ACTIVE & ~NFTLB_PROTO_IP_ACTIVE & ~NFTLB_MARK_ACTIVE;
		}

		if ((*get_service_counter(type, NFTLB_PROTO_IP_PORT_ACTIVE, family) == 0) &&
			(*get_service_counter(type, NFTLB_PROTO_PORT_ACTIVE, family) == 0) &&
			(*get_service_counter(type, NFTLB_PROTO_IP_ACTIVE, family) == 0) &&
			(*get_service_counter(type, NFTLB_MARK_ACTIVE, family) == 0)) {

			// for prerouting stage, do not remove the chain if postrouting is being used
			if (type & NFTLB_F_CHAIN_PRE_DNAT && (
					(*get_service_counter(NFTLB_F_CHAIN_POS_SNAT, NFTLB_PROTO_IP_PORT_ACTIVE, family) != 0) ||
					(*get_service_counter(NFTLB_F_CHAIN_POS_SNAT, NFTLB_PROTO_PORT_ACTIVE, family) != 0) ||
					(*get_service_counter(NFTLB_F_CHAIN_POS_SNAT, NFTLB_PROTO_IP_ACTIVE, family) != 0) ||
					(*get_service_counter(NFTLB_F_CHAIN_POS_SNAT, NFTLB_MARK_ACTIVE, family) != 0)))
				return 0;

			if (type & NFTLB_F_CHAIN_POS_SNAT)
				return 0;

			*base_rules &= ~NFTLB_IP_ACTIVE;
			nft_chain_handler(buf, chain_family, base_chain, NULL, NULL, NULL, 0, ACTION_DELETE);

			if (type & NFTLB_F_CHAIN_ING_FILTER || type & NFTLB_F_CHAIN_ING_DNAT)
				del_ndv_base(if_base_list, a->iface);

			// in prerouting stage, apply the same action to prerouting
			if (type & NFTLB_F_CHAIN_PRE_DNAT) {
				nft_chain_handler(buf, chain_family, NFTLB_TABLE_POSTROUTING, NULL, NULL, NULL, 0, ACTION_DELETE);
				run_farm_map(buf, a, family, type, servicem, 0, 0, 0, ACTION_DELETE);
				base_rules_t = get_rules_applied(NFTLB_F_CHAIN_POS_SNAT, family, "");
				*base_rules_t &= ~NFTLB_IP_ACTIVE & ~NFTLB_PROTO_IP_PORT_ACTIVE & ~NFTLB_PROTO_PORT_ACTIVE & ~NFTLB_PROTO_IP_ACTIVE & ~NFTLB_MARK_ACTIVE;
			}
			return 0;
		}

		rules_needed = *base_rules;

		if (*get_service_counter(type, NFTLB_PROTO_IP_PORT_ACTIVE, family) != 0)
				rules_needed |= NFTLB_PROTO_IP_PORT_ACTIVE;
		if (*get_service_counter(type, NFTLB_PROTO_PORT_ACTIVE, family) != 0)
				rules_needed |= NFTLB_PROTO_PORT_ACTIVE;
		if (*get_service_counter(type, NFTLB_PROTO_IP_ACTIVE, family) != 0)
				rules_needed |= NFTLB_PROTO_IP_ACTIVE;
		if (*get_service_counter(type, NFTLB_MARK_ACTIVE, family) != 0)
				rules_needed |= NFTLB_MARK_ACTIVE;
	}

	if ((rules_needed & NFTLB_IP_ACTIVE) && !(*base_rules & NFTLB_IP_ACTIVE)) {

		nft_chain_handler(buf, chain_family, base_chain, chain_type, chain_hook, chain_device, chain_prio, ACTION_START);
		run_base_chain_filter_ctmark(buf, type, chain_family, base_chain);

		if (type & NFTLB_F_CHAIN_POS_SNAT) {
			get_nft_name_service(servicem, NFTLB_PROTO_IP_PORT_ACTIVE, "-m", type, family);
			run_base_chain_postrouting_masquerade(buf, type, chain_family);
			run_base_chain_postrouting_bckmark(buf, servicem, type, family);
		}
		*base_rules |= NFTLB_IP_ACTIVE;
	}

	if ((rules_needed & NFTLB_PROTO_IP_PORT_ACTIVE) && !(*base_rules & NFTLB_PROTO_IP_PORT_ACTIVE)) {
		get_nft_name_service(service, NFTLB_PROTO_IP_PORT_ACTIVE, trailing, type, family);
		if (type & NFTLB_F_CHAIN_POS_SNAT) {
		} else if (type & NFTLB_F_CHAIN_ING_DNAT) {
			concat_exec_cmd(buf, " ; add map %s %s %s { type %s . %s . %s : verdict ;}", chain_family, NFTLB_TABLE_NAME, service, NFTLB_MAP_TYPE_PROTO, print_nft_family_type(family), NFTLB_MAP_TYPE_INETSRV);
			concat_exec_cmd(buf, " ; add rule %s %s %s %s %s . %s saddr . th sport vmap @%s", chain_family, NFTLB_TABLE_NAME, base_chain, print_nft_family(family), print_nft_family_protocol(family), print_nft_family(family), service);
			*base_rules |= NFTLB_PROTO_IP_PORT_ACTIVE;
		} else if (type & NFTLB_F_CHAIN_FWD_FILTER) {
			concat_exec_cmd(buf, " ; add map %s %s %s { type %s : verdict ;}", chain_family, NFTLB_TABLE_NAME, service, NFTLB_MAP_TYPE_MARK);
			concat_exec_cmd(buf, " ; add rule %s %s %s ct mark vmap @%s", chain_family, NFTLB_TABLE_NAME, base_chain, service);
			*base_rules |= NFTLB_PROTO_IP_PORT_ACTIVE;
		} else {
			concat_exec_cmd(buf, " ; add map %s %s %s { type %s . %s . %s : verdict ;}", chain_family, NFTLB_TABLE_NAME, service, NFTLB_MAP_TYPE_PROTO, print_nft_family_type(family), NFTLB_MAP_TYPE_INETSRV);
			concat_exec_cmd(buf, " ; add rule %s %s %s %s %s . %s daddr . th dport vmap @%s", chain_family, NFTLB_TABLE_NAME, base_chain, print_nft_family(family), print_nft_family_protocol(family), print_nft_family(family), service);
			*base_rules |= NFTLB_PROTO_IP_PORT_ACTIVE;
		}
	}

	if ((rules_needed & NFTLB_PROTO_PORT_ACTIVE) && !(*base_rules & NFTLB_PROTO_PORT_ACTIVE)) {
		get_nft_name_service(service, NFTLB_PROTO_PORT_ACTIVE, trailing, type, family);
		if (type & NFTLB_F_CHAIN_POS_SNAT) {
		} else if (type & NFTLB_F_CHAIN_ING_DNAT) {
			concat_exec_cmd(buf, " ; add map %s %s %s { type %s . %s : verdict ;}", chain_family, NFTLB_TABLE_NAME, service, NFTLB_MAP_TYPE_PROTO, NFTLB_MAP_TYPE_INETSRV);
			concat_exec_cmd(buf, " ; add rule %s %s %s %s %s . th sport vmap @%s", chain_family, NFTLB_TABLE_NAME, base_chain, print_nft_family(family), print_nft_family_protocol(family), service);
			*base_rules |= NFTLB_PROTO_PORT_ACTIVE;
		} else if (type & NFTLB_F_CHAIN_FWD_FILTER) {
			concat_exec_cmd(buf, " ; add map %s %s %s { type %s : verdict ;}", chain_family, NFTLB_TABLE_NAME, service, NFTLB_MAP_TYPE_MARK);
			concat_exec_cmd(buf, " ; add rule %s %s %s ct mark vmap @%s", chain_family, NFTLB_TABLE_NAME, base_chain, service);
			*base_rules |= NFTLB_PROTO_PORT_ACTIVE;
		} else {
			concat_exec_cmd(buf, " ; add map %s %s %s { type %s . %s : verdict ;}", chain_family, NFTLB_TABLE_NAME, service, NFTLB_MAP_TYPE_PROTO, NFTLB_MAP_TYPE_INETSRV);
			concat_exec_cmd(buf, " ; add rule %s %s %s %s %s . th dport vmap @%s", chain_family, NFTLB_TABLE_NAME, base_chain, print_nft_family(family), print_nft_family_protocol(family), service);
			*base_rules |= NFTLB_PROTO_PORT_ACTIVE;
		}
	}

	if ((rules_needed & NFTLB_PROTO_IP_ACTIVE) && !(*base_rules & NFTLB_PROTO_IP_ACTIVE)) {
		get_nft_name_service(service, NFTLB_PROTO_IP_ACTIVE, trailing, type, family);
		if (type & NFTLB_F_CHAIN_POS_SNAT) {
		} else if (type & NFTLB_F_CHAIN_ING_DNAT) {
			concat_exec_cmd(buf, " ; add map %s %s %s { type %s . %s : verdict ;}", chain_family, NFTLB_TABLE_NAME, service, NFTLB_MAP_TYPE_PROTO, print_nft_family_type(family));
			concat_exec_cmd(buf, " ; add rule %s %s %s %s %s . %s saddr vmap @%s", chain_family, NFTLB_TABLE_NAME, base_chain, print_nft_family(family), print_nft_family_protocol(family), print_nft_family(family), service);
			*base_rules |= NFTLB_PROTO_IP_ACTIVE;
		} else if (type & NFTLB_F_CHAIN_FWD_FILTER) {
			concat_exec_cmd(buf, " ; add map %s %s %s { type %s : verdict ;}", chain_family, NFTLB_TABLE_NAME, service, NFTLB_MAP_TYPE_MARK);
			concat_exec_cmd(buf, " ; add rule %s %s %s ct mark vmap @%s", chain_family, NFTLB_TABLE_NAME, base_chain, service);
			*base_rules |= NFTLB_PROTO_IP_ACTIVE;
		} else {
			concat_exec_cmd(buf, " ; add map %s %s %s { type %s . %s : verdict ;}", chain_family, NFTLB_TABLE_NAME, service, NFTLB_MAP_TYPE_PROTO, print_nft_family_type(family));
			concat_exec_cmd(buf, " ; add rule %s %s %s %s %s . %s daddr vmap @%s", chain_family, NFTLB_TABLE_NAME, base_chain, print_nft_family(family), print_nft_family_protocol(family), print_nft_family(family), service);
			*base_rules |= NFTLB_PROTO_IP_ACTIVE;
		}
	}

	return 0;
}

static int run_nftst_rules_gen_srv_data(char **buf, struct nftst *n, char *chain, enum map_modes data_mode)
{
	struct farm *f = nftst_get_farm(n);
	struct backend *b = nftst_get_backend(n);

	switch (data_mode) {
	case BCK_MAP_SRCIPADDR:
		if (f)
			sprintf(*buf, ": %s ", f->srcaddr);
		break;
	case BCK_MAP_NAME:
		sprintf(*buf, ": goto %s ", chain);
		break;
	case BCK_MAP_BCK_BF_SRCIPADDR:
		if (b && b->srcaddr && b->srcaddr != DEFAULT_SRCADDR && strcmp(b->srcaddr, "") != 0)
			sprintf(*buf, ": %s ", b->srcaddr);
		else if (f && f->srcaddr != DEFAULT_SRCADDR && strcmp(f->srcaddr, "") != 0)
			sprintf(*buf, ": %s ", f->srcaddr);
		break;
	default:
		break;
	}

	return 0;
}

static int run_nftst_rules_gen_srv_map(struct sbuffer *buf, struct nftst *n, int family, int type, int proto, int action, enum map_modes key_mode, enum map_modes data_mode)
{
	struct farm *f = nftst_get_farm(n);
	struct address *a = nftst_get_address(n);
	char action_str[NFTLB_MAX_OBJ_NAME] = { 0 };
	char key_str[NFTLB_MAX_OBJ_NAME] = { 0 };
	char *data_str = NULL;
	char chain[NFTLB_MAX_OBJ_NAME] = { 0 };
	char service[NFTLB_MAX_OBJ_NAME] = { 0 };
	char protocol[NFTLB_MAX_OBJ_PROTO] = { 0 };
	char *nft_family = print_nft_table_family(family, type);
	struct backend *b;
	int nports = a->nports;
	int iport = 1;
	int bckmark;
	int output = 0;
	int first_port = 1;
	int structure = 0;

	data_str = calloc(1, 255);
	if (!data_str) {
		tools_printlog(LOG_ERR, "%s():%d: memory allocation error", __FUNCTION__, __LINE__);
		return -1;
	}

	switch (action) {
	case ACTION_RELOAD:
	case ACTION_START:
		sprintf(action_str, "add");
		break;
	case ACTION_STOP:
	case ACTION_DELETE:
		sprintf(action_str, "delete");
		break;
	default:
		return -1;
		break;
	}

	get_chain_name(chain, nftst_get_name(n), type);
	get_address_service(service, nftst_get_address(n), type, nftst_get_family(n), BCK_MAP_NONE);
	snprintf(protocol, NFTLB_MAX_OBJ_PROTO, "%s", print_nft_protocol(proto));

	switch (key_mode) {
	case BCK_MAP_IPADDR:
		run_nftst_rules_gen_srv_data((char **) &data_str, n, chain, data_mode);
		concat_exec_cmd(buf, " ; %s element %s %s %s { %s %s}", action_str, nft_family, NFTLB_TABLE_NAME, service, a->ipaddr, data_str);
		output++;
		break;
	case BCK_MAP_PROTO_IPADDR:
		run_nftst_rules_gen_srv_data((char **) &data_str, n, chain, data_mode);
		concat_exec_cmd(buf, " ; %s element %s %s %s { %s . %s %s}", action_str, nft_family, NFTLB_TABLE_NAME, service, protocol, a->ipaddr, data_str);
		output++;
		break;
	case BCK_MAP_IPADDR_PORT:
		run_nftst_rules_gen_srv_data((char **) &data_str, n, chain, data_mode);

		if (nports == 0)
			break;

		concat_buf(buf, " ; %s element %s %s %s { ", action_str, nft_family, NFTLB_TABLE_NAME, service);

		while (iport <= NFTLB_MAX_PORTS && nports > 0)
		{
			if (!address_search_array_port(a, iport)) { iport++; continue; }

			concat_buf(buf, "%s . %d %s", a->ipaddr, iport, data_str);

			if (nports != 1)
				concat_buf(buf, ", ");

			output++;
			iport++;
			nports--;
		}
		concat_exec_cmd(buf, " }");
		break;
	case BCK_MAP_PROTO_IPADDR_PORT:
		run_nftst_rules_gen_srv_data((char **) &data_str, n, chain, data_mode);

		if (nports == 0)
			break;

		concat_buf(buf, " ; %s element %s %s %s { ", action_str, nft_family, NFTLB_TABLE_NAME, service);

		while (iport <= NFTLB_MAX_PORTS && nports > 0)
		{
			if (!address_search_array_port(a, iport)) { iport++; continue; }

			concat_buf(buf, "%s . %s . %d %s", protocol, a->ipaddr, iport, data_str);

			if (nports != 1)
				concat_buf(buf, ", ");

			output++;
			iport++;
			nports--;
		}
		concat_exec_cmd(buf, " }");
		break;
	case BCK_MAP_PROTO_PORT:
		run_nftst_rules_gen_srv_data((char **) &data_str, n, chain, data_mode);

		if (nports == 0)
			break;

		concat_buf(buf, " ; %s element %s %s %s { ", action_str, nft_family, NFTLB_TABLE_NAME, service);

		while (iport <= NFTLB_MAX_PORTS && nports > 0)
		{
			if (!address_search_array_port(a, iport)) { iport++; continue; }

			if (nports != 1)
				concat_buf(buf, ", ");

			concat_buf(buf, "%s . %d %s", protocol, iport, data_str);
			output++;
			iport++;
			nports--;
		}
		concat_exec_cmd(buf, " }");
		break;
	default:
		nports = (nftst_get_proto(n) == VALUE_PROTO_ALL) ? 1 : a->nports;

		if (nports == 0)
			break;

		while (iport <= NFTLB_MAX_PORTS && nports > 0)
		{
			if (!address_search_array_port(a, iport) && nftst_get_proto(n) != VALUE_PROTO_ALL) { iport++; continue; }

			list_for_each_entry(b, &f->backends, list) {
				if (!backend_validate(b))
					continue;

				get_address_service(service, a, type, nftst_get_family(n), key_mode);

				bckmark = backend_get_mark(b);
				if (type == NFTLB_F_CHAIN_POS_SNAT && bckmark & masquerade_mark)
					continue;

				structure = 0;
				if ((key_mode == BCK_MAP_BCK_ID || key_mode == BCK_MAP_BCK_MARK) && bckmark != DEFAULT_MARK) {
					if (!first_port) { continue; }
					snprintf(key_str, NFTLB_MAX_OBJ_NAME, "0x%x", bckmark);
					structure = NFTLB_MARK_ACTIVE;
				} else if ((key_mode == BCK_MAP_BCK_ID || key_mode == BCK_MAP_BCK_PROTO_IPADDR_F_PORT) && backend_no_port(b)) {
					snprintf(key_str, NFTLB_MAX_OBJ_NAME, "%s . %s . %d", protocol, b->ipaddr, iport);
					structure = NFTLB_PROTO_IP_PORT_ACTIVE;
				} else if ((key_mode == BCK_MAP_BCK_ID || key_mode == BCK_MAP_BCK_PROTO_IPADDR_F_PORT) && !backend_no_port(b)) {
					snprintf(key_str, NFTLB_MAX_OBJ_NAME, "%s . %s . %s", protocol, b->ipaddr, b->port);
					structure = NFTLB_PROTO_IP_PORT_ACTIVE;
				} else if ((key_mode == BCK_MAP_BCK_ID || key_mode == BCK_MAP_BCK_IPADDR_F_PORT) && backend_no_port(b)) {
					snprintf(key_str, NFTLB_MAX_OBJ_NAME, "%s . %d", b->ipaddr, iport);
					structure = NFTLB_PROTO_PORT_ACTIVE;
				} else if (key_mode == BCK_MAP_BCK_ID && !backend_no_port(b)) {
					if (!first_port) { continue; }
					snprintf(key_str, NFTLB_MAX_OBJ_NAME, "%s . %s", b->ipaddr, b->port);
					structure = NFTLB_PROTO_PORT_ACTIVE;
				} else if (key_mode == BCK_MAP_BCK_ID || key_mode == BCK_MAP_BCK_IPADDR) {
					if (!first_port) { continue; }
					snprintf(key_str, NFTLB_MAX_OBJ_NAME, "%s", b->ipaddr);
					structure = NFTLB_PROTO_IP_ACTIVE;
				} else
					if (!first_port) { continue; }

				nftst_set_backend(n, b);
				run_nftst_rules_gen_srv_data((char **) &data_str, n, chain, data_mode);

				if (b->action == ACTION_STOP || b->action == ACTION_DELETE || b->action == ACTION_RELOAD) {
					if (action == ACTION_START)
						continue;
					concat_exec_cmd(buf, " ; delete element %s %s %s { %s }", nft_family, NFTLB_TABLE_NAME, service, key_str);
					update_service_counters(a, type, structure, family, 1, ACTION_DELETE);
				}

				if(!backend_is_usable(b))
					continue;

				if (action == ACTION_RELOAD && b->action == ACTION_NONE)
					continue;

				concat_exec_cmd(buf, " ; %s element %s %s %s { %s %s}", action_str, nft_family, NFTLB_TABLE_NAME, service, key_str, data_str);
				update_service_counters(a, type, structure, family, 1, action);
				output++;
			}
			nftst_set_backend(n, NULL);

			iport++;
			first_port = 0;
			nports--;
			continue;
		}
		break;
	}

	if (data_str)
		free(data_str);

	return output;
}

static void run_nftst_rules_gen_srv_map_by_type(struct sbuffer *buf, struct nftst *n, int type, int family, int protocol, int action)
{
	struct address *a = nftst_get_address(n);
	int elements = 0;

	tools_printlog(LOG_DEBUG, "%s():%d: ", __FUNCTION__, __LINE__);

	if (type & NFTLB_F_CHAIN_ING_FILTER)
		elements = run_nftst_rules_gen_srv_map(buf, n, family, type, protocol, action, address_no_port(a) ? BCK_MAP_PROTO_IPADDR : (address_no_ipaddr(a) ? BCK_MAP_PROTO_PORT : BCK_MAP_PROTO_IPADDR_PORT), BCK_MAP_NAME);
	else if (type & NFTLB_F_CHAIN_PRE_FILTER)
		elements = run_nftst_rules_gen_srv_map(buf, n, family, type, protocol, action, address_no_port(a) ? BCK_MAP_PROTO_IPADDR : (address_no_ipaddr(a) ? BCK_MAP_PROTO_PORT : BCK_MAP_PROTO_IPADDR_PORT), BCK_MAP_NAME);
	else if (type & NFTLB_F_CHAIN_PRE_DNAT)
		elements = run_nftst_rules_gen_srv_map(buf, n, family, type, protocol, action, address_no_port(a) ? BCK_MAP_PROTO_IPADDR : (address_no_ipaddr(a) ? BCK_MAP_PROTO_PORT : BCK_MAP_PROTO_IPADDR_PORT), BCK_MAP_NAME);
	else if (type & NFTLB_F_CHAIN_FWD_FILTER)
		elements = run_nftst_rules_gen_srv_map(buf, n, family, type, protocol, action, BCK_MAP_BCK_MARK, BCK_MAP_NAME);
	else if (type & NFTLB_F_CHAIN_POS_SNAT)
		elements = run_nftst_rules_gen_srv_map(buf, n, family, type, protocol, action, BCK_MAP_BCK_ID, BCK_MAP_BCK_BF_SRCIPADDR);
	else if (type & NFTLB_F_CHAIN_ING_DNAT)
		elements = run_nftst_rules_gen_srv_map(buf, n, family, type, protocol, action, address_no_port(a) ? BCK_MAP_PROTO_IPADDR : (address_no_ipaddr(a) ? BCK_MAP_PROTO_PORT : BCK_MAP_BCK_PROTO_IPADDR_F_PORT), BCK_MAP_NAME);
	else if (type & NFTLB_F_CHAIN_OUT_FILTER)
		elements = run_nftst_rules_gen_srv_map(buf, n, family, type, protocol, action, address_no_port(a) ? BCK_MAP_PROTO_IPADDR : (address_no_ipaddr(a) ? BCK_MAP_PROTO_PORT : BCK_MAP_PROTO_IPADDR_PORT), BCK_MAP_NAME);
	else if (type & NFTLB_F_CHAIN_OUT_DNAT)
		elements = run_nftst_rules_gen_srv_map(buf, n, family, type, protocol, action, address_no_port(a) ? BCK_MAP_PROTO_IPADDR : (address_no_ipaddr(a) ? BCK_MAP_PROTO_PORT : BCK_MAP_PROTO_IPADDR_PORT), BCK_MAP_NAME);
	else
		return;

	if (elements && (~type & NFTLB_F_CHAIN_POS_SNAT) && (~type & NFTLB_F_CHAIN_FWD_FILTER))
		update_service_counters(a, type, family, 0, elements, action);
}

static void run_nftst_rules_gen_srv_map_by_protocol(struct sbuffer *buf, struct nftst *n, int type, int family, int action)
{
	tools_printlog(LOG_DEBUG, "%s():%d: ", __FUNCTION__, __LINE__);

	if (nftst_get_proto(n) != VALUE_PROTO_ALL || (type & NFTLB_F_CHAIN_FWD_FILTER) || (type & NFTLB_F_CHAIN_POS_SNAT)) {
		run_nftst_rules_gen_srv_map_by_type(buf, n, type, family, nftst_get_proto(n), action);
	} else {
		run_nftst_rules_gen_srv_map_by_type(buf, n, type, family, VALUE_PROTO_TCP, action);
		run_nftst_rules_gen_srv_map_by_type(buf, n, type, family, VALUE_PROTO_UDP, action);
		run_nftst_rules_gen_srv_map_by_type(buf, n, type, family, VALUE_PROTO_SCTP, action);
	}
}

static void run_nftst_rules_gen_vsrv(struct sbuffer *buf, struct nftst *n, int type, int family, int srv_action, int action)
{
	tools_printlog(LOG_DEBUG, "%s():%d: pos %d", __FUNCTION__, __LINE__, get_chain_pos_counter(type));

	if (srv_action == ACTION_NONE)
		srv_action = action;

	switch (srv_action) {
	case ACTION_RELOAD:
		run_nftst_rules_gen_chain(buf, n, family, type, action);
		break;
	case ACTION_START:
		run_nftst_rules_gen_chain(buf, n, family, type, action);
		run_nftst_rules_gen_srv_map_by_protocol(buf, n, type, family, srv_action);
		break;
	case ACTION_DELETE:
	case ACTION_STOP:
		run_nftst_rules_gen_srv_map_by_protocol(buf, n, type, family, srv_action);
		run_nftst_rules_gen_chain(buf, n, family, type, action);
		break;
	default:
		break;
	}

	return;
}

static int run_farm_snat(struct sbuffer *buf, struct nftst *n, int family, int action)
{
	struct farm *f = nftst_get_farm(n);

	tools_printlog(LOG_DEBUG, "%s():%d: ", __FUNCTION__, __LINE__);

	if (f->mode != VALUE_MODE_SNAT && f->mode != VALUE_MODE_LOCAL)
		return 0;

	switch (action) {
	case ACTION_RELOAD:
	case ACTION_START:
		run_nftst_rules_gen_srv_map_by_protocol(buf, n, NFTLB_F_CHAIN_POS_SNAT, family, action);
		break;
	case ACTION_STOP:
	case ACTION_DELETE:
		if ((family == VALUE_FAMILY_IPV4 && nft_base_rules.snat_rules_v4) || (family == VALUE_FAMILY_IPV6 && nft_base_rules.snat_rules_v6))
			run_nftst_rules_gen_srv_map_by_protocol(buf, n, NFTLB_F_CHAIN_POS_SNAT, family, action);
		break;
	}

	return 0;
}

static int run_farm_rules_gen_sched(struct sbuffer *buf, struct nftst *n, int family)
{
	struct farm *f = nftst_get_farm(n);
	struct address *a = nftst_get_address(n);

	switch (f->scheduler) {
	case VALUE_SCHED_RR:
		concat_buf(buf, " numgen inc mod %d", f->total_weight);
		break;
	case VALUE_SCHED_WEIGHT:
		concat_buf(buf, " numgen random mod %d", f->total_weight);
		break;
	case VALUE_SCHED_HASH:
		concat_buf(buf, " jhash");
		run_farm_rules_gen_meta_param(buf, a->protocol, family, f->schedparam, NFTLB_MAP_KEY_RULE);
		concat_buf(buf, " mod %d", f->total_weight);
		break;
	case VALUE_SCHED_SYMHASH:
		concat_buf(buf, " symhash mod %d", f->total_weight);
		break;
	default:
		return -1;
	}

	return 0;
}

static int get_nftst_first_port(struct nftst *n)
{
	struct address *a = nftst_get_address(n);
	int iport = 0;

	if (nftst_get_proto(n) == VALUE_PROTO_ALL || a->nports == 0)
		return 0;

	while (iport <= NFTLB_MAX_PORTS && a->nports > 0) {
		if (a->port_list[iport])
			return ++iport;
		iport++;
	}
	return 0;
}

static int run_farm_rules_gen_bck_map(struct sbuffer *buf, struct nftst *n, enum map_modes key_mode, enum map_modes data_mode, int usable)
{
	struct farm *f = nftst_get_farm(n);
	struct backend *b;
	int i = 0;
	int last = 0;
	int new;
	int port;

	concat_buf(buf, " map {");

	list_for_each_entry(b, &f->backends, list) {
		if (usable == NFTLB_CHECK_USABLE && !backend_is_usable(b))
			continue;
		if (usable == NFTLB_CHECK_AVAIL && !backend_is_available(b))
			continue;
		if (data_mode == BCK_MAP_PORT && backend_no_port(b))
			continue;

		if (i != 0)
			concat_buf(buf, ",");

		switch (key_mode) {
		case BCK_MAP_MARK:
			concat_buf(buf, " 0x%x", backend_get_mark(b));
			break;
		case BCK_MAP_IPADDR:
			concat_buf(buf, " %s", b->ipaddr);
			break;
		case BCK_MAP_WEIGHT:
			new = last + b->weight - 1;
			concat_buf(buf, " %d", last);
			if (new != last)
				concat_buf(buf, "-%d", new);
			last = new + 1;
			break;
		case BCK_MAP_ETHADDR:
			concat_buf(buf, " %s", b->ethaddr);
			break;
		default:
			break;
		}

		concat_buf(buf, ":");

		switch (data_mode) {
		case BCK_MAP_MARK:
			concat_buf(buf, " 0x%x", backend_get_mark(b));
			break;
		case BCK_MAP_ETHADDR:
			concat_buf(buf, " %s", b->ethaddr);
			break;
		case BCK_MAP_IPADDR_PORT:
			if (backend_no_port(b)) {
				port = get_nftst_first_port(n);
				concat_buf(buf, " %s . %d", b->ipaddr, port);
			} else
				concat_buf(buf, " %s . %s", b->ipaddr, b->port);
			break;
		case BCK_MAP_PORT:
			concat_buf(buf, " %s", b->port);
			break;
		case BCK_MAP_IPADDR:
			concat_buf(buf, " %s", b->ipaddr);
			break;
		case BCK_MAP_OFACE:
			if (b->oface)
				concat_buf(buf, " %s", b->oface);
			else
				concat_buf(buf, " %s", f->oface);
			break;
		default:
			break;
		}

		i++;
	}

	concat_buf(buf, " }");

	if (i == 0)
		return -1;

	return 0;
}

static void run_farm_helper(struct sbuffer *buf, struct farm *f, int family, int action, char *protocol)
{
	switch (action) {
	case ACTION_START:
		concat_exec_cmd(buf, " ; add ct helper %s %s %s-%s { type \"%s\" protocol %s ; } ;", print_nft_table_family(family, NFTLB_F_CHAIN_PRE_FILTER), NFTLB_TABLE_NAME, obj_print_helper(f->helper), protocol, obj_print_helper(f->helper), protocol);
		break;
	case ACTION_DELETE:
	case ACTION_STOP:
		concat_exec_cmd(buf, " ; delete ct helper %s %s %s-%s ; ", print_nft_table_family(family, NFTLB_F_CHAIN_PRE_FILTER), NFTLB_TABLE_NAME, obj_print_helper(f->helper), protocol);
		break;
	case ACTION_RELOAD:
	default:
		break;
	}
}

static int run_farm_log_prefix(struct sbuffer *buf, struct farm *f, int key, int type, int action)
{
	char logprefix_str[NFTLB_MAX_OBJ_NAME] = { 0 };
	struct nftst *n;

	if (f->log == VALUE_LOG_NONE)
		return 0;

	if (f->log & key) {
		n = nftst_create_from_farm(f);
		print_log_format(logprefix_str, KEY_LOGPREFIX, type, n);
		concat_buf(buf, " log prefix \"%s\"", logprefix_str);
	}

	return 0;
}

static int run_farm_gen_log_rules(struct sbuffer *buf, struct farm *f, int family, char * chain, int key, int type, int action)
{
	if (f->log == VALUE_LOG_NONE)
		return 0;

	if (f->log & key) {
		concat_buf(buf, " ; add rule %s %s %s", print_nft_table_family(family, type), NFTLB_TABLE_NAME, chain);
		run_farm_log_prefix(buf,f, key, type, action);
		concat_exec_cmd(buf, "");
	}

	return 0;
}

static int run_farm_rules_filter_helper(struct sbuffer *buf, struct nftst *n, int family, char *chain, int action)
{
	struct farm *f = nftst_get_farm(n);
	struct address *a = nftst_get_address(n);
	char protocol[NFTLB_MAX_OBJ_NAME] = {0};

	if (!(f->helper != DEFAULT_HELPER && (f->mode == VALUE_MODE_SNAT || f->mode == VALUE_MODE_LOCAL || f->mode == VALUE_MODE_DNAT)))
		return 0;

	if (a->protocol == VALUE_PROTO_TCP || a->protocol == VALUE_PROTO_ALL) {
		sprintf(protocol, "tcp");
		run_farm_helper(buf, f, family, action, protocol);
		if (action == ACTION_START || action == ACTION_RELOAD)
			concat_exec_cmd(buf, " ; add rule %s %s %s %s %s %s ct helper set %s-%s", print_nft_table_family(family, NFTLB_F_CHAIN_PRE_FILTER), NFTLB_TABLE_NAME, chain, print_nft_table_family(family, NFTLB_F_CHAIN_PRE_FILTER), print_nft_family_protocol(family), protocol, obj_print_helper(f->helper), protocol);
	}

	if (a->protocol == VALUE_PROTO_UDP || a->protocol == VALUE_PROTO_ALL) {
		sprintf(protocol, "udp");
		run_farm_helper(buf, f, family, action, protocol);
		if (action == ACTION_START || action == ACTION_RELOAD)
			concat_exec_cmd(buf, " ; add rule %s %s %s %s %s %s ct helper set %s-%s", print_nft_table_family(family, NFTLB_F_CHAIN_PRE_FILTER), NFTLB_TABLE_NAME, chain, print_nft_table_family(family, NFTLB_F_CHAIN_PRE_FILTER), print_nft_family_protocol(family), protocol, obj_print_helper(f->helper), protocol);
	}

	return 0;
}

static int run_farm_sessions_map(struct sbuffer *buf, struct nftst *n, int stype, int family, int action)
{
	struct farm *f = nftst_get_farm(n);
	struct address *a = nftst_get_address(n);
	char map_str[NFTLB_MAX_OBJ_NAME] = { 0 };
	int ttl = 0;

	if (f->persistence == VALUE_META_NONE)
		return 0;

	if (stype == SESSION_TYPE_STATIC)
		snprintf(map_str, NFTLB_MAX_OBJ_NAME, "static-sessions-%s", f->name);
	else {
		snprintf(map_str, NFTLB_MAX_OBJ_NAME, "persist-%s", f->name);
		ttl = f->persistttl;
	}

	if (f->mode == VALUE_MODE_DSR)
		run_farm_map(buf, a, family, NFTLB_F_CHAIN_ING_FILTER, map_str, f->persistence, VALUE_META_DSTMAC, ttl, action);
	else if (f->mode == VALUE_MODE_STLSDNAT)
		run_farm_map(buf, a, family, NFTLB_F_CHAIN_ING_FILTER, map_str, f->persistence, VALUE_META_DSTIP, ttl, action);
	else
		run_farm_map(buf, a, family, NFTLB_F_CHAIN_PRE_FILTER, map_str, f->persistence, VALUE_META_MARK, ttl, action);

	return 0;
}

static int run_farm_manage_sessions(struct sbuffer *buf, struct farm *f, int stype, int family, int action)
{
	char chain[NFTLB_MAX_OBJ_NAME] = { 0 };
	char map_str[NFTLB_MAX_OBJ_NAME] = { 0 };
	char *client;
	struct session *s;
	struct list_head *sessions;

	if (action != ACTION_START && action != ACTION_RELOAD)
		return 0;

	if (f->persistence == VALUE_META_NONE)
		return 0;

	if (f->bcks_usable == 0)
		return 0;

	if ((action != ACTION_START && action != ACTION_RELOAD))
		return 0;

	get_chain_name(chain, f->name, NFTLB_F_CHAIN_ING_FILTER);

	if (stype == SESSION_TYPE_STATIC) {
		snprintf(map_str, NFTLB_MAX_OBJ_NAME, "static-sessions-%s", f->name);
		sessions = &f->static_sessions;
	} else {
		snprintf(map_str, NFTLB_MAX_OBJ_NAME, "persist-%s", f->name);
		sessions = &f->timed_sessions;
	}

	list_for_each_entry(s, sessions, list) {
		client = (char *) malloc(255);
		if (!client) {
			tools_printlog(LOG_ERR, "%s():%d: unable to allocate parsed client %s for farm %s", __FUNCTION__, __LINE__, s->client, f->name);
			continue;
		}

		if (session_get_client(s, &client)) {

			if (f->mode == VALUE_MODE_DSR) {
				if ((action == ACTION_START || s->action == ACTION_START) && s->bck && s->bck->ethaddr != DEFAULT_ETHADDR)
					concat_exec_cmd(buf, " ; add element %s %s %s { %s : %s }", print_nft_table_family(family, get_stage_by_farm_mode(f)), NFTLB_TABLE_NAME, map_str, client, s->bck->ethaddr);
			} else if(f->mode == VALUE_MODE_STLSDNAT) {
				if ((action == ACTION_START || s->action == ACTION_START) && s->bck && s->bck->ipaddr != DEFAULT_IPADDR)
					concat_exec_cmd(buf, " ; add element %s %s %s { %s : %s }", print_nft_table_family(family, get_stage_by_farm_mode(f)), NFTLB_TABLE_NAME, map_str, client, s->bck->ipaddr);
			} else {
				if ((action == ACTION_START || s->action == ACTION_START) && s->bck && s->bck->mark != DEFAULT_MARK && backend_is_available(s->bck))
					concat_exec_cmd(buf, " ; add element %s %s %s { %s : 0x%x }", print_nft_table_family(family, get_stage_by_farm_mode(f)), NFTLB_TABLE_NAME, map_str, client, backend_get_mark(s->bck));
			}

			if (action == ACTION_RELOAD && (s->action == ACTION_STOP || s->action == ACTION_DELETE))
				concat_exec_cmd(buf, " ; delete element %s %s %s { %s }", print_nft_table_family(family, get_stage_by_farm_mode(f)), NFTLB_TABLE_NAME, map_str, client);
			free(client);
		}
		s->action = ACTION_NONE;
	}

	return 0;
}

static int run_farm_rules_update_sessions(struct sbuffer *buf, struct nftst *n, int family, char *chain, int action)
{
	struct farm *f = nftst_get_farm(n);
	struct address *a = nftst_get_address(n);
	char map_str[NFTLB_MAX_OBJ_NAME] = { 0 };

	if (f->persistence == VALUE_META_NONE || f->total_bcks == 0)
		return 0;

	snprintf(map_str, NFTLB_MAX_OBJ_NAME, "persist-%s", f->name);

	if (action != ACTION_START && action != ACTION_RELOAD)
		return 0;

	switch (f->mode) {
	case VALUE_MODE_DSR:
		concat_buf(buf, " update @%s { ",  map_str);
		run_farm_rules_gen_meta_param(buf, a->protocol, family, f->persistence, NFTLB_MAP_KEY_RULE);
		concat_exec_cmd(buf, " : ");
		run_farm_rules_gen_meta_param(buf, a->protocol, family, VALUE_META_DSTMAC, NFTLB_MAP_KEY_RULE);
		concat_exec_cmd(buf, " }");
		break;
	case VALUE_MODE_STLSDNAT:
		concat_buf(buf, " update @%s { ",  map_str);
		run_farm_rules_gen_meta_param(buf, a->protocol, family, f->persistence, NFTLB_MAP_KEY_RULE);
		concat_exec_cmd(buf, " : ");
		run_farm_rules_gen_meta_param(buf, a->protocol, family, VALUE_META_DSTIP, NFTLB_MAP_KEY_RULE);
		concat_exec_cmd(buf, " }");
		break;
	default:
		concat_buf(buf, " ; add rule %s %s %s ct mark != 0x00000000 update @%s { ", print_nft_table_family(family, NFTLB_F_CHAIN_PRE_FILTER), NFTLB_TABLE_NAME, chain, map_str);
		run_farm_rules_gen_meta_param(buf, a->protocol, family, f->persistence, NFTLB_MAP_KEY_RULE);
		concat_exec_cmd(buf, " : ct mark }");
		break;
	}

	return 0;
}

static int run_farm_rules_check_sessions(struct sbuffer *buf, struct nftst *n, int stype, int family, int type, int action)
{
	struct farm *f = nftst_get_farm(n);
	struct address *a = nftst_get_address(n);
	char map_str[NFTLB_MAX_OBJ_NAME] = { 0 };
	char chain[NFTLB_MAX_OBJ_NAME] = { 0 };

	if (f->persistence == VALUE_META_NONE || f->total_bcks == 0)
		return 0;

	if (action != ACTION_START && action != ACTION_RELOAD)
		return 0;

	if (stype == SESSION_TYPE_STATIC)
		snprintf(map_str, NFTLB_MAX_OBJ_NAME, "static-sessions-%s", f->name);
	else
		snprintf(map_str, NFTLB_MAX_OBJ_NAME, "persist-%s", f->name);

	get_chain_name(chain, f->name, type);

	switch (f->mode) {
	case VALUE_MODE_DSR:
		get_chain_name(chain, f->name, NFTLB_F_CHAIN_ING_FILTER);
		concat_buf(buf, " ; add rule %s %s %s ether daddr set", print_nft_table_family(family, NFTLB_F_CHAIN_ING_FILTER), NFTLB_TABLE_NAME, chain);
		run_farm_rules_gen_meta_param(buf, a->protocol, family, f->persistence, NFTLB_MAP_KEY_RULE);
		concat_exec_cmd(buf, " map @%s ether saddr set %s", map_str, a->iethaddr);

		if (stype == SESSION_TYPE_TIMED)
			run_farm_rules_update_sessions(buf, n, family, chain, action);

		concat_buf(buf, " fwd to");
		if (f->bcks_have_if) {
			concat_buf(buf, " ether daddr");
			run_farm_rules_gen_bck_map(buf, n, BCK_MAP_ETHADDR, BCK_MAP_OFACE, NFTLB_CHECK_AVAIL);
		} else
			concat_buf(buf, " %s", f->oface);
		concat_exec_cmd(buf, "");
		break;

	case VALUE_MODE_STLSDNAT:
		get_chain_name(chain, f->name, NFTLB_F_CHAIN_ING_FILTER);
		concat_buf(buf, " ; add rule %s %s %s %s daddr set", print_nft_table_family(family, NFTLB_F_CHAIN_ING_FILTER), NFTLB_TABLE_NAME, chain, print_nft_family(family));
		run_farm_rules_gen_meta_param(buf, a->protocol, family, f->persistence, NFTLB_MAP_KEY_RULE);
		concat_exec_cmd(buf, " map @%s ether daddr set %s daddr", map_str, print_nft_family(family));
		run_farm_rules_gen_bck_map(buf, n, BCK_MAP_IPADDR, BCK_MAP_ETHADDR, NFTLB_CHECK_AVAIL);

		if (f->bcks_have_port) {
			concat_buf(buf, " th dport set ether daddr");
			run_farm_rules_gen_bck_map(buf, n, BCK_MAP_ETHADDR, BCK_MAP_PORT, NFTLB_CHECK_AVAIL);
		}

		concat_buf(buf, " ether saddr set %s", f->oethaddr);

		if (stype == SESSION_TYPE_TIMED)
			run_farm_rules_update_sessions(buf, n, family, chain, action);

		concat_buf(buf, " fwd to");
		if (f->bcks_have_if) {
			concat_buf(buf, " ether daddr");
			run_farm_rules_gen_bck_map(buf, n, BCK_MAP_ETHADDR, BCK_MAP_OFACE, NFTLB_CHECK_AVAIL);
		} else
			concat_buf(buf, " %s", f->oface);
		concat_exec_cmd(buf, "");
		break;

	default:
		get_chain_name(chain, f->name, NFTLB_F_CHAIN_PRE_FILTER);
		if (stype == SESSION_TYPE_STATIC) {
			concat_buf(buf, " ; add rule %s %s %s ct mark set", print_nft_table_family(family, NFTLB_F_CHAIN_PRE_FILTER), NFTLB_TABLE_NAME, chain);
			run_farm_rules_gen_meta_param(buf, a->protocol, family, f->persistence, NFTLB_MAP_KEY_RULE);
			concat_exec_cmd(buf, " map @%s accept", map_str);
		} else {
			concat_buf(buf, " ; add rule %s %s %s ct state new ct mark set", print_nft_table_family(family, NFTLB_F_CHAIN_PRE_FILTER), NFTLB_TABLE_NAME, chain);
			run_farm_rules_gen_meta_param(buf, a->protocol, family, f->persistence, NFTLB_MAP_KEY_RULE);
			concat_exec_cmd(buf, " map @%s", map_str);
		}
		break;
	}

	return 0;
}

static void run_farm_meter(struct sbuffer *buf, struct farm *f, int table_family, int family, int type, char *name, int action)
{
	switch (action) {
	case ACTION_START:
		concat_buf(buf, " ; add set %s %s %s { type %s ; flags dynamic ; ", print_nft_table_family(table_family, NFTLB_F_CHAIN_PRE_FILTER), NFTLB_TABLE_NAME, name, print_nft_family_type(family));

		if (type == KEY_ELEMENTS)
			concat_buf(buf, "counter ; ");

		// ct count doesn't require timeout as it is implemented implicitly
		if (type != KEY_ESTCONNLIMIT &&
			f->limitsttl)
			concat_buf(buf, "timeout %ds; ", f->limitsttl);
		concat_exec_cmd(buf, "} ;");
		break;
	case ACTION_STOP:
		concat_exec_cmd(buf, " ; delete set %s %s %s ; ", print_nft_table_family(table_family, NFTLB_F_CHAIN_PRE_FILTER), NFTLB_TABLE_NAME, name);
		break;
	default:
		break;
	}
}

static int run_farm_log_rate_limit(struct sbuffer *buf, struct nftst *n)
{
	struct farm *f = nftst_get_farm(n);
	struct address *a = nftst_get_address(n);
	char rtlimit_str[NFTLB_MAX_OBJ_NAME] = { 0 };

	if ((f && !f->logrtlimit) || (a && !a->logrtlimit))
		return 0;

	if (f) {
		obj_print_rtlimit(rtlimit_str, f->logrtlimit, f->logrtlimit_unit);
		concat_buf(buf, " limit rate %s", rtlimit_str);
	}

	if (a) {
		obj_print_rtlimit(rtlimit_str, a->logrtlimit, a->logrtlimit_unit);
		concat_buf(buf, " limit rate %s", rtlimit_str);
	}

	return 0;
}

static void run_farm_rules_log_and_verdict(struct sbuffer *buf, struct nftst *n, int logrt, int flags, int verdict, int key, int chain)
{
	char logprefix_str[NFTLB_MAX_OBJ_NAME] = { 0 };

	if (flags & VALUE_VERDICT_LOG) {
		if (logrt) {
			concat_buf(buf, " jump {");
			run_farm_log_rate_limit(buf, n);
		}
		print_log_format(logprefix_str, key, chain, n);
		concat_buf(buf, " log prefix \"%s\"", logprefix_str);
		if (logrt) {
			concat_buf(buf, " ;");
		}
	}

	concat_buf(buf, " %s", print_nft_verdict(flags, verdict));

	if (flags & VALUE_VERDICT_LOG && logrt)
		concat_buf(buf, "; }");
	concat_exec_cmd(buf, "");
}

static int run_farm_rules_filter_policies(struct sbuffer *buf, struct farm *f, int family, char *chain, int action)
{
	char meter_str[NFTLB_MAX_OBJ_NAME] = { 0 };
	char burst_str[NFTLB_MAX_OBJ_NAME] = { 0 };
	struct nftst *n = nftst_create_from_farm(f);
	char rtlimit_str[NFTLB_MAX_OBJ_NAME] = { 0 };

	if ((action == ACTION_START || action == ACTION_RELOAD) && f->tcpstrict == VALUE_SWITCH_ON) {
		concat_buf(buf, " ; add rule %s %s %s ct state invalid",
						print_nft_table_family(family, NFTLB_F_CHAIN_PRE_FILTER), NFTLB_TABLE_NAME, chain);
		run_farm_rules_log_and_verdict(buf, n, f->logrtlimit, f->verdict, VALUE_TYPE_DENY, KEY_TCPSTRICT_LOGPREFIX, NFTLB_F_CHAIN_PRE_FILTER);
	}

	snprintf(meter_str, NFTLB_MAX_OBJ_NAME, "%s-%s", CONFIG_KEY_NEWRTLIMIT, f->name);
	if ((action == ACTION_START && f->newrtlimit != DEFAULT_NEWRTLIMIT) || (action == ACTION_RELOAD && f->reload_action & VALUE_RLD_NEWRTLIMIT_START))
		run_farm_meter(buf, f, family, family, KEY_NEWRTLIMIT, meter_str, ACTION_START);
	if (((action == ACTION_STOP || action == ACTION_DELETE) && f->newrtlimit != DEFAULT_NEWRTLIMIT) || (action == ACTION_RELOAD && f->reload_action & VALUE_RLD_NEWRTLIMIT_STOP))
		run_farm_meter(buf, f, family, family, KEY_NEWRTLIMIT, meter_str, ACTION_STOP);
	if ((action == ACTION_START || action == ACTION_RELOAD) && f->newrtlimit != DEFAULT_NEWRTLIMIT) {
		if (f->newrtlimitbst != DEFAULT_RTLIMITBURST)
			snprintf(burst_str, NFTLB_MAX_OBJ_NAME, "burst %d packets ", f->newrtlimitbst);
		//~ concat_buf(buf, " ; add rule %s %s %s ct state new add @%s { %s saddr limit rate over %s %s counter }",
		obj_print_rtlimit(rtlimit_str, f->newrtlimit, f->newrtlimit_unit);
		concat_buf(buf, " ; add rule %s %s %s ct state new add @%s { %s saddr limit rate over %s %s }",
				   print_nft_table_family(family, NFTLB_F_CHAIN_PRE_FILTER), NFTLB_TABLE_NAME, chain, meter_str, print_nft_family(family), rtlimit_str, burst_str);
		run_farm_rules_log_and_verdict(buf, n, f->logrtlimit, f->verdict, VALUE_TYPE_DENY, KEY_NEWRTLIMIT_LOGPREFIX, NFTLB_F_CHAIN_PRE_FILTER);
	}

	snprintf(meter_str, NFTLB_MAX_OBJ_NAME, "%s-%s", CONFIG_KEY_RSTRTLIMIT, f->name);
	if ((action == ACTION_START && f->rstrtlimit != DEFAULT_RSTRTLIMIT) || (action == ACTION_RELOAD && f->reload_action & VALUE_RLD_RSTRTLIMIT_START))
		run_farm_meter(buf, f, family, family, KEY_RSTRTLIMIT, meter_str, ACTION_START);
	if (((action == ACTION_STOP || action == ACTION_DELETE) && f->rstrtlimit != DEFAULT_RSTRTLIMIT) || (action == ACTION_RELOAD && f->reload_action & VALUE_RLD_RSTRTLIMIT_STOP))
		run_farm_meter(buf, f, family, family, KEY_RSTRTLIMIT, meter_str, ACTION_STOP);
	if ((action == ACTION_START || action == ACTION_RELOAD) && f->rstrtlimit != DEFAULT_RSTRTLIMIT) {
		if (f->rstrtlimitbst != DEFAULT_RTLIMITBURST)
			snprintf(burst_str, NFTLB_MAX_OBJ_NAME, "burst %d packets ", f->rstrtlimitbst);
		//~ concat_buf(buf, " ; add rule %s %s %s tcp flags rst add @%s { %s saddr limit rate over %s %s counter }",
		obj_print_rtlimit(rtlimit_str, f->rstrtlimit, f->rstrtlimit_unit);
		concat_buf(buf, " ; add rule %s %s %s tcp flags rst add @%s { %s saddr limit rate over %s %s }",
				   print_nft_table_family(family, NFTLB_F_CHAIN_PRE_FILTER), NFTLB_TABLE_NAME, chain, meter_str, print_nft_family(family), rtlimit_str, burst_str);
		run_farm_rules_log_and_verdict(buf, n, f->logrtlimit, f->verdict, VALUE_TYPE_DENY, KEY_RSTRTLIMIT_LOGPREFIX, NFTLB_F_CHAIN_PRE_FILTER);
	}

	snprintf(meter_str, NFTLB_MAX_OBJ_NAME, "%s-%s", CONFIG_KEY_ESTCONNLIMIT, f->name);
	if ((action == ACTION_START && f->estconnlimit != DEFAULT_ESTCONNLIMIT) || (action == ACTION_RELOAD && f->reload_action & VALUE_RLD_ESTCONNLIMIT_START))
		run_farm_meter(buf, f, family, family, KEY_ESTCONNLIMIT, meter_str, ACTION_START);
	if (((action == ACTION_STOP || action == ACTION_DELETE) && f->estconnlimit != DEFAULT_ESTCONNLIMIT) || (action == ACTION_RELOAD && f->reload_action & VALUE_RLD_ESTCONNLIMIT_STOP))
		run_farm_meter(buf, f, family, family, KEY_ESTCONNLIMIT, meter_str, ACTION_STOP);
	if ((action == ACTION_START || action == ACTION_RELOAD) && f->estconnlimit != DEFAULT_ESTCONNLIMIT) {
		//~ concat_buf(buf, " ; add rule %s %s %s ct state new add @%s { %s saddr ct count over %d counter }",
		concat_buf(buf, " ; add rule %s %s %s ct state new add @%s { %s saddr ct count over %d }",
						print_nft_table_family(family, NFTLB_F_CHAIN_PRE_FILTER), NFTLB_TABLE_NAME, chain, meter_str, print_nft_family(family), f->estconnlimit);
		run_farm_rules_log_and_verdict(buf, n, f->logrtlimit, f->verdict, VALUE_TYPE_DENY, KEY_ESTCONNLIMIT_LOGPREFIX, NFTLB_F_CHAIN_PRE_FILTER);
	}

	if ((action == ACTION_START || action == ACTION_RELOAD) && f->queue != DEFAULT_QUEUE)
		concat_exec_cmd(buf, " ; add rule %s %s %s tcp flags syn queue num %d bypass",
						print_nft_table_family(family, NFTLB_F_CHAIN_PRE_FILTER), NFTLB_TABLE_NAME, chain, f->queue);
	return 0;
}

static int run_farm_rules_gen_limits_per_bck(struct sbuffer *buf, struct farm *f, int family, char *chain, int action)
{
	struct backend *b;
	struct nftst *n = nftst_create_from_farm(f);

	list_for_each_entry(b, &f->backends, list) {
		if (b->estconnlimit == 0)
			continue;

		if ((b->action == ACTION_STOP && !backend_is_usable(b)) || (action == ACTION_STOP || action == ACTION_DELETE))
			continue;

		nftst_set_backend(n, b);
		concat_buf(buf, " ; add rule %s %s %s ct mark 0x%x ct count over %d",
						print_nft_table_family(family, NFTLB_F_CHAIN_PRE_FILTER), NFTLB_TABLE_NAME, chain, backend_get_mark(b), b->estconnlimit);
		run_farm_rules_log_and_verdict(buf, n, f->logrtlimit, f->verdict, VALUE_TYPE_DENY, KEY_ESTCONNLIMIT_LOGPREFIX, NFTLB_F_CHAIN_PRE_FILTER);
	}

	return 0;
}

static int run_farm_rules_filter_marks(struct sbuffer *buf, struct nftst *n, int family, char *chain, int action)
{
	struct farm *f = nftst_get_farm(n);
	struct backend *b;

	int mark = farm_get_mark(f);

	if (action == ACTION_START || action == ACTION_RELOAD) {
		if (f->bcks_available) {
			concat_buf(buf, " ; add rule %s %s %s ct state new ct mark 0x0 ct mark set", print_nft_table_family(family, NFTLB_F_CHAIN_PRE_FILTER), NFTLB_TABLE_NAME, chain);
			if (f->scheduler == VALUE_SCHED_SYMHASH && f->bcks_available == 1) { // FIXME: Control bug in nftables
				list_for_each_entry(b, &f->backends, list) {
					if (!backend_is_available(b))
						continue;
					concat_buf(buf, " 0x%x", backend_get_mark(b));
				}
			} else {
				if (run_farm_rules_gen_sched(buf, n, family) == -1)
					return -1;
				run_farm_rules_gen_bck_map(buf, n, BCK_MAP_WEIGHT, BCK_MAP_MARK, NFTLB_CHECK_AVAIL);
			}
			run_farm_rules_gen_limits_per_bck(buf, f, family, chain, action);
		} else if (mark != DEFAULT_MARK) {
			concat_buf(buf, " ; add rule %s %s %s ct state new ct mark 0x0 ct mark set 0x%x", print_nft_table_family(family, NFTLB_F_CHAIN_PRE_FILTER), NFTLB_TABLE_NAME, chain, mark);
		}
	} else if (action == ACTION_STOP || action == ACTION_DELETE || (action == ACTION_RELOAD && f->bcks_usable == 0)) {
		run_farm_rules_gen_limits_per_bck(buf, f, family, chain, action);
	}
	concat_exec_cmd(buf, "");

	return 0;
}

static int run_farm_rules_filter(struct sbuffer *buf, struct nftst *n, int family, int action)
{
	struct farm *f = nftst_get_farm(n);
	struct address *a = nftst_get_address(n);
	char chain[NFTLB_MAX_OBJ_NAME] = { 0 };
	int need = need_filter(f);
	int naction = nftst_get_action(n);

	if (!need && f->reload_action == VALUE_RLD_NONE)
		return 0;

	get_chain_name(chain, f->name, NFTLB_F_CHAIN_PRE_FILTER);

	if (action == ACTION_RELOAD && need && (STATEFUL_RLD_START(f->reload_action)))
		action = ACTION_RELOAD;

	if (action == ACTION_RELOAD && !need && (STATEFUL_RLD_STOP(f->reload_action)))
		action = ACTION_STOP;

	switch (action) {
	case ACTION_START:
	case ACTION_RELOAD:
		run_base_table(buf, NFTLB_F_CHAIN_PRE_FILTER, family, action);
		run_base_chain(buf, n, NFTLB_F_CHAIN_PRE_FILTER, family, get_rules_needed(a), action);
		run_nftst_rules_gen_vsrv(buf, n, NFTLB_F_CHAIN_PRE_FILTER, family, naction, action);
		run_farm_rules_filter_policies(buf, f, family, chain, action);
		if (f->mode != VALUE_MODE_LOCAL) {
			run_farm_rules_filter_helper(buf, n, family, chain, action);
			run_farm_sessions_map(buf, n, SESSION_TYPE_STATIC, family, action);
			run_farm_sessions_map(buf, n, SESSION_TYPE_TIMED, family, action);
			run_farm_manage_sessions(buf, f, SESSION_TYPE_STATIC, family, action);
			run_farm_manage_sessions(buf, f, SESSION_TYPE_TIMED, family, action);
			run_farm_rules_check_sessions(buf, n, SESSION_TYPE_STATIC, family, NFTLB_F_CHAIN_PRE_FILTER, action);
			run_farm_rules_check_sessions(buf, n, SESSION_TYPE_TIMED, family, NFTLB_F_CHAIN_PRE_FILTER, action);
			run_farm_rules_filter_marks(buf, n, family, chain, action);
			run_farm_rules_update_sessions(buf, n, family, chain, action);
		}
		break;
	case ACTION_DELETE:
	case ACTION_STOP:
		run_nftst_rules_gen_vsrv(buf, n, NFTLB_F_CHAIN_PRE_FILTER, family, naction, action);
		if (f->mode != VALUE_MODE_LOCAL) {
			run_farm_sessions_map(buf, n, SESSION_TYPE_STATIC, family, action);
			run_farm_sessions_map(buf, n, SESSION_TYPE_TIMED, family, action);
			run_farm_rules_filter_marks(buf, n, family, chain, action);
			run_farm_rules_filter_helper(buf, n, family, chain, action);
		}
		run_farm_rules_filter_policies(buf, f, family, chain, action);
		run_base_chain(buf, n, NFTLB_F_CHAIN_PRE_FILTER, family, get_rules_needed(a), action);
		break;
	default:
		break;
	}

	return 0;
}

static int get_farm_interfaces(struct nftst *n, char *list)
{
	struct backend *b;
	struct farm *f = nftst_get_farm(n);
	struct address *a = nftst_get_address(n);
	int number = 0;
	char *p = NULL;

	if (a->iface) {
		strcat(list, a->iface);
		number++;
	}

	if (f->oface && !(p = strstr(list, f->oface))) {
		if (number)
			strcat(list, ", ");
		strcat(list, f->oface);
		number++;
	}

	list_for_each_entry(b, &f->backends, list) {
		if (b->oface && !(p = strstr(list, b->oface))) {
			if (number)
				strcat(list, ", ");
			strcat(list, b->oface);
			number++;
		}
	}

	return number;
}

static void run_farm_flowtable(struct sbuffer *buf, struct nftst *n, int family, char *name, int action)
{
	char interfaces[NFTLB_MAX_OBJ_NAME] = { 0 };
	struct farm *f = nftst_get_farm(n);

	if (!farm_needs_flowtable(f) || !get_farm_interfaces(n, interfaces))
		return;

	switch (action) {
	case ACTION_START:
		concat_exec_cmd(buf, " ; add flowtable %s %s %s { hook %s priority %d ; devices = { %s } ; } ;", print_nft_table_family(family, NFTLB_F_CHAIN_FWD_FILTER), NFTLB_TABLE_NAME, name, NFTLB_HOOK_INGRESS, nftlb_flowtable_prio++, interfaces);
		break;
	case ACTION_STOP:
	case ACTION_DELETE:
		concat_exec_cmd(buf, " ; delete flowtable %s %s %s ; ", print_nft_table_family(family, NFTLB_F_CHAIN_FWD_FILTER), NFTLB_TABLE_NAME, name);
		nftlb_flowtable_prio--;
		break;
	default:
		break;
	}
	return;
}

static void run_farm_gen_flowtable_rules(struct sbuffer *buf, struct nftst *n, int family, char *chain, char *name, int action)
{
	struct farm *f = nftst_get_farm(n);
	struct address *a = nftst_get_address(n);

	if (!farm_needs_flowtable(f) || !a->iface)
		return;

	concat_exec_cmd(buf, " ; add rule %s %s %s flow add @%s", print_nft_table_family(family, NFTLB_F_CHAIN_FWD_FILTER), NFTLB_TABLE_NAME, chain, name);
	return;
}

static int run_farm_rules_forward(struct sbuffer *buf, struct nftst *n, int family, int action)
{
	struct farm *f = nftst_get_farm(n);
	struct address *a = nftst_get_address(n);
	int naction = nftst_get_action(n);
	char chain[NFTLB_MAX_OBJ_NAME] = { 0 };
	char flowtable[NFTLB_MAX_OBJ_NAME] = { 0 };

	if (!need_forward(f))
		return 0;

	get_chain_name(chain, f->name, NFTLB_F_CHAIN_FWD_FILTER);
	get_flowtable_name(flowtable, f);

	switch (action) {
	case ACTION_START:
		run_base_chain(buf, n, NFTLB_F_CHAIN_FWD_FILTER, family, get_rules_needed(a), action);
		run_nftst_rules_gen_vsrv(buf, n, NFTLB_F_CHAIN_FWD_FILTER, family, naction, action);
		run_farm_gen_log_rules(buf, f, family, chain, VALUE_LOG_FORWARD, NFTLB_F_CHAIN_FWD_FILTER, action);
		run_farm_flowtable(buf, n, family, flowtable, action);
		run_farm_gen_flowtable_rules(buf, n, family, chain, flowtable, action);
		break;
	case ACTION_RELOAD:
		run_base_table(buf, NFTLB_F_CHAIN_FWD_FILTER, family, action);
		run_base_chain(buf, n, NFTLB_F_CHAIN_FWD_FILTER, family, get_rules_needed(a), action);
		run_nftst_rules_gen_vsrv(buf, n, NFTLB_F_CHAIN_FWD_FILTER, family, naction, action);
		run_farm_gen_log_rules(buf, f, family, chain, VALUE_LOG_FORWARD, NFTLB_F_CHAIN_FWD_FILTER, action);
		run_farm_gen_flowtable_rules(buf, n, family, chain, flowtable, action);
		break;
	case ACTION_DELETE:
	case ACTION_STOP:
		run_nftst_rules_gen_vsrv(buf, n, NFTLB_F_CHAIN_FWD_FILTER, family, naction, action);
		run_farm_flowtable(buf, n, family, flowtable, action);
		run_base_chain(buf, n, NFTLB_F_CHAIN_FWD_FILTER, family, get_rules_needed(a), action);
		break;
	default:
		break;
	}

	return 0;
}

static int run_farm_rules_output(struct sbuffer *buf, struct nftst *n, int family, int action)
{
	struct farm *f = nftst_get_farm(n);
	struct address *a = nftst_get_address(n);
	int naction = nftst_get_action(n);

	if (!need_output(f))
		return 0;

	switch (action) {
	case ACTION_START:
		run_base_chain(buf, n, NFTLB_F_CHAIN_OUT_FILTER, family, get_rules_needed(a), action);
		run_nftst_rules_gen_vsrv(buf, n, NFTLB_F_CHAIN_OUT_FILTER, family, naction, action);
		run_base_chain(buf, n, NFTLB_F_CHAIN_OUT_DNAT, family, get_rules_needed(a), action);
		run_nftst_rules_gen_vsrv(buf, n, NFTLB_F_CHAIN_OUT_DNAT, family, naction, action);
		break;
	case ACTION_RELOAD:
		run_base_chain(buf, n, NFTLB_F_CHAIN_OUT_FILTER, family, get_rules_needed(a), action);
		run_nftst_rules_gen_vsrv(buf, n, NFTLB_F_CHAIN_OUT_FILTER, family, naction, action);
		run_base_chain(buf, n, NFTLB_F_CHAIN_OUT_DNAT, family, get_rules_needed(a), action);
		run_nftst_rules_gen_vsrv(buf, n, NFTLB_F_CHAIN_OUT_DNAT, family, naction, action);
		break;
	case ACTION_DELETE:
	case ACTION_STOP:
		run_nftst_rules_gen_vsrv(buf, n, NFTLB_F_CHAIN_OUT_FILTER, family, naction, action);
		run_nftst_rules_gen_vsrv(buf, n, NFTLB_F_CHAIN_OUT_DNAT, family, naction, action);
		run_base_chain(buf, n, NFTLB_F_CHAIN_OUT_FILTER, family, get_rules_needed(a), action);
		run_base_chain(buf, n, NFTLB_F_CHAIN_OUT_DNAT, family, get_rules_needed(a), action);
		break;
	default:
		break;
	}

	return 0;
}

static int run_farm_rules_ingress_policies(struct sbuffer *buf, struct farm *f, char *chain, int action)
{
	struct farmpolicy *fp;
	char meter_str[NFTLB_MAX_OBJ_NAME] = { 0 };
	struct nftst *n = nftst_create_from_farm(f);

	list_for_each_entry(fp, &f->policies, list) {
		nftst_set_policy(n, fp->policy);
		snprintf(meter_str, NFTLB_MAX_OBJ_NAME, "%s-%s-cnt", fp->policy->name, f->name);
		if ((fp->action == ACTION_RELOAD && f->policies_action == ACTION_RELOAD) ||
			(action == ACTION_START && f->policies_action != ACTION_RELOAD) ||
			(action == ACTION_RELOAD && f->policies_action == ACTION_START) ||
			(fp->action == ACTION_START && f->policies_action == ACTION_RELOAD)) {
			run_farm_meter(buf, f, VALUE_FAMILY_NETDEV, fp->policy->family, KEY_ELEMENTS, meter_str, ACTION_START);
			nftst_set_policy(n, fp->policy);

		} else if (((action == ACTION_STOP || action == ACTION_DELETE) && f->policies_action != ACTION_RELOAD) ||
					(action == ACTION_RELOAD && f->policies_action == ACTION_STOP) ||
					(fp->action == ACTION_STOP && f->policies_action == ACTION_RELOAD)) {
			run_farm_meter(buf, f, VALUE_FAMILY_NETDEV, fp->policy->family, KEY_ELEMENTS, meter_str, ACTION_STOP);
		}

		if ((fp->action == ACTION_NONE && (f->policies_action == ACTION_RELOAD || f->policies_action == ACTION_START)) ||
			(fp->action == ACTION_START && (f->policies_action == ACTION_RELOAD || f->policies_action == ACTION_START)) ||
			(fp->action == ACTION_RELOAD && f->policies_action == ACTION_RELOAD)) {
			concat_buf(buf, " ; add rule %s %s %s %s saddr @%s add @%s { %s saddr }",
							NFTLB_NETDEV_FAMILY_STR, NFTLB_TABLE_NAME, chain, print_nft_family(fp->policy->family), fp->policy->name, meter_str, print_nft_family(fp->policy->family));
			run_farm_rules_log_and_verdict(buf, n, f->logrtlimit, f->verdict, fp->policy->type, KEY_LOGPREFIX, NFTLB_F_CHAIN_ING_FILTER);
		}

		fp->action = ACTION_NONE;
	}

	return 0;
}

static int run_nftst_rules_ingress_policies(struct sbuffer *buf, struct nftst *n, char *chain, int action)
{
	struct address *a = nftst_get_address(n);
	struct addresspolicy *ap;

	if (a->policies_action != ACTION_START && a->policies_action != ACTION_RELOAD && action != ACTION_RELOAD)
		return 0;

	list_for_each_entry(ap, &a->policies, list) {
		concat_buf(buf, " ; add rule %s %s %s %s saddr @%s",
						NFTLB_NETDEV_FAMILY_STR, NFTLB_TABLE_NAME, chain, print_nft_family(ap->policy->family), ap->policy->name);
		run_farm_rules_log_and_verdict(buf, n, a->logrtlimit, a->verdict, ap->policy->type, KEY_LOGPREFIX, NFTLB_F_CHAIN_ING_FILTER);
		ap->action = ACTION_NONE;
	}

	return 0;
}

static void get_farm_rules_nat_params(struct sbuffer *buf, struct farm *f, int family)
{
	if (f->bcks_have_port)
		concat_buf(buf, " %s addr . port", print_nft_family(family));
}

static int run_farm_rules_gen_nat(struct sbuffer *buf, struct nftst *n, int family, int type, int action)
{
	struct farm *f = nftst_get_farm(n);
	char chain[NFTLB_MAX_OBJ_NAME] = { 0 };
	char map_str[NFTLB_MAX_OBJ_NAME] = { 0 };
	int bck_map_data = BCK_MAP_IPADDR;

	if (f->bcks_usable == 0)
		return 0;

	get_chain_name(chain, f->name, type);

	switch (f->mode) {
	case VALUE_MODE_DSR:
		run_farm_rules_check_sessions(buf, n, SESSION_TYPE_STATIC, family, NFTLB_F_CHAIN_ING_FILTER, action);
		run_farm_rules_check_sessions(buf, n, SESSION_TYPE_TIMED, family, NFTLB_F_CHAIN_ING_FILTER, action);

		if (f->bcks_available) {
			concat_buf(buf, " ; add rule %s %s %s", print_nft_table_family(family, NFTLB_F_CHAIN_ING_FILTER), NFTLB_TABLE_NAME, chain);
			run_farm_log_prefix(buf, f, VALUE_LOG_INPUT, NFTLB_F_CHAIN_ING_FILTER, ACTION_START);
			// TODO: support of different output interfaces per backend during saddr
			concat_buf(buf, " ether saddr set %s ether daddr set", f->oethaddr);
			run_farm_rules_gen_sched(buf, n, family);
			run_farm_rules_gen_bck_map(buf, n, BCK_MAP_WEIGHT, BCK_MAP_ETHADDR, NFTLB_CHECK_AVAIL);
			run_farm_rules_update_sessions(buf, n, family, chain, action);
			run_farm_log_prefix(buf, f, VALUE_LOG_OUTPUT, NFTLB_F_CHAIN_ING_DNAT, ACTION_START);
			concat_buf(buf, " fwd to");
			if (f->bcks_have_if) {
				concat_buf(buf, " ether daddr");
				run_farm_rules_gen_bck_map(buf, n, BCK_MAP_ETHADDR, BCK_MAP_OFACE, NFTLB_CHECK_AVAIL);
			} else
				concat_buf(buf, " %s", f->oface);
		}
		concat_exec_cmd(buf, "");
		break;
	case VALUE_MODE_STLSDNAT:
		snprintf(map_str, NFTLB_MAX_OBJ_NAME, "map-%s-back", f->name);
		concat_exec_cmd(buf, " ; add rule %s %s %s update @%s { %s saddr : ether saddr }", print_nft_table_family(family, NFTLB_F_CHAIN_ING_FILTER), NFTLB_TABLE_NAME, chain, map_str, print_nft_family(family));

		run_farm_rules_check_sessions(buf, n, SESSION_TYPE_STATIC, family, NFTLB_F_CHAIN_ING_FILTER, action);
		run_farm_rules_check_sessions(buf, n, SESSION_TYPE_TIMED, family, NFTLB_F_CHAIN_ING_FILTER, action);

		if (f->bcks_available) {
			concat_buf(buf, " ; add rule %s %s %s", print_nft_table_family(family, NFTLB_F_CHAIN_ING_FILTER), NFTLB_TABLE_NAME, chain);
			run_farm_log_prefix(buf, f, VALUE_LOG_INPUT, NFTLB_F_CHAIN_ING_FILTER, ACTION_START);
			concat_buf(buf, " %s daddr set", print_nft_family(family));
			run_farm_rules_gen_sched(buf, n, family);
			run_farm_rules_gen_bck_map(buf, n, BCK_MAP_WEIGHT, BCK_MAP_IPADDR, NFTLB_CHECK_AVAIL);
			concat_buf(buf, " ether daddr set %s daddr", print_nft_family(family));
			run_farm_rules_gen_bck_map(buf, n, BCK_MAP_IPADDR, BCK_MAP_ETHADDR, NFTLB_CHECK_AVAIL);

			if (f->bcks_have_port) {
				concat_buf(buf, " th dport set ether daddr");
				run_farm_rules_gen_bck_map(buf, n, BCK_MAP_ETHADDR, BCK_MAP_PORT, NFTLB_CHECK_AVAIL);
			}

			// TODO: support of different output interfaces per backend during saddr
			concat_buf(buf, " ether saddr set %s", f->oethaddr);

			run_farm_rules_update_sessions(buf, n, family, chain, action);

			run_farm_log_prefix(buf, f, VALUE_LOG_OUTPUT, NFTLB_F_CHAIN_ING_DNAT, ACTION_START);
			concat_buf(buf, " fwd to");
			if (f->bcks_have_if) {
				concat_buf(buf, " ether daddr");
				run_farm_rules_gen_bck_map(buf, n, BCK_MAP_ETHADDR, BCK_MAP_OFACE, NFTLB_CHECK_AVAIL);
			} else {
				concat_buf(buf, " %s", f->oface);
			}
		}
		concat_exec_cmd(buf, "");
		break;
	default:
		run_farm_gen_log_rules(buf, f, family, chain, VALUE_LOG_INPUT, NFTLB_F_CHAIN_PRE_DNAT, ACTION_START);

		concat_buf(buf, " ; add rule %s %s %s", print_nft_table_family(family, NFTLB_F_CHAIN_PRE_DNAT), NFTLB_TABLE_NAME, chain);

		if (nftst_get_proto(n) != VALUE_PROTO_ALL)
			concat_buf(buf, " %s %s %s", print_nft_family(family), print_nft_family_protocol(family), print_nft_protocol(nftst_get_proto(n)));

		concat_buf(buf, " dnat");

		if (f->bcks_have_port)
			bck_map_data = BCK_MAP_IPADDR_PORT;

		get_farm_rules_nat_params(buf, f, family);
		concat_buf(buf, " to ct mark");
		run_farm_rules_gen_bck_map(buf, n, BCK_MAP_MARK, bck_map_data, NFTLB_CHECK_USABLE);

		concat_exec_cmd(buf, "");

		break;
	}

	return 0;
}

static int run_nftst_ingress_policies(struct sbuffer *buf, struct nftst *n, int family, int action)
{
	struct farm *f = nftst_get_farm(n);
	struct address *a = nftst_get_address(n);
	int naction = nftst_get_action(n);
	char chain[NFTLB_MAX_OBJ_NAME] = { 0 };

	if ((f && !farm_needs_policies(f)) ||
		(!f && a && !address_needs_policies(a)) ||
		(f && !farm_is_ingress_mode(f) && naction == ACTION_NONE))
		return 0;

	get_chain_name(chain, nftst_get_name(n), NFTLB_F_CHAIN_ING_FILTER);

	switch (action) {
	case ACTION_START:
		if ((f && !farm_is_ingress_mode(f)) || a) {
				run_base_table(buf, NFTLB_F_CHAIN_ING_FILTER, family, ACTION_START);
				run_base_chain(buf, n, NFTLB_F_CHAIN_ING_FILTER, family, get_rules_needed(a), ACTION_START);
				if ((f && f->policies_used > 1) || (a && a->policies_used > 1))
					run_nftst_rules_gen_vsrv(buf, n, NFTLB_F_CHAIN_ING_FILTER, VALUE_FAMILY_NETDEV, ACTION_RELOAD, ACTION_RELOAD);
				else
					run_nftst_rules_gen_vsrv(buf, n, NFTLB_F_CHAIN_ING_FILTER, VALUE_FAMILY_NETDEV, ACTION_START, ACTION_START);
		}

		if (f)
			run_farm_rules_ingress_policies(buf, f, chain, action);
		else if (a)
			run_nftst_rules_ingress_policies(buf, n, chain, action);
		break;
	case ACTION_RELOAD:
		run_nftst_rules_gen_vsrv(buf, n, NFTLB_F_CHAIN_ING_FILTER, VALUE_FAMILY_NETDEV, ACTION_RELOAD, ACTION_RELOAD);
		if (f)
			run_farm_rules_ingress_policies(buf, f, chain, action);
		else if (a)
			run_nftst_rules_ingress_policies(buf, n, chain, action);
		break;
	case ACTION_DELETE:
	case ACTION_STOP:
		if ((f && !farm_is_ingress_mode(f)) || a) {
			run_nftst_rules_gen_vsrv(buf, n, NFTLB_F_CHAIN_ING_FILTER, VALUE_FAMILY_NETDEV, ACTION_STOP, ACTION_STOP);
			run_base_chain(buf, n, NFTLB_F_CHAIN_ING_FILTER, family, get_rules_needed(a), ACTION_STOP);
			run_base_table(buf, NFTLB_F_CHAIN_ING_FILTER, family, ACTION_STOP);
		}

		if (f && f->addresses_used <= 1)
			run_farm_rules_ingress_policies(buf, f, chain, action);
		else if (a)
			run_nftst_rules_ingress_policies(buf, n, chain, action);

		break;
	default:
		break;
	}

	return 0;
}

static int run_farm_dsr(struct sbuffer *buf, struct nftst *n, int family, int action)
{
	struct farm *f = nftst_get_farm(n);
	struct address *a = nftst_get_address(n);
	int naction = nftst_get_action(n);

	switch (action) {
	case ACTION_RELOAD:
	case ACTION_START:
		run_base_table(buf, NFTLB_F_CHAIN_ING_FILTER, family, action);
		run_base_chain(buf, n, NFTLB_F_CHAIN_ING_FILTER, family, get_rules_needed(a), action);
		run_nftst_rules_gen_vsrv(buf, n, NFTLB_F_CHAIN_ING_FILTER, family, naction, action);
		run_nftst_ingress_policies(buf, n, family, ACTION_RELOAD);
		run_farm_sessions_map(buf, n, SESSION_TYPE_STATIC, family, action);
		run_farm_sessions_map(buf, n, SESSION_TYPE_TIMED, family, action);
		run_farm_manage_sessions(buf, f, SESSION_TYPE_STATIC, family, action);
		run_farm_manage_sessions(buf, f, SESSION_TYPE_TIMED, family, action);
		run_farm_rules_gen_nat(buf, n, family, NFTLB_F_CHAIN_ING_FILTER, action);
		break;
	case ACTION_DELETE:
	case ACTION_STOP:
		run_nftst_rules_gen_vsrv(buf, n, NFTLB_F_CHAIN_ING_FILTER, family, naction, action);
		run_farm_manage_sessions(buf, f, SESSION_TYPE_STATIC, family, action);
		run_farm_manage_sessions(buf, f, SESSION_TYPE_TIMED, family, action);
		run_farm_sessions_map(buf, n, SESSION_TYPE_STATIC, family, action);
		run_farm_sessions_map(buf, n, SESSION_TYPE_TIMED, family, action);
		run_base_chain(buf, n, NFTLB_F_CHAIN_ING_FILTER, family, get_rules_needed(a), action);
		run_base_table(buf, NFTLB_F_CHAIN_ING_FILTER, family, action);
		run_nftst_ingress_policies(buf, n, family, f->policies_action);
		break;
	default:
		break;
	}

	return 0;
}

static int run_farm_stlsnat(struct sbuffer *buf, struct nftst *n, int family, int action)
{
	struct farm *f = nftst_get_farm(n);
	struct address *a = nftst_get_address(n);
	int naction = nftst_get_action(n);
	char chain[NFTLB_MAX_OBJ_NAME] = { 0 };
	char map_str[NFTLB_MAX_OBJ_NAME] = { 0 };

	snprintf(map_str, NFTLB_MAX_OBJ_NAME, "map-%s-back", f->name);

	get_chain_name(chain, f->name, NFTLB_F_CHAIN_ING_DNAT);

	switch (action) {
	case ACTION_RELOAD:
	case ACTION_START:
		run_nftst_ingress_policies(buf, n, family, f->policies_action);
		run_base_table(buf, NFTLB_F_CHAIN_ING_FILTER, family, action);
		run_base_chain(buf, n, NFTLB_F_CHAIN_ING_DNAT, family, get_rules_needed(a), action);
		run_nftst_rules_gen_vsrv(buf, n, NFTLB_F_CHAIN_ING_DNAT, family, naction, action);
		run_farm_map(buf, a, family, NFTLB_F_CHAIN_ING_DNAT, map_str, VALUE_META_SRCIP, VALUE_META_SRCMAC, f->persistttl, action);
		concat_exec_cmd(buf, " ; add rule %s %s %s %s saddr set %s ether saddr set %s ether daddr set %s daddr map @%s fwd to %s", print_nft_table_family(family, NFTLB_F_CHAIN_ING_DNAT), NFTLB_TABLE_NAME, chain, print_nft_family(family), a->ipaddr, a->iethaddr, print_nft_family(family), map_str, a->iface);
		run_base_table(buf, NFTLB_F_CHAIN_ING_FILTER, family, action);
		run_base_chain(buf, n, NFTLB_F_CHAIN_ING_FILTER, family, get_rules_needed(a), action);
		run_nftst_rules_gen_vsrv(buf, n, NFTLB_F_CHAIN_ING_FILTER, family, naction, action);
		run_nftst_ingress_policies(buf, n, family, f->policies_action);
		run_farm_sessions_map(buf, n, SESSION_TYPE_STATIC, family, action);
		run_farm_sessions_map(buf, n, SESSION_TYPE_TIMED, family, action);
		run_farm_manage_sessions(buf, f, SESSION_TYPE_STATIC, family, action);
		run_farm_manage_sessions(buf, f, SESSION_TYPE_TIMED, family, action);
		run_farm_rules_gen_nat(buf, n, family, NFTLB_F_CHAIN_ING_FILTER, action);
		break;
	case ACTION_DELETE:
	case ACTION_STOP:
		run_nftst_rules_gen_vsrv(buf, n, NFTLB_F_CHAIN_ING_DNAT, family, naction, action);
		run_nftst_rules_gen_vsrv(buf, n, NFTLB_F_CHAIN_ING_FILTER, family, naction, action);
		run_farm_manage_sessions(buf, f, SESSION_TYPE_STATIC, family, action);
		run_farm_manage_sessions(buf, f, SESSION_TYPE_TIMED, family, action);
		run_farm_sessions_map(buf, n, SESSION_TYPE_STATIC, family, action);
		run_farm_sessions_map(buf, n, SESSION_TYPE_TIMED, family, action);
		run_farm_map(buf, a, family, NFTLB_F_CHAIN_ING_DNAT, map_str, VALUE_META_SRCIP, VALUE_META_SRCMAC, f->persistttl, action);
		run_base_chain(buf, n, NFTLB_F_CHAIN_ING_DNAT, family, get_rules_needed(a), action);
		run_base_chain(buf, n, NFTLB_F_CHAIN_ING_FILTER, family, get_rules_needed(a), action);
		run_base_table(buf, NFTLB_F_CHAIN_ING_FILTER, family, action);
		run_nftst_ingress_policies(buf, n, family, f->policies_action);
		break;
	default:
		break;
	}

	return 0;
}

static int run_farm_nat(struct sbuffer *buf, struct nftst *n, int family, int action)
{
	struct farm *f = nftst_get_farm(n);
	struct address *a = nftst_get_address(n);
	int naction = nftst_get_action(n);

	tools_printlog(LOG_DEBUG, "%s():%d: ", __FUNCTION__, __LINE__);

	switch (action) {
	case ACTION_RELOAD:
	case ACTION_START:
		run_farm_rules_filter(buf, n, family, action);
		run_nftst_ingress_policies(buf, n, family, f->policies_action);
		run_base_table(buf, NFTLB_F_CHAIN_PRE_DNAT, family, action);
		run_base_chain(buf, n, NFTLB_F_CHAIN_PRE_DNAT, family, get_rules_needed(a), action);
		run_base_chain(buf, n, NFTLB_F_CHAIN_POS_SNAT, family, get_rules_needed(a), action);
		run_nftst_rules_gen_vsrv(buf, n, NFTLB_F_CHAIN_PRE_DNAT, family, naction, action);
		run_farm_rules_gen_nat(buf, n, family, NFTLB_F_CHAIN_PRE_DNAT, action);
		run_farm_rules_forward(buf, n, family, action);
		run_farm_rules_output(buf, n, family, action);
		run_farm_snat(buf, n, family, action);
		break;
	case ACTION_DELETE:
	case ACTION_STOP:
		run_farm_rules_forward(buf, n, family, action);
		run_farm_rules_output(buf, n, family, action);
		run_farm_rules_filter(buf, n, family, action);
		run_farm_snat(buf, n, family, action);
		run_nftst_rules_gen_vsrv(buf, n, NFTLB_F_CHAIN_PRE_DNAT, family, naction, action);
		run_base_chain(buf, n, NFTLB_F_CHAIN_PRE_DNAT, family, get_rules_needed(a), action);
		run_base_chain(buf, n, NFTLB_F_CHAIN_POS_SNAT, family, get_rules_needed(a), action);
		run_base_table(buf, NFTLB_F_CHAIN_PRE_DNAT, family, action);
		run_nftst_ingress_policies(buf, n, family, f->policies_action);
		break;
	default:
		break;
	}

	return 0;
}

static int run_farm_local(struct sbuffer *buf, struct nftst *n, int family, int action)
{
	struct farm *f = nftst_get_farm(n);
	struct address *a = nftst_get_address(n);

	switch (action) {
	case ACTION_RELOAD:
	case ACTION_START:
		if (farm_has_source_address(f)) {
			run_base_table(buf, NFTLB_F_CHAIN_PRE_DNAT, family, action);
			run_base_chain(buf, n, NFTLB_F_CHAIN_PRE_DNAT, family, get_rules_needed(a), action);
			run_base_chain(buf, n, NFTLB_F_CHAIN_POS_SNAT, family, get_rules_needed(a), action);
			run_farm_snat(buf, n, family, action);
		}
		run_farm_rules_filter(buf, n, family, action);
		run_nftst_ingress_policies(buf, n, family, f->policies_action);
		run_farm_rules_forward(buf, n, family, action);
		run_farm_rules_output(buf, n, family, action);
		break;
	case ACTION_DELETE:
	case ACTION_STOP:
		run_farm_rules_forward(buf, n, family, action);
		run_farm_rules_output(buf, n, family, action);
		run_farm_rules_filter(buf, n, family, action);
		if (farm_has_source_address(f)) {
			run_farm_snat(buf, n, family, action);
			run_base_chain(buf, n, NFTLB_F_CHAIN_PRE_DNAT, family, get_rules_needed(a), action);
			run_base_chain(buf, n, NFTLB_F_CHAIN_POS_SNAT, family, get_rules_needed(a), action);
		}
		run_base_table(buf, NFTLB_F_CHAIN_PRE_DNAT, family, action);
		run_nftst_ingress_policies(buf, n, family, f->policies_action);
		break;
	default:
		break;
	}

	return 0;
}

static int run_farm_rules(struct sbuffer *buf, struct nftst *n, int family)
{
	struct farm *f = nftst_get_farm(n);
	int action = nftst_get_action(n);

	if (f->action == ACTION_RELOAD && action == ACTION_NONE)
		action = ACTION_RELOAD;

	switch (f->mode) {
	case VALUE_MODE_STLSDNAT:
		run_farm_stlsnat(buf, n, family, action);
		break;
	case VALUE_MODE_DSR:
		run_farm_dsr(buf, n, family, action);
		break;
	case VALUE_MODE_LOCAL:
		run_farm_local(buf, n, family, action);
		break;
	default:
		run_farm_nat(buf, n, family, action);
	}

	return 0;
}

int nft_reset(void)
{
	struct sbuffer buf;
	int ret = 0;

	create_buf(&buf);

	if (nft_base_rules.dnat_rules_v4 ||
	    nft_base_rules.snat_rules_v4 ||
	    nft_base_rules.filter_rules_v4 ||
	    nft_base_rules.fwd_rules_v4 ||
	    nft_base_rules.out_filter_rules_v4 ||
	    nft_base_rules.out_nat_rules_v4)
		nft_table_handler(&buf, print_nft_family(VALUE_FAMILY_IPV4), ACTION_DELETE);

	if (nft_base_rules.dnat_rules_v6 ||
	    nft_base_rules.snat_rules_v6 ||
	    nft_base_rules.filter_rules_v6 ||
	    nft_base_rules.fwd_rules_v6 ||
	    nft_base_rules.out_filter_rules_v6 ||
	    nft_base_rules.out_nat_rules_v6)
		nft_table_handler(&buf, print_nft_family(VALUE_FAMILY_IPV6), ACTION_DELETE);

	if (nft_base_rules.ndv_ingress_rules.n_interfaces ||
		nft_base_rules.ndv_ingress_dnat_rules.n_interfaces ||
		nft_base_rules.ndv_ingress_policies)
		nft_table_handler(&buf, print_nft_family(VALUE_FAMILY_NETDEV), ACTION_DELETE);

	exec_cmd(get_buf_data(&buf));
	clean_buf(&buf);
	clean_rules_counters();

	return ret;
}

int nft_check_tables(void)
{
	char cmd[NFTLB_MAX_OBJ_NAME] = { 0 };
	const char *buf;

	snprintf(cmd, NFTLB_MAX_OBJ_NAME, "list table %s %s", NFTLB_IPV4_FAMILY_STR, NFTLB_TABLE_NAME);
	if (exec_cmd_open(cmd, &buf, 0) == 0)
		nft_base_rules.dnat_rules_v4 = 1;
	exec_cmd_close(buf);

	snprintf(cmd, NFTLB_MAX_OBJ_NAME, "list table %s %s", NFTLB_IPV6_FAMILY_STR, NFTLB_TABLE_NAME);
	if (exec_cmd_open(cmd, &buf, 0) == 0)
		nft_base_rules.dnat_rules_v6 = 1;
	exec_cmd_close(buf);

	snprintf(cmd, NFTLB_MAX_OBJ_NAME, "list table %s %s", NFTLB_NETDEV_FAMILY_STR, NFTLB_TABLE_NAME);
	if (exec_cmd_open(cmd, &buf, 0) == 0)
		nft_base_rules.ndv_ingress_rules.n_interfaces = 1;
	exec_cmd_close(buf);

	return nft_base_rules.dnat_rules_v4 ||
		   nft_base_rules.dnat_rules_v6 ||
		   nft_base_rules.ndv_ingress_rules.n_interfaces;
}

static int run_set_elements(struct sbuffer *buf, struct policy *p)
{
	struct element *e;
	int index = 0;

	if (!p->total_elem)
		return 0;

	switch (p->action) {
	case ACTION_START:
		list_for_each_entry(e, &p->elements, list) {
			if (index)
				concat_buf(buf, ", %s", e->data);
			else {
				index++;
				concat_buf(buf, " ; add element %s %s %s { %s", NFTLB_NETDEV_FAMILY_STR, NFTLB_TABLE_NAME, p->name, e->data);
			}
			e->action = ACTION_NONE;
		}
		if (index)
			concat_exec_cmd(buf, " }");
		break;
	case ACTION_RELOAD:
		list_for_each_entry(e, &p->elements, list) {
			if (e->action != ACTION_START)
				continue;
			if (index)
				concat_buf(buf, ", %s", e->data);
			else {
				index++;
				concat_buf(buf, " ; add element %s %s %s { %s", NFTLB_NETDEV_FAMILY_STR, NFTLB_TABLE_NAME, p->name, e->data);
			}
			e->action = ACTION_NONE;
		}
		if (index)
			concat_exec_cmd(buf, " }");

		index = 0;
		list_for_each_entry(e, &p->elements, list) {
			if (e->action != ACTION_DELETE && e->action != ACTION_STOP)
				continue;
			if (index)
				concat_buf(buf, ", %s", e->data);
			else {
				index++;
				concat_buf(buf, " ; delete element %s %s %s { %s", NFTLB_NETDEV_FAMILY_STR, NFTLB_TABLE_NAME, p->name, e->data);
			}
			e->action = ACTION_NONE;
		}
		if (index)
			concat_exec_cmd(buf, " }");
		break;
	case ACTION_FLUSH:
		concat_exec_cmd(buf, " ; flush set %s %s %s", NFTLB_NETDEV_FAMILY_STR, NFTLB_TABLE_NAME, p->name);
		break;
	case ACTION_DELETE:
	case ACTION_STOP:
		list_for_each_entry(e, &p->elements, list) {
			if (index)
				concat_buf(buf, ", %s", e->data);
			else {
				index++;
				concat_buf(buf, " ; delete element %s %s %s { %s", NFTLB_NETDEV_FAMILY_STR, NFTLB_TABLE_NAME, p->name, e->data);
			}
			e->action = ACTION_NONE;
		}
		if (index)
			concat_exec_cmd(buf, " }");
		break;
	default:
		break;
	}

	return 0;
}

static int run_set_farm_policies(struct sbuffer *buf, struct policy *p)
{
	struct list_head *farms = obj_get_farms();
	struct farm *f, *next;
	struct farmpolicy *fp;
	char meter_str[NFTLB_MAX_OBJ_NAME] = { 0 };

	if (!p->used)
		return 0;

	list_for_each_entry_safe(f, next, farms, list) {
		fp = farmpolicy_lookup_by_name(f, p->name);
		if (!fp)
			continue;

		snprintf(meter_str, NFTLB_MAX_OBJ_NAME, "%s-%s-cnt", p->name, f->name);
		switch (p->action) {
		case ACTION_FLUSH:
			concat_exec_cmd(buf, " ; flush set %s %s %s", NFTLB_NETDEV_FAMILY_STR, NFTLB_TABLE_NAME, meter_str);
			break;
		case ACTION_STOP:
		case ACTION_DELETE:
		case ACTION_START:
		default:
			break;
		}
	}

	return 0;
}

static int run_policy_set(struct sbuffer *buf, struct policy *p)
{
	switch (p->action) {
	case ACTION_START:
		run_base_table(buf, NFTLB_F_CHAIN_ING_FILTER, VALUE_FAMILY_NETDEV, ACTION_START);
		concat_exec_cmd(buf, " ; add set %s %s %s { type %s ; flags interval ; auto-merge ; counter ; }", NFTLB_NETDEV_FAMILY_STR, NFTLB_TABLE_NAME, p->name, print_nft_family_type(p->family));
		nft_base_rules.ndv_ingress_policies++;
		run_set_elements(buf, p);
		break;
	case ACTION_RELOAD:
		run_set_elements(buf, p);
		break;
	case ACTION_FLUSH:
		run_set_elements(buf, p);
		run_set_farm_policies(buf, p);
		break;
	case ACTION_STOP:
	case ACTION_DELETE:
		concat_exec_cmd(buf, " ; delete set %s %s %s", NFTLB_NETDEV_FAMILY_STR, NFTLB_TABLE_NAME, p->name);

		if (nft_base_rules.ndv_ingress_policies > 0)
			nft_base_rules.ndv_ingress_policies--;
		if (nft_base_rules.ndv_ingress_policies == 0)
			run_base_table(buf, NFTLB_F_CHAIN_ING_FILTER, VALUE_FAMILY_NETDEV, ACTION_DELETE);
		break;
	case ACTION_NONE:
	default:
		break;
	}

	p->action = ACTION_NONE;

	print_service_counters();
	print_nft_base_rules();

	return 0;
}

int nft_rulerize_policies(struct policy *p)
{
	struct sbuffer buf;
	int ret = 0;

	create_buf(&buf);

	run_policy_set(&buf, p);
	exec_cmd(get_buf_data(&buf));

	clean_buf(&buf);

	return ret;
}

int nft_get_rules_buffer(const char **buf, int key, struct nftst *n)
{
	struct farm *f = nftst_get_farm(n);
	struct address *a = nftst_get_address(n);
	struct policy *p = nftst_get_policy(n);

	char cmd[NFTLB_MAX_OBJ_NAME] = { 0 };
	int error = 0;

	switch (key) {
	case KEY_SESSIONS:
		if (!f || !a)
			return error;
		snprintf(cmd, NFTLB_MAX_OBJ_NAME, "list map %s nftlb persist-%s", print_nft_table_family(a->family, get_stage_by_farm_mode(f)), f->name);
		break;
	case KEY_POLICIES:
		if (!p)
			return error;
		snprintf(cmd, NFTLB_MAX_OBJ_NAME, "list set netdev nftlb %s", p->name);
		break;
	default:
		return 0;
		break;
	}

	error = exec_cmd_open(cmd, buf, 0);

	return error;
}

void nft_del_rules_buffer(const char *buf)
{
	exec_cmd_close(buf);
}

static int run_address_rules(struct sbuffer *buf, struct nftst *n, int family)
{
	struct address *a = nftst_get_address(n);
	int action = nftst_get_action(n);

	switch (action) {
	case ACTION_RELOAD:
	case ACTION_START:
		run_nftst_ingress_policies(buf, n, family, a->policies_action);
		break;
	case ACTION_DELETE:
	case ACTION_STOP:
		run_nftst_ingress_policies(buf, n, family, a->policies_action);
		break;
	default:
		break;
	}

	return 0;
}

static int run_nftst(struct sbuffer *buf, struct nftst *n)
{
	if ((nftst_get_family(n) == VALUE_FAMILY_IPV4) || (nftst_get_family(n) == VALUE_FAMILY_INET)) {
		if (nftst_has_farm(n))
			run_farm_rules(buf, n, VALUE_FAMILY_IPV4);
		else if (nftst_has_address(n))
			run_address_rules(buf, n, VALUE_FAMILY_IPV4);
	}

	if ((nftst_get_family(n) == VALUE_FAMILY_IPV6) || (nftst_get_family(n) == VALUE_FAMILY_INET)) {
		if (nftst_has_farm(n))
			run_farm_rules(buf, n, VALUE_FAMILY_IPV6);
		else if (nftst_has_address(n))
			run_address_rules(buf, n, VALUE_FAMILY_IPV6);
	}

	return 0;
}

int nft_rulerize_address(struct address *a)
{
	struct sbuffer buf;
	int ret = 0;
	struct nftst *n = nftst_create_from_address(a);

	if (!n)
		return ret;

	create_buf(&buf);

	ret = run_nftst(&buf, n);

	exec_cmd(get_buf_data(&buf));
	clean_buf(&buf);
	nftst_actions_done(n);
	nftst_delete(n);

	return ret;
}

int nft_rulerize_farms(struct farm *f)
{
	struct farmaddress *fa;
	struct nftst *n = nftst_create_from_farm(f);
	struct sbuffer buf;
	int ret = 0;

	create_buf(&buf);

	list_for_each_entry(fa, &f->addresses, list) {
		nftst_set_address(n, fa->address);
		nftst_set_action(n, fa->action);
		run_nftst(&buf, n);
	}

	exec_cmd(get_buf_data(&buf));
	clean_buf(&buf);
	nftst_actions_done(n);
	nftst_delete(n);

	print_service_counters();
	print_nft_base_rules();

	return ret;
}
