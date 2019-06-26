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
#include "farmpolicy.h"
#include "policies.h"
#include "elements.h"
#include "config.h"
#include "list.h"
#include "sbuffer.h"

#include <stdlib.h>
#include <nftables/libnftables.h>
#include <syslog.h>
#include <string.h>

#define NFTLB_MAX_CMD			2048
#define NFTLB_MAX_IFACES		100

#define NFTLB_TABLE_NAME			"nftlb"
#define NFTLB_TABLE_PREROUTING		"prerouting"
#define NFTLB_TABLE_POSTROUTING		"postrouting"
#define NFTLB_TABLE_INGRESS			"ingress"
#define NFTLB_TABLE_FILTER			"filter"

#define NFTLB_TYPE_NONE				""
#define NFTLB_TYPE_NAT				"nat"
#define NFTLB_TYPE_FILTER			"filter"
#define NFTLB_TYPE_NETDEV			"netdev"

#define NFTLB_HOOK_PREROUTING		"prerouting"
#define NFTLB_HOOK_POSTROUTING		"postrouting"
#define NFTLB_HOOK_INGRESS			"ingress"
#define NFTLB_HOOK_FILTER			"filter"

#define NFTLB_PREROUTING_PRIO		0
#define NFTLB_POSTROUTING_PRIO		100
#define NFTLB_INGRESS_PRIO			100
#define NFTLB_FILTER_PRIO			-150
#define NFTLB_RAW_PRIO				-300

#define NFTLB_IPV4_PROTOCOL		"protocol"
#define NFTLB_IPV6_PROTOCOL		"nexthdr"

#define NFTLB_UDP_PROTO			"udp"
#define NFTLB_TCP_PROTO			"tcp"
#define NFTLB_SCTP_PROTO		"sctp"

#define NFTLB_UDP_SERVICES_MAP		"udp-services"
#define NFTLB_TCP_SERVICES_MAP		"tcp-services"
#define NFTLB_SCTP_SERVICES_MAP		"sctp-services"
#define NFTLB_IP_SERVICES_MAP		"services"
#define NFTLB_UDP_SERVICES6_MAP		"udp-services6"
#define NFTLB_TCP_SERVICES6_MAP		"tcp-services6"
#define NFTLB_SCTP_SERVICES6_MAP	"sctp-services6"
#define NFTLB_IP_SERVICES6_MAP		"services6"

#define NFTLB_MAP_KEY_TYPE			0
#define NFTLB_MAP_KEY_RULE			1

#define NFTLB_MAP_TYPE_IPV4		"ipv4_addr"
#define NFTLB_MAP_TYPE_IPV6		"ipv6_addr"
#define NFTLB_MAP_TYPE_INETSRV	"inet_service"
#define NFTLB_MAP_TYPE_MAC		"ether_addr"
#define NFTLB_MAP_TYPE_MARK		"mark"

#define NFTLB_IPV4_FAMILY		"ip"
#define NFTLB_IPV6_FAMILY		"ip6"
#define NFTLB_NETDEV_FAMILY		"netdev"

#define NFTLB_IPV4_ACTIVE		(1 << 0)
#define NFTLB_IPV4_UDP_ACTIVE		(1 << 1)
#define NFTLB_IPV4_TCP_ACTIVE		(1 << 2)
#define NFTLB_IPV4_SCTP_ACTIVE		(1 << 3)
#define NFTLB_IPV4_IP_ACTIVE		(1 << 4)
#define NFTLB_IPV6_ACTIVE		(1 << 5)
#define NFTLB_IPV6_UDP_ACTIVE		(1 << 6)
#define NFTLB_IPV6_TCP_ACTIVE		(1 << 7)
#define NFTLB_IPV6_SCTP_ACTIVE		(1 << 8)
#define NFTLB_IPV6_IP_ACTIVE		(1 << 9)

#define NFTLB_NFT_DADDR			"daddr"
#define NFTLB_NFT_DPORT			"dport"
#define NFTLB_NFT_SADDR			"saddr"
#define NFTLB_NFT_SPORT			"sport"

#define NFTLB_NFT_VERDICT_DROP		"drop"
#define NFTLB_NFT_VERDICT_ACCEPT	"accept"
#define NFTLB_NFT_PREFIX_POLICY_BL	"BL"
#define NFTLB_NFT_PREFIX_POLICY_WL	"WL"

#define NFTLB_NFT_ACTION_ADD		"add"
#define NFTLB_NFT_ACTION_DEL		"delete"
#define NFTLB_NFT_ACTION_FLUSH		"flush"

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
	BCK_MAP_BCK_IPADDR_BF_PORT,
	BCK_MAP_BCK_BF_SRCIPADDR
};

struct if_base_rule {
	char			*ifname;
	unsigned int		active;
};

struct if_base_rule * ndv_base_rules[NFTLB_MAX_IFACES];
unsigned int n_ndv_base_rules = 0;
unsigned int nat_base_rules = 0;
unsigned int filter_base_rules = 0;


static int exec_cmd(char *cmd)
{
	struct nft_ctx *ctx;
	int error;

	if (strlen(cmd) == 0 || strcmp(cmd, "") == 0)
		return 0;
	syslog(LOG_NOTICE, "nft command exec : %s", cmd);

	ctx = nft_ctx_new(0);
	nft_ctx_buffer_error(ctx);

	error = nft_run_cmd_from_buffer(ctx, cmd);

	if (error)
		syslog(LOG_ERR, "nft command error : %s", nft_ctx_get_error_buffer(ctx));

	nft_ctx_unbuffer_error(ctx);
	nft_ctx_free(ctx);

	return error;
}

static char * print_nft_service(int family, int proto)
{
	if (family == VALUE_FAMILY_IPV6) {
		switch (proto) {
		case VALUE_PROTO_TCP:
			return NFTLB_TCP_SERVICES6_MAP;
		case VALUE_PROTO_UDP:
			return NFTLB_UDP_SERVICES6_MAP;
		case VALUE_PROTO_SCTP:
			return NFTLB_SCTP_SERVICES6_MAP;
		default:
			return NFTLB_IP_SERVICES6_MAP;
		}
	} else {
		switch (proto) {
		case VALUE_PROTO_TCP:
			return NFTLB_TCP_SERVICES_MAP;
		case VALUE_PROTO_UDP:
			return NFTLB_UDP_SERVICES_MAP;
		case VALUE_PROTO_SCTP:
			return NFTLB_SCTP_SERVICES_MAP;
		default:
			return NFTLB_IP_SERVICES_MAP;
		}
	}
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
	case VALUE_FAMILY_IPV6:
		return NFTLB_IPV6_FAMILY;
	default:
		return NFTLB_IPV4_FAMILY;
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

static char * print_nft_table_family(int family, int mode)
{
	if (mode == VALUE_MODE_DSR || mode == VALUE_MODE_STLSDNAT)
		return NFTLB_NETDEV_FAMILY;
	else if (family == VALUE_FAMILY_IPV6)
		return NFTLB_IPV6_FAMILY;
	else
		return NFTLB_IPV4_FAMILY;
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

static char * print_nft_verdict(enum type type)
{
	if (type == VALUE_TYPE_WHITE)
		return NFTLB_NFT_VERDICT_ACCEPT;
	else
		return NFTLB_NFT_VERDICT_DROP;
}

static char * print_nft_prefix_policy(enum type type)
{
	if (type == VALUE_TYPE_WHITE)
		return NFTLB_NFT_PREFIX_POLICY_WL;
	else
		return NFTLB_NFT_PREFIX_POLICY_BL;
}

static void get_range_ports(const char *ptr, int *first, int *last)
{
	sscanf(ptr, "%d-%d[^,]", first, last);
}

static struct if_base_rule * get_ndv_base(char *ifname)
{
	unsigned int i;

	for (i = 0; i < n_ndv_base_rules; i++) {
		if (strcmp(ndv_base_rules[i]->ifname, ifname) == 0)
			return ndv_base_rules[i];
	}

	return NULL;
}

static struct if_base_rule * add_ndv_base(char *ifname)
{
	struct if_base_rule *ifentry;

	if (n_ndv_base_rules == NFTLB_MAX_IFACES)
		return NULL;

	ifentry = (struct if_base_rule *)malloc(sizeof(struct if_base_rule));
	if (!ifentry)
		return NULL;

	ndv_base_rules[n_ndv_base_rules] = ifentry;
	n_ndv_base_rules++;

	ifentry->ifname = (char *)malloc(strlen(ifname));
	if (!ifentry->ifname)
		return NULL;

	sprintf(ifentry->ifname, "%s", ifname);
	ifentry->active = 0;

	return ifentry;
}

static int reset_ndv_base(void)
{
	unsigned int i;

	for (i = 0; i < n_ndv_base_rules; i++) {
		if (ndv_base_rules[i]->ifname)
			free(ndv_base_rules[i]->ifname);
		if (ndv_base_rules[i])
			free(ndv_base_rules[i]);
	}

	return 0;
}

static unsigned int get_rules_needed(int family, int protocol, int key)
{
	unsigned int ret = 0;

	if (family == VALUE_FAMILY_IPV4 || family == VALUE_FAMILY_INET) {
		switch (protocol) {
		case VALUE_PROTO_UDP:
			ret |= NFTLB_IPV4_ACTIVE | NFTLB_IPV4_UDP_ACTIVE;
			break;
		case VALUE_PROTO_TCP:
			ret |= NFTLB_IPV4_ACTIVE | NFTLB_IPV4_TCP_ACTIVE;
			break;
		case VALUE_PROTO_SCTP:
			ret |= NFTLB_IPV4_ACTIVE | NFTLB_IPV4_SCTP_ACTIVE;
			break;
		default:
			ret |= NFTLB_IPV4_ACTIVE | NFTLB_IPV4_IP_ACTIVE;
			break;
		}
	}

	if (family == VALUE_FAMILY_IPV6 || family == VALUE_FAMILY_INET) {
		switch (protocol) {
		case VALUE_PROTO_UDP:
			ret |= NFTLB_IPV6_ACTIVE | NFTLB_IPV6_UDP_ACTIVE;
			break;
		case VALUE_PROTO_TCP:
			ret |= NFTLB_IPV6_ACTIVE | NFTLB_IPV6_TCP_ACTIVE;
			break;
		case VALUE_PROTO_SCTP:
			ret |= NFTLB_IPV6_ACTIVE | NFTLB_IPV6_SCTP_ACTIVE;
			break;
		default:
			ret |= NFTLB_IPV6_ACTIVE | NFTLB_IPV6_IP_ACTIVE;
			break;
		}
	}

	return ret;
}

static void logprefix_replace(char *buf, char *token, char *value)
{
	char tmp[255] = { 0 };
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

static void print_log_format(char *buf, int key, struct farm *f, struct backend *b, struct policy *p)
{
	if (!f) {
		return;
	}

	switch (key) {
	case KEY_LOGPREFIX:
		if (p) {
			sprintf(buf, "%s", p->logprefix);
			logprefix_replace(buf, "KNAME", "policy");
			logprefix_replace(buf, "FNAME", f->name);
			logprefix_replace(buf, "PNAME", p->name);
			logprefix_replace(buf, "TYPE", print_nft_prefix_policy(p->type));
			return;
		}
		sprintf(buf, "%s", f->logprefix);
		logprefix_replace(buf, "KNAME", CONFIG_KEY_LOG);
		logprefix_replace(buf, "FNAME", f->name);
		if (f->log & VALUE_LOG_INPUT)
			logprefix_replace(buf, "TYPE", "IN");
		break;
	case KEY_NEWRTLIMIT_LOGPREFIX:
		sprintf(buf, "%s", f->newrtlimit_logprefix);
		logprefix_replace(buf, "KNAME", CONFIG_KEY_NEWRTLIMIT);
		logprefix_replace(buf, "FNAME", f->name);
		break;
	case KEY_RSTRTLIMIT_LOGPREFIX:
		sprintf(buf, "%s", f->rstrtlimit_logprefix);
		logprefix_replace(buf, "KNAME", CONFIG_KEY_RSTRTLIMIT);
		logprefix_replace(buf, "FNAME", f->name);
		break;
	case KEY_ESTCONNLIMIT_LOGPREFIX:
		if (b) {
			sprintf(buf, "%s", b->estconnlimit_logprefix);
			logprefix_replace(buf, "KNAME", CONFIG_KEY_ESTCONNLIMIT);
			logprefix_replace(buf, "FNAME", f->name);
			logprefix_replace(buf, "BNAME", b->name);
			return;
		}
		sprintf(buf, "%s", f->estconnlimit_logprefix);
		logprefix_replace(buf, "KNAME", CONFIG_KEY_ESTCONNLIMIT);
		logprefix_replace(buf, "FNAME", f->name);
		break;
	case KEY_TCPSTRICT_LOGPREFIX:
		sprintf(buf, "%s", f->tcpstrict_logprefix);
		logprefix_replace(buf, "KNAME", CONFIG_KEY_TCPSTRICT);
		logprefix_replace(buf, "FNAME", f->name);
		break;
	default:
		break;
	}
}

static int need_filter(struct farm *f)
{
	return (!farm_is_ingress_mode(f)) && (f->helper != DEFAULT_HELPER || f->bcks_are_marked || f->mark != DEFAULT_MARK || farm_get_masquerade(f) ||
			f->newrtlimit != DEFAULT_NEWRTLIMIT || f->rstrtlimit != DEFAULT_RSTRTLIMIT || f->estconnlimit != DEFAULT_ESTCONNLIMIT ||
			f->tcpstrict != DEFAULT_TCPSTRICT || f->queue != DEFAULT_QUEUE || f->persistence != DEFAULT_PERSIST ||
			(f->srcaddr != DEFAULT_SRCADDR && strcmp(f->srcaddr, "") != 0));
}

static int run_base_table(struct sbuffer *buf, char *family_str)
{
	concat_buf(buf, " ; add table %s %s", family_str, NFTLB_TABLE_NAME);
	return 0;
}

static int run_base_chain_ndv(struct sbuffer *buf, struct farm *f, int key)
{
	struct if_base_rule *if_base;
	unsigned int rules_needed;
	char *if_str = f->iface;
	char *addr_str = NFTLB_NFT_DADDR;
	char *port_str = NFTLB_NFT_DPORT;
	char chain[255] = { 0 };

	if (key == KEY_OFACE) {
		if_str = f->oface;
		addr_str = NFTLB_NFT_SADDR;
		port_str = NFTLB_NFT_SPORT;
	}

	sprintf(chain, "%s-%s", NFTLB_TABLE_INGRESS, if_str);

	rules_needed = get_rules_needed(f->family, f->protocol, key);
	if_base = get_ndv_base(if_str);

	if (!if_base)
		if_base = add_ndv_base(if_str);

	if (((rules_needed & NFTLB_IPV4_ACTIVE) && !(if_base->active & NFTLB_IPV4_ACTIVE)) ||
	    ((rules_needed & NFTLB_IPV6_ACTIVE) && !(if_base->active & NFTLB_IPV6_ACTIVE))) {
		concat_buf(buf, " ; add chain %s %s %s { type %s hook %s device %s priority %d ;}", NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, chain, NFTLB_TYPE_FILTER, NFTLB_HOOK_INGRESS, if_str, NFTLB_INGRESS_PRIO);
		if_base->active |= NFTLB_IPV4_ACTIVE;
		if_base->active |= NFTLB_IPV6_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV4_UDP_ACTIVE) && !(if_base->active & NFTLB_IPV4_UDP_ACTIVE)) {
		concat_buf(buf, " ; add map %s %s %s-%s { type %s . %s : verdict ;}", NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, print_nft_service(VALUE_FAMILY_IPV4, f->protocol), if_str, NFTLB_MAP_TYPE_IPV4, NFTLB_MAP_TYPE_INETSRV);
		concat_buf(buf, " ; add rule %s %s %s %s %s . %s %s vmap @%s-%s", NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, chain, NFTLB_IPV4_FAMILY, addr_str, NFTLB_UDP_PROTO, port_str, print_nft_service(VALUE_FAMILY_IPV4, f->protocol), if_str);
		if_base->active |= NFTLB_IPV4_UDP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV4_TCP_ACTIVE) && !(if_base->active & NFTLB_IPV4_TCP_ACTIVE)) {
		concat_buf(buf, " ; add map %s %s %s-%s { type %s . %s : verdict ;}", NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, print_nft_service(VALUE_FAMILY_IPV4, f->protocol), if_str, NFTLB_MAP_TYPE_IPV4, NFTLB_MAP_TYPE_INETSRV);
		concat_buf(buf, " ; add rule %s %s %s %s %s . %s %s vmap @%s-%s", NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, chain, NFTLB_IPV4_FAMILY, addr_str, NFTLB_TCP_PROTO, port_str, print_nft_service(VALUE_FAMILY_IPV4, f->protocol), if_str);
		if_base->active |= NFTLB_IPV4_TCP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV4_SCTP_ACTIVE) && !(if_base->active & NFTLB_IPV4_SCTP_ACTIVE)) {
		concat_buf(buf, " ; add map %s %s %s-%s { type %s . %s : verdict ;}", NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, print_nft_service(VALUE_FAMILY_IPV4, f->protocol), if_str, NFTLB_MAP_TYPE_IPV4, NFTLB_MAP_TYPE_INETSRV);
		concat_buf(buf, " ; add rule %s %s %s %s %s . %s %s vmap @%s-%s", NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, chain, NFTLB_IPV4_FAMILY, addr_str, NFTLB_SCTP_PROTO, port_str, print_nft_service(VALUE_FAMILY_IPV4, f->protocol), if_str);
		if_base->active |= NFTLB_IPV4_SCTP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV6_UDP_ACTIVE) && !(if_base->active & NFTLB_IPV6_UDP_ACTIVE)) {
		concat_buf(buf, " ; add map %s %s %s-%s { type %s . %s : verdict ;}", NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, print_nft_service(VALUE_FAMILY_IPV6, f->protocol), if_str, NFTLB_MAP_TYPE_IPV6, NFTLB_MAP_TYPE_INETSRV);
		concat_buf(buf, " ; add rule %s %s %s %s %s . %s %s vmap @%s-%s", NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, chain, NFTLB_IPV6_FAMILY, addr_str, NFTLB_UDP_PROTO, port_str, print_nft_service(VALUE_FAMILY_IPV6, f->protocol), if_str);
		if_base->active |= NFTLB_IPV6_UDP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV6_TCP_ACTIVE) && !(if_base->active & NFTLB_IPV6_TCP_ACTIVE)) {
		concat_buf(buf, " ; add map %s %s %s-%s { type %s . %s : verdict ;}", NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, print_nft_service(VALUE_FAMILY_IPV6, f->protocol), if_str, NFTLB_MAP_TYPE_IPV6, NFTLB_MAP_TYPE_INETSRV);
		concat_buf(buf, " ; add rule %s %s %s %s %s . %s %s vmap @%s-%s", NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, chain, NFTLB_IPV6_FAMILY, addr_str, NFTLB_TCP_PROTO, port_str, print_nft_service(VALUE_FAMILY_IPV6, f->protocol), if_str);
		if_base->active |= NFTLB_IPV6_TCP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV6_SCTP_ACTIVE) && !(if_base->active & NFTLB_IPV6_SCTP_ACTIVE)) {
		concat_buf(buf, " ; add map %s %s %s-%s { type %s . %s : verdict ;}", NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, print_nft_service(VALUE_FAMILY_IPV6, f->protocol), if_str, NFTLB_MAP_TYPE_IPV6, NFTLB_MAP_TYPE_INETSRV);
		concat_buf(buf, " ; add rule %s %s %s %s %s . %s %s vmap @%s-%s", NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, chain, NFTLB_IPV6_FAMILY, addr_str, NFTLB_SCTP_PROTO, port_str, print_nft_service(VALUE_FAMILY_IPV6, f->protocol), if_str);
		if_base->active |= NFTLB_IPV6_SCTP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV4_IP_ACTIVE) && !(if_base->active & NFTLB_IPV4_IP_ACTIVE)) {
		concat_buf(buf, " ; add map %s %s %s-%s { type %s : verdict ;}", NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, print_nft_service(VALUE_FAMILY_IPV4, f->protocol), if_str, NFTLB_MAP_TYPE_IPV4);
		concat_buf(buf, " ; add rule %s %s %s %s %s vmap @%s-%s", NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, chain, NFTLB_IPV4_FAMILY, addr_str, print_nft_service(VALUE_FAMILY_IPV4, f->protocol), if_str);
		if_base->active |= NFTLB_IPV4_IP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV6_IP_ACTIVE) && !(if_base->active & NFTLB_IPV6_IP_ACTIVE)) {
		concat_buf(buf, " ; add map %s %s %s-%s { type %s : verdict ;}", NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, print_nft_service(VALUE_FAMILY_IPV6, f->protocol), if_str, NFTLB_MAP_TYPE_IPV6);
		concat_buf(buf, " ; add rule %s %s %s %s %s vmap @%s-%s", NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, chain, NFTLB_IPV6_FAMILY, addr_str, print_nft_service(VALUE_FAMILY_IPV6, f->protocol), if_str);
		if_base->active |= NFTLB_IPV6_IP_ACTIVE;
	}

	return 0;
}

static int run_base_nat(struct sbuffer *buf, struct farm *f)
{
	unsigned int rules_needed = get_rules_needed(f->family, f->protocol, KEY_IFACE);

	if ((rules_needed & NFTLB_IPV4_ACTIVE) && !(nat_base_rules & NFTLB_IPV4_ACTIVE)) {
		run_base_table(buf, NFTLB_IPV4_FAMILY);
		concat_buf(buf, " ; add chain %s %s %s { type %s hook %s priority %d ;}", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_PREROUTING, NFTLB_TYPE_NAT, NFTLB_HOOK_PREROUTING, NFTLB_PREROUTING_PRIO);
		concat_buf(buf, " ; add chain %s %s %s { type %s hook %s priority %d ;}", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, NFTLB_TYPE_NAT, NFTLB_HOOK_POSTROUTING, NFTLB_POSTROUTING_PRIO);
		concat_buf(buf, " ; add rule %s %s %s ct mark and 0x%x == 0x%x masquerade", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, NFTLB_POSTROUTING_MARK, NFTLB_POSTROUTING_MARK);
		nat_base_rules |= NFTLB_IPV4_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV6_ACTIVE) && !(nat_base_rules & NFTLB_IPV6_ACTIVE)) {
		run_base_table(buf, NFTLB_IPV6_FAMILY);
		concat_buf(buf, " ; add chain %s %s %s { type %s hook %s priority %d ;}", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_PREROUTING, NFTLB_TYPE_NAT, NFTLB_HOOK_PREROUTING, NFTLB_PREROUTING_PRIO);
		concat_buf(buf, " ; add chain %s %s %s { type %s hook %s priority %d ;}", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, NFTLB_TYPE_NAT, NFTLB_HOOK_POSTROUTING, NFTLB_POSTROUTING_PRIO);
		concat_buf(buf, " ; add rule %s %s %s ct mark and 0x%x == 0x%x masquerade", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, NFTLB_POSTROUTING_MARK, NFTLB_POSTROUTING_MARK);
		nat_base_rules |= NFTLB_IPV6_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV4_UDP_ACTIVE) && !(nat_base_rules & NFTLB_IPV4_UDP_ACTIVE)) {
		concat_buf(buf, " ; add map %s %s %s-%s { type %s . %s : verdict ;}", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TYPE_NAT, NFTLB_UDP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV4, NFTLB_MAP_TYPE_INETSRV);
		concat_buf(buf, " ; add rule %s %s %s %s daddr . %s dport vmap @%s-%s", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_PREROUTING, NFTLB_IPV4_FAMILY, NFTLB_UDP_PROTO, NFTLB_TYPE_NAT, NFTLB_UDP_SERVICES_MAP);
		concat_buf(buf, " ; add map %s %s %s-back { type %s . %s : %s ;}", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_UDP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV4, NFTLB_MAP_TYPE_INETSRV, NFTLB_MAP_TYPE_IPV4);
		concat_buf(buf, " ; add rule %s %s %s snat to %s daddr . %s dport map @%s-back", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, NFTLB_IPV4_FAMILY, NFTLB_UDP_PROTO, NFTLB_UDP_SERVICES_MAP);
		concat_buf(buf, " ; add map %s %s %s-m-back { type %s : %s ;}", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_UDP_SERVICES_MAP, NFTLB_MAP_TYPE_MARK, NFTLB_MAP_TYPE_IPV4);
		concat_buf(buf, " ; add rule %s %s %s snat to ct mark map @%s-m-back", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, NFTLB_UDP_SERVICES_MAP);
		nat_base_rules |= NFTLB_IPV4_UDP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV4_TCP_ACTIVE) && !(nat_base_rules & NFTLB_IPV4_TCP_ACTIVE)) {
		concat_buf(buf, " ; add map %s %s %s-%s { type %s . %s : verdict ;}", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TYPE_NAT, NFTLB_TCP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV4, NFTLB_MAP_TYPE_INETSRV);
		concat_buf(buf, " ; add rule %s %s %s %s daddr . %s dport vmap @%s-%s", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_PREROUTING, NFTLB_IPV4_FAMILY, NFTLB_TCP_PROTO, NFTLB_TYPE_NAT, NFTLB_TCP_SERVICES_MAP);
		concat_buf(buf, " ; add map %s %s %s-back { type %s . %s : %s ;}", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TCP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV4, NFTLB_MAP_TYPE_INETSRV, NFTLB_MAP_TYPE_IPV4);
		concat_buf(buf, " ; add rule %s %s %s snat to %s daddr . %s dport map @%s-back", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, NFTLB_IPV4_FAMILY, NFTLB_TCP_PROTO, NFTLB_TCP_SERVICES_MAP);
		concat_buf(buf, " ; add map %s %s %s-m-back { type %s : %s ;}", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TCP_SERVICES_MAP, NFTLB_MAP_TYPE_MARK, NFTLB_MAP_TYPE_IPV4);
		concat_buf(buf, " ; add rule %s %s %s snat to ct mark map @%s-m-back", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, NFTLB_TCP_SERVICES_MAP);
		nat_base_rules |= NFTLB_IPV4_TCP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV4_SCTP_ACTIVE) && !(nat_base_rules & NFTLB_IPV4_SCTP_ACTIVE)) {
		concat_buf(buf, " ; add map %s %s %s-%s { type %s . %s : verdict ;}", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TYPE_NAT, NFTLB_SCTP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV4, NFTLB_MAP_TYPE_INETSRV);
		concat_buf(buf, " ; add rule %s %s %s %s daddr . %s dport vmap @%s-%s", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_PREROUTING, NFTLB_IPV4_FAMILY, NFTLB_SCTP_PROTO, NFTLB_TYPE_NAT, NFTLB_SCTP_SERVICES_MAP);
		concat_buf(buf, " ; add map %s %s %s-back { type %s . %s : %s ;}", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_SCTP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV4, NFTLB_MAP_TYPE_INETSRV, NFTLB_MAP_TYPE_IPV4);
		concat_buf(buf, " ; add rule %s %s %s snat to %s daddr . %s dport map @%s-back", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, NFTLB_IPV4_FAMILY, NFTLB_SCTP_PROTO, NFTLB_SCTP_SERVICES_MAP);
		concat_buf(buf, " ; add map %s %s %s-m-back { type %s : %s ;}", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_SCTP_SERVICES_MAP, NFTLB_MAP_TYPE_MARK, NFTLB_MAP_TYPE_IPV4);
		concat_buf(buf, " ; add rule %s %s %s snat to ct mark map @%s-m-back", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, NFTLB_SCTP_SERVICES_MAP);
		nat_base_rules |= NFTLB_IPV4_SCTP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV4_IP_ACTIVE) && !(nat_base_rules & NFTLB_IPV4_IP_ACTIVE)) {
		concat_buf(buf, " ; add map %s %s %s-%s { type %s : verdict ;}", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TYPE_NAT, NFTLB_IP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV4);
		concat_buf(buf, " ; add rule %s %s %s %s daddr vmap @%s-%s", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_PREROUTING, NFTLB_IPV4_FAMILY, NFTLB_TYPE_NAT, NFTLB_IP_SERVICES_MAP);
		concat_buf(buf, " ; add map %s %s %s-back { type %s : %s ;}", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_IP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV4, NFTLB_MAP_TYPE_IPV4);
		concat_buf(buf, " ; add rule %s %s %s snat to %s daddr map @%s-back", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, NFTLB_IPV4_FAMILY, NFTLB_IP_SERVICES_MAP);
		concat_buf(buf, " ; add map %s %s %s-m-back { type %s : %s ;}", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_IP_SERVICES_MAP, NFTLB_MAP_TYPE_MARK, NFTLB_MAP_TYPE_IPV4);
		concat_buf(buf, " ; add rule %s %s %s snat to ct mark map @%s-m-back", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, NFTLB_IP_SERVICES_MAP);
		nat_base_rules |= NFTLB_IPV4_IP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV6_UDP_ACTIVE) && !(nat_base_rules & NFTLB_IPV6_UDP_ACTIVE)) {
		concat_buf(buf, " ; add map %s %s %s-%s { type %s . %s : verdict ;}", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TYPE_NAT, NFTLB_UDP_SERVICES6_MAP, NFTLB_MAP_TYPE_IPV6, NFTLB_MAP_TYPE_INETSRV);
		concat_buf(buf, " ; add rule %s %s %s %s daddr . %s dport vmap @%s-%s", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_PREROUTING, NFTLB_IPV6_FAMILY, NFTLB_UDP_PROTO, NFTLB_TYPE_NAT, NFTLB_UDP_SERVICES6_MAP);
		concat_buf(buf, " ; add map %s %s %s-back { type %s . %s : %s ;}", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_UDP_SERVICES6_MAP, NFTLB_MAP_TYPE_IPV6, NFTLB_MAP_TYPE_INETSRV, NFTLB_MAP_TYPE_IPV6);
		concat_buf(buf, " ; add rule %s %s %s snat to %s daddr . %s dport map @%s-back", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, NFTLB_IPV6_FAMILY, NFTLB_UDP_PROTO, NFTLB_UDP_SERVICES6_MAP);
		concat_buf(buf, " ; add map %s %s %s-m-back { type %s : %s ;}", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_UDP_SERVICES_MAP, NFTLB_MAP_TYPE_MARK, NFTLB_MAP_TYPE_IPV6);
		concat_buf(buf, " ; add rule %s %s %s snat to ct mark map @%s-m-back", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, NFTLB_UDP_SERVICES_MAP);
		nat_base_rules |= NFTLB_IPV6_UDP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV6_TCP_ACTIVE) && !(nat_base_rules & NFTLB_IPV6_TCP_ACTIVE)) {
		concat_buf(buf, " ; add map %s %s %s-%s { type %s . %s : verdict ;}", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TYPE_NAT, NFTLB_TCP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV6, NFTLB_MAP_TYPE_INETSRV);
		concat_buf(buf, " ; add rule %s %s %s %s daddr . %s dport vmap @%s-%s", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_PREROUTING, NFTLB_IPV6_FAMILY, NFTLB_TCP_PROTO, NFTLB_TYPE_NAT, NFTLB_TCP_SERVICES_MAP);
		concat_buf(buf, " ; add map %s %s %s-back { type %s . %s : %s ;}", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TCP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV6, NFTLB_MAP_TYPE_INETSRV, NFTLB_MAP_TYPE_IPV6);
		concat_buf(buf, " ; add rule %s %s %s snat to %s daddr . %s dport map @%s-back", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, NFTLB_IPV6_FAMILY, NFTLB_TCP_PROTO, NFTLB_TCP_SERVICES_MAP);
		concat_buf(buf, " ; add map %s %s %s-m-back { type %s : %s ;}", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TCP_SERVICES_MAP, NFTLB_MAP_TYPE_MARK, NFTLB_MAP_TYPE_IPV6);
		concat_buf(buf, " ; add rule %s %s %s snat to ct mark map @%s-m-back", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, NFTLB_TCP_SERVICES_MAP);
		nat_base_rules |= NFTLB_IPV6_TCP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV6_SCTP_ACTIVE) && !(nat_base_rules & NFTLB_IPV6_SCTP_ACTIVE)) {
		concat_buf(buf, " ; add map %s %s %s-%s { type %s . %s : verdict ;}", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TYPE_NAT, NFTLB_SCTP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV6, NFTLB_MAP_TYPE_INETSRV);
		concat_buf(buf, " ; add rule %s %s %s %s daddr . %s dport vmap @%s-%s", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_PREROUTING, NFTLB_IPV6_FAMILY, NFTLB_SCTP_PROTO, NFTLB_TYPE_NAT, NFTLB_SCTP_SERVICES_MAP);
		concat_buf(buf, " ; add map %s %s %s-back { type %s . %s : %s ;}", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_SCTP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV6, NFTLB_MAP_TYPE_INETSRV, NFTLB_MAP_TYPE_IPV6);
		concat_buf(buf, " ; add rule %s %s %s snat to %s daddr . %s dport map @%s-back", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, NFTLB_IPV6_FAMILY, NFTLB_SCTP_PROTO, NFTLB_SCTP_SERVICES_MAP);
		concat_buf(buf, " ; add map %s %s %s-m-back { type %s : %s ;}", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_SCTP_SERVICES_MAP, NFTLB_MAP_TYPE_MARK, NFTLB_MAP_TYPE_IPV6);
		concat_buf(buf, " ; add rule %s %s %s snat to ct mark map @%s-m-back", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, NFTLB_SCTP_SERVICES_MAP);
		nat_base_rules |= NFTLB_IPV6_SCTP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV6_IP_ACTIVE) && !(nat_base_rules & NFTLB_IPV6_IP_ACTIVE)) {
		concat_buf(buf, " ; add map %s %s %s-%s { type %s : verdict ;}", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TYPE_NAT, NFTLB_IP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV6);
		concat_buf(buf, " ; add rule %s %s %s %s daddr vmap @%s-%s", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_PREROUTING, NFTLB_IPV6_FAMILY, NFTLB_TYPE_NAT, NFTLB_IP_SERVICES_MAP);
		concat_buf(buf, " ; add map %s %s %s-back { type %s : %s ;}", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_IP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV6, NFTLB_MAP_TYPE_IPV6);
		concat_buf(buf, " ; add rule %s %s %s snat to %s daddr map @%s-back", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, NFTLB_IPV6_FAMILY, NFTLB_IP_SERVICES_MAP);
		concat_buf(buf, " ; add map %s %s %s-m-back { type %s : %s ;}", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_IP_SERVICES_MAP, NFTLB_MAP_TYPE_MARK, NFTLB_MAP_TYPE_IPV6);
		concat_buf(buf, " ; add rule %s %s %s snat to ct mark map @%s-m-back", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, NFTLB_IP_SERVICES_MAP);
		nat_base_rules |= NFTLB_IPV6_IP_ACTIVE;
	}

	return 0;
}

static int run_base_filter(struct sbuffer *buf, struct farm *f)
{
	unsigned int rules_needed = get_rules_needed(f->family, f->protocol, KEY_IFACE);

	if ((rules_needed & NFTLB_IPV4_ACTIVE) && !(filter_base_rules & NFTLB_IPV4_ACTIVE)) {
		run_base_table(buf, NFTLB_IPV4_FAMILY);
		concat_buf(buf, " ; add chain %s %s %s { type %s hook %s priority %d ;}", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_FILTER, NFTLB_TYPE_FILTER, NFTLB_HOOK_PREROUTING, NFTLB_FILTER_PRIO);
		concat_buf(buf, " ; add rule %s %s %s mark set ct mark", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_FILTER);
		filter_base_rules |= NFTLB_IPV4_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV6_ACTIVE) && !(filter_base_rules & NFTLB_IPV6_ACTIVE)) {
		run_base_table(buf, NFTLB_IPV6_FAMILY);
		concat_buf(buf, " ; add chain %s %s %s { type %s hook %s priority %d ;}", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_FILTER, NFTLB_TYPE_FILTER, NFTLB_HOOK_PREROUTING, NFTLB_FILTER_PRIO);
		concat_buf(buf, " ; add rule %s %s %s mark set ct mark", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_FILTER);
		filter_base_rules |= NFTLB_IPV6_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV4_UDP_ACTIVE) && !(filter_base_rules & NFTLB_IPV4_UDP_ACTIVE)) {
		concat_buf(buf, " ; add map %s %s %s-%s { type %s . %s : verdict ;}", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TYPE_FILTER, NFTLB_UDP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV4, NFTLB_MAP_TYPE_INETSRV);
		concat_buf(buf, " ; add rule %s %s %s %s daddr . %s dport vmap @%s-%s", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_FILTER, NFTLB_IPV4_FAMILY, NFTLB_UDP_PROTO, NFTLB_TYPE_FILTER, NFTLB_UDP_SERVICES_MAP);
		filter_base_rules |= NFTLB_IPV4_UDP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV4_TCP_ACTIVE) && !(filter_base_rules & NFTLB_IPV4_TCP_ACTIVE)) {
		concat_buf(buf, " ; add map %s %s %s-%s { type %s . %s : verdict ;}", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TYPE_FILTER, NFTLB_TCP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV4, NFTLB_MAP_TYPE_INETSRV);
		concat_buf(buf, " ; add rule %s %s %s %s daddr . %s dport vmap @%s-%s", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_FILTER, NFTLB_IPV4_FAMILY, NFTLB_TCP_PROTO, NFTLB_TYPE_FILTER, NFTLB_TCP_SERVICES_MAP);
		filter_base_rules |= NFTLB_IPV4_TCP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV4_SCTP_ACTIVE) && !(filter_base_rules & NFTLB_IPV4_SCTP_ACTIVE)) {
		concat_buf(buf, " ; add map %s %s %s-%s { type %s . %s : verdict ;}", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TYPE_FILTER, NFTLB_SCTP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV4, NFTLB_MAP_TYPE_INETSRV);
		concat_buf(buf, " ; add rule %s %s %s %s daddr . %s dport vmap @%s-%s", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_FILTER, NFTLB_IPV4_FAMILY, NFTLB_SCTP_PROTO, NFTLB_TYPE_FILTER, NFTLB_SCTP_SERVICES_MAP);
		filter_base_rules |= NFTLB_IPV4_SCTP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV4_IP_ACTIVE) && !(filter_base_rules & NFTLB_IPV4_IP_ACTIVE)) {
		concat_buf(buf, " ; add map %s %s %s-%s { type %s : verdict ;}", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TYPE_FILTER, NFTLB_IP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV4);
		concat_buf(buf, " ; add rule %s %s %s %s daddr vmap @%s-%s", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_FILTER, NFTLB_IPV4_FAMILY, NFTLB_TYPE_FILTER, NFTLB_IP_SERVICES_MAP);
		filter_base_rules |= NFTLB_IPV4_IP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV6_UDP_ACTIVE) && !(filter_base_rules & NFTLB_IPV6_UDP_ACTIVE)) {
		concat_buf(buf, " ; add map %s %s %s-%s { type %s . %s : verdict ;}", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TYPE_FILTER, NFTLB_UDP_SERVICES6_MAP, NFTLB_MAP_TYPE_IPV6, NFTLB_MAP_TYPE_INETSRV);
		concat_buf(buf, " ; add rule %s %s %s %s daddr . %s dport vmap @%s-%s", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_FILTER, NFTLB_IPV6_FAMILY, NFTLB_UDP_PROTO, NFTLB_TYPE_FILTER, NFTLB_UDP_SERVICES6_MAP);
		filter_base_rules |= NFTLB_IPV6_UDP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV6_TCP_ACTIVE) && !(filter_base_rules & NFTLB_IPV6_TCP_ACTIVE)) {
		concat_buf(buf, " ; add map %s %s %s-%s { type %s . %s : verdict ;}", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TYPE_FILTER, NFTLB_TCP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV6, NFTLB_MAP_TYPE_INETSRV);
		concat_buf(buf, " ; add rule %s %s %s %s daddr . %s dport vmap @%s-%s", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_FILTER, NFTLB_IPV6_FAMILY, NFTLB_TCP_PROTO, NFTLB_TYPE_FILTER, NFTLB_TCP_SERVICES_MAP);
		filter_base_rules |= NFTLB_IPV6_TCP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV6_SCTP_ACTIVE) && !(filter_base_rules & NFTLB_IPV6_SCTP_ACTIVE)) {
		concat_buf(buf, " ; add map %s %s %s-%s { type %s . %s : verdict ;}", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TYPE_FILTER, NFTLB_SCTP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV6, NFTLB_MAP_TYPE_INETSRV);
		concat_buf(buf, " ; add rule %s %s %s %s daddr . %s dport vmap @%s-%s", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_FILTER, NFTLB_IPV6_FAMILY, NFTLB_SCTP_PROTO, NFTLB_TYPE_FILTER, NFTLB_SCTP_SERVICES_MAP);
		filter_base_rules |= NFTLB_IPV6_SCTP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV6_IP_ACTIVE) && !(filter_base_rules & NFTLB_IPV6_IP_ACTIVE)) {
		concat_buf(buf, " ; add map %s %s %s-%s { type %s : verdict ;}", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TYPE_FILTER, NFTLB_IP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV6);
		concat_buf(buf, " ; add rule %s %s %s %s daddr vmap @%s-%s", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_FILTER, NFTLB_IPV6_FAMILY, NFTLB_TYPE_FILTER, NFTLB_IP_SERVICES_MAP);
		filter_base_rules |= NFTLB_IPV6_IP_ACTIVE;
	}

	return 0;
}

static int run_farm_rules_gen_chains(struct sbuffer *buf, char *nft_family, char *chain, int action)
{
	switch (action) {
	case ACTION_RELOAD:
		concat_buf(buf, " ; flush chain %s %s %s", nft_family, NFTLB_TABLE_NAME, chain);
		break;
	case ACTION_START:
		concat_buf(buf, " ; add chain %s %s %s", nft_family, NFTLB_TABLE_NAME, chain);
		break;
	case ACTION_DELETE:
		concat_buf(buf, " ; flush chain %s %s %s", nft_family, NFTLB_TABLE_NAME, chain);
		concat_buf(buf, " ; delete chain %s %s %s", nft_family, NFTLB_TABLE_NAME, chain);
		break;
	default:
		break;
	}

	return 0;
}

static int get_array_ports(int *port_list, struct farm *f)
{
	int index = 0;
	char *ptr;
	int i, new;
	int last = 0;

	ptr = f->virtports;
	while (ptr != NULL && *ptr != '\0') {
		last = new = 0;
		get_range_ports(ptr, &new, &last);
		if (last == 0)
			last = new;
		if (new > last)
			goto next;
		for (i = new; i <= last; i++, index++)
			port_list[index] = i;
next:
		ptr = strchr(ptr, ',');
		if (ptr != NULL)
			ptr++;
	}

	return index;
}

static int run_farm_rules_gen_srv_data(char **buf, struct farm *f, struct backend *b, char *chain, enum map_modes data_mode)
{
	switch (data_mode) {
	case BCK_MAP_SRCIPADDR:
		if (f != NULL)
			sprintf(*buf, ": %s ", f->srcaddr);
		break;
	case BCK_MAP_NAME:
		sprintf(*buf, ": goto %s ", chain);
		break;
	case BCK_MAP_BCK_BF_SRCIPADDR:
		if (b != NULL && b->srcaddr != DEFAULT_SRCADDR && strcmp(b->srcaddr, "") != 0)
			sprintf(*buf, ": %s ", b->srcaddr);
		else if (f != NULL && f->srcaddr != DEFAULT_SRCADDR && strcmp(f->srcaddr, "") != 0)
			sprintf(*buf, ": %s ", f->srcaddr);
		break;
	default:
		break;
	}

	return 0;
}

static int run_farm_rules_gen_srv(struct sbuffer *buf, struct farm *f, char *nft_family, char *chain, char *service, int action, enum map_modes key_mode, enum map_modes data_mode)
{
	int port_list[65535] = { 0 };
	char action_str[255] = { 0 };
	char *data_str;
	struct backend *b;
	int nports;
	int i;

	data_str = calloc(1, 255);
	if (!data_str) {
		syslog(LOG_ERR, "%s():%d: memory allocation error", __FUNCTION__, __LINE__);
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
		break;
	}

	/* avoid port in cases of listening from all protocols */
	if (f->protocol == VALUE_PROTO_ALL && key_mode == BCK_MAP_IPADDR_PORT)
		key_mode = BCK_MAP_IPADDR;
	if (f->protocol == VALUE_PROTO_ALL && (key_mode == BCK_MAP_BCK_IPADDR_F_PORT || key_mode == BCK_MAP_BCK_IPADDR_BF_PORT))
		key_mode = BCK_MAP_BCK_IPADDR;

	switch (key_mode) {
	case BCK_MAP_IPADDR:
		run_farm_rules_gen_srv_data((char **) &data_str, f, NULL, chain, data_mode);
		concat_buf(buf, " ; %s element %s %s %s { %s %s}", action_str, nft_family, NFTLB_TABLE_NAME, service, f->virtaddr, data_str);
		break;
	case BCK_MAP_BCK_IPADDR:
		list_for_each_entry(b, &f->backends, list) {
			if (b->action == ACTION_STOP || b->action == ACTION_DELETE) {
				if (action == ACTION_START)
					continue;
				concat_buf(buf, " ; delete element %s %s %s { %s }", nft_family, NFTLB_TABLE_NAME, service, b->ipaddr);
			}
			if(!backend_is_available(b))
				continue;
			run_farm_rules_gen_srv_data((char **) &data_str, f, b, chain, data_mode);
			concat_buf(buf, " ; %s element %s %s %s { %s %s}", action_str, nft_family, NFTLB_TABLE_NAME, service, b->ipaddr, data_str);
		}
		break;
	case BCK_MAP_BCK_MARK:
		list_for_each_entry(b, &f->backends, list) {
			if (b->action == ACTION_STOP || b->action == ACTION_DELETE) {
				if (action == ACTION_START)
					continue;
				concat_buf(buf, " ; delete element %s %s %s { %s }", nft_family, NFTLB_TABLE_NAME, service, b->mark);
			}
			if(!backend_is_available(b))
				continue;
			run_farm_rules_gen_srv_data((char **) &data_str, f, b, chain, data_mode);
			concat_buf(buf, " ; %s element %s %s %s { %x %s }", action_str, nft_family, NFTLB_TABLE_NAME, service, b->mark, data_str);
		}
		break;
	case BCK_MAP_IPADDR_PORT:
		run_farm_rules_gen_srv_data((char **) &data_str, f, NULL, chain, data_mode);
		nports = get_array_ports(port_list, f);
		for (i = 0; i < nports; i++)
			concat_buf(buf, " ; %s element %s %s %s { %s . %d %s}", action_str, nft_family, NFTLB_TABLE_NAME, service, f->virtaddr, port_list[i], data_str);
		break;
	case BCK_MAP_BCK_IPADDR_F_PORT:
		nports = get_array_ports(port_list, f);
		for (i = 0; i < nports; i++) {
			list_for_each_entry(b, &f->backends, list) {
				if (b->action == ACTION_STOP || b->action == ACTION_DELETE || b->action == ACTION_RELOAD) {
					if (action == ACTION_START)
						continue;
					concat_buf(buf, " ; delete element %s %s %s { %s . %d }", nft_family, NFTLB_TABLE_NAME, service, b->ipaddr, port_list[i]);
				}
				if(!backend_is_available(b))
					continue;
				run_farm_rules_gen_srv_data((char **) &data_str, f, b, chain, data_mode);
				concat_buf(buf, " ; %s element %s %s %s { %s . %d %s}", action_str, nft_family, NFTLB_TABLE_NAME, service, b->ipaddr, port_list[i], data_str);
			}
		}
		break;
	case BCK_MAP_BCK_IPADDR_BF_PORT:

		list_for_each_entry(b, &f->backends, list) {
			run_farm_rules_gen_srv_data((char **) &data_str, f, b, chain, data_mode);
			if (strcmp(b->port, DEFAULT_PORT) == 0) {

				nports = get_array_ports(port_list, f);
				for (i = 0; i < nports; i++) {
					if (b->action == ACTION_STOP || b->action == ACTION_DELETE || b->action == ACTION_RELOAD) {
						if (action == ACTION_START)
							continue;
						concat_buf(buf, " ; delete element %s %s %s { %s . %d }", nft_family, NFTLB_TABLE_NAME, service, b->ipaddr, port_list[i]);
					}
					if(!backend_is_available(b))
						continue;
					concat_buf(buf, " ; %s element %s %s %s { %s . %d %s}", action_str, nft_family, NFTLB_TABLE_NAME, service, b->ipaddr, port_list[i], data_str);
				}

			} else {
				if (b->action == ACTION_STOP || b->action == ACTION_DELETE || b->action == ACTION_RELOAD) {
					if (action == ACTION_START)
						continue;
					concat_buf(buf, " ; delete element %s %s %s { %s . %s }", nft_family, NFTLB_TABLE_NAME, service, b->ipaddr, b->port);
				}
				if(!backend_is_available(b))
					continue;
				concat_buf(buf, " ; %s element %s %s %s { %s . %s %s}", action_str, nft_family, NFTLB_TABLE_NAME, service, b->ipaddr, b->port, data_str);
			}
		}
		break;
	default:
		return -1;
		break;
	}

	return 0;
}

static int run_farm_snat(struct sbuffer *buf, struct farm *f, int family, int action)
{
	char name[255] = { 0 };

	if (f->mode != VALUE_MODE_SNAT || farm_get_masquerade(f))
		return 0;

	if (f->bcks_are_marked) {
		sprintf(name, "%s-m-back", print_nft_service(family, f->protocol));
		run_farm_rules_gen_srv(buf, f, print_nft_table_family(family, f->mode), name, name, action, BCK_MAP_BCK_MARK, BCK_MAP_BCK_BF_SRCIPADDR);
	} else {
		sprintf(name, "%s-back", print_nft_service(family, f->protocol));
		run_farm_rules_gen_srv(buf, f, print_nft_table_family(family, f->mode), name, name, action, BCK_MAP_BCK_IPADDR_BF_PORT, BCK_MAP_BCK_BF_SRCIPADDR);
	}

	return 0;
}

static int run_farm_stlsnat(struct sbuffer *buf, struct farm *f, int family, int action)
{
	char action_str[255] = { 0 };
	char chain[255] = { 0 };
	char services[255] = { 0 };

	sprintf(chain, "%s-back", f->name);
	sprintf(services, "%s-%s", print_nft_service(family, f->protocol), f->oface);

	switch (action) {
	case ACTION_DELETE:
		sprintf(action_str, "delete");
		run_farm_rules_gen_srv(buf, f, print_nft_table_family(family, f->mode), chain, services, action, BCK_MAP_BCK_IPADDR_F_PORT, BCK_MAP_NAME);
		run_farm_rules_gen_chains(buf, print_nft_table_family(family, f->mode), chain, action);
		break;
	default:
		sprintf(action_str, "add");
		run_farm_rules_gen_chains(buf, print_nft_table_family(family, f->mode), chain, action);
		concat_buf(buf, " ; %s rule %s %s %s %s saddr set %s ether saddr set %s fwd to %s", action_str, print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, chain, print_nft_family(family), f->virtaddr, f->iethaddr, f->iface);
		run_farm_rules_gen_srv(buf, f, print_nft_table_family(family, f->mode), chain, services, action, BCK_MAP_BCK_IPADDR_F_PORT, BCK_MAP_NAME);
		break;
	}

	return 0;
}

static int run_farm_rules_gen_meta_param(struct sbuffer *buf, struct farm *f, int family, int param, int type)
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
		(type == NFTLB_MAP_KEY_TYPE) ? concat_buf(buf, " inet_service") : concat_buf(buf, " %s sport", print_nft_protocol(f->protocol));
		items++;
	}

	if (param & VALUE_META_DSTPORT) {
		if (items)
			concat_buf(buf, " .");
		(type == NFTLB_MAP_KEY_TYPE) ? concat_buf(buf, " inet_service") : concat_buf(buf, " %s dport", print_nft_protocol(f->protocol));
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

	return 0;
}

static int run_farm_rules_gen_sched(struct sbuffer *buf, struct farm *f, int family)
{
	switch (f->scheduler) {
	case VALUE_SCHED_RR:
		concat_buf(buf, " numgen inc mod %d", f->total_weight);
		break;
	case VALUE_SCHED_WEIGHT:
		concat_buf(buf, " numgen random mod %d", f->total_weight);
		break;
	case VALUE_SCHED_HASH:
		concat_buf(buf, " jhash");
		run_farm_rules_gen_meta_param(buf, f, family, f->schedparam, NFTLB_MAP_KEY_RULE);
		concat_buf(buf, " mod %d", f->total_weight);
		break;
	case VALUE_SCHED_SYMHASH:
		if (f->bcks_available != 1)	// FIXME: Control bug in nftables
			concat_buf(buf, " symhash mod %d", f->total_weight);
		break;
	default:
		return -1;
	}

	return 0;
}

static int get_farm_mark(struct farm *f)
{
	int mark = f->mark;

	if (farm_get_masquerade(f))
		mark |= NFTLB_POSTROUTING_MARK;

	return mark;
}

static int run_farm_rules_gen_bck_map(struct sbuffer *buf, struct farm *f, enum map_modes key_mode, enum map_modes data_mode)
{
	struct backend *b;
	int offset = get_farm_mark(f);
	int i = 0;
	int last = 0;
	int new;

	// FIXME: Control bug in nftables
	if (f->scheduler == VALUE_SCHED_SYMHASH && f->bcks_available == 1) {
		list_for_each_entry(b, &f->backends, list) {
			if(!backend_is_available(b))
				continue;

			switch (data_mode) {
			case BCK_MAP_MARK:
				concat_buf(buf, " 0x%x", b->mark | offset);
				break;
			case BCK_MAP_ETHADDR:
				concat_buf(buf, " %s", b->ethaddr);
				break;
			case BCK_MAP_IPADDR:
				concat_buf(buf, " %s", b->ipaddr);
				break;
			default:
				break;
			}
		}
		return 0;
	}

	concat_buf(buf, " map {");

	list_for_each_entry(b, &f->backends, list) {
		if(!backend_is_available(b))
			continue;

		if (i != 0)
			concat_buf(buf, ",");

		switch (key_mode) {
		case BCK_MAP_MARK:
			concat_buf(buf, " 0x%x", b->mark | offset);
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
		default:
			break;
		}

		concat_buf(buf, ":");

		switch (data_mode) {
		case BCK_MAP_MARK:
			concat_buf(buf, " 0x%x", b->mark | offset);
			break;
		case BCK_MAP_ETHADDR:
			concat_buf(buf, " %s", b->ethaddr);
			break;
		case BCK_MAP_IPADDR:
			concat_buf(buf, " %s", b->ipaddr);
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
		concat_buf(buf, " ; add ct helper %s %s %s-%s { type \"%s\" protocol %s ; } ;", print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, obj_print_helper(f->helper), protocol, obj_print_helper(f->helper), protocol);
		break;
	case ACTION_DELETE:
	case ACTION_STOP:
		concat_buf(buf, " ; delete ct helper %s %s %s-%s ; ", print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, obj_print_helper(f->helper), protocol);
		break;
	case ACTION_RELOAD:
	default:
		break;
	}
}

static int run_farm_rules_filter_helper(struct sbuffer *buf, struct farm *f, int family, char *chain, int action)
{
	char protocol[255] = {0};

	if (!(f->helper != DEFAULT_HELPER && (f->mode == VALUE_MODE_SNAT || f->mode == VALUE_MODE_DNAT)))
		return 0;

	if (f->protocol == VALUE_PROTO_TCP || f->protocol == VALUE_PROTO_ALL) {
		sprintf(protocol, "tcp");
		run_farm_helper(buf, f, family, action, protocol);
		if (action == ACTION_START || action == ACTION_RELOAD)
			concat_buf(buf, " ; add rule %s %s %s %s %s %s ct helper set %s-%s", print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, chain, print_nft_table_family(family, f->mode), print_nft_family_protocol(family), protocol, obj_print_helper(f->helper), protocol);
	}

	if (f->protocol == VALUE_PROTO_UDP || f->protocol == VALUE_PROTO_ALL) {
		sprintf(protocol, "udp");
		run_farm_helper(buf, f, family, action, protocol);
		if (action == ACTION_START || action == ACTION_RELOAD)
			concat_buf(buf, " ; add rule %s %s %s %s %s %s ct helper set %s-%s", print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, chain, print_nft_table_family(family, f->mode), print_nft_family_protocol(family), protocol, obj_print_helper(f->helper), protocol);
	}

	return 0;
}

static void run_farm_persistence(struct sbuffer *buf, struct farm *f, int family, int action)
{
	switch (action) {
	case ACTION_START:
		concat_buf(buf, " ; add map %s %s persist-%s { type ", print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, f->name);
		run_farm_rules_gen_meta_param(buf, f, family, f->persistence, NFTLB_MAP_KEY_TYPE);
		concat_buf(buf, " : mark; timeout %ds; }", f->persistttl);
		break;
	case ACTION_DELETE:
	case ACTION_STOP:
		concat_buf(buf, " ; delete map %s %s persist-%s", print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, f->name);
		break;
	case ACTION_RELOAD:
	default:
		break;
	}
}

static int run_farm_rules_filter_persistence(struct sbuffer *buf, struct farm *f, int family, char *chain, int action)
{
	if (f->persistence == VALUE_META_NONE)
		return 0;

	run_farm_persistence(buf, f, family, action);

	if ((action != ACTION_START && action != ACTION_RELOAD) || (!f->bcks_are_marked))
		return 0;

	concat_buf(buf, " ; add rule %s %s %s update @persist-%s { ", print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, chain, f->name);
	run_farm_rules_gen_meta_param(buf, f, family, f->persistence, NFTLB_MAP_KEY_RULE);
	concat_buf(buf, " : ct mark }");
	return 0;
}

static void run_farm_meter(struct sbuffer *buf, struct farm *f, int family, char *name, int action)
{
	switch (action) {
	case ACTION_START:
		concat_buf(buf, " ; add set %s %s %s { type %s ; flags dynamic ; } ;", print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, name, print_nft_family_type(family));
		break;
	case ACTION_STOP:
		concat_buf(buf, " ; delete set %s %s %s ; ", print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, name);
		break;
	default:
		break;
	}
}

static int run_farm_rules_filter_policies(struct sbuffer *buf, struct farm *f, int family, char *chain, int action)
{
	char logprefix_str[255] = { 0 };
	char meter_str[255] = { 0 };
	char burst_str[255] = { 0 };

	if ((action == ACTION_START || action == ACTION_RELOAD) && f->tcpstrict == VALUE_SWITCH_ON) {
		print_log_format(logprefix_str, KEY_TCPSTRICT_LOGPREFIX, f, NULL, NULL);
		concat_buf(buf, " ; add rule %s %s %s ct state invalid log prefix \"%s\" drop",
					print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, chain, logprefix_str);
	}

	sprintf(meter_str, "%s-%s", CONFIG_KEY_NEWRTLIMIT, f->name);
	print_log_format(logprefix_str, KEY_NEWRTLIMIT_LOGPREFIX, f, NULL, NULL);
	if ((action == ACTION_START && f->newrtlimit != DEFAULT_NEWRTLIMIT) || (f->reload_action & VALUE_RLD_NEWRTLIMIT_START))
		run_farm_meter(buf, f, family, meter_str, ACTION_START);
	if (((action == ACTION_STOP || action == ACTION_DELETE) && f->newrtlimit != DEFAULT_NEWRTLIMIT) || (f->reload_action & VALUE_RLD_NEWRTLIMIT_STOP))
		run_farm_meter(buf, f, family, meter_str, ACTION_STOP);
	if ((action == ACTION_START || action == ACTION_RELOAD) && f->newrtlimit != DEFAULT_NEWRTLIMIT) {
		if (f->newrtlimitbst != DEFAULT_RTLIMITBURST)
			sprintf(burst_str, "burst %d packets ", f->newrtlimitbst);
		concat_buf(buf, " ; add rule %s %s %s ct state new add @%s { ip saddr limit rate over %d/second %s} log prefix \"%s\" drop",
					print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, chain, meter_str, f->newrtlimit, burst_str, logprefix_str);
	}

	sprintf(meter_str, "%s-%s", CONFIG_KEY_RSTRTLIMIT, f->name);
	print_log_format(logprefix_str, KEY_RSTRTLIMIT_LOGPREFIX, f, NULL, NULL);
	if ((action == ACTION_START && f->rstrtlimit != DEFAULT_RSTRTLIMIT) || (f->reload_action & VALUE_RLD_RSTRTLIMIT_START))
		run_farm_meter(buf, f, family, meter_str, ACTION_START);
	if (((action == ACTION_STOP || action == ACTION_DELETE) && f->rstrtlimit != DEFAULT_RSTRTLIMIT) || (f->reload_action & VALUE_RLD_RSTRTLIMIT_STOP))
		run_farm_meter(buf, f, family, meter_str, ACTION_STOP);
	if ((action == ACTION_START || action == ACTION_RELOAD) && f->rstrtlimit != DEFAULT_RSTRTLIMIT) {
		if (f->rstrtlimitbst != DEFAULT_RTLIMITBURST)
			sprintf(burst_str, "burst %d packets ", f->rstrtlimitbst);
		concat_buf(buf, " ; add rule %s %s %s tcp flags rst add @%s { ip saddr limit rate over %d/second %s} log prefix \"%s\" drop",
					print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, chain, meter_str, f->rstrtlimit, burst_str, logprefix_str);
	}

	sprintf(meter_str, "%s-%s", CONFIG_KEY_ESTCONNLIMIT, f->name);
	print_log_format(logprefix_str, KEY_ESTCONNLIMIT_LOGPREFIX, f, NULL, NULL);
	if ((action == ACTION_START && f->estconnlimit != DEFAULT_ESTCONNLIMIT) || (f->reload_action & VALUE_RLD_ESTCONNLIMIT_START))
		run_farm_meter(buf, f, family, meter_str, ACTION_START);
	if (((action == ACTION_STOP || action == ACTION_DELETE) && f->estconnlimit != DEFAULT_ESTCONNLIMIT) || (f->reload_action & VALUE_RLD_ESTCONNLIMIT_STOP))
		run_farm_meter(buf, f, family, meter_str, ACTION_STOP);
	if ((action == ACTION_START || action == ACTION_RELOAD) && f->estconnlimit != DEFAULT_ESTCONNLIMIT)
		concat_buf(buf, " ; add rule %s %s %s ct state new add @%s { ip saddr ct count over %d } log prefix \"%s\" drop",
					print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, chain, meter_str, f->estconnlimit, logprefix_str);

	if ((action == ACTION_START || action == ACTION_RELOAD) && f->queue != DEFAULT_QUEUE)
		concat_buf(buf, " ; add rule %s %s %s tcp flags syn queue num %d bypass",
					print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, chain, f->queue);

	return 0;
}

static int run_farm_rules_gen_meter_per_bck(struct sbuffer *buf, struct farm *f, int family, char *chain, int action)
{
	struct backend *b;
	int offset = get_farm_mark(f);
	char meter_str[255] = { 0 };
	char logprefix_str[255] = { 0 };

	list_for_each_entry(b, &f->backends, list) {
		if (b->estconnlimit == 0)
			continue;

		sprintf(meter_str, "%s-%s-%s", CONFIG_KEY_ESTCONNLIMIT, f->name, b->name);
		print_log_format(logprefix_str, KEY_ESTCONNLIMIT_LOGPREFIX, f, b, NULL);

		if (action == ACTION_START || b->action == ACTION_START)
			run_farm_meter(buf, f, family, meter_str, ACTION_START);

		if ((b->action == ACTION_STOP) || ((action == ACTION_STOP || action == ACTION_DELETE) && backend_is_available(b))) {
			run_farm_meter(buf, f, family, meter_str, ACTION_STOP);
			continue;
		}

		if (backend_is_available(b))
			concat_buf(buf, " ; add rule %s %s %s ct mark 0x%x add @%s { ip saddr ct count over %d } log prefix \"%s\" drop",
						print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, chain, b->mark | offset, meter_str, b->estconnlimit, logprefix_str);
	}

	return 0;
}

static int run_farm_rules_filter_marks(struct sbuffer *buf, struct farm *f, int family, char *chain, int action)
{
	int mark = get_farm_mark(f);

	if (!f->bcks_are_marked && mark == DEFAULT_MARK)
		return 0;

	if ((action == ACTION_START || action == ACTION_RELOAD ) && f->bcks_available != 0) {
		concat_buf(buf, " ; add rule %s %s %s", print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, chain);
		if (f->bcks_are_marked) {
			concat_buf(buf, " ct mark set");
			if (run_farm_rules_gen_sched(buf, f, family) == -1)
				return -1;
			run_farm_rules_gen_bck_map(buf, f, BCK_MAP_WEIGHT, BCK_MAP_MARK);
			run_farm_rules_gen_meter_per_bck(buf, f, family, chain, action);
		} else if (mark != DEFAULT_MARK) {
			concat_buf(buf, " ct mark set");
			concat_buf(buf, " 0x%x", mark);
		}
	} else if (action == ACTION_STOP || action == ACTION_DELETE || (action == ACTION_RELOAD && f->bcks_available == 0)) {
		run_farm_rules_gen_meter_per_bck(buf, f, family, chain, action);
	}

	return 0;
}

static int run_farm_rules_filter(struct sbuffer *buf, struct farm *f, int family, int action)
{
	char chain[255] = {0};
	char service[255] = {0};

	sprintf(chain, "%s-%s", NFTLB_TYPE_FILTER, f->name);
	sprintf(service, "%s-%s", NFTLB_TYPE_FILTER, print_nft_service(family, f->protocol));

	switch (action) {
	case ACTION_START:
	case ACTION_RELOAD:
		run_farm_rules_gen_chains(buf, print_nft_table_family(family, f->mode), chain, action);
		run_farm_rules_filter_policies(buf, f, family, chain, action);
		run_farm_rules_filter_helper(buf, f, family, chain, action);
		run_farm_rules_filter_marks(buf, f, family, chain, action);
		run_farm_rules_filter_persistence(buf, f, family, chain, action);
		if (action == ACTION_START)
			run_farm_rules_gen_srv(buf, f, print_nft_table_family(family, f->mode), chain, service, action, BCK_MAP_IPADDR_PORT, BCK_MAP_NAME);
		break;
	case ACTION_DELETE:
	case ACTION_STOP:
		run_farm_rules_gen_srv(buf, f, print_nft_table_family(family, f->mode), chain, service, action, BCK_MAP_IPADDR_PORT, BCK_MAP_NONE);
		run_farm_rules_gen_chains(buf, print_nft_table_family(family, f->mode), chain, action);
		run_farm_rules_filter_persistence(buf, f, family, chain, action);
		run_farm_rules_filter_marks(buf, f, family, chain, action);
		run_farm_rules_filter_helper(buf, f, family, chain, action);
		run_farm_rules_filter_policies(buf, f, family, chain, action);
		break;
	default:
		break;
	}

	return 0;
}

static int run_farm_rules_ingress_policies(struct sbuffer *buf, struct farm *f, int family, char *chain)
{
	struct farmpolicy *fp;
	char logprefix_str[255] = { 0 };

	if (f->policies_action != ACTION_START && f->policies_action != ACTION_RELOAD)
		return 0;

	list_for_each_entry(fp, &f->policies, list) {
		if (fp->policy->type != VALUE_TYPE_WHITE)
			continue;

		print_log_format(logprefix_str, KEY_LOGPREFIX, f, NULL, fp->policy);
		concat_buf(buf, " ; add rule %s %s %s %s saddr @%s log prefix \"%s\" %s",
					NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, chain, print_nft_family(family), fp->policy->name, logprefix_str, print_nft_verdict(fp->policy->type));
		fp->action = ACTION_NONE;
	}

	list_for_each_entry(fp, &f->policies, list) {
		if (fp->policy->type != VALUE_TYPE_BLACK)
			continue;

		print_log_format(logprefix_str, KEY_LOGPREFIX, f, NULL, fp->policy);
		concat_buf(buf, " ; add rule %s %s %s %s saddr @%s log prefix \"%s\" %s",
					NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, chain, print_nft_family(family), fp->policy->name, logprefix_str, print_nft_verdict(fp->policy->type));
		fp->action = ACTION_NONE;
	}

	return 0;
}

static int run_farm_ingress_policies(struct sbuffer *buf, struct farm *f, int family, int action)
{
	char chain[255] = {0};
	char service[255] = {0};

	if (!farm_needs_policies(f))
		return 0;

	sprintf(chain, "%s", f->name);
	sprintf(service, "%s-%s", print_nft_service(f->family, f->protocol), f->iface);

	if (f->policies_action == ACTION_START) {
		if (!farm_is_ingress_mode(f)) {
			run_base_chain_ndv(buf, f, KEY_IFACE);
			run_farm_rules_gen_chains(buf, NFTLB_NETDEV_FAMILY, chain, ACTION_START);
			run_farm_rules_gen_srv(buf, f, NFTLB_NETDEV_FAMILY, chain, service, f->policies_action, BCK_MAP_IPADDR_PORT, BCK_MAP_NAME);
		}
		run_farm_rules_ingress_policies(buf, f, family, chain);
	} else if (f->policies_action == ACTION_STOP && !farm_is_ingress_mode(f)) {
		run_farm_rules_gen_srv(buf, f, NFTLB_NETDEV_FAMILY, chain, service, f->policies_action, BCK_MAP_IPADDR_PORT, BCK_MAP_NAME);
		run_farm_rules_gen_chains(buf, NFTLB_NETDEV_FAMILY, chain, ACTION_DELETE);
	} else if (f->policies_action == ACTION_RELOAD) {
		if (!farm_is_ingress_mode(f)) {
			run_base_chain_ndv(buf, f, KEY_IFACE);
			run_farm_rules_gen_chains(buf, NFTLB_NETDEV_FAMILY, chain, ACTION_RELOAD);
		}
		run_farm_rules_ingress_policies(buf, f, family, chain);
	} else {
	}

	f->policies_action = ACTION_NONE;

	return 0;
}

static int run_farm_rules_gen_logs(struct sbuffer *buf, struct farm *f, int family, char *chain, int action)
{
	char logprefix_str[255] = { 0 };

	if (f->log == VALUE_LOG_NONE)
		return 0;

	concat_buf(buf, " ; add rule %s %s %s", print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, chain);

	if (f->log & VALUE_LOG_INPUT) {
		print_log_format(logprefix_str, KEY_LOGPREFIX, f, NULL, NULL);
		concat_buf(buf, " log prefix \"%s\"", logprefix_str);
	}

	// TODO: missing other log stages (forward, output)

	return 0;
}

static int run_farm_rules_gen_nat_per_bck(struct sbuffer *buf, struct farm *f, int family, char *chain)
{
	struct backend *b;
	int offset = get_farm_mark(f);

	list_for_each_entry(b, &f->backends, list) {
		if(!backend_is_available(b))
			continue;

		concat_buf(buf, " ; add rule %s %s %s %s %s %s ct mark 0x%x dnat to %s", print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, chain, print_nft_table_family(family, f->mode), print_nft_family_protocol(family), print_nft_protocol(f->protocol), b->mark | offset, b->ipaddr);
		if (strcmp(b->port, "") != 0)
			concat_buf(buf, ":%s", b->port);
	}
	return 0;
}

static int run_farm_rules_gen_nat(struct sbuffer *buf, struct farm *f, int family, char *chain)
{
	if (f->bcks_available == 0)
		return 0;

	switch (f->mode) {
	case VALUE_MODE_DSR:
		concat_buf(buf, " ; add rule %s %s %s ether saddr set %s ether daddr set", print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, chain, f->iethaddr);
		run_farm_rules_gen_sched(buf, f, family);
		run_farm_rules_gen_bck_map(buf, f, BCK_MAP_WEIGHT, BCK_MAP_ETHADDR);
		concat_buf(buf, " fwd to %s", f->oface);
		break;
	case VALUE_MODE_STLSDNAT:
		concat_buf(buf, " ; add rule %s %s %s %s daddr set", print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, chain, print_nft_family(family));
		run_farm_rules_gen_sched(buf, f, family);
		run_farm_rules_gen_bck_map(buf, f, BCK_MAP_WEIGHT, BCK_MAP_IPADDR);
		concat_buf(buf, " ether daddr set ip daddr");
		run_farm_rules_gen_bck_map(buf, f, BCK_MAP_IPADDR, BCK_MAP_ETHADDR);
		concat_buf(buf, " fwd to %s", f->oface);
		break;
	default:
		if (!f->bcks_are_marked) {
			concat_buf(buf, " ; add rule %s %s %s dnat to", print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, chain);
			run_farm_rules_gen_sched(buf, f, family);
			run_farm_rules_gen_bck_map(buf, f, BCK_MAP_WEIGHT, BCK_MAP_IPADDR);
			return 0;
		}

		if (!f->bcks_have_port) {
			concat_buf(buf, " ; add rule %s %s %s dnat to", print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, chain);
			concat_buf(buf, " ct mark");
			run_farm_rules_gen_bck_map(buf, f, BCK_MAP_MARK, BCK_MAP_IPADDR);
			return 0;
		}

		run_farm_rules_gen_nat_per_bck(buf, f, family, chain);
		break;
	}

	return 0;
}

static int run_farm_rules(struct sbuffer *buf, struct farm *f, int family, int action)
{
	char chain[255] = {0};
	char service[255] = {0};

	switch (f->mode) {
	case VALUE_MODE_STLSDNAT:
		sprintf(chain, "%s", f->name);
		sprintf(service, "%s-%s", print_nft_service(family, f->protocol), f->iface);
		run_base_table(buf, NFTLB_NETDEV_FAMILY);
		run_base_chain_ndv(buf, f, KEY_OFACE);
		run_base_chain_ndv(buf, f, KEY_IFACE);
		run_farm_rules_gen_chains(buf, print_nft_table_family(family, f->mode), chain, action);
		run_farm_ingress_policies(buf, f, family, action);
		run_farm_rules_gen_logs(buf, f, family, chain, action);
		run_farm_rules_gen_nat(buf, f, family, chain);
		run_farm_stlsnat(buf, f, family, action);
		break;
	case VALUE_MODE_DSR:
		sprintf(chain, "%s", f->name);
		sprintf(service, "%s-%s", print_nft_service(family, f->protocol), f->iface);
		run_base_table(buf, NFTLB_NETDEV_FAMILY);
		run_base_chain_ndv(buf, f, KEY_IFACE);
		run_farm_rules_gen_chains(buf, print_nft_table_family(family, f->mode), chain, action);
		run_farm_ingress_policies(buf, f, family, action);
		run_farm_rules_gen_logs(buf, f, family, chain, action);
		run_farm_rules_gen_nat(buf, f, family, chain);
		break;
	default:
		sprintf(chain, "%s-%s", NFTLB_TYPE_NAT, f->name);
		sprintf(service, "%s-%s", NFTLB_TYPE_NAT, print_nft_service(family, f->protocol));
		run_base_nat(buf, f);
		if (need_filter(f)) {
			run_base_filter(buf, f);
			run_farm_rules_filter(buf, f, family, action);
		}
		run_farm_ingress_policies(buf, f, family, action);
		run_farm_rules_gen_chains(buf, print_nft_table_family(family, f->mode), chain, action);
		run_farm_rules_gen_logs(buf, f, family, chain, action);
		run_farm_rules_gen_nat(buf, f, family, chain);
		run_farm_snat(buf, f, family, action);
	}

	if (action == ACTION_START)
		run_farm_rules_gen_srv(buf, f, print_nft_table_family(family, f->mode), chain, service, action, BCK_MAP_IPADDR_PORT, BCK_MAP_NAME);

	return 0;
}

static int run_farm(struct sbuffer *buf, struct farm *f, int action)
{
	if ((f->family == VALUE_FAMILY_IPV4) || (f->family == VALUE_FAMILY_INET)) {
		run_farm_rules(buf, f, VALUE_FAMILY_IPV4, action);
	}

	if ((f->family == VALUE_FAMILY_IPV6) || (f->family == VALUE_FAMILY_INET)) {
		run_farm_rules(buf, f, VALUE_FAMILY_IPV6, action);
	}

	return 0;
}

static int del_farm_rules(struct sbuffer *buf, struct farm *f, int family)
{
	int ret = 0;
	char chain[255] = {0};
	char service[255] = {0};
	char fchain[255] = {0};
	char fservice[255] = {0};

	if (farm_is_ingress_mode(f)) {
		sprintf(chain, "%s", f->name);
		sprintf(service, "%s-%s", print_nft_service(family, f->protocol), f->iface);
	} else {
		sprintf(chain, "%s-%s", NFTLB_TYPE_NAT, f->name);
		sprintf(service, "%s-%s", NFTLB_TYPE_NAT, print_nft_service(family, f->protocol));
		sprintf(fchain, "%s-%s", NFTLB_TYPE_FILTER, f->name);
		sprintf(fservice, "%s-%s", NFTLB_TYPE_FILTER, print_nft_service(family, f->protocol));
	}


	if (need_filter(f))
		run_farm_rules_filter(buf, f, family, ACTION_DELETE);

	run_farm_rules_gen_srv(buf, f, print_nft_table_family(family, f->mode), chain, service, ACTION_DELETE, BCK_MAP_IPADDR_PORT, BCK_MAP_NONE);
	run_farm_rules_gen_chains(buf, print_nft_table_family(family, f->mode), chain, ACTION_DELETE);

	return ret;
}

static int del_farm(struct sbuffer *buf, struct farm *f)
{
	int ret = 0;

	if ((f->family == VALUE_FAMILY_IPV4) || (f->family == VALUE_FAMILY_INET)) {
		run_farm_ingress_policies(buf, f, VALUE_FAMILY_IPV4, ACTION_STOP);
		del_farm_rules(buf, f, VALUE_FAMILY_IPV4);
	}

	if ((f->family == VALUE_FAMILY_IPV6) || (f->family == VALUE_FAMILY_INET)) {
		run_farm_ingress_policies(buf, f, VALUE_FAMILY_IPV6, ACTION_STOP);
		del_farm_rules(buf, f, VALUE_FAMILY_IPV6);
	}

	if (f->mode == VALUE_MODE_SNAT) {
		if ((f->family == VALUE_FAMILY_IPV4) || (f->family == VALUE_FAMILY_INET)) {
			run_farm_snat(buf, f, VALUE_FAMILY_IPV4, ACTION_DELETE);
		}
		if ((f->family == VALUE_FAMILY_IPV6) || (f->family == VALUE_FAMILY_INET)) {
			run_farm_snat(buf, f, VALUE_FAMILY_IPV6, ACTION_DELETE);
		}
	}

	if (f->mode == VALUE_MODE_STLSDNAT) {
		if ((f->family == VALUE_FAMILY_IPV4) || (f->family == VALUE_FAMILY_INET)) {
			run_farm_stlsnat(buf, f, VALUE_FAMILY_IPV4, ACTION_DELETE);
		}
		if ((f->family == VALUE_FAMILY_IPV6) || (f->family == VALUE_FAMILY_INET)) {
			run_farm_stlsnat(buf, f, VALUE_FAMILY_IPV6, ACTION_DELETE);
		}
	}

	return ret;
}

static int nft_actions_done(struct farm *f)
{
	struct backend *b;

	list_for_each_entry(b, &f->backends, list)
		b->action = ACTION_NONE;

	f->action = ACTION_NONE;
	f->reload_action = VALUE_RLD_NONE;

	return 0;
}

int nft_reset(void)
{
	struct sbuffer buf;
	int ret = 0;

	create_buf(&buf);
	concat_buf(&buf, "flush ruleset");
	exec_cmd(get_buf_data(&buf));
	clean_buf(&buf);

	reset_ndv_base();
	n_ndv_base_rules = 0;
	nat_base_rules = 0;

	return ret;
}

int nft_rulerize(struct farm *f)
{
	struct sbuffer buf;
	int ret = 0;

	create_buf(&buf);

	switch (f->action) {
	case ACTION_START:
	case ACTION_RELOAD:
		ret = run_farm(&buf, f, f->action);
		break;
	case ACTION_STOP:
	case ACTION_DELETE:
		ret = del_farm(&buf, f);
		break;
	case ACTION_NONE:
	default:
		break;
	}

	exec_cmd(get_buf_data(&buf));
	clean_buf(&buf);
	nft_actions_done(f);

	return ret;
}

static int run_set_elements(struct sbuffer *buf, struct policy *p)
{
	struct element *e;
	char action_str[255] = "add";

	list_for_each_entry(e, &p->elements, list) {
		switch (p->action){
		case ACTION_START:
			concat_buf(buf, " ; add element %s %s %s { %s }", NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, p->name, e->data);
		break;
		case ACTION_RELOAD:
			if (e->action == ACTION_DELETE || e->action == ACTION_STOP)
				sprintf(action_str, "delete");
			concat_buf(buf, " ; %s element %s %s %s { %s }", action_str, NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, p->name, e->data);
			sprintf(action_str, "add");
		break;
		default:
		break;
		}
		e->action = ACTION_NONE;
	}

	return 0;
}

static int run_policy_set(struct sbuffer *buf, struct policy *p)
{
	switch (p->action) {
	case ACTION_START:
		run_base_table(buf, NFTLB_NETDEV_FAMILY);
		concat_buf(buf, " ; add set %s %s %s { type ipv4_addr ; flags interval ; }", NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, p->name);
		run_set_elements(buf, p);
		break;
	case ACTION_RELOAD:
		run_set_elements(buf, p);
		break;
	case ACTION_STOP:
	case ACTION_DELETE:
		concat_buf(buf, " ; flush set %s %s %s", NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, p->name);
		concat_buf(buf, " ; delete set %s %s %s", NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, p->name);
		break;
	case ACTION_NONE:
	default:
		break;
	}

	p->action = ACTION_NONE;

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
