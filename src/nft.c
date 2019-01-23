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
#include "config.h"
#include "list.h"
#include "sbuffer.h"

#include <stdlib.h>
#include <nftables/nftables.h>
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
#define NFTLB_INGRESS_PRIO			0
#define NFTLB_FILTER_PRIO			-150

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

#define NFTLB_MAP_TYPE_IPV4		"ipv4_addr"
#define NFTLB_MAP_TYPE_IPV6		"ipv6_addr"
#define NFTLB_MAP_TYPE_INETSRV		"inet_service"

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
	BCK_MAP_BCK_IPADDR_F_PORT
};

struct if_base_rule {
	char			*ifname;
	unsigned int		active;
};

struct if_base_rule * ndv_base_rules[NFTLB_MAX_IFACES];
unsigned int n_ndv_base_rules = 0;
unsigned int nat_base_rules = 0;
unsigned int filter_base_rules = 0;


static int exec_cmd(struct nft_ctx *ctx, char *cmd)
{
	syslog(LOG_INFO, "Executing: nft << %s", cmd);
	return nft_run_cmd_from_buffer(ctx, cmd, strlen(cmd));
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

static char * print_nft_family(int family)
{
	switch (family) {
	case VALUE_FAMILY_IPV6:
		return NFTLB_IPV6_FAMILY;
	default:
		return NFTLB_IPV4_FAMILY;
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

static int need_filter(struct farm *f)
{
	return (f->helper != DEFAULT_HELPER || (!farm_is_ingress_mode(f) && f->bcks_are_marked) || f->mark != DEFAULT_MARK || farm_get_masquerade(f));
}

static int run_base_ndv(struct nft_ctx *ctx, struct farm *f, int key)
{
	struct sbuffer buf;
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

	create_buf(&buf);

	if (((rules_needed & NFTLB_IPV4_ACTIVE) && !(if_base->active & NFTLB_IPV4_ACTIVE)) ||
	    ((rules_needed & NFTLB_IPV6_ACTIVE) && !(if_base->active & NFTLB_IPV6_ACTIVE))) {
		concat_buf(&buf, " ; add table %s %s", NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME);
		concat_buf(&buf, " ; add chain %s %s %s { type %s hook %s device %s priority %d ;}", NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, chain, NFTLB_TYPE_FILTER, NFTLB_HOOK_INGRESS, if_str, NFTLB_INGRESS_PRIO);
		if_base->active |= NFTLB_IPV4_ACTIVE;
		if_base->active |= NFTLB_IPV6_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV4_UDP_ACTIVE) && !(if_base->active & NFTLB_IPV4_UDP_ACTIVE)) {
		concat_buf(&buf, " ; add map %s %s %s-%s { type %s . %s : verdict ;}", NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, print_nft_service(VALUE_FAMILY_IPV4, f->protocol), if_str, NFTLB_MAP_TYPE_IPV4, NFTLB_MAP_TYPE_INETSRV);
		concat_buf(&buf, " ; add rule %s %s %s %s %s . %s %s vmap @%s-%s", NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, chain, NFTLB_IPV4_FAMILY, addr_str, NFTLB_UDP_PROTO, port_str, print_nft_service(VALUE_FAMILY_IPV4, f->protocol), if_str);
		if_base->active |= NFTLB_IPV4_UDP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV4_TCP_ACTIVE) && !(if_base->active & NFTLB_IPV4_TCP_ACTIVE)) {
		concat_buf(&buf, " ; add map %s %s %s-%s { type %s . %s : verdict ;}", NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, print_nft_service(VALUE_FAMILY_IPV4, f->protocol), if_str, NFTLB_MAP_TYPE_IPV4, NFTLB_MAP_TYPE_INETSRV);
		concat_buf(&buf, " ; add rule %s %s %s %s %s . %s %s vmap @%s-%s", NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, chain, NFTLB_IPV4_FAMILY, addr_str, NFTLB_TCP_PROTO, port_str, print_nft_service(VALUE_FAMILY_IPV4, f->protocol), if_str);
		if_base->active |= NFTLB_IPV4_TCP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV4_SCTP_ACTIVE) && !(if_base->active & NFTLB_IPV4_SCTP_ACTIVE)) {
		concat_buf(&buf, " ; add map %s %s %s-%s { type %s . %s : verdict ;}", NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, print_nft_service(VALUE_FAMILY_IPV4, f->protocol), if_str, NFTLB_MAP_TYPE_IPV4, NFTLB_MAP_TYPE_INETSRV);
		concat_buf(&buf, " ; add rule %s %s %s %s %s . %s %s vmap @%s-%s", NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, chain, NFTLB_IPV4_FAMILY, addr_str, NFTLB_SCTP_PROTO, port_str, print_nft_service(VALUE_FAMILY_IPV4, f->protocol), if_str);
		if_base->active |= NFTLB_IPV4_SCTP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV6_UDP_ACTIVE) && !(if_base->active & NFTLB_IPV6_UDP_ACTIVE)) {
		concat_buf(&buf, " ; add map %s %s %s-%s { type %s . %s : verdict ;}", NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, print_nft_service(VALUE_FAMILY_IPV6, f->protocol), if_str, NFTLB_MAP_TYPE_IPV6, NFTLB_MAP_TYPE_INETSRV);
		concat_buf(&buf, " ; add rule %s %s %s %s %s . %s %s vmap @%s-%s", NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, chain, NFTLB_IPV6_FAMILY, addr_str, NFTLB_UDP_PROTO, port_str, print_nft_service(VALUE_FAMILY_IPV6, f->protocol), if_str);
		if_base->active |= NFTLB_IPV6_UDP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV6_TCP_ACTIVE) && !(if_base->active & NFTLB_IPV6_TCP_ACTIVE)) {
		concat_buf(&buf, " ; add map %s %s %s-%s { type %s . %s : verdict ;}", NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, print_nft_service(VALUE_FAMILY_IPV6, f->protocol), if_str, NFTLB_MAP_TYPE_IPV6, NFTLB_MAP_TYPE_INETSRV);
		concat_buf(&buf, " ; add rule %s %s %s %s %s . %s %s vmap @%s-%s", NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, chain, NFTLB_IPV6_FAMILY, addr_str, NFTLB_TCP_PROTO, port_str, print_nft_service(VALUE_FAMILY_IPV6, f->protocol), if_str);
		if_base->active |= NFTLB_IPV6_TCP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV6_SCTP_ACTIVE) && !(if_base->active & NFTLB_IPV6_SCTP_ACTIVE)) {
		concat_buf(&buf, " ; add map %s %s %s-%s { type %s . %s : verdict ;}", NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, print_nft_service(VALUE_FAMILY_IPV6, f->protocol), if_str, NFTLB_MAP_TYPE_IPV6, NFTLB_MAP_TYPE_INETSRV);
		concat_buf(&buf, " ; add rule %s %s %s %s %s . %s %s vmap @%s-%s", NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, chain, NFTLB_IPV6_FAMILY, addr_str, NFTLB_SCTP_PROTO, port_str, print_nft_service(VALUE_FAMILY_IPV6, f->protocol), if_str);
		if_base->active |= NFTLB_IPV6_SCTP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV4_IP_ACTIVE) && !(if_base->active & NFTLB_IPV4_IP_ACTIVE)) {
		concat_buf(&buf, " ; add map %s %s %s-%s { type %s : verdict ;}", NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, print_nft_service(VALUE_FAMILY_IPV4, f->protocol), if_str, NFTLB_MAP_TYPE_IPV4);
		concat_buf(&buf, " ; add rule %s %s %s %s %s vmap @%s-%s", NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, chain, NFTLB_IPV4_FAMILY, addr_str, print_nft_service(VALUE_FAMILY_IPV4, f->protocol), if_str);
		if_base->active |= NFTLB_IPV4_IP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV6_IP_ACTIVE) && !(if_base->active & NFTLB_IPV6_IP_ACTIVE)) {
		concat_buf(&buf, " ; add map %s %s %s-%s { type %s : verdict ;}", NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, print_nft_service(VALUE_FAMILY_IPV6, f->protocol), if_str, NFTLB_MAP_TYPE_IPV6);
		concat_buf(&buf, " ; add rule %s %s %s %s %s vmap @%s-%s", NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, chain, NFTLB_IPV6_FAMILY, addr_str, print_nft_service(VALUE_FAMILY_IPV6, f->protocol), if_str);
		if_base->active |= NFTLB_IPV6_IP_ACTIVE;
	}

	if (!isempty_buf(&buf))
		exec_cmd(ctx, get_buf_data(&buf));

	clean_buf(&buf);

	return 0;
}

static int run_base_nat(struct nft_ctx *ctx, struct farm *f)
{
	struct sbuffer buf;
	unsigned int rules_needed = get_rules_needed(f->family, f->protocol, KEY_IFACE);

	create_buf(&buf);

	if ((rules_needed & NFTLB_IPV4_ACTIVE) && !(nat_base_rules & NFTLB_IPV4_ACTIVE)) {
		concat_buf(&buf, " ; add table %s %s", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME);
		concat_buf(&buf, " ; add chain %s %s %s { type %s hook %s priority %d ;}", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_PREROUTING, NFTLB_TYPE_NAT, NFTLB_HOOK_PREROUTING, NFTLB_PREROUTING_PRIO);
		concat_buf(&buf, " ; add chain %s %s %s { type %s hook %s priority %d ;}", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, NFTLB_TYPE_NAT, NFTLB_HOOK_POSTROUTING, NFTLB_POSTROUTING_PRIO);
		concat_buf(&buf, " ; add rule %s %s %s ct mark and 0x%x == 0x%x masquerade", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, NFTLB_POSTROUTING_MARK, NFTLB_POSTROUTING_MARK);
		nat_base_rules |= NFTLB_IPV4_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV6_ACTIVE) && !(nat_base_rules & NFTLB_IPV6_ACTIVE)) {
		concat_buf(&buf, " ; add table %s %s", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME);
		concat_buf(&buf, " ; add chain %s %s %s { type %s hook %s priority %d ;}", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_PREROUTING, NFTLB_TYPE_NAT, NFTLB_HOOK_PREROUTING, NFTLB_PREROUTING_PRIO);
		concat_buf(&buf, " ; add chain %s %s %s { type %s hook %s priority %d ;}", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, NFTLB_TYPE_NAT, NFTLB_HOOK_POSTROUTING, NFTLB_POSTROUTING_PRIO);
		concat_buf(&buf, " ; add rule %s %s %s ct mark and 0x%x == 0x%x masquerade", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, NFTLB_POSTROUTING_MARK, NFTLB_POSTROUTING_MARK);
		nat_base_rules |= NFTLB_IPV6_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV4_UDP_ACTIVE) && !(nat_base_rules & NFTLB_IPV4_UDP_ACTIVE)) {
		concat_buf(&buf, " ; add map %s %s %s-%s { type %s . %s : verdict ;}", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TYPE_NAT, NFTLB_UDP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV4, NFTLB_MAP_TYPE_INETSRV);
		concat_buf(&buf, " ; add rule %s %s %s %s daddr . %s dport vmap @%s-%s", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_PREROUTING, NFTLB_IPV4_FAMILY, NFTLB_UDP_PROTO, NFTLB_TYPE_NAT, NFTLB_UDP_SERVICES_MAP);
		concat_buf(&buf, " ; add map %s %s %s-back { type %s . %s : %s ;}", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_UDP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV4, NFTLB_MAP_TYPE_INETSRV, NFTLB_MAP_TYPE_IPV4);
		concat_buf(&buf, " ; add rule %s %s %s snat to %s daddr . %s dport map @%s-back", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, NFTLB_IPV4_FAMILY, NFTLB_UDP_PROTO, NFTLB_UDP_SERVICES_MAP);
		nat_base_rules |= NFTLB_IPV4_UDP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV4_TCP_ACTIVE) && !(nat_base_rules & NFTLB_IPV4_TCP_ACTIVE)) {
		concat_buf(&buf, " ; add map %s %s %s-%s { type %s . %s : verdict ;}", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TYPE_NAT, NFTLB_TCP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV4, NFTLB_MAP_TYPE_INETSRV);
		concat_buf(&buf, " ; add rule %s %s %s %s daddr . %s dport vmap @%s-%s", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_PREROUTING, NFTLB_IPV4_FAMILY, NFTLB_TCP_PROTO, NFTLB_TYPE_NAT, NFTLB_TCP_SERVICES_MAP);
		concat_buf(&buf, " ; add map %s %s %s-back { type %s . %s : %s ;}", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TCP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV4, NFTLB_MAP_TYPE_INETSRV, NFTLB_MAP_TYPE_IPV4);
		concat_buf(&buf, " ; add rule %s %s %s snat to %s daddr . %s dport map @%s-back", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, NFTLB_IPV4_FAMILY, NFTLB_TCP_PROTO, NFTLB_TCP_SERVICES_MAP);
		nat_base_rules |= NFTLB_IPV4_TCP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV4_SCTP_ACTIVE) && !(nat_base_rules & NFTLB_IPV4_SCTP_ACTIVE)) {
		concat_buf(&buf, " ; add map %s %s %s-%s { type %s . %s : verdict ;}", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TYPE_NAT, NFTLB_SCTP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV4, NFTLB_MAP_TYPE_INETSRV);
		concat_buf(&buf, " ; add rule %s %s %s %s daddr . %s dport vmap @%s-%s", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_PREROUTING, NFTLB_IPV4_FAMILY, NFTLB_SCTP_PROTO, NFTLB_TYPE_NAT, NFTLB_SCTP_SERVICES_MAP);
		concat_buf(&buf, " ; add map %s %s %s-back { type %s . %s : %s ;}", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_SCTP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV4, NFTLB_MAP_TYPE_INETSRV, NFTLB_MAP_TYPE_IPV4);
		concat_buf(&buf, " ; add rule %s %s %s snat to %s daddr . %s dport map @%s-back", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, NFTLB_IPV4_FAMILY, NFTLB_SCTP_PROTO, NFTLB_SCTP_SERVICES_MAP);
		nat_base_rules |= NFTLB_IPV4_SCTP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV4_IP_ACTIVE) && !(nat_base_rules & NFTLB_IPV4_IP_ACTIVE)) {
		concat_buf(&buf, " ; add map %s %s %s-%s { type %s : verdict ;}", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TYPE_NAT, NFTLB_IP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV4);
		concat_buf(&buf, " ; add rule %s %s %s %s daddr vmap @%s-%s", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_PREROUTING, NFTLB_IPV4_FAMILY, NFTLB_TYPE_NAT, NFTLB_IP_SERVICES_MAP);
		concat_buf(&buf, " ; add map %s %s %s-back { type %s : %s ;}", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_IP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV4, NFTLB_MAP_TYPE_IPV4);
		concat_buf(&buf, " ; add rule %s %s %s snat to %s daddr map @%s-back", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, NFTLB_IPV4_FAMILY, NFTLB_IP_SERVICES_MAP);
		nat_base_rules |= NFTLB_IPV4_IP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV6_UDP_ACTIVE) && !(nat_base_rules & NFTLB_IPV6_UDP_ACTIVE)) {
		concat_buf(&buf, " ; add map %s %s %s-%s { type %s . %s : verdict ;}", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TYPE_NAT, NFTLB_UDP_SERVICES6_MAP, NFTLB_MAP_TYPE_IPV6, NFTLB_MAP_TYPE_INETSRV);
		concat_buf(&buf, " ; add rule %s %s %s %s daddr . %s dport vmap @%s-%s", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_PREROUTING, NFTLB_IPV6_FAMILY, NFTLB_UDP_PROTO, NFTLB_TYPE_NAT, NFTLB_UDP_SERVICES6_MAP);
		concat_buf(&buf, " ; add map %s %s %s-back { type %s . %s : %s ;}", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_UDP_SERVICES6_MAP, NFTLB_MAP_TYPE_IPV6, NFTLB_MAP_TYPE_INETSRV, NFTLB_MAP_TYPE_IPV6);
		concat_buf(&buf, " ; add rule %s %s %s snat to %s daddr . %s dport map @%s-back", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, NFTLB_IPV6_FAMILY, NFTLB_UDP_PROTO, NFTLB_UDP_SERVICES6_MAP);
		nat_base_rules |= NFTLB_IPV6_UDP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV6_TCP_ACTIVE) && !(nat_base_rules & NFTLB_IPV6_TCP_ACTIVE)) {
		concat_buf(&buf, " ; add map %s %s %s-%s { type %s . %s : verdict ;}", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TYPE_NAT, NFTLB_TCP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV6, NFTLB_MAP_TYPE_INETSRV);
		concat_buf(&buf, " ; add rule %s %s %s %s daddr . %s dport vmap @%s-%s", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_PREROUTING, NFTLB_IPV6_FAMILY, NFTLB_TCP_PROTO, NFTLB_TYPE_NAT, NFTLB_TCP_SERVICES_MAP);
		concat_buf(&buf, " ; add map %s %s %s-back { type %s . %s : %s ;}", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TCP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV6, NFTLB_MAP_TYPE_INETSRV, NFTLB_MAP_TYPE_IPV6);
		concat_buf(&buf, " ; add rule %s %s %s snat to %s daddr . %s dport map @%s-back", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, NFTLB_IPV6_FAMILY, NFTLB_TCP_PROTO, NFTLB_TCP_SERVICES_MAP);
		nat_base_rules |= NFTLB_IPV6_TCP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV6_SCTP_ACTIVE) && !(nat_base_rules & NFTLB_IPV6_SCTP_ACTIVE)) {
		concat_buf(&buf, " ; add map %s %s %s-%s { type %s . %s : verdict ;}", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TYPE_NAT, NFTLB_SCTP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV6, NFTLB_MAP_TYPE_INETSRV);
		concat_buf(&buf, " ; add rule %s %s %s %s daddr . %s dport vmap @%s-%s", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_PREROUTING, NFTLB_IPV6_FAMILY, NFTLB_SCTP_PROTO, NFTLB_TYPE_NAT, NFTLB_SCTP_SERVICES_MAP);
		concat_buf(&buf, " ; add map %s %s %s-back { type %s . %s : %s ;}", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_SCTP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV6, NFTLB_MAP_TYPE_INETSRV, NFTLB_MAP_TYPE_IPV6);
		concat_buf(&buf, " ; add rule %s %s %s snat to %s daddr . %s dport map @%s-back", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, NFTLB_IPV6_FAMILY, NFTLB_SCTP_PROTO, NFTLB_SCTP_SERVICES_MAP);
		nat_base_rules |= NFTLB_IPV6_SCTP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV6_IP_ACTIVE) && !(nat_base_rules & NFTLB_IPV6_IP_ACTIVE)) {
		concat_buf(&buf, " ; add map %s %s %s-%s { type %s : verdict ;}", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TYPE_NAT, NFTLB_IP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV6);
		concat_buf(&buf, " ; add rule %s %s %s %s daddr vmap @%s-%s", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_PREROUTING, NFTLB_IPV6_FAMILY, NFTLB_TYPE_NAT, NFTLB_IP_SERVICES_MAP);
		concat_buf(&buf, " ; add map %s %s %s-back { type %s : %s ;}", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_IP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV6, NFTLB_MAP_TYPE_IPV6);
		concat_buf(&buf, " ; add rule %s %s %s snat to %s daddr map @%s-back", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, NFTLB_IPV6_FAMILY, NFTLB_IP_SERVICES_MAP);
		nat_base_rules |= NFTLB_IPV6_IP_ACTIVE;
	}

	if (!isempty_buf(&buf))
		exec_cmd(ctx, get_buf_data(&buf));

	clean_buf(&buf);

	return 0;
}

static int run_base_filter(struct nft_ctx *ctx, struct farm *f)
{
	struct sbuffer buf;
	unsigned int rules_needed = get_rules_needed(f->family, f->protocol, KEY_IFACE);

	create_buf(&buf);

	if ((rules_needed & NFTLB_IPV4_ACTIVE) && !(nat_base_rules & NFTLB_IPV4_ACTIVE)) {
		concat_buf(&buf, " ; add table %s %s", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME);
		concat_buf(&buf, " ; add chain %s %s %s { type %s hook %s priority %d ;}", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_FILTER, NFTLB_TYPE_FILTER, NFTLB_HOOK_PREROUTING, NFTLB_FILTER_PRIO);
		concat_buf(&buf, " ; add rule %s %s %s mark set ct mark", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_FILTER);
		filter_base_rules |= NFTLB_IPV4_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV6_ACTIVE) && !(nat_base_rules & NFTLB_IPV6_ACTIVE)) {
		concat_buf(&buf, " ; add table %s %s", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME);
		concat_buf(&buf, " ; add chain %s %s %s { type %s hook %s priority %d ;}", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_FILTER, NFTLB_TYPE_FILTER, NFTLB_HOOK_PREROUTING, NFTLB_FILTER_PRIO);
		concat_buf(&buf, " ; add rule %s %s %s mark set ct mark", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_FILTER);
		filter_base_rules |= NFTLB_IPV6_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV4_UDP_ACTIVE) && !(nat_base_rules & NFTLB_IPV4_UDP_ACTIVE)) {
		concat_buf(&buf, " ; add map %s %s %s-%s { type %s . %s : verdict ;}", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TYPE_FILTER, NFTLB_UDP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV4, NFTLB_MAP_TYPE_INETSRV);
		concat_buf(&buf, " ; add rule %s %s %s %s daddr . %s dport vmap @%s-%s", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_FILTER, NFTLB_IPV4_FAMILY, NFTLB_UDP_PROTO, NFTLB_TYPE_FILTER, NFTLB_UDP_SERVICES_MAP);
		filter_base_rules |= NFTLB_IPV4_UDP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV4_TCP_ACTIVE) && !(nat_base_rules & NFTLB_IPV4_TCP_ACTIVE)) {
		concat_buf(&buf, " ; add map %s %s %s-%s { type %s . %s : verdict ;}", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TYPE_FILTER, NFTLB_TCP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV4, NFTLB_MAP_TYPE_INETSRV);
		concat_buf(&buf, " ; add rule %s %s %s %s daddr . %s dport vmap @%s-%s", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_FILTER, NFTLB_IPV4_FAMILY, NFTLB_TCP_PROTO, NFTLB_TYPE_FILTER, NFTLB_TCP_SERVICES_MAP);
		filter_base_rules |= NFTLB_IPV4_TCP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV4_SCTP_ACTIVE) && !(nat_base_rules & NFTLB_IPV4_SCTP_ACTIVE)) {
		concat_buf(&buf, " ; add map %s %s %s-%s { type %s . %s : verdict ;}", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TYPE_FILTER, NFTLB_SCTP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV4, NFTLB_MAP_TYPE_INETSRV);
		concat_buf(&buf, " ; add rule %s %s %s %s daddr . %s dport vmap @%s-%s", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_FILTER, NFTLB_IPV4_FAMILY, NFTLB_SCTP_PROTO, NFTLB_TYPE_FILTER, NFTLB_SCTP_SERVICES_MAP);
		filter_base_rules |= NFTLB_IPV4_SCTP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV4_IP_ACTIVE) && !(nat_base_rules & NFTLB_IPV4_IP_ACTIVE)) {
		concat_buf(&buf, " ; add map %s %s %s-%s { type %s : verdict ;}", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TYPE_FILTER, NFTLB_IP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV4);
		concat_buf(&buf, " ; add rule %s %s %s %s daddr vmap @%s-%s", NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_FILTER, NFTLB_IPV4_FAMILY, NFTLB_TYPE_FILTER, NFTLB_IP_SERVICES_MAP);
		filter_base_rules |= NFTLB_IPV4_IP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV6_UDP_ACTIVE) && !(nat_base_rules & NFTLB_IPV6_UDP_ACTIVE)) {
		concat_buf(&buf, " ; add map %s %s %s-%s { type %s . %s : verdict ;}", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TYPE_FILTER, NFTLB_UDP_SERVICES6_MAP, NFTLB_MAP_TYPE_IPV6, NFTLB_MAP_TYPE_INETSRV);
		concat_buf(&buf, " ; add rule %s %s %s %s daddr . %s dport vmap @%s-%s", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_FILTER, NFTLB_IPV6_FAMILY, NFTLB_UDP_PROTO, NFTLB_TYPE_FILTER, NFTLB_UDP_SERVICES6_MAP);
		filter_base_rules |= NFTLB_IPV6_UDP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV6_TCP_ACTIVE) && !(nat_base_rules & NFTLB_IPV6_TCP_ACTIVE)) {
		concat_buf(&buf, " ; add map %s %s %s-%s { type %s . %s : verdict ;}", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TYPE_FILTER, NFTLB_TCP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV6, NFTLB_MAP_TYPE_INETSRV);
		concat_buf(&buf, " ; add rule %s %s %s %s daddr . %s dport vmap @%s-%s", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_FILTER, NFTLB_IPV6_FAMILY, NFTLB_TCP_PROTO, NFTLB_TYPE_FILTER, NFTLB_TCP_SERVICES_MAP);
		filter_base_rules |= NFTLB_IPV6_TCP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV6_SCTP_ACTIVE) && !(nat_base_rules & NFTLB_IPV6_SCTP_ACTIVE)) {
		concat_buf(&buf, " ; add map %s %s %s-%s { type %s . %s : verdict ;}", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TYPE_FILTER, NFTLB_SCTP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV6, NFTLB_MAP_TYPE_INETSRV);
		concat_buf(&buf, " ; add rule %s %s %s %s daddr . %s dport vmap @%s-%s", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_FILTER, NFTLB_IPV6_FAMILY, NFTLB_SCTP_PROTO, NFTLB_TYPE_FILTER, NFTLB_SCTP_SERVICES_MAP);
		filter_base_rules |= NFTLB_IPV6_SCTP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV6_IP_ACTIVE) && !(nat_base_rules & NFTLB_IPV6_IP_ACTIVE)) {
		concat_buf(&buf, " ; add map %s %s %s-%s { type %s : verdict ;}", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TYPE_FILTER, NFTLB_IP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV6);
		concat_buf(&buf, " ; add rule %s %s %s %s daddr vmap @%s-%s", NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_FILTER, NFTLB_IPV6_FAMILY, NFTLB_TYPE_FILTER, NFTLB_IP_SERVICES_MAP);
		filter_base_rules |= NFTLB_IPV6_IP_ACTIVE;
	}

	if (!isempty_buf(&buf))
		exec_cmd(ctx, get_buf_data(&buf));

	clean_buf(&buf);

	return 0;
}

static void run_farm_rules_gen_chains(struct sbuffer *buf, struct farm *f, char *chain, int family, int action)
{
	switch (action) {
	case ACTION_RELOAD:
		concat_buf(buf, " ; flush chain %s %s %s", print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, chain);
		break;
	case ACTION_START:
		concat_buf(buf, " ; add chain %s %s %s", print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, chain);
		break;
	case ACTION_DELETE:
		concat_buf(buf, " ; flush chain %s %s %s", print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, chain);
		concat_buf(buf, " ; delete chain %s %s %s", print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, chain);
		break;
	default:
		break;
	}
}

static int run_farm_rules_gen_sched_param(struct sbuffer *buf, struct farm *f, int family)
{
	int items = 0;

	if ((f->schedparam & VALUE_SCHEDPARAM_NONE) ||
		(f->schedparam & VALUE_SCHEDPARAM_SRCIP)) {
		concat_buf(buf, " %s saddr", print_nft_family(family));
		items++;
	}

	if (f->schedparam & VALUE_SCHEDPARAM_DSTIP) {
		if (items)
			concat_buf(buf, " .");
		concat_buf(buf, " %s daddr", print_nft_family(family));
		items++;
	}

	if (f->schedparam & VALUE_SCHEDPARAM_SRCPORT) {
		if (items)
			concat_buf(buf, " .");
		concat_buf(buf, " %s sport", print_nft_protocol(f->protocol));
		items++;
	}

	if (f->schedparam & VALUE_SCHEDPARAM_DSTPORT) {
		if (items)
			concat_buf(buf, " .");
		concat_buf(buf, " %s dport", print_nft_protocol(f->protocol));
		items++;
	}

	if (f->schedparam & VALUE_SCHEDPARAM_SRCMAC) {
		if (items)
			concat_buf(buf, " .");
		concat_buf(buf, " ether saddr");
		items++;
	}

	if (f->schedparam & VALUE_SCHEDPARAM_DSTMAC) {
		if (items)
			concat_buf(buf, " .");
		concat_buf(buf, " ether daddr");
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
		run_farm_rules_gen_sched_param(buf, f, family);
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

static int run_farm_rules_gen_bck_map(struct sbuffer *buf, struct farm *f, enum map_modes key_mode, enum map_modes data_mode, int offset)
{
	struct backend *b;
	int i = 0;
	int last = 0;
	int new;

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

static int run_farm_rules_gen_srv(struct sbuffer *buf, struct farm *f, int family, char *chain, char *service, int action, enum map_modes key_mode, enum map_modes data_mode)
{
	int port_list[65535] = { 0 };
	char action_str[255] = { 0 };
	char data_str[255] = { 0 };
	struct backend *b;
	int nports;
	int i;

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

	switch (data_mode) {
	case BCK_MAP_SRCIPADDR:
		sprintf(data_str, ": %s ", f->srcaddr);
		break;
	case BCK_MAP_NAME:
		sprintf(data_str, ": goto %s ", chain);
		break;
	default:
		break;
	}

	switch (key_mode) {
	case BCK_MAP_IPADDR:
		concat_buf(buf, " ; %s element %s %s %s { %s %s}", action_str, print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, service, f->virtaddr, data_str);
		break;
	case BCK_MAP_BCK_IPADDR:
		list_for_each_entry(b, &f->backends, list) {
			if (b->action == ACTION_STOP || b->action == ACTION_DELETE)
				concat_buf(buf, " ; delete element %s %s %s { %s }", print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, service, b->ipaddr);
			if(!backend_is_available(b))
				continue;
			concat_buf(buf, " ; %s element %s %s %s { %s %s}", action_str, print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, service, b->ipaddr, data_str);
		}
		break;
	case BCK_MAP_IPADDR_PORT:
		nports = get_array_ports(port_list, f);
		for (i = 0; i < nports; i++)
			concat_buf(buf, " ; %s element %s %s %s { %s . %d %s}", action_str, print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, service, f->virtaddr, port_list[i], data_str);
		break;
	case BCK_MAP_BCK_IPADDR_F_PORT:
		nports = get_array_ports(port_list, f);
		for (i = 0; i < nports; i++) {
			list_for_each_entry(b, &f->backends, list) {
				if (b->action == ACTION_STOP || b->action == ACTION_DELETE)
					concat_buf(buf, " ; delete element %s %s %s { %s . %d }", print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, service, b->ipaddr, port_list[i]);
				if(!backend_is_available(b))
					continue;
				concat_buf(buf, " ; %s element %s %s %s { %s . %d %s}", action_str, print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, service, b->ipaddr, port_list[i], data_str);
			}
		}
		break;
	default:
		return -1;
		break;
	}

	return 0;
}

static int run_farm_rules_filter_policies(struct sbuffer *buf, struct farm *f, int family, char *chain)
{
	char meter_str[255] = {};
	char burst_str[255] = {};

	if (f->newrtlimitbst > 0)
		sprintf(burst_str, "burst %d packets ", f->newrtlimitbst);

	if (f->newrtlimit > 0) {
		sprintf(meter_str, "%s-%s", CONFIG_KEY_NEWRTLIMIT, f->name);
		concat_buf(buf, " ; add rule %s %s %s ct state new meter %s { ip saddr limit rate over %d/second %s} log prefix \"%s\" drop",
					print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, chain, meter_str, f->newrtlimit, burst_str, meter_str);
	}

	if (f->rstrtlimit > 0) {
		sprintf(meter_str, "%s-%s", CONFIG_KEY_RSTRTLIMIT, f->name);
		concat_buf(buf, " ; add rule %s %s %s tcp flags rst meter %s { ip saddr limit rate over %d/second } log prefix \"%s\" drop",
					print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, chain, meter_str, f->rstrtlimit, meter_str);
	}

	if (f->estconnlimit > 0) {
		sprintf(meter_str, "%s-%s", CONFIG_KEY_ESTCONNLIMIT, f->name);
		concat_buf(buf, " ; add rule %s %s %s ct state new meter %s { ip saddr ct count over %d } log prefix \"%s\" drop",
					print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, chain, meter_str, f->estconnlimit, meter_str);
	}

	if (f->tcpstrict == VALUE_SWITCH_ON) {
		sprintf(meter_str, "%s-%s", CONFIG_KEY_TCPSTRICT, f->name);
		concat_buf(buf, " ; add rule %s %s %s ct state invalid log prefix \"%s\" drop",
					print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, chain, meter_str);
	}

	if (f->queue != DEFAULT_QUEUE) {
		sprintf(meter_str, "%s-%s", CONFIG_KEY_QUEUE, f->name);
		concat_buf(buf, " ; add rule %s %s %s tcp flags syn queue num %d bypass log prefix \"%s\"",
					print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, chain, f->queue, meter_str);
	}

	return 0;
}

static int run_farm_rules_filter(struct nft_ctx *ctx, struct sbuffer *buf, struct farm *f, int family, int action, int mark)
{
	struct sbuffer buf2;
	char chain[255] = {0};
	char service[255] = {0};

	sprintf(chain, "%s-%s", NFTLB_TYPE_FILTER, f->name);
	sprintf(service, "%s-%s", NFTLB_TYPE_FILTER, print_nft_service(family, f->protocol));

	run_farm_rules_gen_chains(buf, f, chain, family, action);

	run_farm_rules_filter_policies(buf, f, family, chain);

	/* no bck rules */
	if (f->bcks_available == 0)
		goto norules;

	/* backends rule */
	concat_buf(buf, " ; add rule %s %s %s", print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, chain);

	/* helpers */
	if (f->helper != DEFAULT_HELPER && (f->mode == VALUE_MODE_SNAT || f->mode == VALUE_MODE_DNAT)) {
		concat_buf(buf, " ct helper set %s", obj_print_helper(f->helper));
		create_buf(&buf2);
		concat_buf(&buf2, " ; add ct helper %s %s %s { type \"%s\" protocol %s ; }", print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, obj_print_helper(f->helper), obj_print_helper(f->helper), obj_print_proto(f->protocol));
		exec_cmd(ctx, get_buf_data(&buf2));
		clean_buf(&buf2);
	}

	if (f->bcks_are_marked) {
		concat_buf(buf, " ct mark set");
		if (run_farm_rules_gen_sched(buf, f, family) == -1)
			return -1;
		run_farm_rules_gen_bck_map(buf, f, BCK_MAP_WEIGHT, BCK_MAP_MARK, mark);
	} else if (mark != DEFAULT_MARK) {
		concat_buf(buf, " ct mark set");
		concat_buf(buf, " 0x%x", mark);
	}

norules:
	if (action == ACTION_RELOAD)
		return 0;

	if (f->protocol == VALUE_PROTO_ALL) {
		run_farm_rules_gen_srv(buf, f, family, chain, service, action, BCK_MAP_IPADDR, BCK_MAP_NAME);
	} else {
		run_farm_rules_gen_srv(buf, f, family, chain, service, action, BCK_MAP_IPADDR_PORT, BCK_MAP_NAME);
	}

	return 0;
}

static int run_farm_rules(struct nft_ctx *ctx, struct farm *f, int family, int action)
{
	struct sbuffer buf;
	char chain[255] = {0};
	char service[255] = {0};
	int mark = 0;
	int out = 0;

	create_buf(&buf);

	if (farm_is_ingress_mode(f)) {
		sprintf(chain, "%s", f->name);
		sprintf(service, "%s-%s", print_nft_service(family, f->protocol), f->iface);
	} else {
		sprintf(chain, "%s-%s", NFTLB_TYPE_NAT, f->name);
		sprintf(service, "%s-%s", NFTLB_TYPE_NAT, print_nft_service(family, f->protocol));
	}

	run_farm_rules_gen_chains(&buf, f, chain, family, action);

	if (!farm_is_ingress_mode(f)) {
		/* set marks */
		mark = f->mark;
		if (farm_get_masquerade(f))
			mark |= NFTLB_POSTROUTING_MARK;

		if (need_filter(f))
			run_farm_rules_filter(ctx, &buf, f, family, action, mark);
	}

	/* no bck rules */
	if (f->bcks_available == 0)
		goto avoidrules;

	/* backends rule */
	concat_buf(&buf, " ; add rule %s %s %s", print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, chain);

	/* input log */
	if (f->log & VALUE_LOG_INPUT)
		concat_buf(&buf, " log prefix \"INPUT-%s \"", chain);

	switch (f->mode) {
	case VALUE_MODE_DSR:
		concat_buf(&buf, " ether saddr set %s ether daddr set", f->iethaddr);
		break;
	case VALUE_MODE_STLSDNAT:
		concat_buf(&buf, " %s daddr set", print_nft_family(family));
		break;
	default:
		concat_buf(&buf, " dnat to");
	}

	if ((farm_is_ingress_mode(f) || !f->bcks_are_marked) && run_farm_rules_gen_sched(&buf, f, family) == -1)
		return -1;

	if (f->mode == VALUE_MODE_DSR)
		out = run_farm_rules_gen_bck_map(&buf, f, BCK_MAP_WEIGHT, BCK_MAP_ETHADDR, 0);
	else {
		if(f->mode == VALUE_MODE_STLSDNAT || !f->bcks_are_marked) {
			out = run_farm_rules_gen_bck_map(&buf, f, BCK_MAP_WEIGHT, BCK_MAP_IPADDR, 0);
			if (f->mode == VALUE_MODE_STLSDNAT) {
				concat_buf(&buf, " ether daddr set ip daddr");
				out = run_farm_rules_gen_bck_map(&buf, f, BCK_MAP_IPADDR, BCK_MAP_ETHADDR, 0);
			}
		} else {
			concat_buf(&buf, " ct mark");
			out = run_farm_rules_gen_bck_map(&buf, f, BCK_MAP_MARK, BCK_MAP_IPADDR, mark);
		}
	}

	if (out == -1)
		return -1;

	if (farm_is_ingress_mode(f))
		concat_buf(&buf, " fwd to %s", f->oface);

avoidrules:
	if (action == ACTION_RELOAD) {
		exec_cmd(ctx, get_buf_data(&buf));
		clean_buf(&buf);
		return 0;
	}

	if (f->protocol == VALUE_PROTO_ALL) {
		run_farm_rules_gen_srv(&buf, f, family, chain, service, action, BCK_MAP_IPADDR, BCK_MAP_NAME);
	} else {
		run_farm_rules_gen_srv(&buf, f, family, chain, service, action, BCK_MAP_IPADDR_PORT, BCK_MAP_NAME);
	}

	exec_cmd(ctx, get_buf_data(&buf));
	clean_buf(&buf);

	return 0;
}

static int run_farm_snat(struct nft_ctx *ctx, struct farm *f, int family, int action)
{
	struct sbuffer buf;
	char name[255] = { 0 };

	if (farm_get_masquerade(f))
		return 0;

	sprintf(name, "%s-back", print_nft_service(family, f->protocol));
	create_buf(&buf);

	if (f->protocol == VALUE_PROTO_ALL)
		run_farm_rules_gen_srv(&buf, f, family, name, name, action, BCK_MAP_BCK_IPADDR, BCK_MAP_SRCIPADDR);
	else
		run_farm_rules_gen_srv(&buf, f, family, name, name, action, BCK_MAP_BCK_IPADDR_F_PORT, BCK_MAP_SRCIPADDR);

	exec_cmd(ctx, get_buf_data(&buf));
	clean_buf(&buf);

	return 0;
}

static int run_farm_stlsnat(struct nft_ctx *ctx, struct farm *f, int family, int action)
{
	struct sbuffer buf;
	char action_str[255] = { 0 };
	char chain[255] = { 0 };
	char services[255] = { 0 };

	sprintf(chain, "%s-back", f->name);
	sprintf(services, "%s-%s", print_nft_service(family, f->protocol), f->oface);

	create_buf(&buf);

	switch (action) {
	case ACTION_DELETE:
		sprintf(action_str, "delete");
		run_farm_rules_gen_srv(&buf, f, family, chain, services, action, BCK_MAP_BCK_IPADDR_F_PORT, BCK_MAP_NAME);
		run_farm_rules_gen_chains(&buf, f, chain, family, action);
		break;
	default:
		sprintf(action_str, "add");
		run_farm_rules_gen_chains(&buf, f, chain, family, action);
		concat_buf(&buf, " ; %s rule %s %s %s %s saddr set %s ether saddr set %s fwd to %s", action_str, print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, chain, print_nft_family(family), f->virtaddr, f->iethaddr, f->iface);
		run_farm_rules_gen_srv(&buf, f, family, chain, services, action, BCK_MAP_BCK_IPADDR_F_PORT, BCK_MAP_NAME);
		break;
	}

	exec_cmd(ctx, get_buf_data(&buf));
	clean_buf(&buf);

	return 0;
}

static int run_farm(struct nft_ctx *ctx, struct farm *f, int action)
{
	int ret = 0;

	switch (f->mode) {
	case VALUE_MODE_STLSDNAT:
		run_base_ndv(ctx, f, KEY_OFACE);
		/* fallthrough */
	case VALUE_MODE_DSR:
		run_base_ndv(ctx, f, KEY_IFACE);
		break;
	default:
		if (need_filter(f))
			run_base_filter(ctx, f);
		run_base_nat(ctx, f);
	}

	if ((f->family == VALUE_FAMILY_IPV4) || (f->family == VALUE_FAMILY_INET))
		run_farm_rules(ctx, f, VALUE_FAMILY_IPV4, action);
	if ((f->family == VALUE_FAMILY_IPV6) || (f->family == VALUE_FAMILY_INET))
		run_farm_rules(ctx, f, VALUE_FAMILY_IPV6, action);

	if (f->mode == VALUE_MODE_SNAT) {
		if ((f->family == VALUE_FAMILY_IPV4) || (f->family == VALUE_FAMILY_INET)) {
			run_farm_snat(ctx, f, VALUE_FAMILY_IPV4, action);
		}
		if ((f->family == VALUE_FAMILY_IPV6) || (f->family == VALUE_FAMILY_INET)) {
			run_farm_snat(ctx, f, VALUE_FAMILY_IPV6, action);
		}
	}

	if (f->mode == VALUE_MODE_STLSDNAT) {
		if ((f->family == VALUE_FAMILY_IPV4) || (f->family == VALUE_FAMILY_INET)) {
			run_farm_stlsnat(ctx, f, VALUE_FAMILY_IPV4, action);
		}
		if ((f->family == VALUE_FAMILY_IPV6) || (f->family == VALUE_FAMILY_INET)) {
			run_farm_stlsnat(ctx, f, VALUE_FAMILY_IPV6, action);
		}
	}

	return ret;
}

static int del_farm_rules(struct nft_ctx *ctx, struct farm *f, int family)
{
	struct sbuffer buf;
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

	create_buf(&buf);

	if (f->protocol == VALUE_PROTO_ALL) {
		if (need_filter(f))
			run_farm_rules_gen_srv(&buf, f, family, fchain, fservice, ACTION_DELETE, BCK_MAP_IPADDR, BCK_MAP_NONE);
		run_farm_rules_gen_srv(&buf, f, family, chain, service, ACTION_DELETE, BCK_MAP_IPADDR, BCK_MAP_NONE);
	} else {
		if (need_filter(f))
			run_farm_rules_gen_srv(&buf, f, family, fchain, fservice, ACTION_DELETE, BCK_MAP_IPADDR_PORT, BCK_MAP_NONE);
		run_farm_rules_gen_srv(&buf, f, family, chain, service, ACTION_DELETE, BCK_MAP_IPADDR_PORT, BCK_MAP_NONE);
	}

	if (need_filter(f))
		run_farm_rules_gen_chains(&buf, f, fchain, family, ACTION_DELETE);
	run_farm_rules_gen_chains(&buf, f, chain, family, ACTION_DELETE);

	exec_cmd(ctx, get_buf_data(&buf));
	clean_buf(&buf);

	return ret;
}

static int del_farm(struct nft_ctx *ctx, struct farm *f)
{
	int ret = 0;

	if ((f->family == VALUE_FAMILY_IPV4) || (f->family == VALUE_FAMILY_INET))
		del_farm_rules(ctx, f, VALUE_FAMILY_IPV4);
	if ((f->family == VALUE_FAMILY_IPV6) || (f->family == VALUE_FAMILY_INET))
		del_farm_rules(ctx, f, VALUE_FAMILY_IPV6);

	if (f->mode == VALUE_MODE_SNAT) {
		if ((f->family == VALUE_FAMILY_IPV4) || (f->family == VALUE_FAMILY_INET)) {
			run_farm_snat(ctx, f, VALUE_FAMILY_IPV4, ACTION_DELETE);
		}
		if ((f->family == VALUE_FAMILY_IPV6) || (f->family == VALUE_FAMILY_INET)) {
			run_farm_snat(ctx, f, VALUE_FAMILY_IPV6, ACTION_DELETE);
		}
	}

	if (f->mode == VALUE_MODE_STLSDNAT) {
		if ((f->family == VALUE_FAMILY_IPV4) || (f->family == VALUE_FAMILY_INET)) {
			run_farm_stlsnat(ctx, f, VALUE_FAMILY_IPV4, ACTION_DELETE);
		}
		if ((f->family == VALUE_FAMILY_IPV6) || (f->family == VALUE_FAMILY_INET)) {
			run_farm_stlsnat(ctx, f, VALUE_FAMILY_IPV6, ACTION_DELETE);
		}
	}

	return ret;
}

static int nft_actions_done(struct farm *f)
{
	struct backend *b;

	list_for_each_entry(b, &f->backends, list) {
		b->action = ACTION_NONE;
	}

	f->action = ACTION_NONE;

	return 0;
}

int nft_reset(void)
{
	struct nft_ctx *ctx = nft_ctx_new(0);
	struct sbuffer buf;
	int ret = 0;

	create_buf(&buf);
	concat_buf(&buf, "flush ruleset");
	exec_cmd(ctx, get_buf_data(&buf));
	clean_buf(&buf);

	nft_ctx_free(ctx);

	reset_ndv_base();
	n_ndv_base_rules = 0;
	nat_base_rules = 0;

	return ret;
}

int nft_rulerize(struct farm *f)
{
	struct nft_ctx *ctx = nft_ctx_new(0);
	int ret = 0;

	switch (f->action) {
	case ACTION_START:
	case ACTION_RELOAD:
		ret = run_farm(ctx, f, f->action);
		break;
	case ACTION_STOP:
	case ACTION_DELETE:
		ret = del_farm(ctx, f);
		break;
	case ACTION_NONE:
	default:
		break;
	}

	nft_actions_done(f);

	nft_ctx_free(ctx);

	return ret;
}
