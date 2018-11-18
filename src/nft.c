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

#include <stdlib.h>
#include <nftables/nftables.h>
#include <syslog.h>
#include <string.h>


#define NFTLB_MAX_CMD			2048
#define NFTLB_MAX_IFACES		100

#define NFTLB_TABLE_NAME		"nftlb"
#define NFTLB_TABLE_PREROUTING		"prerouting"
#define NFTLB_TABLE_INGRESS		"ingress"
#define NFTLB_TABLE_POSTROUTING		"postrouting"

#define NFTLB_HOOK_PREROUTING		"prerouting"
#define NFTLB_HOOK_POSTROUTING		"postrouting"
#define NFTLB_HOOK_INGRESS		"ingress"

#define NFTLB_PREROUTING_PRIO		0
#define NFTLB_INGRESS_PRIO		0
#define NFTLB_POSTROUTING_PRIO		100

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

enum map_modes {
	BCK_MAP_NONE,
	BCK_MAP_IPADDR,
	BCK_MAP_ETHADDR,
	BCK_MAP_WEIGHT,
	BCK_MAP_MARK,
	BCK_MAP_IPADDR_PORT,
	BCK_MAP_NAME,
	BCK_MAP_NAME_BACK,
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

static int isempty_buf(char *buf)
{
	return (buf[0] == 0);
}

static int exec_cmd(struct nft_ctx *ctx, char *cmd)
{
	syslog(LOG_INFO, "Executing: nft << %s", cmd);
	return nft_run_cmd_from_buffer(ctx, cmd, strlen(cmd));
}

static char * print_nft_service(int family, int proto, int key)
{
	if (family == VALUE_FAMILY_IPV6) {
		if (key == KEY_OFACE)
			return NFTLB_IP_SERVICES6_MAP;

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
		if (key == KEY_OFACE)
			return NFTLB_IP_SERVICES_MAP;

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
		if (key == KEY_OFACE) {
			ret |= NFTLB_IPV4_ACTIVE | NFTLB_IPV4_IP_ACTIVE;
			return ret;
		}

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
		if (key == KEY_OFACE) {
			ret |= NFTLB_IPV6_ACTIVE | NFTLB_IPV6_IP_ACTIVE;
			return ret;
		}

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

static int run_base_ndv(struct nft_ctx *ctx, struct farm *f, int key)
{
	char buf[NFTLB_MAX_CMD] = { 0 };
	struct if_base_rule *if_base;
	unsigned int rules_needed;
	char *if_str;

	if (key == KEY_OFACE)
		if_str = f->oface;
	else
		if_str = f->iface;

	rules_needed = get_rules_needed(f->family, f->protocol, key);
	if_base = get_ndv_base(if_str);

	if (!if_base)
		if_base = add_ndv_base(if_str);

	if (((rules_needed & NFTLB_IPV4_ACTIVE) && !(if_base->active & NFTLB_IPV4_ACTIVE)) ||
	    ((rules_needed & NFTLB_IPV6_ACTIVE) && !(if_base->active & NFTLB_IPV6_ACTIVE))) {
		sprintf(buf, "%s ; add table %s %s", buf, NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME);
		sprintf(buf, "%s ; add chain %s %s %s-%s { type filter hook %s device %s priority %d ;}", buf, NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_INGRESS, if_str, NFTLB_HOOK_INGRESS, if_str, NFTLB_INGRESS_PRIO);
		if_base->active |= NFTLB_IPV4_ACTIVE;
		if_base->active |= NFTLB_IPV6_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV4_UDP_ACTIVE) && !(if_base->active & NFTLB_IPV4_UDP_ACTIVE)) {
		sprintf(buf, "%s ; add map %s %s %s { type %s . %s : verdict ;}", buf, NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, NFTLB_UDP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV4, NFTLB_MAP_TYPE_INETSRV);
		sprintf(buf, "%s ; add rule %s %s %s-%s %s daddr . %s dport vmap @%s", buf, NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_INGRESS, if_str, NFTLB_IPV4_FAMILY, NFTLB_UDP_PROTO, NFTLB_UDP_SERVICES_MAP);
		if_base->active |= NFTLB_IPV4_UDP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV4_TCP_ACTIVE) && !(if_base->active & NFTLB_IPV4_TCP_ACTIVE)) {
		sprintf(buf, "%s ; add map %s %s %s { type %s . %s : verdict ;}", buf, NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, NFTLB_TCP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV4, NFTLB_MAP_TYPE_INETSRV);
		sprintf(buf, "%s ; add rule %s %s %s-%s %s daddr . %s dport vmap @%s", buf, NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_INGRESS, if_str, NFTLB_IPV4_FAMILY, NFTLB_TCP_PROTO, NFTLB_TCP_SERVICES_MAP);
		if_base->active |= NFTLB_IPV4_TCP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV4_SCTP_ACTIVE) && !(if_base->active & NFTLB_IPV4_SCTP_ACTIVE)) {
		sprintf(buf, "%s ; add map %s %s %s { type %s . %s : verdict ;}", buf, NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, NFTLB_SCTP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV4, NFTLB_MAP_TYPE_INETSRV);
		sprintf(buf, "%s ; add rule %s %s %s-%s %s daddr . %s dport vmap @%s", buf, NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_INGRESS, if_str, NFTLB_IPV4_FAMILY, NFTLB_SCTP_PROTO, NFTLB_SCTP_SERVICES_MAP);
		if_base->active |= NFTLB_IPV4_SCTP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV6_UDP_ACTIVE) && !(if_base->active & NFTLB_IPV6_UDP_ACTIVE)) {
		sprintf(buf, "%s ; add map %s %s %s { type %s . %s : verdict ;}", buf, NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, NFTLB_UDP_SERVICES6_MAP, NFTLB_MAP_TYPE_IPV6, NFTLB_MAP_TYPE_INETSRV);
		sprintf(buf, "%s ; add rule %s %s %s-%s %s daddr . %s dport vmap @%s", buf, NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_INGRESS, if_str, NFTLB_IPV6_FAMILY, NFTLB_UDP_PROTO, NFTLB_UDP_SERVICES6_MAP);
		if_base->active |= NFTLB_IPV6_UDP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV6_TCP_ACTIVE) && !(if_base->active & NFTLB_IPV6_TCP_ACTIVE)) {
		sprintf(buf, "%s ; add map %s %s %s { type %s . %s : verdict ;}", buf, NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, NFTLB_TCP_SERVICES6_MAP, NFTLB_MAP_TYPE_IPV6, NFTLB_MAP_TYPE_INETSRV);
		sprintf(buf, "%s ; add rule %s %s %s-%s %s daddr . %s dport vmap @%s", buf, NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_INGRESS, if_str, NFTLB_IPV6_FAMILY, NFTLB_TCP_PROTO, NFTLB_TCP_SERVICES6_MAP);
		if_base->active |= NFTLB_IPV6_TCP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV6_SCTP_ACTIVE) && !(if_base->active & NFTLB_IPV6_SCTP_ACTIVE)) {
		sprintf(buf, "%s ; add map %s %s %s { type %s . %s : verdict ;}", buf, NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, NFTLB_SCTP_SERVICES6_MAP, NFTLB_MAP_TYPE_IPV6, NFTLB_MAP_TYPE_INETSRV);
		sprintf(buf, "%s ; add rule %s %s %s-%s %s daddr . %s dport vmap @%s", buf, NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_INGRESS, if_str, NFTLB_IPV6_FAMILY, NFTLB_SCTP_PROTO, NFTLB_SCTP_SERVICES6_MAP);
		if_base->active |= NFTLB_IPV6_SCTP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV4_IP_ACTIVE) && !(if_base->active & NFTLB_IPV4_IP_ACTIVE)) {
		sprintf(buf, "%s ; add map %s %s %s { type %s : verdict ;}", buf, NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, NFTLB_IP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV4);
		sprintf(buf, "%s ; add rule %s %s %s-%s %s saddr vmap @%s", buf, NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_INGRESS, if_str, NFTLB_IPV4_FAMILY, NFTLB_IP_SERVICES_MAP);
		if_base->active |= NFTLB_IPV4_IP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV6_IP_ACTIVE) && !(if_base->active & NFTLB_IPV6_IP_ACTIVE)) {
		sprintf(buf, "%s ; add map %s %s %s { type %s : verdict ;}", buf, NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, NFTLB_IP_SERVICES6_MAP, NFTLB_MAP_TYPE_IPV6);
		sprintf(buf, "%s ; add rule %s %s %s-%s %s saddr vmap @%s", buf, NFTLB_NETDEV_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_INGRESS, if_str, NFTLB_IPV6_FAMILY, NFTLB_IP_SERVICES6_MAP);
		if_base->active |= NFTLB_IPV6_IP_ACTIVE;
	}

	if (!isempty_buf(buf))
		exec_cmd(ctx, buf);

	return 0;
}

static int run_base_nat(struct nft_ctx *ctx, struct farm *f)
{
	char buf[NFTLB_MAX_CMD] = { 0 };
	unsigned int rules_needed = get_rules_needed(f->family, f->protocol, KEY_IFACE);

	if ((rules_needed & NFTLB_IPV4_ACTIVE) && !(nat_base_rules & NFTLB_IPV4_ACTIVE)) {
		sprintf(buf, "%s ; add table %s %s", buf, NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME);
		sprintf(buf, "%s ; add chain %s %s %s { type nat hook %s priority %d ;}", buf, NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_PREROUTING, NFTLB_HOOK_PREROUTING, NFTLB_PREROUTING_PRIO);
		sprintf(buf, "%s ; add chain %s %s %s { type nat hook %s priority %d ;}", buf, NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, NFTLB_HOOK_POSTROUTING, NFTLB_POSTROUTING_PRIO);
		sprintf(buf, "%s ; add rule %s %s %s ct mark and 0x%x == 0x%x masquerade", buf, NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, NFTLB_POSTROUTING_MARK, NFTLB_POSTROUTING_MARK);
		nat_base_rules |= NFTLB_IPV4_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV6_ACTIVE) && !(nat_base_rules & NFTLB_IPV6_ACTIVE)) {
		sprintf(buf, "%s ; add table %s %s", buf, NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME);
		sprintf(buf, "%s ; add chain %s %s %s { type nat hook %s priority %d ;}", buf, NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_PREROUTING, NFTLB_HOOK_PREROUTING, NFTLB_PREROUTING_PRIO);
		sprintf(buf, "%s ; add chain %s %s %s { type nat hook %s priority %d ;}", buf, NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, NFTLB_HOOK_POSTROUTING, NFTLB_POSTROUTING_PRIO);
		sprintf(buf, "%s ; add rule %s %s %s ct mark and 0x%x == 0x%x masquerade", buf, NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, NFTLB_POSTROUTING_MARK, NFTLB_POSTROUTING_MARK);
		nat_base_rules |= NFTLB_IPV6_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV4_UDP_ACTIVE) && !(nat_base_rules & NFTLB_IPV4_UDP_ACTIVE)) {
		sprintf(buf, "%s ; add map %s %s %s { type %s . %s : verdict ;}", buf, NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_UDP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV4, NFTLB_MAP_TYPE_INETSRV);
		sprintf(buf, "%s ; add rule %s %s %s %s daddr . %s dport vmap @%s", buf, NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_PREROUTING, NFTLB_IPV4_FAMILY, NFTLB_UDP_PROTO, NFTLB_UDP_SERVICES_MAP);
		sprintf(buf, "%s ; add map %s %s %s-back { type %s . %s : %s ;}", buf, NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_UDP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV4, NFTLB_MAP_TYPE_INETSRV, NFTLB_MAP_TYPE_IPV4);
		sprintf(buf, "%s ; add rule %s %s %s snat to %s daddr . %s dport map @%s-back", buf, NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, NFTLB_IPV4_FAMILY, NFTLB_UDP_PROTO, NFTLB_UDP_SERVICES_MAP);
		nat_base_rules |= NFTLB_IPV4_UDP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV4_TCP_ACTIVE) && !(nat_base_rules & NFTLB_IPV4_TCP_ACTIVE)) {
		sprintf(buf, "%s ; add map %s %s %s { type %s . %s : verdict ;}", buf, NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TCP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV4, NFTLB_MAP_TYPE_INETSRV);
		sprintf(buf, "%s ; add rule %s %s %s %s daddr . %s dport vmap @%s", buf, NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_PREROUTING, NFTLB_IPV4_FAMILY, NFTLB_TCP_PROTO, NFTLB_TCP_SERVICES_MAP);
		sprintf(buf, "%s ; add map %s %s %s-back { type %s . %s : %s ;}", buf, NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TCP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV4, NFTLB_MAP_TYPE_INETSRV, NFTLB_MAP_TYPE_IPV4);
		sprintf(buf, "%s ; add rule %s %s %s snat to %s daddr . %s dport map @%s-back", buf, NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, NFTLB_IPV4_FAMILY, NFTLB_TCP_PROTO, NFTLB_TCP_SERVICES_MAP);
		nat_base_rules |= NFTLB_IPV4_TCP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV4_SCTP_ACTIVE) && !(nat_base_rules & NFTLB_IPV4_SCTP_ACTIVE)) {
		sprintf(buf, "%s ; add map %s %s %s { type %s . %s : verdict ;}", buf, NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_SCTP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV4, NFTLB_MAP_TYPE_INETSRV);
		sprintf(buf, "%s ; add rule %s %s %s %s daddr . %s dport vmap @%s", buf, NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_PREROUTING, NFTLB_IPV4_FAMILY, NFTLB_SCTP_PROTO, NFTLB_SCTP_SERVICES_MAP);
		sprintf(buf, "%s ; add map %s %s %s-back { type %s . %s : %s ;}", buf, NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_SCTP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV4, NFTLB_MAP_TYPE_INETSRV, NFTLB_MAP_TYPE_IPV4);
		sprintf(buf, "%s ; add rule %s %s %s snat to %s daddr . %s dport map @%s-back", buf, NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, NFTLB_IPV4_FAMILY, NFTLB_SCTP_PROTO, NFTLB_SCTP_SERVICES_MAP);
		nat_base_rules |= NFTLB_IPV4_SCTP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV4_IP_ACTIVE) && !(nat_base_rules & NFTLB_IPV4_IP_ACTIVE)) {
		sprintf(buf, "%s ; add map %s %s %s { type %s : verdict ;}", buf, NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_IP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV4);
		sprintf(buf, "%s ; add rule %s %s %s %s daddr vmap @%s", buf, NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_PREROUTING, NFTLB_IPV4_FAMILY, NFTLB_IP_SERVICES_MAP);
		sprintf(buf, "%s ; add map %s %s %s-back { type %s : %s ;}", buf, NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_IP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV4, NFTLB_MAP_TYPE_IPV4);
		sprintf(buf, "%s ; add rule %s %s %s snat to %s daddr map @%s-back", buf, NFTLB_IPV4_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, NFTLB_IPV4_FAMILY, NFTLB_IP_SERVICES_MAP);
		nat_base_rules |= NFTLB_IPV4_IP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV6_UDP_ACTIVE) && !(nat_base_rules & NFTLB_IPV6_UDP_ACTIVE)) {
		sprintf(buf, "%s ; add map %s %s %s { type %s . %s : verdict ;}", buf, NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_UDP_SERVICES6_MAP, NFTLB_MAP_TYPE_IPV6, NFTLB_MAP_TYPE_INETSRV);
		sprintf(buf, "%s ; add rule %s %s %s %s daddr . %s dport vmap @%s", buf, NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_PREROUTING, NFTLB_IPV6_FAMILY, NFTLB_UDP_PROTO, NFTLB_UDP_SERVICES6_MAP);
		sprintf(buf, "%s ; add map %s %s %s-back { type %s . %s : %s ;}", buf, NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_UDP_SERVICES6_MAP, NFTLB_MAP_TYPE_IPV6, NFTLB_MAP_TYPE_INETSRV, NFTLB_MAP_TYPE_IPV6);
		sprintf(buf, "%s ; add rule %s %s %s snat to %s daddr . %s dport map @%s-back", buf, NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, NFTLB_IPV6_FAMILY, NFTLB_UDP_PROTO, NFTLB_UDP_SERVICES6_MAP);
		nat_base_rules |= NFTLB_IPV6_UDP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV6_TCP_ACTIVE) && !(nat_base_rules & NFTLB_IPV6_TCP_ACTIVE)) {
		sprintf(buf, "%s ; add map %s %s %s { type %s . %s : verdict ;}", buf, NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TCP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV6, NFTLB_MAP_TYPE_INETSRV);
		sprintf(buf, "%s ; add rule %s %s %s %s daddr . %s dport vmap @%s", buf, NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_PREROUTING, NFTLB_IPV6_FAMILY, NFTLB_TCP_PROTO, NFTLB_TCP_SERVICES_MAP);
		sprintf(buf, "%s ; add map %s %s %s-back { type %s . %s : %s ;}", buf, NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TCP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV6, NFTLB_MAP_TYPE_INETSRV, NFTLB_MAP_TYPE_IPV6);
		sprintf(buf, "%s ; add rule %s %s %s snat to %s daddr . %s dport map @%s-back", buf, NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, NFTLB_IPV6_FAMILY, NFTLB_TCP_PROTO, NFTLB_TCP_SERVICES_MAP);
		nat_base_rules |= NFTLB_IPV6_TCP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV6_SCTP_ACTIVE) && !(nat_base_rules & NFTLB_IPV6_SCTP_ACTIVE)) {
		sprintf(buf, "%s ; add map %s %s %s { type %s . %s : verdict ;}", buf, NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_SCTP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV6, NFTLB_MAP_TYPE_INETSRV);
		sprintf(buf, "%s ; add rule %s %s %s %s daddr . %s dport vmap @%s", buf, NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_PREROUTING, NFTLB_IPV6_FAMILY, NFTLB_SCTP_PROTO, NFTLB_SCTP_SERVICES_MAP);
		sprintf(buf, "%s ; add map %s %s %s-back { type %s . %s : %s ;}", buf, NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_SCTP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV6, NFTLB_MAP_TYPE_INETSRV, NFTLB_MAP_TYPE_IPV6);
		sprintf(buf, "%s ; add rule %s %s %s snat to %s daddr . %s dport map @%s-back", buf, NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, NFTLB_IPV6_FAMILY, NFTLB_SCTP_PROTO, NFTLB_SCTP_SERVICES_MAP);
		nat_base_rules |= NFTLB_IPV6_SCTP_ACTIVE;
	}

	if ((rules_needed & NFTLB_IPV6_IP_ACTIVE) && !(nat_base_rules & NFTLB_IPV6_IP_ACTIVE)) {
		sprintf(buf, "%s ; add map %s %s %s { type %s : verdict ;}", buf, NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_IP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV6);
		sprintf(buf, "%s ; add rule %s %s %s %s daddr vmap @%s", buf, NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_PREROUTING, NFTLB_IPV6_FAMILY, NFTLB_IP_SERVICES_MAP);
		sprintf(buf, "%s ; add map %s %s %s-back { type %s : %s ;}", buf, NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_IP_SERVICES_MAP, NFTLB_MAP_TYPE_IPV6, NFTLB_MAP_TYPE_IPV6);
		sprintf(buf, "%s ; add rule %s %s %s snat to %s daddr map @%s-back", buf, NFTLB_IPV6_FAMILY, NFTLB_TABLE_NAME, NFTLB_TABLE_POSTROUTING, NFTLB_IPV6_FAMILY, NFTLB_IP_SERVICES_MAP);
		nat_base_rules |= NFTLB_IPV6_IP_ACTIVE;
	}

	if (!isempty_buf(buf))
		exec_cmd(ctx, buf);

	return 0;
}

static void run_farm_rules_gen_chains(char *buf, struct farm *f, char *chain, int family, int action)
{
	switch (action) {
	case ACTION_RELOAD:
		sprintf(buf, "%s ; flush chain %s %s %s", buf, print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, chain);
		break;
	case ACTION_START:
		sprintf(buf, "%s ; add chain %s %s %s", buf, print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, chain);
		break;
	case ACTION_DELETE:
		sprintf(buf, "%s ; flush chain %s %s %s", buf, print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, chain);
		sprintf(buf, "%s ; delete chain %s %s %s", buf, print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, chain);
		break;
	default:
		break;
	}
}

static int run_farm_rules_gen_sched(char *buf, struct farm *f, int family)
{
	switch (f->scheduler) {
	case VALUE_SCHED_RR:
		sprintf(buf, "%s numgen inc mod %d", buf, f->total_weight);
		break;
	case VALUE_SCHED_WEIGHT:
		sprintf(buf, "%s numgen random mod %d", buf, f->total_weight);
		break;
	case VALUE_SCHED_HASH:
		if ((f->protocol != VALUE_PROTO_TCP || f->protocol == VALUE_PROTO_SCTP) &&
		    (f->mode == VALUE_MODE_DSR || f->mode == VALUE_MODE_STLSDNAT))
			sprintf(buf, "%s jhash %s saddr . %s sport mod %d", buf, print_nft_family(family), print_nft_protocol(f->protocol), f->total_weight);
		else
			sprintf(buf, "%s jhash %s saddr mod %d", buf, print_nft_family(family), f->total_weight);
		break;
	case VALUE_SCHED_SYMHASH:
		sprintf(buf, "%s symhash mod %d", buf, f->total_weight);
		break;
	default:
		return -1;
	}

	return 0;
}

static int run_farm_rules_gen_bck_map(char *buf, struct farm *f, enum map_modes key_mode, enum map_modes data_mode, int offset)
{
	char key_str[255] = { 0 };
	char data_str[255] = { 0 };
	struct backend *b;
	int i = 0;
	int last = 0;
	int new;

	sprintf(buf, "%s map {", buf);

	list_for_each_entry(b, &f->backends, list) {
		if(!backend_is_available(b))
			continue;

		if (i != 0)
			sprintf(buf, "%s,", buf);

		switch (key_mode) {
		case BCK_MAP_MARK:
			sprintf(key_str, "0x%x", b->mark | offset);
			break;
		case BCK_MAP_WEIGHT:
			new = last + b->weight - 1;
			sprintf(key_str, "%d", last);
			if (new != last)
				sprintf(key_str, "%s-%d", key_str, new);
			last = new + 1;
			break;
		default:
			break;
		}

		switch (data_mode) {
		case BCK_MAP_MARK:
			sprintf(data_str, "0x%x", b->mark | offset);
			break;
		case BCK_MAP_ETHADDR:
			sprintf(data_str, "%s", b->ethaddr);
			break;
		case BCK_MAP_IPADDR:
			sprintf(data_str, "%s", b->ipaddr);
			break;
		default:
			break;
		}

		sprintf(buf, "%s %s: %s", buf, key_str, data_str);
		i++;
	}

	sprintf(buf, "%s }", buf);

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

static int run_farm_rules_gen_srv(char *buf, struct farm *f, int family, char * name, int action, enum map_modes key_mode, enum map_modes data_mode)
{
	int port_list[65535] = { 0 };
	char action_str[255] = { 0 };
	char data_str[255] = { 0 };
	struct backend *b;
	int nports;
	int i;

	switch (action) {
	case ACTION_DELETE:
		sprintf(action_str, "delete");
		break;
	default:
		sprintf(action_str, "add");
		break;
	}

	switch (data_mode) {
	case BCK_MAP_SRCIPADDR:
		sprintf(data_str, ": %s ", f->srcaddr);
		break;
	case BCK_MAP_NAME:
		sprintf(data_str, ": goto %s ", f->name);
		break;
	case BCK_MAP_NAME_BACK:
		sprintf(data_str, ": goto %s-back ", f->name);
		break;
	default:
		break;
	}

	switch (key_mode) {
	case BCK_MAP_IPADDR:
		sprintf(buf, "%s ; %s element %s %s %s { %s %s}", buf, action_str, print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, name, f->virtaddr, data_str);
		break;
	case BCK_MAP_BCK_IPADDR:
		list_for_each_entry(b, &f->backends, list) {
			if(!backend_is_available(b))
				continue;
			sprintf(buf, "%s ; add element %s %s %s { %s %s}", buf, print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, name, b->ipaddr, data_str);
		}
		break;
	case BCK_MAP_IPADDR_PORT:
		nports = get_array_ports(port_list, f);
		for (i = 0; i < nports; i++)
			sprintf(buf, "%s ; %s element %s %s %s { %s . %d %s}", buf, action_str, print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, name, f->virtaddr, port_list[i], data_str);
		break;
	case BCK_MAP_BCK_IPADDR_F_PORT:
		nports = get_array_ports(port_list, f);
		for (i = 0; i < nports; i++) {
			list_for_each_entry(b, &f->backends, list) {
				if(!backend_is_available(b))
					continue;
				sprintf(buf, "%s ; add element %s %s %s { %s . %d %s}", buf, print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, name, b->ipaddr, port_list[i], data_str);
			}
		}
		break;
	default:
		return -1;
		break;
	}

	return 0;
}

static int run_farm_rules(struct nft_ctx *ctx, struct farm *f, int family, int action)
{
	char buf[NFTLB_MAX_CMD] = { 0 };
	char buf2[NFTLB_MAX_CMD] = { 0 };
	int out = 0;
	int mark;

	run_farm_rules_gen_chains(buf, f, f->name, family, action);

	/* input log */
	if (f->log & VALUE_LOG_INPUT)
		sprintf(buf, "%s ; add rule %s %s %s log prefix \"INPUT-%s \"", buf, print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, f->name, f->name);

	/* no bck rules */
	if (f->bcks_available == 0)
		goto avoidrules;

	/* backends rule */
	sprintf(buf, "%s ; add rule %s %s %s", buf, print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, f->name);

	/* helpers */
	if (f->helper && (f->mode == VALUE_MODE_SNAT || f->mode == VALUE_MODE_DNAT)) {
		sprintf(buf, "%s ct helper set %s", buf, obj_print_helper(f->helper));
		sprintf(buf2, "%s ; add ct helper %s %s %s { type \"%s\" protocol %s ; }", buf2, print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, obj_print_helper(f->helper), obj_print_helper(f->helper), obj_print_proto(f->protocol));
		exec_cmd(ctx, buf2);
	}

	/* set marks */
	mark = f->mark;
	if (f->mode == VALUE_MODE_SNAT && farm_get_masquerade(f))
		mark |= NFTLB_POSTROUTING_MARK;

	if (mark != DEFAULT_MARK || f->bcks_are_marked)
		sprintf(buf, "%s ct mark set", buf);

	if (f->bcks_are_marked) {
		if (run_farm_rules_gen_sched(buf, f, family) == -1)
			return -1;
		run_farm_rules_gen_bck_map(buf, f, BCK_MAP_WEIGHT, BCK_MAP_MARK, mark);
	} else if (mark != DEFAULT_MARK) {
		sprintf(buf, "%s 0x%x", buf, mark);
	}

	switch (f->mode) {
	case VALUE_MODE_DSR:
		sprintf(buf, "%s ether saddr set %s ether daddr set", buf, f->iethaddr);
		break;
	case VALUE_MODE_STLSDNAT:
		sprintf(buf, "%s %s daddr set", buf, print_nft_family(family));
		break;
	default:
		sprintf(buf, "%s dnat to", buf);
	}

	if (!f->bcks_are_marked && run_farm_rules_gen_sched(buf, f, family) == -1)
		return -1;

	if (f->mode == VALUE_MODE_DSR)
		out = run_farm_rules_gen_bck_map(buf, f, BCK_MAP_WEIGHT, BCK_MAP_ETHADDR, 0);
	else {
		if(!f->bcks_are_marked)
			out = run_farm_rules_gen_bck_map(buf, f, BCK_MAP_WEIGHT, BCK_MAP_IPADDR, 0);
		else {
			sprintf(buf, "%s ct mark", buf);
			out = run_farm_rules_gen_bck_map(buf, f, BCK_MAP_MARK, BCK_MAP_IPADDR, mark);
		}
	}

	if (out == -1)
		return -1;

	if (f->mode == VALUE_MODE_DSR || f->mode == VALUE_MODE_STLSDNAT)
		sprintf(buf, "%s fwd to %s", buf, f->oface);

avoidrules:
	if (action == ACTION_RELOAD) {
		exec_cmd(ctx, buf);
		return 0;
	}

	if (f->protocol == VALUE_PROTO_ALL)
		run_farm_rules_gen_srv(buf, f, family, print_nft_service(family, f->protocol, KEY_IFACE), action, BCK_MAP_IPADDR, BCK_MAP_NAME);
	else
		run_farm_rules_gen_srv(buf, f, family, print_nft_service(family, f->protocol, KEY_IFACE), action, BCK_MAP_IPADDR_PORT, BCK_MAP_NAME);

	exec_cmd(ctx, buf);

	return 0;
}

static int run_farm_snat(struct nft_ctx *ctx, struct farm *f, int family)
{
	char buf[NFTLB_MAX_CMD] = { 0 };
	char name[255] = { 0 };

	if (farm_get_masquerade(f))
		return 0;

	sprintf(name, "%s-back", print_nft_service(family, f->protocol, KEY_IFACE));

	if (f->protocol == VALUE_PROTO_ALL)
		run_farm_rules_gen_srv(buf, f, family, name, ACTION_START, BCK_MAP_BCK_IPADDR, BCK_MAP_SRCIPADDR);
	else
		run_farm_rules_gen_srv(buf, f, family, name, ACTION_START, BCK_MAP_BCK_IPADDR_F_PORT, BCK_MAP_SRCIPADDR);

	exec_cmd(ctx, buf);

	return 0;
}

static int run_farm_stlsnat(struct nft_ctx *ctx, struct farm *f, int family, int action)
{
	char buf[NFTLB_MAX_CMD] = { 0 };
	char name[255] = { 0 };

	sprintf(name, "%s-back", f->name);
	run_farm_rules_gen_chains(buf, f, name, family, action);
	sprintf(buf, "%s ; add rule %s %s %s %s saddr set %s fwd to %s", buf, print_nft_table_family(family, f->mode), NFTLB_TABLE_NAME, name, print_nft_family(family), f->virtaddr, f->iface);

	run_farm_rules_gen_srv(buf, f, family, print_nft_service(family, f->protocol, KEY_OFACE), ACTION_START, BCK_MAP_BCK_IPADDR, BCK_MAP_NAME_BACK);

	exec_cmd(ctx, buf);

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
		run_base_nat(ctx, f);
	}

	if ((f->family == VALUE_FAMILY_IPV4) || (f->family == VALUE_FAMILY_INET))
		run_farm_rules(ctx, f, VALUE_FAMILY_IPV4, action);
	if ((f->family == VALUE_FAMILY_IPV6) || (f->family == VALUE_FAMILY_INET))
		run_farm_rules(ctx, f, VALUE_FAMILY_IPV6, action);

	if (f->mode == VALUE_MODE_SNAT) {
		if ((f->family == VALUE_FAMILY_IPV4) || (f->family == VALUE_FAMILY_INET)) {
			run_farm_snat(ctx, f, VALUE_FAMILY_IPV4);
		}
		if ((f->family == VALUE_FAMILY_IPV6) || (f->family == VALUE_FAMILY_INET)) {
			run_farm_snat(ctx, f, VALUE_FAMILY_IPV6);
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
	char buf[NFTLB_MAX_CMD] = { 0 };
	int ret = 0;

	if (f->protocol == VALUE_PROTO_ALL)
		run_farm_rules_gen_srv(buf, f, family, print_nft_service(family, f->protocol, KEY_IFACE), ACTION_DELETE, BCK_MAP_IPADDR, BCK_MAP_NONE);
	else
		run_farm_rules_gen_srv(buf, f, family, print_nft_service(family, f->protocol, KEY_IFACE), ACTION_DELETE, BCK_MAP_IPADDR_PORT, BCK_MAP_NONE);

	run_farm_rules_gen_chains(buf, f, f->name, family, ACTION_DELETE);

	exec_cmd(ctx, buf);

	return ret;
}

static int del_farm(struct nft_ctx *ctx, struct farm *f)
{
	int ret = 0;

	if ((f->family == VALUE_FAMILY_IPV4) || (f->family == VALUE_FAMILY_INET))
		del_farm_rules(ctx, f, VALUE_FAMILY_IPV4);
	if ((f->family == VALUE_FAMILY_IPV6) || (f->family == VALUE_FAMILY_INET))
		del_farm_rules(ctx, f, VALUE_FAMILY_IPV6);

	return ret;
}

int nft_reset(void)
{
	struct nft_ctx *ctx = nft_ctx_new(0);
	char buf[NFTLB_MAX_CMD] = { 0 };
	int ret = 0;

	sprintf(buf, "flush ruleset");
	exec_cmd(ctx, buf);

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

	f->action = ACTION_NONE;

	nft_ctx_free(ctx);

	return ret;
}
