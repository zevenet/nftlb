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
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <ifaddrs.h>
#include <ev.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/if_arp.h>
#include <linux/rtnetlink.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <libmnl/libmnl.h>

#include "network.h"
#include "events.h"
#include "farms.h"
#include "checksum.h"

#define ARP_TABLE_RETRY_SLEEP	1000

static int net_event_enabled;

struct net_io {
	ev_io *io;
	struct rtgenmsg *rt;
	struct nlmsghdr *nlh;
};

static struct net_io io_handle;
struct mnl_socket *nl;

struct icmp_packet
{
	struct ip iphdr;
	struct icmp icmphdr;
	uint8_t data[ICMP_DATALEN];
};

struct icmpv6_packet
{
	struct ip6_hdr iphdr;
	struct icmp6_hdr icmphdr;
	uint8_t data[ICMP_DATALEN];
};

struct ntl_data {
	unsigned char	family;
	struct in6_addr	*src_ipaddr;
	unsigned char	src_ethaddr[ETH_HW_ADDR_LEN];
	struct in6_addr	*dst_ipaddr;
	unsigned char	dst_ethaddr[ETH_HW_ADDR_LEN];
	int				oifidx;
};

struct ntl_request {
	struct mnl_socket *nl;
	struct nlmsghdr *nlh;
	struct rtgenmsg *rt;
	struct rtmsg *rtm;
	unsigned int portid;
	int msgtype;
	char *buf;
	void *cb;
	void *data;
};

static int net_cmp_ipv6(struct in6_addr *ip1, struct in6_addr *ip2)
{
	int i = 0;
	for(i = 0; i < 16; ++i) {
		if (ip1->s6_addr[i] != ip2->s6_addr[i])
			return -1;
	}
	return 0;
}

static int net_get_addr_family(char *vip)
{
	if (strstr(vip, ":"))
		return AF_INET6;
	else
		return AF_INET;
}

static int send_ping(void *data)
{
	struct ntl_data *sdata = data;
	struct sockaddr_ll device;
	struct icmp_packet pckt4;
	struct icmpv6_packet pckt6;
	ssize_t ret = 0;
	int sock;
	int frame_len_v6 = ETHER_HDRLEN + IP6_HDRLEN + ICMP_HDRLEN + ICMP_DATALEN;
	uint8_t frame_v6[frame_len_v6];
	int frame_len_v4 = ETHER_HDRLEN + IP4_HDRLEN + ICMP_HDRLEN + ICMP_DATALEN;
	uint8_t frame_v4[frame_len_v4];
	int *frame_len;
	uint8_t *frame;
	int flags[4];

	syslog(LOG_DEBUG, "%s():%d: sending ping", __FUNCTION__, __LINE__);

	if (sdata->family == AF_INET6) {
		frame_len = &frame_len_v6;
		frame = frame_v6;

		memset(&device, 0, sizeof(device));
		device.sll_ifindex = sdata->oifidx;
		device.sll_family = AF_PACKET;
		memcpy(device.sll_addr, sdata->src_ethaddr, ETH_HW_ADDR_LEN * sizeof(uint8_t));
		device.sll_halen = 6;

		frame_v6[0] = 0xff;
		frame_v6[1] = 0xff;
		frame_v6[2] = 0xff;
		frame_v6[3] = 0xff;
		frame_v6[4] = 0xff;
		frame_v6[5] = 0xff;
		frame_v6[6] = (uint8_t)sdata->src_ethaddr[0];
		frame_v6[7] = (uint8_t)sdata->src_ethaddr[1];
		frame_v6[8] = (uint8_t)sdata->src_ethaddr[2];
		frame_v6[9] = (uint8_t)sdata->src_ethaddr[3];
		frame_v6[10] = (uint8_t)sdata->src_ethaddr[4];
		frame_v6[11] = (uint8_t)sdata->src_ethaddr[5];
		frame_v6[12] = ETH_P_IPV6 / 256;
		frame_v6[13] = ETH_P_IPV6 % 256;

		pckt6.iphdr.ip6_flow = htonl((6 << 28) | (0 << 20) | 0);
		pckt6.iphdr.ip6_plen = htons(ICMP_HDRLEN + 4);
		pckt6.iphdr.ip6_nxt = IPPROTO_ICMPV6;
		pckt6.iphdr.ip6_hops = 255;
		memcpy(&pckt6.iphdr.ip6_src, sdata->src_ipaddr, sizeof(struct in6_addr));
		memcpy(&pckt6.iphdr.ip6_dst, sdata->dst_ipaddr, sizeof(struct in6_addr));

		pckt6.icmphdr.icmp6_type = ICMP6_ECHO_REQUEST;
		pckt6.icmphdr.icmp6_code = 0;
		pckt6.icmphdr.icmp6_id = htons(1000);
		pckt6.icmphdr.icmp6_seq = htons(0);

		pckt6.data[0] = 'H';
		pckt6.data[1] = 'o';
		pckt6.data[2] = 'l';
		pckt6.data[3] = 'a';

		pckt6.icmphdr.icmp6_cksum = 0;
		pckt6.icmphdr.icmp6_cksum = icmp6_checksum(pckt6.iphdr, pckt6.icmphdr, pckt6.data, ICMP_DATALEN);
		memcpy(frame_v6 + ETHER_HDRLEN, &pckt6.iphdr, IP6_HDRLEN * sizeof(uint8_t));
		memcpy(frame_v6 + ETHER_HDRLEN + IP6_HDRLEN, &pckt6.icmphdr, ICMP_HDRLEN * sizeof(uint8_t));
		memcpy(frame_v6 + ETHER_HDRLEN + IP6_HDRLEN + ICMP_HDRLEN, pckt6.data, ICMP_DATALEN * sizeof(uint8_t));
	} else {
		frame_len = &frame_len_v4;
		frame = frame_v4;

		memset(&device, 0, sizeof(device));
		device.sll_ifindex = sdata->oifidx;
		device.sll_family = AF_PACKET;
		memcpy(device.sll_addr, sdata->src_ethaddr, ETH_HW_ADDR_LEN * sizeof(uint8_t));
		device.sll_halen = 6;

		frame_v4[0] = 0xff;
		frame_v4[1] = 0xff;
		frame_v4[2] = 0xff;
		frame_v4[3] = 0xff;
		frame_v4[4] = 0xff;
		frame_v4[5] = 0xff;
		frame_v4[6] = (uint8_t)sdata->src_ethaddr[0];
		frame_v4[7] = (uint8_t)sdata->src_ethaddr[1];
		frame_v4[8] = (uint8_t)sdata->src_ethaddr[2];
		frame_v4[9] = (uint8_t)sdata->src_ethaddr[3];
		frame_v4[10] = (uint8_t)sdata->src_ethaddr[4];
		frame_v4[11] = (uint8_t)sdata->src_ethaddr[5];
		frame_v4[12] = ETH_P_IP / 256;
		frame_v4[13] = ETH_P_IP % 256;

		pckt4.iphdr.ip_hl = IP4_HDRLEN / sizeof(uint32_t);
		pckt4.iphdr.ip_v = 4;
		pckt4.iphdr.ip_tos = 0;
		pckt4.iphdr.ip_len = htons(IP4_HDRLEN + ICMP_HDRLEN + ICMP_DATALEN);
		pckt4.iphdr.ip_id = htons(0);

		pckt4.data[0] = 'H';
		pckt4.data[1] = 'o';
		pckt4.data[2] = 'l';
		pckt4.data[3] = 'a';

		flags[0] = 0;
		flags[1] = 0;
		flags[2] = 0;
		flags[3] = 0;

		pckt4.iphdr.ip_off = htons((flags[0] << 15)
			+ (flags[1] << 14) + (flags[2] << 13)
			+  flags[3]);
		pckt4.iphdr.ip_ttl = 255;
		pckt4.iphdr.ip_p = IPPROTO_ICMP;
		memcpy(&pckt4.iphdr.ip_src, sdata->src_ipaddr, sizeof(struct in_addr));
		memcpy(&pckt4.iphdr.ip_dst, sdata->dst_ipaddr, sizeof(struct in_addr));
		pckt4.iphdr.ip_sum = 0;
		pckt4.iphdr.ip_sum = checksum ((uint16_t *) &pckt4.iphdr, IP4_HDRLEN);

		pckt4.icmphdr.icmp_type = ICMP_ECHO;
		pckt4.icmphdr.icmp_code = 0;
		pckt4.icmphdr.icmp_id = htons(1000);
		pckt4.icmphdr.icmp_seq = htons(0);
		pckt4.icmphdr.icmp_cksum = icmp4_checksum (pckt4.icmphdr, pckt4.data, ICMP_DATALEN);

		memcpy(frame_v4 + ETHER_HDRLEN, &pckt4.iphdr, IP4_HDRLEN * sizeof(uint8_t));
		memcpy(frame_v4 + ETHER_HDRLEN + IP4_HDRLEN, &pckt4.icmphdr, ICMP_HDRLEN * sizeof(uint8_t));
		memcpy(frame_v4 + ETHER_HDRLEN + IP4_HDRLEN + ICMP_HDRLEN, pckt4.data, ICMP_DATALEN * sizeof(uint8_t));
	}

	sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock < 0) {
		syslog(LOG_ERR, "%s():%d: open socket error", __FUNCTION__, __LINE__);
		ret = -1;
		goto out;
	}

	if (sendto(sock, frame, *frame_len, 0, (struct sockaddr *) &device, sizeof(device)) <= 0) {
		syslog(LOG_ERR, "%s():%d: sendto error", __FUNCTION__, __LINE__);
		ret = -1;
	}

out:
	if (ret && sock > 0) {
		syslog(LOG_DEBUG, "%s():%d: cleanup socket", __FUNCTION__, __LINE__);
		close(sock);
	}

	return ret;
}

static int data_attr_neigh_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NDA_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NDA_DST:
	case NDA_LLADDR:
		if (mnl_attr_validate(attr, MNL_TYPE_BINARY) < 0) {
			syslog(LOG_ERR, "%s():%d: mnl_attr_validate error", __FUNCTION__, __LINE__);
			return MNL_CB_ERROR;
		}
		break;
	default:
		return MNL_CB_ERROR;
	}

	tb[type] = attr;

	return MNL_CB_OK;
}

static int data_getdst_neigh_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[NDA_MAX + 1] = {};
	struct ndmsg *ndm = mnl_nlmsg_get_payload(nlh);
	struct in6_addr *ipaddr;
	void *ethaddr;
	char out[INET6_ADDRSTRLEN];
	char out1[INET6_ADDRSTRLEN];
	struct ntl_data *sdata = data;
	int matches = 0;

	syslog(LOG_DEBUG, "%s():%d: getting ethernet address destination", __FUNCTION__, __LINE__);

	mnl_attr_parse(nlh, sizeof(*ndm), data_attr_neigh_cb, tb);

	if (!tb[NDA_DST])
		return MNL_CB_OK;

	ipaddr = mnl_attr_get_payload(tb[NDA_DST]);

	inet_ntop(sdata->family, ipaddr, out, INET6_ADDRSTRLEN);
	inet_ntop(sdata->family, sdata->dst_ipaddr, out1, INET6_ADDRSTRLEN);

	if (sdata->family == AF_INET6)
		matches = (net_cmp_ipv6(ipaddr, sdata->dst_ipaddr) == 0);
	else
		matches = (memcmp(ipaddr, sdata->dst_ipaddr, INET_ADDRSTRLEN) == 0);

	if (matches &&
	    ((ndm->ndm_state & NUD_REACHABLE) || (ndm->ndm_state & NUD_PERMANENT) || (ndm->ndm_state & NUD_STALE))) {
		mnl_attr_parse(nlh, sizeof(*ndm), data_attr_neigh_cb, tb);
		if (tb[NDA_LLADDR]) {
			ethaddr = mnl_attr_get_payload(tb[NDA_LLADDR]);
			memcpy(&sdata->dst_ethaddr, ethaddr, 6);

			syslog(LOG_INFO, "%s():%d: get ether address index=%d family=%d dst=%s eth=%02x:%02x:%02x:%02x:%02x:%02x sts=%d",
			       __FUNCTION__, __LINE__,
			       ndm->ndm_ifindex, ndm->ndm_family, out, sdata->dst_ethaddr[0],
			       sdata->dst_ethaddr[1], sdata->dst_ethaddr[2], sdata->dst_ethaddr[3],
			       sdata->dst_ethaddr[4], sdata->dst_ethaddr[5], ndm->ndm_state);
		}

		return MNL_CB_STOP;
	}

	return MNL_CB_OK;
}

static int data_route_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, RTA_MAX) < 0)
		return MNL_CB_OK;

	tb[type] = attr;
	return MNL_CB_OK;
}

static int data_getdst_route_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[RTA_MAX + 1] = {};
	struct rtmsg *rm = mnl_nlmsg_get_payload(nlh);
	struct ntl_data *sdata = data;

	syslog(LOG_DEBUG, "%s():%d: getting interface route destination", __FUNCTION__, __LINE__);

	mnl_attr_parse(nlh, sizeof(*rm), data_route_attr_cb, tb);

	if (tb[RTA_OIF]) {
		sdata->oifidx = mnl_attr_get_u32(tb[RTA_OIF]);
		syslog(LOG_INFO, "%s():%d: get routing interface to destination is %u", __FUNCTION__, __LINE__, sdata->oifidx);
		return MNL_CB_STOP;
	}

	return MNL_CB_STOP;
}

static int ntl_request(struct ntl_request *ntl)
{
	int ret, out = 0;

	ntl->nl = mnl_socket_open(NETLINK_ROUTE);
	if (ntl->nl == NULL) {
		syslog(LOG_ERR, "%s():%d: mnl_socket_open error", __FUNCTION__, __LINE__);
		return -1;
	}

	if (mnl_socket_bind(ntl->nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		syslog(LOG_ERR, "%s():%d: mnl_socket_bind error", __FUNCTION__, __LINE__);
		return -1;
	}
	ntl->portid = mnl_socket_get_portid(ntl->nl);

	if (mnl_socket_sendto(ntl->nl, ntl->nlh, ntl->nlh->nlmsg_len) < 0) {
		syslog(LOG_ERR, "%s():%d: mnl_socket_sendto error", __FUNCTION__, __LINE__);
		return -1;
	}

	ret = mnl_socket_recvfrom(ntl->nl, ntl->buf, MNL_SOCKET_BUFFER_SIZE);
	while (ret > 0) {
		ret = mnl_cb_run(ntl->buf, ret, ntl->nlh->nlmsg_seq, ntl->portid, ntl->cb, ntl->data);
		if (ret <= MNL_CB_STOP) {
			out = 0 | out;
			goto end;
		} else {
			out = -1;
		}

		ret = mnl_socket_recvfrom(ntl->nl, ntl->buf, MNL_SOCKET_BUFFER_SIZE);
	}

	if (ret == -1) {
		syslog(LOG_ERR, "%s():%d: mnl_socket_recvfrom error", __FUNCTION__, __LINE__);
		ret = -1;
	}

end:
	mnl_socket_close(ntl->nl);

	return out;
}

int net_get_neigh_ether(unsigned char **dst_ethaddr, unsigned char *src_ethaddr, unsigned char family, char *src_ipaddr, char *dst_ipaddr, int outdev)
{
	struct ntl_request ntl;
	struct ntl_data *data;
	int ret = 0;

	syslog(LOG_DEBUG, "%s():%d: source mac address %s source ip address %s destination ip address %s iface %d", __FUNCTION__, __LINE__, src_ethaddr, src_ipaddr, dst_ipaddr, outdev);

	ntl.buf = (char *) malloc(MNL_SOCKET_BUFFER_SIZE);

	ntl.nlh = mnl_nlmsg_put_header(ntl.buf);
	ntl.nlh->nlmsg_type = RTM_GETNEIGH;
	ntl.nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	ntl.nlh->nlmsg_seq = time(NULL);

	ntl.rt = mnl_nlmsg_put_extra_header(ntl.nlh, sizeof(struct rtgenmsg));
	ntl.rt->rtgen_family = AF_INET | AF_INET6;
	ntl.cb = data_getdst_neigh_cb;

	syslog(LOG_DEBUG, "%s():%d: source ether is %02x:%02x:%02x:%02x:%02x:%02x",
	       __FUNCTION__, __LINE__, src_ethaddr[0], src_ethaddr[1], src_ethaddr[2],
	       src_ethaddr[3], src_ethaddr[4], src_ethaddr[5]);

	data = (struct ntl_data *)calloc(1, sizeof(struct ntl_data));
	if (!data) {
		syslog(LOG_ERR, "%s():%d: memory allocation error", __FUNCTION__, __LINE__);
		return -1;
	}

	ntl.data = (void *)data;

	data->dst_ipaddr = (struct in6_addr *)calloc(1, sizeof(struct in6_addr));
	if (!data->dst_ipaddr){
		syslog(LOG_ERR, "%s():%d: memory allocation error", __FUNCTION__, __LINE__);
		return -1;
	}

	if (family == VALUE_FAMILY_IPV6)
		data->family = AF_INET6;
	else
		data->family = AF_INET;

	if (inet_pton(data->family, dst_ipaddr, data->dst_ipaddr) <= 0) {
		syslog(LOG_ERR, "%s():%d: network translation error for %s", __FUNCTION__, __LINE__, dst_ipaddr);
		return -1;
	}

	data->oifidx = outdev;

	ret = ntl_request(&ntl);

	if (ret != 0) {
		ret = -1;
		syslog(LOG_DEBUG, "%s():%d: not found, send ping to %s", __FUNCTION__, __LINE__, dst_ipaddr);

		data->src_ipaddr = (struct in6_addr *)calloc(1, sizeof(struct in6_addr));
		if (!data->src_ipaddr){
			syslog(LOG_ERR, "%s():%d: memory allocation error", __FUNCTION__, __LINE__);
			return ret;
		}

		if (inet_pton(data->family, src_ipaddr, data->src_ipaddr) <= 0) {
			syslog(LOG_ERR, "%s():%d: network translation error for %s", __FUNCTION__, __LINE__, src_ipaddr);
			return ret;
		}

		memcpy(data->src_ethaddr, src_ethaddr, ETH_HW_ADDR_LEN);
		send_ping(data);
		free(data->src_ipaddr);
	}

	memcpy(dst_ethaddr, data->dst_ethaddr, ETH_HW_ADDR_LEN);
	free(ntl.buf);
	free(data->dst_ipaddr);
	free(data);

	return ret;
}

int net_get_local_ifidx_per_remote_host(char *dst_ipaddr, int *outdev)
{
	struct ntl_request ntl;
	struct ntl_data *data;
	struct sockaddr_in6 addr;
	int ipv = net_get_addr_family(dst_ipaddr);
	int ret = 0;

	syslog(LOG_DEBUG, "%s():%d: dst ip address is %s", __FUNCTION__, __LINE__, dst_ipaddr);

	ntl.buf = (char *) malloc(MNL_SOCKET_BUFFER_SIZE);

	ntl.nlh = mnl_nlmsg_put_header(ntl.buf);
	ntl.nlh->nlmsg_type = RTM_GETROUTE;
	ntl.nlh->nlmsg_flags = NLM_F_REQUEST;
	ntl.nlh->nlmsg_seq = time(NULL);

	ntl.rtm = mnl_nlmsg_put_extra_header(ntl.nlh, sizeof(struct rtmsg));
	ntl.rtm->rtm_family = ipv;
	ntl.rtm->rtm_dst_len = 128;
	ntl.rtm->rtm_src_len = 0;
	ntl.rtm->rtm_tos = 0;
	ntl.rtm->rtm_protocol = RTPROT_UNSPEC;
	ntl.rtm->rtm_table = RT_TABLE_UNSPEC;
	ntl.rtm->rtm_type = RTN_UNSPEC;
	ntl.rtm->rtm_scope = RT_SCOPE_UNIVERSE;
	ntl.rtm->rtm_flags = RTM_F_LOOKUP_TABLE;

	data = (struct ntl_data *)calloc(1, sizeof(struct ntl_data));
	if (!data) {
		syslog(LOG_ERR, "%s():%d: memory allocation error", __FUNCTION__, __LINE__);
		return -1;
	}

	data->dst_ipaddr = (struct in6_addr *)calloc(1, sizeof(struct in6_addr));
	if (!data->dst_ipaddr){
		syslog(LOG_ERR, "%s():%d: memory allocation error", __FUNCTION__, __LINE__);
		return -1;
	}

	ntl.cb = data_getdst_route_cb;
	ntl.data = (void *)data;
	data->family = ipv;

	if (!inet_pton(ipv, dst_ipaddr, &(addr.sin6_addr.s6_addr))) {
		syslog(LOG_ERR, "%s():%d: network translation error for %s", __FUNCTION__, __LINE__, dst_ipaddr);
		return -1;
	}

	mnl_attr_put(ntl.nlh, RTA_DST, 4 * sizeof(uint32_t), &(addr.sin6_addr));

	ret = ntl_request(&ntl);

	if (ret != 0) {
		syslog(LOG_ERR, "%s():%d: not found route to %s", __FUNCTION__, __LINE__, dst_ipaddr);
		return -1;
	}

	syslog(LOG_DEBUG, "%s():%d: found route to %s via %d", __FUNCTION__, __LINE__, dst_ipaddr, data->oifidx);

	*outdev = data->oifidx;

	free(ntl.buf);
	free(data->dst_ipaddr);
	free(data);

	return ret;
}

int net_get_local_ifinfo(unsigned char **ether, const char *indev)
{
	int ret = -1;
	struct ifreq ifr;
	int sd;

	syslog(LOG_DEBUG, "%s():%d: netlink get local interface info for %s", __FUNCTION__, __LINE__, indev);

	sd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);

	if (sd <= 0) {
		syslog(LOG_ERR, "%s():%d: open socket error", __FUNCTION__, __LINE__);
		goto out;
	}

	strcpy(ifr.ifr_name, indev);

	if (ioctl(sd, SIOCGIFHWADDR, &ifr) == -1) {
		syslog(LOG_ERR, "%s():%d: ioctl SIOCGIFHWADDR error", __FUNCTION__, __LINE__);
		goto out;
	}

	memcpy(ether, ifr.ifr_hwaddr.sa_data, ETH_HW_ADDR_LEN * sizeof(unsigned char));

	ret = 0;
out:
	if (sd > 0)
		close(sd);

	return ret;
}

int net_get_local_ifname_per_vip(char *strvip, char *outdev)
{
	struct sockaddr_storage addr;
	int ipv;
	int found = 0;
	struct sockaddr_in *ipaddr;
	struct sockaddr_in6 *ipaddr6;
	struct ifaddrs *ifaddrs, *ifaddr;

	if (!strvip || strcmp(strvip, "") == 0) {
		syslog(LOG_ERR, "%s():%d: vip is not set yet", __FUNCTION__, __LINE__);
		return -1;
	}

	syslog(LOG_DEBUG, "%s():%d: netlink get local interface name for %s", __FUNCTION__, __LINE__, strvip);

	ipv = net_get_addr_family(strvip);

	if (getifaddrs(&ifaddrs) == -1) {
		syslog(LOG_ERR, "%s():%d: cannot get interfaces list", __FUNCTION__, __LINE__);
		return -1;
	}

	for (ifaddr = ifaddrs; ifaddr != NULL && !found; ifaddr = ifaddr->ifa_next) {
		if (ifaddr->ifa_addr == NULL) continue;

		switch (ipv) {
		case AF_INET6:
			if (ifaddr->ifa_addr->sa_family != AF_INET6)
				continue;
			ipaddr6 = (struct sockaddr_in6 *)ifaddr->ifa_addr;
			inet_pton(AF_INET6, strvip, &((struct sockaddr_in6 *) &addr)->sin6_addr);
			if (net_cmp_ipv6(&((struct sockaddr_in6 *) &addr)->sin6_addr, &(ipaddr6->sin6_addr)) == 0) {
				found = 1;
				strcpy(outdev, ifaddr->ifa_name);
			}
			break;
		case AF_INET:
			if (ifaddr->ifa_addr->sa_family != AF_INET)
				continue;
			ipaddr = (struct sockaddr_in *)ifaddr->ifa_addr;
			inet_pton(AF_INET, strvip, &((struct sockaddr_in *) &addr)->sin_addr);
			if (((struct sockaddr_in *) &addr)->sin_addr.s_addr == ipaddr->sin_addr.s_addr) {
				found = 1;
				strcpy(outdev, ifaddr->ifa_name);
			}
			break;
		}
	}

	freeifaddrs(ifaddrs);

	syslog(LOG_DEBUG, "%s():%d: netlink get local interface name is %s", __FUNCTION__, __LINE__, outdev);

	return !found;
}

static int data_getev_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[NDA_MAX + 1] = {};
	struct ndmsg *ndm = mnl_nlmsg_get_payload(nlh);
	struct in6_addr *ipaddr;
	char str_ipaddr[INET6_ADDRSTRLEN] = { 0 };
	void *ethaddr;
	unsigned char dst_ethaddr[ETH_HW_ADDR_LEN];
	char streth[ETH_HW_STR_LEN] = {};

	syslog(LOG_DEBUG, "%s():%d: netlink read new info", __FUNCTION__, __LINE__);

	if (nlh->nlmsg_type != RTM_NEWNEIGH)
		return MNL_CB_STOP;

	mnl_attr_parse(nlh, sizeof(*ndm), data_attr_neigh_cb, tb);

	if (tb[NDA_DST]) {
		ipaddr = mnl_attr_get_payload(tb[NDA_DST]);
		inet_ntop(ndm->ndm_family, ipaddr, str_ipaddr, INET6_ADDRSTRLEN);
	}

	if (tb[NDA_LLADDR]) {
		ethaddr = mnl_attr_get_payload(tb[NDA_LLADDR]);
		memcpy(dst_ethaddr, ethaddr, ETH_HW_ADDR_LEN);

		sprintf(streth, "%02x:%02x:%02x:%02x:%02x:%02x", dst_ethaddr[0], dst_ethaddr[1],
			dst_ethaddr[2], dst_ethaddr[3], dst_ethaddr[4], dst_ethaddr[5]);

		if ((ndm->ndm_state & NUD_REACHABLE) || (ndm->ndm_state & NUD_PERMANENT) || (ndm->ndm_state & NUD_STALE))
			farm_s_set_backend_ether_by_oifidx(ndm->ndm_ifindex, str_ipaddr, streth);

		syslog(LOG_DEBUG, "%s():%d: [NEW NEIGH] family=%u ifindex=%u state=%u dstaddr=%s macaddr=%s",
		       __FUNCTION__, __LINE__, ndm->ndm_family, ndm->ndm_ifindex, ndm->ndm_state, str_ipaddr,
		       streth);
	}

	return MNL_CB_STOP;
}

static void ntlk_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	int ret, out;

	syslog(LOG_DEBUG, "%s():%d: netlink callback executed", __FUNCTION__, __LINE__);

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, 0, 0, data_getev_cb, NULL);
		if (ret <= MNL_CB_STOP) {
			out = 0 | out;
			return;
		} else {
			out = -1;
		}
		ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	}

	if (ret == -1) {
		syslog(LOG_ERR, "%s():%d: netlink error", __FUNCTION__, __LINE__);
		ret = -1;
	}
}

int net_eventd_init(void)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	int sock;
	struct ev_loop *st_ev_loop = get_loop();

	syslog(LOG_DEBUG, "%s():%d: net eventd launched", __FUNCTION__, __LINE__);

	io_handle.io = events_create_ntlnk();

	io_handle.nlh = mnl_nlmsg_put_header(buf);
	io_handle.nlh->nlmsg_type = RTM_GETNEIGH;
	io_handle.nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	io_handle.nlh->nlmsg_seq = time(NULL);

	io_handle.rt = mnl_nlmsg_put_extra_header(io_handle.nlh, sizeof(struct rtgenmsg));
	io_handle.rt->rtgen_family = AF_INET;

	nl = mnl_socket_open(NETLINK_ROUTE);
	if (nl == NULL) {
		syslog(LOG_ERR, "%s():%d: mnl_socket_open error", __FUNCTION__, __LINE__);
		return -1;
	}

	sock = mnl_socket_get_fd(nl);

	if (mnl_socket_bind(nl, RTM_GETNEIGH, MNL_SOCKET_AUTOPID) < 0) {
		syslog(LOG_ERR, "%s():%d: mnl_socket_bind error", __FUNCTION__, __LINE__);
		return -1;
	}

	ev_io_init(io_handle.io, ntlk_cb, sock, EV_READ);
	ev_io_start(st_ev_loop, io_handle.io);

	net_event_enabled = 1;

	return 0;
}

int net_eventd_stop(void)
{
	struct ev_loop *st_ev_loop = get_loop();

	syslog(LOG_DEBUG, "%s():%d: net eventd stopped", __FUNCTION__, __LINE__);

	ev_io_stop(st_ev_loop, io_handle.io);
	mnl_socket_close(nl);

	if (io_handle.io)
		free(io_handle.io);

	net_event_enabled = 0;

	return 0;
}

int net_get_event_enabled(void)
{
	syslog(LOG_DEBUG, "%s():%d: net eventd is %d", __FUNCTION__, __LINE__, net_event_enabled);
	return net_event_enabled;
}

int net_strim_netface(char *name)
{
	char *ptr;

	if ((ptr = strstr(name, ":")) != NULL) {
		*ptr = '\0';
		return 1;
	}

	return 0;
}
