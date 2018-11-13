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
#include <sys/ioctl.h>
#include <netinet/ip_icmp.h>
#include <linux/rtnetlink.h>
#include <libmnl/libmnl.h>
#include <arpa/inet.h>
#include <linux/if_arp.h>
#include <ev.h>

#include "network.h"
#include "events.h"
#include "farms.h"

#define IP_ADDR_LEN		4
#define IP6_ADDR_LEN		16
#define ICMP_PROTO		1
#define ICMP_PACKETSIZE		64

#define ARP_TABLE_RETRY_SLEEP	1000

#define GET_INET_LEN(family)	((family == AF_INET6) ? IP6_ADDR_LEN : IP_ADDR_LEN)

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
	struct icmphdr hdr;
	char data[ICMP_PACKETSIZE - sizeof(struct icmphdr)];
};


struct ntl_data {
	unsigned char	family;
	struct in6_addr	*src_ipaddr;
	unsigned char	src_ethaddr[ETH_HW_ADDR_LEN];
	struct in6_addr	*dst_ipaddr;
	unsigned char	dst_ethaddr[ETH_HW_ADDR_LEN];
	int		oifidx;
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

static int send_ping(void *data)
{
	struct ntl_data *sdata = data;
	struct sockaddr_in remote_addr;
	struct icmp_packet pckt;
	ssize_t ret = 0;
	int sock;

	syslog(LOG_DEBUG, "%s():%d: sending ping", __FUNCTION__, __LINE__);

	bzero(&remote_addr, sizeof(remote_addr));
	remote_addr.sin_family = sdata->family;
	remote_addr.sin_port = 0;
	memcpy(&remote_addr.sin_addr.s_addr, &sdata->dst_ipaddr->s6_addr, GET_INET_LEN(sdata->family) * sizeof(unsigned char));

	sock = socket(PF_INET, SOCK_RAW, ICMP_PROTO);
	if (sock < 0) {
		syslog(LOG_ERR, "%s():%d: open socket error", __FUNCTION__, __LINE__);
		ret = -1;
		goto out;
	}

	bzero(&pckt, sizeof(pckt));
	pckt.hdr.type = ICMP_ECHO;
	pckt.hdr.un.echo.id = 1;
	bzero(pckt.data, ICMP_PACKETSIZE - sizeof(struct icmphdr));
	pckt.hdr.un.echo.sequence = 1;

	if (sendto(sock, &pckt, sizeof(pckt), 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr)) <= 0) {
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

	syslog(LOG_DEBUG, "%s():%d: getting ethernet address destination", __FUNCTION__, __LINE__);

	mnl_attr_parse(nlh, sizeof(*ndm), data_attr_neigh_cb, tb);

	if (!tb[NDA_DST])
		return MNL_CB_OK;

	ipaddr = mnl_attr_get_payload(tb[NDA_DST]);

	inet_ntop(AF_INET, ipaddr, out, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET, sdata->dst_ipaddr, out1, INET6_ADDRSTRLEN);

	if (memcmp(ipaddr, sdata->dst_ipaddr, GET_INET_LEN(sdata->family)) == 0 &&
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

	switch(type) {
	case RTA_TABLE:
	case RTA_DST:
	case RTA_SRC:
	case RTA_OIF:
	case RTA_FLOW:
	case RTA_PREFSRC:
	case RTA_GATEWAY:
	case RTA_PRIORITY:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			syslog(LOG_ERR, "%s():%d: mnl_attr_validate error", __FUNCTION__, __LINE__);
			return MNL_CB_ERROR;
		}
		break;
        case RTA_METRICS:
                if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0) {
			syslog(LOG_ERR, "%s():%d: mnl_attr_validate error", __FUNCTION__, __LINE__);
                        return MNL_CB_ERROR;
                }
                break;
	}

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

	syslog(LOG_DEBUG, "%s():%d: source mac address %s source ip address %s destination ip address %s", __FUNCTION__, __LINE__, src_ethaddr, src_ipaddr, dst_ipaddr);

	ntl.buf = (char *) malloc(MNL_SOCKET_BUFFER_SIZE);

	ntl.nlh = mnl_nlmsg_put_header(ntl.buf);
	ntl.nlh->nlmsg_type = RTM_GETNEIGH;
	ntl.nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	ntl.nlh->nlmsg_seq = time(NULL);

	ntl.rt = mnl_nlmsg_put_extra_header(ntl.nlh, sizeof(struct rtgenmsg));
	ntl.rt->rtgen_family = AF_INET;

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

	if (family != 0)
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
		syslog(LOG_DEBUG, "%s():%d: not found, send ping for %s", __FUNCTION__, __LINE__, dst_ipaddr);

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
	struct sockaddr_in addr;
	int ret = 0;

	syslog(LOG_DEBUG, "%s():%d: dst ip address is %s", __FUNCTION__, __LINE__, dst_ipaddr);

	ntl.buf = (char *) malloc(MNL_SOCKET_BUFFER_SIZE);

	ntl.nlh = mnl_nlmsg_put_header(ntl.buf);
	ntl.nlh->nlmsg_type = RTM_GETROUTE;
	ntl.nlh->nlmsg_flags = NLM_F_REQUEST;
	ntl.nlh->nlmsg_seq = time(NULL);

	ntl.rtm = mnl_nlmsg_put_extra_header(ntl.nlh, sizeof(struct rtmsg));
	ntl.rtm->rtm_family = AF_INET;
	ntl.rtm->rtm_dst_len = 32;
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
	data->family = ntl.rtm->rtm_family;

	if (!inet_pton(AF_INET, dst_ipaddr, &(addr.sin_addr))) {
		syslog(LOG_ERR, "%s():%d: network translation error for %s", __FUNCTION__, __LINE__, dst_ipaddr);
		return -1;
	}

	mnl_attr_put(ntl.nlh, RTA_DST, sizeof(uint32_t), &addr.sin_addr.s_addr);

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
	int ret = -1;
	struct sockaddr_storage addr;
	struct ifconf ifc;
	struct ifreq *ifr;
	char buf[16384];
	int sd = 0;
	int i, found = 0;
	size_t len;
	struct sockaddr_in *ipaddr;

	if (strcmp(strvip, "") == 0) {
		syslog(LOG_ERR, "%s():%d: vip is not set yet", __FUNCTION__, __LINE__);
		goto out;
	}

	syslog(LOG_DEBUG, "%s():%d: netlink get local interface name for %s", __FUNCTION__, __LINE__, strvip);

	inet_aton(strvip, &((struct sockaddr_in *) &addr)->sin_addr);

	sd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);

	if (sd <= 0) {
		syslog(LOG_ERR, "%s():%d: open socket error", __FUNCTION__, __LINE__);
		goto out;
	}

	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = buf;

	if (ioctl(sd, SIOCGIFCONF, &ifc) == -1) {
		syslog(LOG_ERR, "%s():%d: ioctl SIOCGIFCONF error", __FUNCTION__, __LINE__);
		goto out;
	}

	ifr = ifc.ifc_req;

	for(i = 0; i < ifc.ifc_len && !found;) {
		len = sizeof(*ifr);
		ipaddr = (struct sockaddr_in*)&((*ifr).ifr_addr);

		if (ipaddr->sin_addr.s_addr == ((struct sockaddr_in *) &addr)->sin_addr.s_addr) {
			found = 1;
			strcpy(outdev, ifr->ifr_name);
			ret = 0;
		}

		ifr = (struct ifreq*)((char*)ifr+len);
		i += len;
	}

	syslog(LOG_DEBUG, "%s():%d: netlink get local interface name is %s", __FUNCTION__, __LINE__, outdev);

out:
	if (sd > 0)
		close(sd);

	return ret;
}

static int data_getev_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[NDA_MAX + 1] = {};
	struct ndmsg *ndm = mnl_nlmsg_get_payload(nlh);
	struct in6_addr *ipaddr;
	char str_ipaddr[INET6_ADDRSTRLEN];
	void *ethaddr;
	unsigned char dst_ethaddr[ETH_HW_ADDR_LEN];
	char streth[ETH_HW_STR_LEN] = {};

	syslog(LOG_DEBUG, "%s():%d: netlink read new info", __FUNCTION__, __LINE__);

	if (nlh->nlmsg_type != RTM_NEWNEIGH)
		return MNL_CB_STOP;

	mnl_attr_parse(nlh, sizeof(*ndm), data_attr_neigh_cb, tb);

	if (tb[NDA_DST]) {
		ipaddr = mnl_attr_get_payload(tb[NDA_DST]);
		inet_ntop(AF_INET, ipaddr, str_ipaddr, INET6_ADDRSTRLEN);
	}

	if (tb[NDA_LLADDR]) {
		ethaddr = mnl_attr_get_payload(tb[NDA_LLADDR]);
		memcpy(dst_ethaddr, ethaddr, ETH_HW_ADDR_LEN);

		sprintf(streth, "%02x:%02x:%02x:%02x:%02x:%02x", dst_ethaddr[0], dst_ethaddr[1],
			dst_ethaddr[2], dst_ethaddr[3], dst_ethaddr[4], dst_ethaddr[5]);

		if ((ndm->ndm_state & NUD_REACHABLE) || (ndm->ndm_state & NUD_PERMANENT))
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
	free(io_handle.io);

	net_event_enabled = 0;

	return 0;
}

int net_get_event_enabled(void)
{
	syslog(LOG_DEBUG, "%s():%d: net eventd is %d", __FUNCTION__, __LINE__, net_event_enabled);
	return net_event_enabled;
}


