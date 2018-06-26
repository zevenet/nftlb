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


static int send_ping(void *data)
{
	struct ntl_data *sdata = data;
	struct sockaddr_in remote_addr;
	struct icmp_packet pckt;
	ssize_t ret = EXIT_SUCCESS;
	int sock;

	syslog(LOG_DEBUG, "%s():%d: sending ping", __FUNCTION__, __LINE__);

	bzero(&remote_addr, sizeof(remote_addr));
	remote_addr.sin_family = sdata->family;
	remote_addr.sin_port = 0;
	memcpy(&remote_addr.sin_addr.s_addr, &sdata->dst_ipaddr->s6_addr, GET_INET_LEN(sdata->family) * sizeof(unsigned char));

	sock = socket(PF_INET, SOCK_RAW, ICMP_PROTO);
	if (sock < 0) {
		syslog(LOG_ERR, "%s():%d: open socket error", __FUNCTION__, __LINE__);
		ret = EXIT_FAILURE;
		goto out;
	}

	bzero(&pckt, sizeof(pckt));
	pckt.hdr.type = ICMP_ECHO;
	pckt.hdr.un.echo.id = 1;
	bzero(pckt.data, ICMP_PACKETSIZE - sizeof(struct icmphdr));
	pckt.hdr.un.echo.sequence = 1;

	if (sendto(sock, &pckt, sizeof(pckt), 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr)) <= 0) {
		syslog(LOG_ERR, "%s():%d: sendto error", __FUNCTION__, __LINE__);
		ret = EXIT_FAILURE;
	}

out:
	if (ret && sock > 0) {
		syslog(LOG_DEBUG, "%s():%d: cleanup socket", __FUNCTION__, __LINE__);
		close(sock);
	}

	return ret;
}


static int data_attr_cb(const struct nlattr *attr, void *data)
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


static int data_getdst_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[NDA_MAX + 1] = {};
	struct ndmsg *ndm = mnl_nlmsg_get_payload(nlh);
	struct in6_addr *ipaddr;
	void *ethaddr;
	char out[INET6_ADDRSTRLEN];
	char out1[INET6_ADDRSTRLEN];
	struct ntl_data *sdata = data;

	syslog(LOG_DEBUG, "%s():%d: getting destination ethaddr", __FUNCTION__, __LINE__);

	mnl_attr_parse(nlh, sizeof(*ndm), data_attr_cb, tb);

	if (!tb[NDA_DST])
		return MNL_CB_OK;

	ipaddr = mnl_attr_get_payload(tb[NDA_DST]);

	inet_ntop(AF_INET, ipaddr, out, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET, sdata->dst_ipaddr, out1, INET6_ADDRSTRLEN);

	if (memcmp(ipaddr, sdata->dst_ipaddr, GET_INET_LEN(sdata->family)) == 0 &&
	    ((ndm->ndm_state & NUD_REACHABLE) || (ndm->ndm_state & NUD_PERMANENT) || (ndm->ndm_state & NUD_STALE))) {
		mnl_attr_parse(nlh, sizeof(*ndm), data_attr_cb, tb);
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


static int ntl_request(void *data)
{
	struct mnl_socket *nl;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct rtgenmsg *rt;
	int ret, out = EXIT_SUCCESS;
	unsigned int seq, portid;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = RTM_GETNEIGH;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq = seq = time(NULL);

	rt = mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtgenmsg));
	rt->rtgen_family = AF_INET;

	nl = mnl_socket_open(NETLINK_ROUTE);
	if (nl == NULL) {
		syslog(LOG_ERR, "%s():%d: mnl_socket_open error", __FUNCTION__, __LINE__);
		return EXIT_FAILURE;
	}

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		syslog(LOG_ERR, "%s():%d: mnl_socket_bind error", __FUNCTION__, __LINE__);
		return EXIT_FAILURE;
	}
	portid = mnl_socket_get_portid(nl);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		syslog(LOG_ERR, "%s():%d: mnl_socket_sendto error", __FUNCTION__, __LINE__);
		return EXIT_FAILURE;
	}

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, seq, portid, data_getdst_cb, data);

		if (ret <= MNL_CB_STOP) {
			out = EXIT_SUCCESS | out;
			goto end;
		} else {
			out = EXIT_FAILURE;
		}

		ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	}

	if (ret == -1) {
		syslog(LOG_ERR, "%s():%d: mnl_socket_recvfrom error", __FUNCTION__, __LINE__);
		ret = EXIT_FAILURE;
	}

end:
	mnl_socket_close(nl);

	return out;
}


int net_get_neigh_ether(unsigned char **dst_ethaddr, unsigned char *src_ethaddr, unsigned char family, char *src_ipaddr, char *dst_ipaddr, int outdev)
{
	int ret = EXIT_SUCCESS;

	syslog(LOG_DEBUG, "%s():%d: source ether is %02x:%02x:%02x:%02x:%02x:%02x",
	       __FUNCTION__, __LINE__, src_ethaddr[0], src_ethaddr[1], src_ethaddr[2],
	       src_ethaddr[3], src_ethaddr[4], src_ethaddr[5]);

	struct ntl_data *data = (struct ntl_data *)calloc(1, sizeof(struct ntl_data));
	if (!data) {
		syslog(LOG_ERR, "%s():%d: memory allocation error", __FUNCTION__, __LINE__);
		return EXIT_FAILURE;
	}

	data->dst_ipaddr = (struct in6_addr *)calloc(1, sizeof(struct in6_addr));
	if (!data->dst_ipaddr){
		syslog(LOG_ERR, "%s():%d: memory allocation error", __FUNCTION__, __LINE__);
		return EXIT_FAILURE;
	}

	if (family != 0)
		data->family = AF_INET6;
	else
		data->family = AF_INET;

	if (inet_pton(data->family, dst_ipaddr, data->dst_ipaddr) <= 0) {
		syslog(LOG_ERR, "%s():%d: network translation error for %s", __FUNCTION__, __LINE__, dst_ipaddr);
		return EXIT_FAILURE;
	}

	data->oifidx = outdev;

	ret = ntl_request(data);

	if (ret != EXIT_SUCCESS) {
		syslog(LOG_DEBUG, "%s():%d: not found, send ping for %s", __FUNCTION__, __LINE__, dst_ipaddr);

		data->src_ipaddr = (struct in6_addr *)calloc(1, sizeof(struct in6_addr));
		if (!data->src_ipaddr){
			syslog(LOG_ERR, "%s():%d: memory allocation error", __FUNCTION__, __LINE__);
			return EXIT_FAILURE;
		}

		if (inet_pton(data->family, src_ipaddr, data->src_ipaddr) <= 0) {
			syslog(LOG_ERR, "%s():%d: network translation error for %s", __FUNCTION__, __LINE__, src_ipaddr);
			return EXIT_FAILURE;
		}

		memcpy(data->src_ethaddr, src_ethaddr, ETH_HW_ADDR_LEN);

		send_ping(data);
		/* second attempt */
		usleep(ARP_TABLE_RETRY_SLEEP);
		ret = ntl_request(data);

		free(data->src_ipaddr);
	}

	memcpy(dst_ethaddr, data->dst_ethaddr, ETH_HW_ADDR_LEN);
	free(data->dst_ipaddr);
	free(data);

	return ret;
}


int net_get_local_ifinfo(unsigned char **ether, int *ifindex, const char *indev)
{
	int ret = EXIT_FAILURE;
	struct ifreq ifr;
	int sd;

	syslog(LOG_DEBUG, "%s():%d: netlink get local interface info for %s", __FUNCTION__, __LINE__, indev);

	sd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);

	if (sd <= 0) {
		syslog(LOG_ERR, "%s():%d: open socket error", __FUNCTION__, __LINE__);
		goto out;
	}

	if (strlen(indev) > (IFNAMSIZ - 1)) {
		syslog(LOG_ERR, "%s():%d: %ld chars too long interface name, max = %i", __FUNCTION__, __LINE__, strlen(indev), IFNAMSIZ - 1);
		goto out;
	}

	strcpy(ifr.ifr_name, indev);

	if (ioctl(sd, SIOCGIFINDEX, &ifr) == -1) {
		syslog(LOG_ERR, "%s():%d: ioctl SIOCGIFINDEX error", __FUNCTION__, __LINE__);
		goto out;
	}

	*ifindex = ifr.ifr_ifindex;

	if (ioctl(sd, SIOCGIFHWADDR, &ifr) == -1) {
		syslog(LOG_ERR, "%s():%d: ioctl SIOCGIFHWADDR error", __FUNCTION__, __LINE__);
		goto out;
	}

	memcpy(ether, ifr.ifr_hwaddr.sa_data, ETH_HW_ADDR_LEN * sizeof(unsigned char));

	ret = EXIT_SUCCESS;
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

	mnl_attr_parse(nlh, sizeof(*ndm), data_attr_cb, tb);

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
			out = EXIT_SUCCESS | out;
			return;
		} else {
			out = EXIT_FAILURE;
		}
		ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	}

	if (ret == -1) {
		syslog(LOG_ERR, "%s():%d: netlink error", __FUNCTION__, __LINE__);
		ret = EXIT_FAILURE;
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
		return EXIT_FAILURE;
	}

	sock = mnl_socket_get_fd(nl);

	if (mnl_socket_bind(nl, RTM_GETNEIGH, MNL_SOCKET_AUTOPID) < 0) {
		syslog(LOG_ERR, "%s():%d: mnl_socket_bind error", __FUNCTION__, __LINE__);
		return EXIT_FAILURE;
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


