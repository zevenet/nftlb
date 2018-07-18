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

#ifndef _NETWORK_H_
#define _NETWORK_H_

#define ETH_HW_ADDR_LEN		6
#define ETH_HW_STR_LEN		18

int net_get_neigh_ether(unsigned char **dst_ethaddr, unsigned char *src_ethaddr, unsigned char family, char *src_ipaddr, char *dst_ipaddr, int outdev);
int net_get_local_ifidx_per_remote_host(char *dst_ipaddr, int *outdev);
int net_get_local_ifinfo(unsigned char **ether, const char *indev);
int net_get_local_ifname_per_vip(char *strvip, char *outdev);
int net_eventd_init(void);
int net_eventd_stop(void);
int net_get_event_enabled(void);

#endif /* _NETWORK_H_ */
