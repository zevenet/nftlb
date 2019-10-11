/*  Copyright (C) 2011-2015  P.D. Buchan (pdbuchan@yahoo.com)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _CHECKSUM_H_
#define _CHECKSUM_H_

#include <arpa/inet.h>

#define ETHER_HDRLEN			14
#define IP4_HDRLEN				20
#define IP6_HDRLEN				40
#define ICMP_HDRLEN				8
#define	ICMP_DATALEN			4

uint16_t checksum(uint16_t *addr, int len);
uint16_t icmp6_checksum(struct ip6_hdr iphdr, struct icmp6_hdr icmp6hdr, uint8_t *payload, int payloadlen);
uint16_t icmp4_checksum(struct icmp icmphdr, uint8_t *payload, int payloadlen);

#endif /* _CHECKSUM_H_ */
