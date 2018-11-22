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

#ifndef _CONFIG_H_
#define _CONFIG_H_

#include "objects.h"

#define CONFIG_KEY_FARMS		"farms"
#define CONFIG_KEY_NAME			"name"
#define CONFIG_KEY_NEWNAME		"newname"
#define CONFIG_KEY_FQDN			"fqdn"
#define CONFIG_KEY_IFACE		"iface"
#define CONFIG_KEY_OFACE		"oface"
#define CONFIG_KEY_FAMILY		"family"
#define CONFIG_KEY_ETHADDR		"ether-addr"
#define CONFIG_KEY_VIRTADDR		"virtual-addr"
#define CONFIG_KEY_VIRTPORTS		"virtual-ports"
#define CONFIG_KEY_IPADDR		"ip-addr"
#define CONFIG_KEY_SRCADDR		"source-addr"
#define CONFIG_KEY_PORTS		"ports"
#define CONFIG_KEY_MODE			"mode"
#define CONFIG_KEY_PROTO		"protocol"
#define CONFIG_KEY_SCHED		"scheduler"
#define CONFIG_KEY_HELPER		"helper"
#define CONFIG_KEY_LOG			"log"
#define CONFIG_KEY_MARK			"mark"
#define CONFIG_KEY_STATE		"state"
#define CONFIG_KEY_BCKS			"backends"
#define CONFIG_KEY_WEIGHT		"weight"
#define CONFIG_KEY_PRIORITY		"priority"
#define CONFIG_KEY_ACTION		"action"

#define CONFIG_VALUE_FAMILY_IPV4	"ipv4"
#define CONFIG_VALUE_FAMILY_IPV6	"ipv6"
#define CONFIG_VALUE_FAMILY_INET	"inet"
#define CONFIG_VALUE_MODE_SNAT		"snat"
#define CONFIG_VALUE_MODE_DNAT		"dnat"
#define CONFIG_VALUE_MODE_DSR		"dsr"
#define CONFIG_VALUE_MODE_STLSDNAT	"stlsdnat"
#define CONFIG_VALUE_PROTO_TCP		"tcp"
#define CONFIG_VALUE_PROTO_UDP		"udp"
#define CONFIG_VALUE_PROTO_SCTP		"sctp"
#define CONFIG_VALUE_PROTO_ALL		"all"
#define CONFIG_VALUE_SCHED_RR		"rr"
#define CONFIG_VALUE_SCHED_WEIGHT	"weight"
#define CONFIG_VALUE_SCHED_HASH		"hash"
#define CONFIG_VALUE_SCHED_SYMHASH	"symhash"
#define CONFIG_VALUE_HELPER_NONE		"none"
#define CONFIG_VALUE_HELPER_AMANDA		"amanda"
#define CONFIG_VALUE_HELPER_FTP			"ftp"
#define CONFIG_VALUE_HELPER_H323		"h323"
#define CONFIG_VALUE_HELPER_IRC			"irc"
#define CONFIG_VALUE_HELPER_NETBIOSNS	"netbios-ns"
#define CONFIG_VALUE_HELPER_PPTP		"pptp"
#define CONFIG_VALUE_HELPER_SANE		"sane"
#define CONFIG_VALUE_HELPER_SIP			"sip"
#define CONFIG_VALUE_HELPER_SNMP		"snmp"
#define CONFIG_VALUE_HELPER_TFTP		"tftp"
#define CONFIG_VALUE_LOG_NONE			"none"
#define CONFIG_VALUE_LOG_INPUT			"input"
#define CONFIG_VALUE_LOG_FORWARD		"forward"
#define CONFIG_VALUE_LOG_OUTPUT			"output"
#define CONFIG_VALUE_STATE_UP		"up"
#define CONFIG_VALUE_STATE_DOWN		"down"
#define CONFIG_VALUE_STATE_OFF		"off"
#define CONFIG_VALUE_STATE_CONFERR	"config_error"
#define CONFIG_VALUE_ACTION_DELETE	"delete"
#define CONFIG_VALUE_ACTION_STOP	"stop"
#define CONFIG_VALUE_ACTION_START	"start"
#define CONFIG_VALUE_ACTION_RELOAD	"reload"
#define CONFIG_VALUE_ACTION_NONE	"none"

enum config_src {
	CONFIG_SRC_FILE,
	CONFIG_SRC_BUFFER,
};

struct config_pair {
	enum levels	level;
	enum keys	key;
	char		*str_value;
	int		int_value;
};

void config_pair_init(struct config_pair *c);
int config_file(const char *file);
int config_buffer(const char *buf);
int config_print_farms(char **buf, char *name);
int config_set_farm_action(const char *name, const char *value);
int config_set_backend_action(const char *fname, const char *bname, const char *value);
void config_print_response(char **buf, const char *message);

#endif /* _CONFIG_H_ */
