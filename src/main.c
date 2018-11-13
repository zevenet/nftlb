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

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <unistd.h>

#include "config.h"
#include "objects.h"
#include "server.h"
#include "events.h"
#include "network.h"

#define NFTLB_SERVER_MODE		0
#define NFTLB_EXIT_MODE			1

#define NFTLB_LOGLEVEL_DEFAULT		LOG_NOTICE

static void print_usage(const char *prog_name)
{
	fprintf(stderr,
		"%s, nftables load balancer - Version %s\n"
		"(c) 2018 by Laura Garcia <laura.garcia@zevenet.com>\n"
		"Usage: %s\n"
		"  [ -h | --help ]			Show this help\n"
		"  [ -l <LEVEL> | --log <LEVEL> ]	Set the syslog level\n"
		"  [ -c <FILE> | --config <FILE> ]	Launch with the given configuration file\n"
		"  [ -k <KEY> | --key <KEY> ]		Set the authentication key, otherwise it'll be generated\n"
		"  [ -e | --exit ]			Don't execute the server\n"
		"  [ -6 | --ipv6 ]			Enable IPv6 listening port\n"
		"  [ -H <HOST> | --host <HOST> ]		Set the host for the listening port\n"
		"  [ -P <PORT> | --port <PORT> ]		Set the port for the listening port\n"
		, prog_name, VERSION, prog_name);
}

static const struct option options[] = {
	{ .name = "help",	.has_arg = 0,	.val = 'h' },
	{ .name = "log",	.has_arg = 1,	.val = 'l' },
	{ .name = "config",	.has_arg = 1,	.val = 'c' },
	{ .name = "key",	.has_arg = 1,	.val = 'k' },
	{ .name = "exit",	.has_arg = 0,	.val = 'e' },
	{ .name = "ipv6",	.has_arg = 0,	.val = '6' },
	{ .name = "host",	.has_arg = 1,	.val = 'H' },
	{ .name = "port",	.has_arg = 1,	.val = 'P' },
	{ NULL },
};

static void nftlb_sighandler(int signo)
{
	syslog(LOG_INFO, "shuting down %s, bye", PACKAGE);
	server_fini();
	exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
	int		mode = NFTLB_SERVER_MODE;
	int		c;
	int		loglevel = NFTLB_LOGLEVEL_DEFAULT;
	const char	*config = NULL;

	while ((c = getopt_long(argc, argv, "hl:c:k:e6H:P:", options, NULL)) != -1) {
		switch (c) {
		case 'h':
			print_usage(argv[0]);
			return EXIT_SUCCESS;
		case 'l':
			loglevel = atoi(optarg);
			break;
		case 'c':
			config = optarg;
			break;
		case 'k':
			server_set_key(optarg);
			break;
		case 'e':
			mode = NFTLB_EXIT_MODE;
			break;
		case '6':
			server_set_ipv6();
			break;
		case 'H':
			server_set_host(optarg);
			break;
		case 'P':
			server_set_port(atoi(optarg));
			break;
		default:
			fprintf(stderr, "Unknown option -%c\n", optopt);
			syslog(LOG_ERR, "Unknown option -%c", optopt);
			return EXIT_FAILURE;
		}
	}

	if (signal(SIGINT, nftlb_sighandler) == SIG_ERR ||
	    signal(SIGTERM, nftlb_sighandler) == SIG_ERR ||
	    signal(SIGPIPE, SIG_IGN) == SIG_ERR)
		return EXIT_FAILURE;

	objects_init();

	loop_init();

	if (config && config_file(config) != 0)
		return EXIT_FAILURE;

	if (loglevel > NFTLB_LOGLEVEL_DEFAULT)
		obj_print();

	obj_rulerize();

	if (mode == NFTLB_EXIT_MODE)
		return EXIT_SUCCESS;

	if (server_init() != 0) {
		fprintf(stderr, "Cannot start server-ev: %s\n", strerror(errno));
		return EXIT_FAILURE;
	}

	loop_run();

	return EXIT_SUCCESS;
}
