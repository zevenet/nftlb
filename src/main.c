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
#include <errno.h>
#include <unistd.h>
#include <execinfo.h>

#include "config.h"
#include "objects.h"
#include "server.h"
#include "events.h"
#include "network.h"
#include "nft.h"
#include "tools.h"

#define NFTLB_SERVER_MODE		0
#define NFTLB_FG_MODE			0
#define NFTLB_BG_MODE			1
#define NFTLB_EXIT_MODE			1
#define NFTLB_NFT_SERIALIZE		0

unsigned int serialize = NFTLB_NFT_SERIALIZE;
int masquerade_mark = NFTLB_MASQUERADE_MARK_DEFAULT;

static void print_usage(const char *prog_name)
{
	fprintf(stderr,
		"%s, nftables load balancer - Version %s\n"
		"(c) 2018 by Laura Garcia <laura.garcia@zevenet.com>\n"
		"Usage: %s\n"
		"  [ -h | --help ]			Show this help\n"
		"  [ -l <LEVEL> | --log <LEVEL> ]	Set the syslog level\n"
		"  [ -L <OUTPUT> | --log-output <OUTPUT> ]	Set the daemon logs output\n"
		"  [ -c <FILE> | --config <FILE> ]	Launch with the given configuration file\n"
		"  [ -k <KEY> | --key <KEY> ]		Set the authentication key, otherwise it'll be generated\n"
		"  [ -e | --exit ]			Don't execute the server\n"
		"  [ -d | --daemon ]		Run in daemon mode\n"
		"  [ -6 | --ipv6 ]			Enable IPv6 listening port\n"
		"  [ -H <HOST> | --host <HOST> ]		Set the host for the listening port\n"
		"  [ -P <PORT> | --port <PORT> ]		Set the port for the listening port\n"
		"  [ -S | --serial ]			Serialize nft commands\n"
		"  [ -m | --masquerade-mark ]			Set masquerade mark in hex\n"
		, prog_name, VERSION, prog_name);
}

static const struct option options[] = {
	{ .name = "help",	.has_arg = 0,	.val = 'h' },
	{ .name = "log",	.has_arg = 1,	.val = 'l' },
	{ .name = "log-output",	.has_arg = 1,	.val = 'L' },
	{ .name = "config",	.has_arg = 1,	.val = 'c' },
	{ .name = "key",	.has_arg = 1,	.val = 'k' },
	{ .name = "exit",	.has_arg = 0,	.val = 'e' },
	{ .name = "daemon",	.has_arg = 0,	.val = 'd' },
	{ .name = "ipv6",	.has_arg = 0,	.val = '6' },
	{ .name = "host",	.has_arg = 1,	.val = 'H' },
	{ .name = "port",	.has_arg = 1,	.val = 'P' },
	{ .name = "serial",	.has_arg = 0,	.val = 'S' },
	{ .name = "masquerade-mark",	.has_arg = 1,	.val = 'm' },
	{ NULL },
};

static void nftlb_sighandler(int signo)
{
	tools_printlog(LOG_INFO, "shutting down %s, bye", PACKAGE);
	server_fini();
	exit(EXIT_SUCCESS);
}

static void nftlb_trace() {
	void *buffer[255];
	char **str;
	int i;
	const int calls = backtrace(buffer, sizeof(buffer) / sizeof(void *));

	tools_printlog(LOG_ERR, "SIGSEGV received!");
	backtrace_symbols_fd(buffer, calls, 1);

	str = backtrace_symbols(buffer, calls);
	if (!str) {
		tools_printlog(LOG_ERR, "No backtrace strings found!");
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < calls; i++)
		tools_printlog(LOG_ERR, "%s", str[i]);
	free(str);

	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	int		c;
	int		mode = NFTLB_SERVER_MODE;
	int		run_mode = NFTLB_FG_MODE;
	int		loglevel = NFTLB_LOG_LEVEL_DEFAULT;
	int		logoutput = NFTLB_LOG_OUTPUT_DEFAULT;
	const char	*config = NULL;

	while ((c = getopt_long(argc, argv, "hl:L:c:k:ed6H:P:Sm:", options, NULL)) != -1) {
		switch (c) {
		case 'h':
			print_usage(argv[0]);
			return EXIT_SUCCESS;
		case 'l':
			loglevel = atoi(optarg);
			break;
		case 'L':
			logoutput = atoi(optarg);
			break;
		case 'c':
			config = optarg;
			break;
		case 'k':
			server_set_key(optarg);
			sprintf(optarg, "%*s", (int)strlen(optarg) - 1, " ");
			break;
		case 'e':
			mode = NFTLB_EXIT_MODE;
			break;
		case 'd':
			run_mode = NFTLB_BG_MODE;
			break;
		case '6':
			server_set_ipv6();
			break;
		case 'H':
			server_set_host(optarg);
			break;
		case 'P':
			server_set_port(optarg);
			break;
		case 'S':
			serialize = 1;
			break;
		case 'm':
			masquerade_mark = (int)strtol(optarg, NULL, 16);
			break;
		default:
			tools_printlog(LOG_ERR, "Unknown option -%c", optopt);
			return EXIT_FAILURE;
		}
	}

	if (signal(SIGINT, nftlb_sighandler) == SIG_ERR ||
	    signal(SIGTERM, nftlb_sighandler) == SIG_ERR ||
	    signal(SIGPIPE, SIG_IGN) == SIG_ERR ||
	    signal(SIGSEGV, nftlb_trace) == SIG_ERR) {
		tools_printlog(LOG_ERR, "Error assigning signals");
		return EXIT_FAILURE;
	}

	tools_log_set_level(loglevel);
	tools_log_set_output(logoutput);

	if (nft_check_tables())
		nft_reset();

	objects_init();

	loop_init();

	if (config && config_file(config) != 0)
		return EXIT_FAILURE;

	if (loglevel > NFTLB_LOG_LEVEL_DEFAULT)
		obj_print();

	obj_rulerize(OBJ_START);

	if (mode == NFTLB_EXIT_MODE)
		return EXIT_SUCCESS;

	if (server_init() != 0) {
		tools_printlog(LOG_ERR, "Cannot start server-ev: %s\n", strerror(errno));
		return EXIT_FAILURE;
	}

	if ( run_mode ){
		switch (fork()) {
			case 0:
				break;
			case -1:
				tools_printlog(LOG_ERR, "Daemon mode aborted: %s", strerror(errno));
				return EXIT_FAILURE;
			default:
				return EXIT_SUCCESS;
		}
	}

	loop_run();

	return EXIT_SUCCESS;
}
