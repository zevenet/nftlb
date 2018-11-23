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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ev.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "server.h"
#include "config.h"
#include "nft.h"
#include "events.h"

#define SRV_MAX_BUF			40960
#define SRV_MAX_HEADER			300
#define SRV_MAX_IDENT			200
#define SRV_KEY_LENGTH			16

#define SRV_PORT_DEF			5555

#define STR_GET_ACTION			"GET"
#define STR_POST_ACTION			"POST"
#define STR_PUT_ACTION			"PUT"
#define STR_DELETE_ACTION		"DELETE"

#define HTTP_PROTO			"HTTP/1.1 "
#define HTTP_LINE_END			"\r\n"
#define HTTP_HEADER_CONTENTLEN		"Content-Length: "
#define HTTP_HEADER_KEY			"Key: "

extern struct ev_io *srv_accept;

enum ws_methods {
	WS_GET_ACTION,
	WS_POST_ACTION,
	WS_PUT_ACTION,
	WS_DELETE_ACTION,
};

enum ws_responses {
	WS_HTTP_500,
	WS_HTTP_401,
	WS_HTTP_200,
};

struct nftlb_http_state {
	enum ws_methods		method;
	char			uri[SRV_MAX_IDENT];
	char			*body;
	enum ws_responses	status_code;
	char			*body_response;
};

static const char *ws_str_responses[] = {
	HTTP_PROTO "500 Internal Server Error" HTTP_LINE_END,
	HTTP_PROTO "401 Unauthorized" HTTP_LINE_END,
	HTTP_PROTO "200 OK" HTTP_LINE_END,
};

struct nftlb_server {
	int			clients;
	char			*key;
	int			family;
	char			*host;
	int			port;
	int			sd;
};

static struct nftlb_server nftserver = {
	.family	= AF_INET,
	.host	= NULL,
	.port	= SRV_PORT_DEF,
};

static int auth_key(const char *recvkey)
{
	return (strcmp(nftserver.key, recvkey) == 0);
}

static int get_request(char *buf, struct nftlb_http_state *state)
{
	char method[SRV_MAX_IDENT] = {0};
	char strkey[SRV_MAX_IDENT] = {0};
	char *ptr;

	if ((ptr = strstr(buf, "Key: ")) == NULL) {
		state->status_code = WS_HTTP_401;
		return -1;
	}

	sscanf(ptr, "Key: %199[^\r\n]", strkey);

	if (!auth_key(strkey)) {
		state->status_code = WS_HTTP_401;
		return -1;
	}

	sscanf(buf, "%199[^ ] %199[^ ] ", method, state->uri);

	if (strncmp(method, STR_GET_ACTION, 3) == 0) {
		state->method = WS_GET_ACTION;
	} else if (strncmp(method, STR_POST_ACTION, 4) == 0) {
		state->method = WS_POST_ACTION;
	} else if (strncmp(method, STR_PUT_ACTION, 5) == 0) {
		state->method = WS_PUT_ACTION;
	} else if (strncmp(method, STR_DELETE_ACTION, 6) == 0) {
		state->method = WS_DELETE_ACTION;
	} else {
		state->status_code = WS_HTTP_500;
		return -1;
	}

	if (state->method != WS_POST_ACTION &&
	    state->method != WS_PUT_ACTION)
		return 0;

	state->body = strstr(buf, "\r\n\r\n");
	if (state->body)
		state->body += 4;

	return 0;
}

static int send_get_response(struct nftlb_http_state *state)
{
	char farm[SRV_MAX_IDENT] = {0};
	char farms[SRV_MAX_IDENT] = {0};

	sscanf(state->uri, "/%199[^/]/%199[^/\n]", farms, farm);

	if (strcmp(farms, CONFIG_KEY_FARMS) != 0) {
		state->status_code = WS_HTTP_500;
		return -1;
	}

	if (config_print_farms(&state->body_response, farm) == 0) {
		state->status_code = WS_HTTP_200;
		return 0;
	}

	state->status_code = WS_HTTP_500;
	return -1;
}

static int send_delete_response(struct nftlb_http_state *state)
{
	char farm[SRV_MAX_IDENT] = {0};
	char bck[SRV_MAX_IDENT] = {0};
	char farms[SRV_MAX_IDENT] = {0};
	char bcks[SRV_MAX_IDENT] = {0};
	int ret;

	sscanf(state->uri, "/%199[^/]/%199[^/]/%199[^/]/%199[^\n]",
	       farms, farm, bcks, bck);

	if (strcmp(farms, CONFIG_KEY_FARMS) != 0) {
		state->status_code = WS_HTTP_500;
		return -1;
	}

	state->body_response = malloc(SRV_MAX_BUF);
	if (!state->body_response) {
		state->status_code = WS_HTTP_500;
		return -1;
	}

	if (strcmp(bcks,CONFIG_KEY_BCKS) == 0) {
		ret = config_set_backend_action(farm, bck, CONFIG_VALUE_ACTION_DELETE);
		if (ret != 0) {
			config_print_response(&state->body_response,
					      "error deleting backend");
			goto delete_end;
		}
		ret = config_set_farm_action(farm, CONFIG_VALUE_ACTION_RELOAD);
		if (ret != 0) {
			config_print_response(&state->body_response,
					      "error reloading farm");
			goto delete_end;
		}
		ret = obj_rulerize();
		if (ret != 0) {
			config_print_response(&state->body_response,
					      "error generating rules");
			goto delete_end;
		}
	} else {
		ret = config_set_farm_action(farm, CONFIG_VALUE_ACTION_STOP);
		if (ret != 0) {
			config_print_response(&state->body_response,
					      "error stopping farm");
			goto delete_end;
		}
		ret = obj_rulerize();
		if (ret != 0) {
			config_print_response(&state->body_response,
					      "error generating rules");
			goto delete_end;
		}
		config_set_farm_action(farm, CONFIG_VALUE_ACTION_DELETE);
		if (ret != 0) {
			config_print_response(&state->body_response,
					      "error deleting farm");
			goto delete_end;
		}
	}

	config_print_response(&state->body_response, "success");

delete_end:
	state->status_code = WS_HTTP_200;
	return 0;
}

static int send_post_response(struct nftlb_http_state *state)
{
	if (strncmp(state->uri, "/farms", 6) != 0) {
		state->status_code = WS_HTTP_500;
		return -1;
	}

	state->body_response = malloc(SRV_MAX_IDENT);
	if (!state->body_response) {
		state->status_code = WS_HTTP_500;
		return -1;
	}

	if (config_buffer(state->body) != 0) {
		config_print_response(&state->body_response,
				      "error parsing buffer");
		goto post_end;
	}

	if (obj_rulerize() != 0) {
		config_print_response(&state->body_response,
				      "error generating rules");
		goto post_end;
	}

	config_print_response(&state->body_response, "success");

post_end:
	state->status_code = WS_HTTP_200;
	return 0;
}

static int send_response(struct nftlb_http_state *state)
{
	switch (state->method) {
	case WS_GET_ACTION:
		return send_get_response(state);
	case WS_POST_ACTION:
	case WS_PUT_ACTION:
		return send_post_response(state);
	case WS_DELETE_ACTION:
		return send_delete_response(state);
	default:
		return -1;
	}
}

/* If client doesn't send us anything in 30 seconds, close connection. */
#define NFTLB_CLIENT_TIMEOUT	30

struct nftlb_client {
	struct ev_io		io;
	struct ev_timer		timer;
	struct sockaddr_in	addr;
};

static void nftlb_client_release(struct ev_loop *loop, struct nftlb_client *cli)
{
	ev_io_stop(loop, &cli->io);
	close(cli->io.fd);
	free(cli);
}

static void nftlb_http_send_response(struct ev_io *io,
				     struct nftlb_http_state *state, int size)
{
	char response[SRV_MAX_HEADER];

	sprintf(response, "%s%s%d%s%s", ws_str_responses[state->status_code],
		HTTP_HEADER_CONTENTLEN, size,
		HTTP_LINE_END, HTTP_LINE_END);
	send(io->fd, response, strlen(response), 0);
}

static void nftlb_read_cb(struct ev_loop *loop, struct ev_io *io, int revents)
{
	char buffer[SRV_MAX_BUF] = {0};
	struct nftlb_http_state state;
	struct nftlb_client *cli;
	ssize_t size;

	if (EV_ERROR & revents) {
		syslog(LOG_ERR, "Server got invalid event from client read");
		return;
	}
	cli = container_of(io, struct nftlb_client, io);

	size = recv(io->fd, buffer, SRV_MAX_BUF, 0);
	if (size < 0)
		return;
	if (size == 0) {
		syslog(LOG_DEBUG, "connection closed by client %s:%hu\n",
		       inet_ntoa(cli->addr.sin_addr), ntohs(cli->addr.sin_port));
		goto end;
	}

	if (get_request(buffer, &state) < 0) {
		nftlb_http_send_response(io, &state, 0);
		goto end;
	}

	if (send_response(&state) < 0) {
		nftlb_http_send_response(io, &state, 0);
		goto end;
	}

	nftlb_http_send_response(io, &state, strlen(state.body_response));
	send(io->fd, state.body_response, strlen(state.body_response), 0);

	syslog(LOG_DEBUG, "connection closed by server %s:%hu\n",
	       inet_ntoa(cli->addr.sin_addr), ntohs(cli->addr.sin_port));
end:
	bzero(buffer, size);
	free(state.body_response);

	ev_timer_stop(loop, &cli->timer);
	nftlb_client_release(loop, cli);

	syslog(LOG_DEBUG, "%d client(s) connected", --nftserver.clients);
	return;
}

static void nftlb_timer_cb(struct ev_loop *loop, ev_timer *timer, int events)
{
	struct nftlb_client *cli;

	cli = container_of(timer, struct nftlb_client, timer);

	syslog(LOG_ERR, "timeout for client %s:%hu\n",
	       inet_ntoa(cli->addr.sin_addr), ntohs(cli->addr.sin_port));

	nftlb_client_release(loop, cli);
}

static void accept_cb(struct ev_loop *loop, struct ev_io *io, int revents)
{
	struct sockaddr_in client_addr;
	socklen_t addrlen = sizeof(client_addr);
	struct nftlb_client *cli;
	int client_sd;

	if (EV_ERROR & revents) {
		syslog(LOG_ERR, "Server got an invalid event from client");
		return;
	}

	client_sd = accept(io->fd, (struct sockaddr *)&client_addr, &addrlen);
	if (client_sd < 0) {
		syslog(LOG_ERR, "Server accept error");
		return;
	}

	cli = malloc(sizeof(struct nftlb_client));
	if (!cli) {
		syslog(LOG_ERR, "No memory available to allocate new client");
		return;
	}
	memcpy(&cli->addr, &client_addr, sizeof(cli->addr));

	ev_io_init(&cli->io, nftlb_read_cb, client_sd, EV_READ);
	ev_io_start(loop, &cli->io);
	ev_timer_init(&cli->timer, nftlb_timer_cb, NFTLB_CLIENT_TIMEOUT, 0.);
	ev_timer_start(loop, &cli->timer);

	syslog(LOG_DEBUG, "connection from %s:%hu",
	       inet_ntoa(cli->addr.sin_addr), ntohs(cli->addr.sin_port));
	syslog(LOG_DEBUG, "%d client(s) connected", ++nftserver.clients);
}

int server_init(void)
{
	struct sockaddr_in addr = {};
	socklen_t addrlen = sizeof(addr);
	struct ev_loop *st_ev_loop = get_loop();
	struct ev_io *st_ev_accept = events_create_srv();
	int server_sd;
	int yes = 1;

	if (!nftserver.key)
		server_set_key(NULL);

	printf("Key: %s\n", nftserver.key);

	server_sd = socket(nftserver.family, SOCK_STREAM, 0);
	if (server_sd < 0) {
		fprintf(stderr, "Server socket error\n");
		syslog(LOG_ERR, "Server socket error");
		return -1;
	}
	setsockopt(server_sd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

	addr.sin_family = nftserver.family;
	addr.sin_port = htons(nftserver.port);
	if (nftserver.host == NULL)
		addr.sin_addr.s_addr = INADDR_ANY;
	else
		inet_aton(nftserver.host, &addr.sin_addr);

	if (bind(server_sd, (struct sockaddr *) &addr, addrlen) != 0) {
		fprintf(stderr, "Server bind error\n");
		syslog(LOG_ERR, "Server bind error");
		return -1;
	}

	if (listen(server_sd, 2) < 0) {
		fprintf(stderr, "Server listen error\n");
		syslog(LOG_ERR, "Server listen error");
		return -1;
	}
	nftserver.sd = server_sd;

	ev_io_init(st_ev_accept, accept_cb, server_sd, EV_READ);
	ev_io_start(st_ev_loop, st_ev_accept);

	return 0;
}

void server_fini(void)
{
	close(nftserver.sd);
}

void server_set_host(char *host)
{
	nftserver.host = malloc(strlen(host)+1);

	if (!nftserver.host) {
		syslog(LOG_ERR, "No memory available to allocate the server host");
		return;
	}

	sprintf(nftserver.host, "%s", host);
}

void server_set_port(int port)
{
	nftserver.port = port;
}

void server_set_key(char *key)
{
	int i;

	if (!nftserver.key) {
		nftserver.key = (char *)malloc(SRV_MAX_IDENT);
		if (!nftserver.key) {
			syslog(LOG_ERR, "No memory available to allocate the server key");
			return;
		}
	}

	if (!key) {
		srand((unsigned int) time(0) + getpid());
		for (i = 0; i < SRV_KEY_LENGTH; ++i)
			nftserver.key[i] = rand() % 94 + 33;
		nftserver.key[i] = '\0';
	} else
		snprintf(nftserver.key, SRV_MAX_IDENT, "%s", key);
}

void server_set_ipv6(void)
{
	nftserver.family = AF_INET6;
}
