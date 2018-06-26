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

#define SRV_MAX_BUF			4096
#define SRV_MAX_HEADER			300
#define SRV_MAX_IDENT			200
#define SRV_KEY_LENGTH			16

#define SRV_PORT_DEF			5555
#define SRV_HOST_DEF			INADDR_ANY
#define SRV_DUAL_DEF			0

#define SRV_FAMILY_DEF			SRV_IPV4
#define SRV_IPV4			AF_INET
#define SRV_IPV6			AF_INET6

#define STR_GET_ACTION			"GET"
#define STR_POST_ACTION			"POST"
#define STR_PUT_ACTION			"PUT"
#define STR_DELETE_ACTION		"DELETE"

#define HTTP_PROTO			"HTTP/1.1 "
#define HTTP_LINE_END			"\r\n"
#define HTTP_HEADER_CONTENTLEN		"Content-Length: "
#define HTTP_HEADER_KEY			"Key: "
#define HTTP_MIN_CONTINUE		2

extern struct ev_io *srv_accept;

enum ws_actions {
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

const char * ws_str_responses[] = {
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
};

struct nftlb_server nftserver = {
	.family	= SRV_FAMILY_DEF,
	.host	= NULL,
	.port	= SRV_PORT_DEF,
};

static int auth_key(const char *recvkey)
{
	return (strcmp(nftserver.key, recvkey) == 0);
}

static int get_request(char *buf, int *action, char **uri, char **content)
{
	char straction[SRV_MAX_IDENT] = {0};
	char strkey[SRV_MAX_IDENT] = {0};
	char *ptr;

	if ((ptr = strstr(buf, "Key: ")) == NULL)
		return WS_HTTP_401;

	sscanf(ptr, "Key: %199[^\r\n]", strkey);

	if (!auth_key(strkey))
		return WS_HTTP_401;

	sscanf(buf, "%199[^ ] %199[^ ] ", straction, *uri);

	if (strncmp(straction, STR_GET_ACTION, 3) == 0) {
		*action = WS_GET_ACTION;
	} else if (strncmp(straction, STR_POST_ACTION, 4) == 0) {
		*action = WS_POST_ACTION;
	} else if (strncmp(straction, STR_PUT_ACTION, 5) == 0) {
		*action = WS_PUT_ACTION;
	} else if (strncmp(straction, STR_DELETE_ACTION, 6) == 0) {
		*action = WS_DELETE_ACTION;
	} else {
		return WS_HTTP_500;
	}

	if ((*action != WS_POST_ACTION) && (*action != WS_PUT_ACTION))
		return HTTP_MIN_CONTINUE;

	if ((*content = strstr(buf, "\r\n\r\n")))
		*content += 4;

	return HTTP_MIN_CONTINUE;
}

static int send_get_response(char **buf, char *uri)
{
	char farm[SRV_MAX_IDENT] = {0};
	char farms[SRV_MAX_IDENT] = {0};

	sscanf(uri, "/%199[^/]/%199[^/\n]", farms, farm);

	if (strcmp(farms, CONFIG_KEY_FARMS) != 0)
		return WS_HTTP_500;

	if (config_print_farms(buf, farm) == EXIT_SUCCESS)
		return WS_HTTP_200;
	else
		return WS_HTTP_500;
}

static int send_delete_response(char **buf, char *uri, char *content)
{
	char farm[SRV_MAX_IDENT] = {0};
	char bck[SRV_MAX_IDENT] = {0};
	char farms[SRV_MAX_IDENT] = {0};
	char bcks[SRV_MAX_IDENT] = {0};
	int ret;

	sscanf(uri, "/%199[^/]/%199[^/]/%199[^/]/%199[^\n]", farms, farm, bcks, bck);

	if (strcmp(farms, CONFIG_KEY_FARMS) != 0)
		return WS_HTTP_500;

	*buf = (char *)malloc(SRV_MAX_IDENT);

	if (strcmp(bcks,CONFIG_KEY_BCKS) == 0) {
		ret = config_set_backend_action(farm, bck, CONFIG_VALUE_ACTION_DELETE);
		if (ret != EXIT_SUCCESS) {
			config_print_response(buf, "error deleting backend");
			goto delete_end;
		}
		ret = config_set_farm_action(farm, CONFIG_VALUE_ACTION_RELOAD);
		if (ret != EXIT_SUCCESS) {
			config_print_response(buf, "error reloading farm");
			goto delete_end;
		}
		ret = nft_rulerize();
		if (ret != EXIT_SUCCESS) {
			config_print_response(buf, "error generating rules");
			goto delete_end;
		}
	} else {
		ret = config_set_farm_action(farm, CONFIG_VALUE_ACTION_STOP);
		if (ret != EXIT_SUCCESS) {
			config_print_response(buf, "error stopping farm");
			goto delete_end;
		}
		ret = nft_rulerize();
		if (ret != EXIT_SUCCESS) {
			config_print_response(buf, "error generating rules");
			goto delete_end;
		}
		config_set_farm_action(farm, CONFIG_VALUE_ACTION_DELETE);
		if (ret != EXIT_SUCCESS) {
			config_print_response(buf, "error deleting farm");
			goto delete_end;
		}
	}

	config_print_response(buf, "success");

delete_end:
	return WS_HTTP_200;
}

static int send_post_response(char **buf, char *uri, char *content)
{
	if (strncmp(uri, "/farms", 6) != 0)
		return WS_HTTP_500;

	*buf = (char *)malloc(SRV_MAX_IDENT);

	if (config_buffer(content) != EXIT_SUCCESS) {
		config_print_response(buf, "error parsing buffer");
		goto post_end;
	}

	if (nft_rulerize() != EXIT_SUCCESS) {
		config_print_response(buf, "error generating rules");
		goto post_end;
	}

	config_print_response(buf, "success");

post_end:
	return WS_HTTP_200;
}

static int send_response(char **buf, int action, char *uri, char *content)
{
	switch (action) {
	case WS_GET_ACTION:
		return send_get_response(buf, uri);
	case WS_POST_ACTION:
	case WS_PUT_ACTION:
		return send_post_response(buf, uri, content);
	case WS_DELETE_ACTION:
		return send_delete_response(buf, uri, content);
	default:
		return -1;
	}
}

static void read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	char buffer[SRV_MAX_BUF] = {0};
	char resheader[SRV_MAX_HEADER];
	char *buf_res = NULL;
	char *uri = (char *)malloc(SRV_MAX_IDENT);
	char *content;
	int action;
	ssize_t size;
	int bufsize = 0;
	int code;

	if(EV_ERROR & revents) {
		syslog(LOG_ERR, "Server got invalid event from client read");
		return;
	}

	size = recv(watcher->fd, buffer, SRV_MAX_BUF, 0);

	if(size < 0) {
		syslog(LOG_ERR, "Server read error from client");
		return;
	}

	if(size == 0)
		goto end;

	code = get_request(buffer, &action, &uri, &content);
	if (code < HTTP_MIN_CONTINUE) {
		sprintf(resheader, "%s%s%d%s%s", ws_str_responses[code], HTTP_HEADER_CONTENTLEN, 0, HTTP_LINE_END, HTTP_LINE_END);
		send(watcher->fd, resheader, strlen(resheader), 0);
		goto end;
	}

	code = send_response(&buf_res, action, uri, content);
	if (code < HTTP_MIN_CONTINUE) {
		sprintf(resheader, "%s%s%d%s%s", ws_str_responses[code], HTTP_HEADER_CONTENTLEN, 0, HTTP_LINE_END, HTTP_LINE_END);
		send(watcher->fd, resheader, strlen(resheader), 0);
		goto end;
	}

	if (buf_res != NULL)
		bufsize = strlen(buf_res);

	sprintf(resheader, "%s", ws_str_responses[code]);
	sprintf(resheader, "%s%s%d%s%s", resheader,
		HTTP_HEADER_CONTENTLEN, bufsize, HTTP_LINE_END, HTTP_LINE_END);
	send(watcher->fd, resheader, strlen(resheader), 0);

	if (buf_res != NULL)
		send(watcher->fd, buf_res, bufsize, 0);

end:
	bzero(buffer, size);

	if (buf_res != NULL)
		free(buf_res);

	ev_io_stop(loop, watcher);

	if (watcher != NULL)
		free(watcher);

	syslog(LOG_DEBUG, "%d client(s) connected", --nftserver.clients);
	return;
}

static void accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	struct sockaddr_storage client_addr;
	socklen_t addrlen = sizeof(client_addr);
	int client_sd;
	struct ev_io *w_client = (struct ev_io*) malloc(sizeof(struct ev_io));

	if(EV_ERROR & revents) {
		syslog(LOG_ERR, "Server got an invalid event from client");
		return;
	}

	client_sd = accept(watcher->fd, (struct sockaddr *)&client_addr,
			   &addrlen);

	if (client_sd < 0) {
		syslog(LOG_ERR, "Server accept error");
		return;
	}

	syslog(LOG_DEBUG, "%d client(s) connected", ++nftserver.clients);

	ev_io_init(w_client, read_cb, client_sd, EV_READ);
	ev_io_start(loop, w_client);
}

int server_init(void)
{
	int sd;
	struct sockaddr_storage addr;
	socklen_t addrlen = sizeof(addr);
	struct ev_loop *st_ev_loop = get_loop();
	struct ev_io *st_ev_accept = events_create_srv();

	if (!nftserver.key)
		server_set_key(NULL);

	printf("Key: %s\n", nftserver.key);

	if ( (sd = socket(nftserver.family, SOCK_STREAM, 0)) < 0 ) {
		fprintf(stderr, "Server socket error\n");
		syslog(LOG_ERR, "Server socket error");
		return EXIT_FAILURE;
	}

	bzero(&addr, addrlen);
	addr.ss_family = nftserver.family;
	((struct sockaddr_in *) &addr)->sin_port = htons(nftserver.port);
	if (nftserver.host == NULL)
		((struct sockaddr_in *) &addr)->sin_addr.s_addr = SRV_HOST_DEF;
	else
		inet_aton(nftserver.host, &((struct sockaddr_in *) &addr)->sin_addr);

	if (bind(sd, (struct sockaddr *) &addr, addrlen) != 0) {
		fprintf(stderr, "Server bind error\n");
		syslog(LOG_ERR, "Server bind error");
		return EXIT_FAILURE;
	}

	if (listen(sd, 2) < 0) {
		fprintf(stderr, "Server listen error\n");
		syslog(LOG_ERR, "Server listen error");
		return EXIT_FAILURE;
	}

	ev_io_init(st_ev_accept, accept_cb, sd, EV_READ);
	ev_io_start(st_ev_loop, st_ev_accept);

	return EXIT_SUCCESS;
}

void server_set_host(char *host)
{
	nftserver.host = malloc(strlen(host));
	sprintf(nftserver.host, "%s", host);
}

void server_set_port(int port)
{
	nftserver.port = port;
}

void server_set_key(char *key)
{
	int i;

	if (!nftserver.key)
		nftserver.key = (char *)malloc(SRV_MAX_IDENT);

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
