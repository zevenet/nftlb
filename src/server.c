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
#include <stdbool.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ev.h>
#include <time.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "server.h"
#include "config.h"
#include "nft.h"
#include "events.h"
#include "zcu_sbuffer.h"
#include "zcu_log.h"
#include "zcu_http.h"

#define SRV_MAX_BUF				1024
#define SRV_MAX_HEADER			300
#define SRV_MAX_IDENT			200
#define SRV_KEY_LENGTH			16

#define SRV_PORT_DEF			"5555"

#define STR_GET_ACTION			"GET"
#define STR_POST_ACTION			"POST"
#define STR_PUT_ACTION			"PUT"
#define STR_DELETE_ACTION		"DELETE"
#define STR_PATCH_ACTION		"PATCH"

extern struct ev_io *srv_accept;

enum ws_methods {
	WS_GET_ACTION,
	WS_POST_ACTION,
	WS_PUT_ACTION,
	WS_DELETE_ACTION,
	WS_PATCH_ACTION,
};

struct nftlb_http_state {
	enum ws_methods		method;
	char			uri[SRV_MAX_IDENT];
	char			*body;
	enum ws_responses	status_code;
	char			*body_response;
};

struct nftlb_server {
	char			*key;
	int			family;
	char			*host;
	char			*port;
	int			sd;
};

static struct nftlb_server nftserver = {
	.family	= AF_INET,
	.host	= NULL,
	.port	= NULL,
};

static int parse_to_http_status(int code)
{
	switch (code) {
	case PARSER_OK:
	case PARSER_IDEM_VALUE:
		return WS_HTTP_200;
	case PARSER_STRUCT_FAILED:
	case PARSER_VALID_FAILED:
		return WS_HTTP_400;
	case PARSER_OBJ_UNKNOWN:
		return WS_HTTP_404;
	case PARSER_FAILED:
	default:
		return WS_HTTP_500;
	}
}

/*
	Check for strings equality in constant time.
	Taken from <https://nachtimwald.com/2017/04/02/constant-time-string-comparison-in-c/>
*/
static bool str_iseq(const char *s1, const char *s2)
{
	int m = 0;
	volatile size_t i = 0;
	volatile size_t j = 0;
	volatile size_t k = 0;

	if (s1 == NULL || s2 == NULL)
		return false;

	while (true) {
		m |= s1[i] ^ s2[j];

		if (s1[i] == '\0')
			break;
		i++;

		if (s2[j] != '\0')
			j++;
		if (s2[j] == '\0')
			k++;
	}

	return m == 0;
}

static bool auth_key(const char *recvkey)
{
	return str_iseq(nftserver.key, recvkey);
}

static int get_request(int fd, struct zcu_buffer *buf, struct nftlb_http_state *state)
{
	char method[SRV_MAX_IDENT] = {0};
	char strkey[SRV_MAX_IDENT] = {0};
	int contlength = 0;
	int times = 0;
	int total_read_size = 0;
	char *ptr;
	int size;
	int head;
	int bytes_left;
	int cont_100 = 0;

	if ((ptr = strstr(zcu_buf_get_data(buf), "Key: ")) == NULL) {
		state->status_code = WS_HTTP_401;
		return -1;
	}

	sscanf(ptr, "Key: %199[^\r\n]", strkey);

	if (!auth_key(strkey)) {
		state->status_code = WS_HTTP_401;
		return -1;
	}

	sscanf(zcu_buf_get_data(buf), "%199[^ ] %199[^ ] ", method, state->uri);

	zcu_log_print(LOG_NOTICE, "%s():%d: request: %s %s", __FUNCTION__, __LINE__, method, state->uri);

	if (strncmp(method, STR_GET_ACTION, 4) == 0) {
		state->method = WS_GET_ACTION;
	} else if (strncmp(method, STR_POST_ACTION, 5) == 0) {
		state->method = WS_POST_ACTION;
	} else if (strncmp(method, STR_PUT_ACTION, 4) == 0) {
		state->method = WS_PUT_ACTION;
	} else if (strncmp(method, STR_DELETE_ACTION, 7) == 0) {
		state->method = WS_DELETE_ACTION;
	} else if (strncmp(method, STR_PATCH_ACTION, 6) == 0) {
		state->method = WS_PATCH_ACTION;
	} else {
		state->status_code = parse_to_http_status(PARSER_STRUCT_FAILED);
		return -1;
	}

	if (state->method == WS_GET_ACTION)
		return 0;

	state->body = strstr(zcu_buf_get_data(buf), "\r\n\r\n");
	if (!state->body) {
		zcu_log_print(LOG_ERR, "Not found body section in the request");
		state->status_code = parse_to_http_status(PARSER_STRUCT_FAILED);
		return -1;
	}
	state->body += 4;
	head = state->body - zcu_buf_get_data(buf);

	if ((ptr = strstr(zcu_buf_get_data(buf), "Expect: 100-continue")) != NULL) {
		cont_100 = 1;
		send(fd, "HTTP/1.1 100 Continue\r\n\r\n", 25, 0);
	}

	if ((ptr = strstr(zcu_buf_get_data(buf), "Content-Length: ")) != NULL) {
		sscanf(ptr, "Content-Length: %i[^\r\n]", &contlength);

		if (head + contlength >= zcu_buf_get_size(buf))
			times = ((head + contlength - zcu_buf_get_size(buf)) / EXTRA_SIZE) + 1;
		if (times == 0)
			goto receive;

		if (zcu_buf_resize(buf, times)) {
			zcu_log_print(LOG_ERR, "Error resizing the buffer %d times from a size of %d!", times, zcu_buf_get_size(buf));
			state->status_code = WS_HTTP_500;
			return -1;
		}
	}

receive:
	state->body = zcu_buf_get_data(buf) + head;
	total_read_size = zcu_buf_get_next(buf) - state->body;
	while ((total_read_size < contlength) || cont_100) {
		cont_100 = 0;
		bytes_left = EXTRA_SIZE;
		if (contlength - total_read_size < EXTRA_SIZE)
			bytes_left = contlength - total_read_size;
		if (bytes_left <= 0)
			goto final;
		size = recv(fd, zcu_buf_get_next(buf), bytes_left, 0);
		if (size <= 0)
			goto final;
		buf->next += size;
		total_read_size += size;
	}

final:
	zcu_buf_concat(buf, "\0");

	return 0;
}

static int init_http_state(struct nftlb_http_state *state)
{
	state->body_response = malloc(SRV_MAX_BUF);
	if (!state->body_response) {
		state->status_code = parse_to_http_status(PARSER_STRUCT_FAILED);
		return -1;
	}

	return 0;
}

static int fin_http_state(struct nftlb_http_state *state)
{
	if (state->body_response)
		free(state->body_response);
	return 0;
}

static int server_load_config(const char *body_request, char *response, int action)
{
	int ret = config_buffer(body_request, action);
	switch (ret) {
	case PARSER_OK:
		break;
	case PARSER_STRUCT_FAILED:
		snprintf(response, SRV_MAX_IDENT, "%s", "the structure is invalid");
		break;
	case PARSER_OBJ_UNKNOWN:
		snprintf(response, SRV_MAX_IDENT, "%s", "the object to modify is unknown");
		break;
	default:
		snprintf(response, SRV_MAX_IDENT, "%s", "error parsing buffer");
		break;
	}

	return ret;
}

static int send_get_response(struct nftlb_http_state *state)
{
	char firstlevel[SRV_MAX_IDENT] = {0};
	char secondlevel[SRV_MAX_IDENT] = {0};
	char thirdlevel[SRV_MAX_IDENT] = {0};
	char fourthlevel[SRV_MAX_IDENT] = {0};
	int ret = PARSER_STRUCT_FAILED;

	sscanf(state->uri, "/%199[^/]/%199[^/]/%199[^/]/%199[^\n]",
	       firstlevel, secondlevel, thirdlevel, fourthlevel);

	if (strcmp(firstlevel, CONFIG_KEY_FARMS) == 0) {

		if (strcmp(thirdlevel, CONFIG_KEY_SESSIONS) == 0)
			ret = config_print_farm_sessions(&state->body_response, secondlevel);
		else if (strcmp(thirdlevel, "") == 0)
			ret = config_print_farms(&state->body_response, secondlevel);

	} else if (strcmp(firstlevel, CONFIG_KEY_POLICIES) == 0)
		ret = config_print_policies(&state->body_response, secondlevel);

	else if (strcmp(firstlevel, CONFIG_KEY_ADDRESSES) == 0)
		ret = config_print_addresses(&state->body_response, secondlevel);

	state->status_code = parse_to_http_status(ret);
	if (ret) {
		config_print_response(&state->body_response, "%s%s", "invalid request",
							  config_get_output());
		config_delete_output();
	}
	return 0;
}

static int send_delete_response(struct nftlb_http_state *state)
{
	char firstlevel[SRV_MAX_IDENT] = {0};
	char secondlevel[SRV_MAX_IDENT] = {0};
	char thirdlevel[SRV_MAX_IDENT] = {0};
	char fourthlevel[SRV_MAX_IDENT] = {0};
	char fifthlevel[SRV_MAX_IDENT] = {0};
	char message[SRV_MAX_IDENT] = {0};
	int ret = PARSER_OK;

	sscanf(state->uri, "/%199[^/]/%199[^/]/%199[^/]/%199[^/]/%199[^\n]",
	       firstlevel, secondlevel, thirdlevel, fourthlevel, fifthlevel);

	if (strcmp(firstlevel, CONFIG_KEY_FARMS) != 0 &&
		strcmp(firstlevel, CONFIG_KEY_POLICIES) != 0 &&
		strcmp(firstlevel, CONFIG_KEY_ADDRESSES) != 0) {
		snprintf(message, SRV_MAX_IDENT, "%s", "invalid request");
		ret = PARSER_OBJ_UNKNOWN;
		goto delete_end;
	}

	snprintf(message, SRV_MAX_IDENT, "%s", "success");
	if (strlen(state->body) == 0) {

		if (strcmp(firstlevel, CONFIG_KEY_FARMS) == 0 &&
			strcmp(thirdlevel, CONFIG_KEY_BCKS) == 0 &&
			strcmp(fifthlevel, CONFIG_KEY_SESSIONS) == 0) {
			ret = config_set_session_backend_action(secondlevel, fourthlevel, CONFIG_VALUE_ACTION_DELETE);
			if (ret)
				snprintf(message, SRV_MAX_IDENT, "%s", "error deleting sessions from backend");

		} else if (strcmp(firstlevel, CONFIG_KEY_FARMS) == 0 &&
			strcmp(thirdlevel, CONFIG_KEY_BCKS) == 0) {
			ret = config_set_backend_action(secondlevel, fourthlevel, CONFIG_VALUE_ACTION_DELETE);
			if (ret)
				snprintf(message, SRV_MAX_IDENT, "%s", "error deleting backend");

		} else if (strcmp(firstlevel, CONFIG_KEY_FARMS) == 0 &&
			strcmp(thirdlevel, CONFIG_KEY_SESSIONS) == 0) {
			ret = config_set_session_action(secondlevel, fourthlevel, CONFIG_VALUE_ACTION_STOP);
			if (ret)
				snprintf(message, SRV_MAX_IDENT, "%s", "error deleting session");

		} else if (strcmp(firstlevel, CONFIG_KEY_FARMS) == 0 &&
			strcmp(thirdlevel, CONFIG_KEY_ADDRESSES) == 0) {
			config_set_farm_action(secondlevel, CONFIG_VALUE_ACTION_RELOAD);
			ret = config_set_farmaddress_action(secondlevel, fourthlevel, CONFIG_VALUE_ACTION_STOP);
			if (ret) {
				snprintf(message, SRV_MAX_IDENT, "%s", "error deleting farm address");
				goto delete_end;
			}
			obj_rulerize(OBJ_START);
			config_set_farmaddress_action(secondlevel, fourthlevel, CONFIG_VALUE_ACTION_DELETE);

		} else if (strcmp(firstlevel, CONFIG_KEY_FARMS) == 0 &&
				   strcmp(thirdlevel, CONFIG_KEY_POLICIES) == 0) {
			config_set_farm_action(secondlevel, CONFIG_VALUE_ACTION_RELOAD);
			ret = config_set_fpolicy_action(secondlevel, fourthlevel, CONFIG_VALUE_ACTION_STOP);
			if (ret) {
				snprintf(message, SRV_MAX_IDENT, "%s", "error deleting farm policy");
				goto delete_end;
			}
			obj_rulerize(OBJ_START);
			config_set_farm_action(secondlevel, CONFIG_VALUE_ACTION_RELOAD);
			config_set_fpolicy_action(secondlevel, fourthlevel, CONFIG_VALUE_ACTION_DELETE);

		} else if (strcmp(firstlevel, CONFIG_KEY_POLICIES) == 0 &&
				   strcmp(thirdlevel, CONFIG_KEY_ELEMENTS) == 0) {
			ret = config_get_elements(secondlevel);
			if (ret) {
				snprintf(message, SRV_MAX_IDENT, "%s", "could not get the policy elements");
				goto delete_end;
			}

			// subnet support
			if (strcmp(fifthlevel,"") != 0 &&
				(strlen(fourthlevel) + strlen(fifthlevel) + 1 < SRV_MAX_IDENT)) {
				strcat(fourthlevel, "/");
				strcat(fourthlevel, fifthlevel);
			}

			ret = config_set_element_action(secondlevel, fourthlevel, CONFIG_VALUE_ACTION_STOP);
			if (ret) {
				snprintf(message, SRV_MAX_IDENT, "%s", "error deleting policy element");
				config_delete_elements(secondlevel);
				goto delete_end;
			}
			if (strcmp(fourthlevel, "") != 0) {
				config_set_policy_action(secondlevel, CONFIG_VALUE_ACTION_RELOAD);
				ret = config_set_element_action(secondlevel, fourthlevel, CONFIG_VALUE_ACTION_STOP);
				if (ret) {
					snprintf(message, SRV_MAX_IDENT, "%s", "error deleting policy element");
					config_delete_elements(secondlevel);
					goto delete_end;
				}
			} else {
				config_set_policy_action(secondlevel, CONFIG_VALUE_ACTION_FLUSH);
				config_set_element_action(secondlevel, fourthlevel, CONFIG_VALUE_ACTION_NONE);
			}
			obj_rulerize(OBJ_START);
			config_delete_elements(secondlevel);

		} else if (strcmp(firstlevel, CONFIG_KEY_FARMS) == 0 &&
				   strcmp(thirdlevel, "") == 0) {
			ret = config_set_farm_action(secondlevel, CONFIG_VALUE_ACTION_STOP);
			if (ret) {
				snprintf(message, SRV_MAX_IDENT, "%s", "error deleting farm");
				goto delete_end;
			}
			obj_rulerize(OBJ_START);
			config_set_farm_action(secondlevel, CONFIG_VALUE_ACTION_DELETE);

		} else if (strcmp(firstlevel, CONFIG_KEY_POLICIES) == 0 &&
				   strcmp(thirdlevel, "") == 0) {

			ret = config_set_policy_action(secondlevel, CONFIG_VALUE_ACTION_STOP);
			if (ret) {
				snprintf(message, SRV_MAX_IDENT, "%s", "error stopping policy");
				goto delete_end;
			}
			obj_rulerize(OBJ_START_INV);

			ret = config_set_policy_action(secondlevel, CONFIG_VALUE_ACTION_DELETE);
			if (ret)
				snprintf(message, SRV_MAX_IDENT, "%s", "error deleting policy");

		} else if (strcmp(firstlevel, CONFIG_KEY_ADDRESSES) == 0 &&
				   strcmp(thirdlevel, "") == 0) {

			ret = config_set_address_action(secondlevel, CONFIG_VALUE_ACTION_STOP);
			if (ret) {
				snprintf(message, SRV_MAX_IDENT, "%s", "error stopping address");
				goto delete_end;
			}
			obj_rulerize(OBJ_START_INV);

			ret = config_set_address_action(secondlevel, CONFIG_VALUE_ACTION_DELETE);
			if (ret)
				snprintf(message, SRV_MAX_IDENT, "%s", "error deleting address");

		} else {
			snprintf(message, SRV_MAX_IDENT, "%s", "invalid request");
			ret = PARSER_STRUCT_FAILED;
		}

	} else {

		ret = server_load_config(state->body, message, ACTION_STOP);
		if (ret != PARSER_OK)
			goto delete_end;

		if (obj_rulerize(OBJ_START)) {
			snprintf(message, SRV_MAX_IDENT, "%s", "error generating rules");
			ret = PARSER_FAILED;
		}
	}

delete_end:
	config_print_response(&state->body_response, "%s%s", message, config_get_output());
	config_delete_output();
	state->status_code = parse_to_http_status(ret);

	return 0;
}

static int send_post_response(struct nftlb_http_state *state)
{
	char firstlevel[SRV_MAX_IDENT] = {0};
	char message[SRV_MAX_IDENT] = {0};
	int ret = 0;

	sscanf(state->uri, "/%199[^\n]", firstlevel);

	if ((strcmp(firstlevel, CONFIG_KEY_FARMS) != 0) &&
		(strcmp(firstlevel, CONFIG_KEY_POLICIES) != 0) &&
		(strcmp(firstlevel, CONFIG_KEY_ADDRESSES) != 0)) {
		snprintf(message, SRV_MAX_IDENT, "%s", "invalid request");
		ret = PARSER_OBJ_UNKNOWN;
		goto post_end;
	}

	ret = server_load_config(state->body, message, ACTION_START);
	if (ret != PARSER_OK)
		goto post_end;

	snprintf(message, SRV_MAX_IDENT, "%s", "success");
	if (obj_rulerize(OBJ_START)) {
		snprintf(message, SRV_MAX_IDENT, "%s", "error generating rules");
		ret = PARSER_FAILED;
	}

post_end:
	config_print_response(&state->body_response, "%s%s", message, config_get_output());
	config_delete_output();
	state->status_code = parse_to_http_status(ret);

	return 0;
}

static int send_patch_response(struct nftlb_http_state *state)
{
	char firstlevel[SRV_MAX_IDENT] = {0};
	char secondlevel[SRV_MAX_IDENT] = {0};
	char thirdlevel[SRV_MAX_IDENT] = {0};
	char message[SRV_MAX_IDENT] = {0};
	int ret = 0;

	sscanf(state->uri, "/%199[^/]/%199[^/]/%199[^\n]", firstlevel, secondlevel, thirdlevel);

	// PATCH /farms/<my_farm>/policies/
	if (strcmp(firstlevel, CONFIG_KEY_FARMS) == 0) {
		if (strcmp(thirdlevel, CONFIG_KEY_POLICIES) != 0)
			goto patch_invalid_request;

		if (config_check_farm(secondlevel) != PARSER_OK)
			goto patch_object_unknown;

		config_set_farm_action(secondlevel, CONFIG_VALUE_ACTION_RELOAD);
		config_set_fpolicy_action(secondlevel, NULL, CONFIG_VALUE_ACTION_STOP);

		if (obj_rulerize(OBJ_START)) {
			snprintf(message, SRV_MAX_IDENT, "%s", "error generating rules");
			ret = PARSER_FAILED;
			goto patch_end;
		}

		config_set_fpolicy_action(secondlevel, NULL, CONFIG_VALUE_ACTION_DELETE);
		config_set_fpolicy_action(secondlevel, NULL, CONFIG_VALUE_ACTION_NONE);

		ret = server_load_config(state->body, message, ACTION_START);
		if (ret != PARSER_OK)
			goto patch_end;

		if (obj_rulerize(OBJ_START)) {
			snprintf(message, SRV_MAX_IDENT, "%s", "error generating rules");
			ret = PARSER_FAILED;
			goto patch_end;
		}

		snprintf(message, SRV_MAX_IDENT, "%s", "success");
		goto patch_end;
	}

	// PATCH /policies/
	if (strcmp(firstlevel, CONFIG_KEY_POLICIES) == 0) {
		if (config_check_policy(secondlevel) != PARSER_OK)
			goto patch_object_unknown;

		ret = server_load_config(state->body, message, ACTION_START);
		if (ret != PARSER_OK)
			goto patch_end;

		config_set_policy_action(secondlevel, CONFIG_VALUE_ACTION_FLUSH);

		if (obj_rulerize(OBJ_START)) {
			snprintf(message, SRV_MAX_IDENT, "%s", "error generating rules");
			ret = PARSER_FAILED;
			goto patch_end;
		}

		snprintf(message, SRV_MAX_IDENT, "%s", "success");
		goto patch_end;
	}

patch_invalid_request:
	snprintf(message, SRV_MAX_IDENT, "%s", "invalid request");
	ret = PARSER_OBJ_UNKNOWN;
	goto patch_end;

patch_object_unknown:
	snprintf(message, SRV_MAX_IDENT, "%s", "the object to modify is unknown");
	ret = PARSER_OBJ_UNKNOWN;
	goto patch_end;

patch_end:
	config_print_response(&state->body_response, "%s%s", message, config_get_output());
	config_delete_output();
	state->status_code = parse_to_http_status(ret);

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
	case WS_PATCH_ACTION:
		return send_patch_response(state);
	default:
		return -1;
	}
}

/* If client doesn't send us anything in 30 seconds, close connection. */
#define NFTLB_CLIENT_TIMEOUT	30

struct nftlb_client {
	struct ev_io		io;
	struct ev_timer		timer;
	struct sockaddr_storage	addr;
};

static char *nftlb_client_address(struct sockaddr_storage *addr, char *str)
{
	unsigned short port;
	if (!addr) {
		str[0] = 0;
		return str;
	}

	switch (addr->ss_family)
	{
	case AF_INET6:
		port = htons(((struct sockaddr_in6 *)addr)->sin6_port);
		sprintf(str,"%s:%hu",inet_ntop(addr->ss_family, 
			&(((struct sockaddr_in6 *)addr)->sin6_addr), str, 
			INET6_ADDRSTRLEN + 6),port);
		break;
	case AF_INET:
		port = htons(((struct sockaddr_in *)addr)->sin_port);
		sprintf(str,"%s:%hu",inet_ntop(addr->ss_family, 
			&(((struct sockaddr_in *)addr)->sin_addr), str, 
			INET6_ADDRSTRLEN + 6),port);
		break;
	default:
		break;
	}
	return str;
}

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
	struct zcu_buffer buf;
	struct nftlb_http_state state;
	struct nftlb_client *cli;
	ssize_t size;
	char cli_address[INET6_ADDRSTRLEN + 6]; //max address length + port length

	if (EV_ERROR & revents) {
		zcu_log_print(LOG_ERR, "Server got invalid event from client read");
		return;
	}
	cli = container_of(io, struct nftlb_client, io);

	zcu_buf_create(&buf);
	size = recv(io->fd, zcu_buf_get_data(&buf), ZCU_DEF_BUFFER_SIZE - 1, 0);
	if (size < 0)
		return;

	buf.next = size;

	if (size == 0) {
		zcu_log_print(LOG_DEBUG, "connection closed by client %s\n",
					   nftlb_client_address(&cli->addr, cli_address));
		goto end_no_state;
	}

	if (init_http_state(&state))
		goto end_no_state;

	if (get_request(io->fd, &buf, &state) < 0) {
		nftlb_http_send_response(io, &state, 0);
		goto end;
	}

	if (send_response(&state) < 0) {
		nftlb_http_send_response(io, &state, 0);
		goto end;
	}

	nftlb_http_send_response(io, &state, strlen(state.body_response));
	send(io->fd, state.body_response, strlen(state.body_response), 0);

	zcu_log_print(LOG_DEBUG, "connection closed by server %s\n",
				   nftlb_client_address(&cli->addr, cli_address));
end:
	fin_http_state(&state);
end_no_state:
	zcu_buf_clean(&buf);

	ev_timer_stop(loop, &cli->timer);
	nftlb_client_release(loop, cli);

	return;
}

static void nftlb_timer_cb(struct ev_loop *loop, ev_timer *timer, int events)
{
	struct nftlb_client *cli;
	char cli_address[INET6_ADDRSTRLEN + 6]; //max address length + port length

	cli = container_of(timer, struct nftlb_client, timer);

	zcu_log_print(LOG_ERR, "timeout for client %s\n",
				   nftlb_client_address(&cli->addr, cli_address));

	nftlb_client_release(loop, cli);
}

static void accept_cb(struct ev_loop *loop, struct ev_io *io, int revents)
{
	struct sockaddr_storage client_addr;
	socklen_t addrlen = sizeof(client_addr);
	struct nftlb_client *cli;
	int client_sd;

	if (EV_ERROR & revents) {
		zcu_log_print(LOG_ERR, "Server got an invalid event from client");
		return;
	}

	client_sd = accept(io->fd, (struct sockaddr *)&client_addr, &addrlen);
	if (client_sd < 0) {
		zcu_log_print(LOG_ERR, "Server accept error");
		return;
	}

	cli = malloc(sizeof(struct nftlb_client));
	if (!cli) {
		zcu_log_print(LOG_ERR, "No memory available to allocate new client");
		return;
	}
	memcpy(&cli->addr, &client_addr, sizeof(cli->addr));

	ev_io_init(&cli->io, nftlb_read_cb, client_sd, EV_READ);
	ev_io_start(loop, &cli->io);
	ev_timer_init(&cli->timer, nftlb_timer_cb, NFTLB_CLIENT_TIMEOUT, 0.);
	ev_timer_start(loop, &cli->timer);
}

int server_init(void)
{
	struct addrinfo hints = {};
	struct addrinfo *result;
	const char *host;
	const char *port;
	struct ev_loop *st_ev_loop = get_loop();
	struct ev_io *st_ev_accept = events_create_srv();
	int server_sd;
	int yes = 1, s;

	if (!nftserver.key)
		server_set_key(NULL);

	printf("Key: %s\n", nftserver.key);

	if (nftserver.host == NULL)
		switch(nftserver.family) {
		case AF_INET:
			host = "0.0.0.0";
			break;
		case AF_INET6:
			host = "::";
			break;
		default:
			host = INADDR_ANY;
			break;
		}
	else
		host = nftserver.host;
	if (nftserver.port == NULL)
		port = SRV_PORT_DEF;
	else
		port = nftserver.port;

	hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM; /* Datagram socket */
	hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */

	s = getaddrinfo(host, port, &hints, &result);
	if (s != 0) {
		zcu_log_print(LOG_ERR, "getaddrinfo: %s\n", gai_strerror(s));
		return -1;
	}

	server_sd = socket(result->ai_family, SOCK_STREAM, 0);
	if (server_sd < 0) {
		zcu_log_print(LOG_ERR, "Server socket error");
		return -1;
	}
	setsockopt(server_sd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

	if (bind(server_sd, result->ai_addr, result->ai_addrlen) != 0) {
		zcu_log_print(LOG_ERR, "Server bind error");
		freeaddrinfo(result);
		return -1;
	}
	freeaddrinfo(result);

	if (listen(server_sd, 2) < 0) {
		zcu_log_print(LOG_ERR, "Server listen error");
		return -1;
	}
	nftserver.sd = server_sd;

	ev_io_init(st_ev_accept, accept_cb, server_sd, EV_READ);
	ev_io_start(st_ev_loop, st_ev_accept);

	return 0;
}

void server_fini(void)
{
	events_delete_srv();
	close(nftserver.sd);
}

void server_set_host(const char *host)
{
	nftserver.host = malloc(strlen(host)+1);

	if (!nftserver.host) {
		zcu_log_print(LOG_ERR, "No memory available to allocate the server host");
		return;
	}

	sprintf(nftserver.host, "%s", host);
}

void server_set_port(const char *port)
{
	nftserver.port = malloc(strlen(port)+1);
	if (!nftserver.port) {
		zcu_log_print(LOG_ERR, "No memory available to allocate the server port");
		return;
	}

	sprintf(nftserver.port, "%s", port);
}

void server_set_key(char *key)
{
	int i;

	if (!nftserver.key) {
		nftserver.key = (char *)malloc(SRV_MAX_IDENT);
		if (!nftserver.key) {
			zcu_log_print(LOG_ERR, "No memory available to allocate the server key");
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
