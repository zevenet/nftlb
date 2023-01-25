/*
 * Copyright (C) 2022 Zevenet S.L. <zproxy@zevenet.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _ZCU_HTTP_H_
#define _ZCU_HTTP_H_

#define SRV_MAX_HEADER			300
#define HTTP_PROTO			"HTTP/1.1 "
#define HTTP_LINE_END			"\r\n"
#define HTTP_HEADER_CONTENTLEN		"Content-Length: "
#define HTTP_HEADER_KEY			"Key: "
#define HTTP_HEADER_CONTENT_PLAIN "Content-Type: text/plain" HTTP_LINE_END
#define HTTP_HEADER_CONTENT_JSON "Content-Type: application/json" HTTP_LINE_END
#define HTTP_HEADER_EXPIRES "Expires: now" HTTP_LINE_END
#define HTTP_HEADER_PRAGMA_NO_CACHE "Pragma: no-cache" HTTP_LINE_END
#define HTTP_HEADER_CACHE_CONTROL "Cache-control: no-cache,no-store" HTTP_LINE_END

enum ws_responses {
	WS_HTTP_500,    // internal server error
	WS_HTTP_400,    // bad request
	WS_HTTP_401,    // unauthorized
	WS_HTTP_404,    // not found
	WS_HTTP_405,    // method not allowed
	WS_HTTP_409,    // conflict
	WS_HTTP_200,    // ok
	WS_HTTP_201,    // created
	WS_HTTP_204,    // no content
};

static const char *ws_str_responses[] = {
	HTTP_PROTO "500 Internal Server Error" HTTP_LINE_END,
	HTTP_PROTO "400 Bad Request" HTTP_LINE_END,
	HTTP_PROTO "401 Unauthorized" HTTP_LINE_END,
	HTTP_PROTO "404 Not Found" HTTP_LINE_END,
	HTTP_PROTO "405 Method Not Allowed" HTTP_LINE_END,
	HTTP_PROTO "409 Conflict" HTTP_LINE_END,
	HTTP_PROTO "200 OK" HTTP_LINE_END,
	HTTP_PROTO "201 Created" HTTP_LINE_END,
	HTTP_PROTO "204 No Content" HTTP_LINE_END,
};

#endif /* _ZCU_HTTP_H_ */
