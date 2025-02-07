#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>
#include "cweb.h"

#define ARRAY_LEN(arr) (sizeof(arr) / sizeof((arr)[0]))

void not_found(struct response *res);
void bad_request(struct response *res);

struct route {
	struct route_spec *spec;
	size_t n_segments;
	struct {
		bool is_glob;
		char *str;
	} *segments;
};

static char *kvlist_get(struct kvlist *kvs, char *name) {
	for (size_t i = 0; i < kvs->n; i++) {
		if (strcmp(name, kvs->l[i].name) == 0)
			return kvs->l[i].value;
	}
	return NULL;
}

static struct kv *kvlist_extend(struct kvlist *kvs) {
	kvs->n += 1;
	kvs->l = realloc(kvs->l, sizeof(kvs->l[0]) * kvs->n);
	return &kvs->l[kvs->n - 1];
}

static void kvlist_init(struct kvlist *kvs) {
	kvs->n = 0;
	kvs->l = NULL;
}

static void makelower(char *str) {
	while (*str) {
		*str = tolower(*str);
		str++;
	}
}

/*
 * Read from `fd` into `buf` at least until a "\r\n\r\n" is seen (or buf fills up).
 * Returns the number of bytes read, or -1 if `buf` was filled without seeing a "\r\n\r\n".
 */
static ssize_t recv_until_rnrn(int fd, char *buf, size_t cap) {
	ssize_t nread = 0;
	size_t first_unchecked = 0;

	while (cap != 0) {
		ssize_t r = read(fd, buf + nread, cap);
		if (r == -1) {
			perror("read");
			return -1;
		}
		nread += r;
		cap -= r;

		while (nread - first_unchecked >= 4) {
			if (memcmp("\r\n\r\n", buf + first_unchecked, 4) == 0)
				return nread;
			first_unchecked += 1;
		}
	}
	return -1;
}

static void respond(int fd, struct response *res) {
	// send status line
	if (dprintf(fd, "HTTP/1.0 %d x\r\n", res->status) < 0) {
		perror("dprintf");
		return;
	}

	// send headers
	for (size_t i = 0; i < res->headers.n; i++) {
		struct kv *h = res->headers.l + i;
		if (dprintf(fd, "%s: %s\r\n", h->name, h->value) < 0) {
			perror("dprintf");
			return;
		}
	}
	// Content-Length, end headers
	if (dprintf(fd, "Content-Length: %zu\r\n\r\n", res->body_len) < 0) {
		perror("dprintf");
		return;
	}

	// body
	if (res->body_len)
		write(fd, res->body, res->body_len);
}

static bool route_matches(struct route *r, struct request *req) {
	if (r->n_segments != req->n_segments)
		return false;

	for (size_t i = 0; i < r->n_segments; i++) {
		if (r->segments[i].is_glob)
			continue;

		if (strcmp(r->segments[i].str, req->segments[i]) != 0)
			return false;
	}

	return true;
}

static struct route *find_route(struct route *routes, size_t n, struct request *req) {
	for (size_t i = 0; i < n; i++) {
		struct route *r = routes + i;
		if (route_matches(r, req))
			return r;
	}
	return NULL;
}

static bool segmentize(char *path, struct request *req) {
	req->n_segments = 0;
	req->segments = NULL;

	if (*path != '/')
		return false;
	path++;

	while (*path) {
		req->n_segments += 1;
		req->segments = realloc(req->segments, sizeof(req->segments[0]) * req->n_segments);
		req->segments[req->n_segments - 1] = path;
		while (*path && *path != '/')
			path++;
		if (*path == '/') {
			*path = '\0';
			path++;
		}
	}
	return true;
}

static bool parse_uri(struct request *req, char *uri) {
	if (*uri == '\0')
		return false;

	char *path = uri;
	while (*uri && *uri != '?')
		uri++;
	// overwrite a trailing slash
	if (uri[-1] == '/' && uri - 1 != path)
		uri[-1] = '\0';
	else
		*uri = '\0';
	uri++;

	kvlist_init(&req->params);
	// query params
	while (*uri) {
		struct kv *q = kvlist_extend(&req->params);

		q->name = uri;
		while (*uri && *uri != '=' && *uri != '&')
			uri++;

		if (*uri == '=') {
			*uri = '\0';
			uri++;
			q->value = uri;
			while (*uri && *uri != '&')
				uri++;
			if (*uri == '&') {
				*uri = '\0';
				uri++;
			}
		} else if (*uri == '&') {
			*uri = '\0';
			uri++;
			q->value = "";
		} else {
			q->value = "";
		}
	}

	if (!segmentize(path, req))
		return false;
	return true;
}

static bool parse_cookie(struct request *req, char *str) {
	kvlist_init(&req->cookies);

	while (*str) {
		struct kv *new = kvlist_extend(&req->cookies);

		new->name = str;
		while (*str && *str != '=')
			str++;
		if (*str == 0)
			return false;
		*str = 0;
		str++;

		new->value = str;
		while (*str && *str != ';')
			str++;
		if (*str == 0)
			continue;
		*str = 0;
		str++;

		while (*str && *str == ' ')
			str++;
	}

	return true;
}

/*
 * Returns true on success, false on failure.
 * The resulting request's lifetime is tied to that of `buf`.
 * `buf`'s ownership is passed to this function; NUL bytes are inserted in
 * certain places to terminate strings.
 */
static bool parse_request(struct request *req, char *buf, size_t bufsiz) {
	if (bufsiz == 0)
		return false;

	// extract method
	char *method_str = buf;
	while (bufsiz && *buf != ' ') {
		buf++;
		bufsiz--;
	}
	if (bufsiz == 0)
		return false;
	*buf = '\0';
	buf++;
	bufsiz--;

	if (strcmp("GET", method_str) == 0)
		req->method = METHOD_GET;
	else
		return false;

	// extract uri
	char *uri = buf;
	while (bufsiz && *buf != ' ') {
		buf++;
		bufsiz--;
	}
	if (bufsiz == 0)
		return false;
	*buf = '\0';
	buf++;
	bufsiz--;

	req->uri = strdup(uri);
	if (!parse_uri(req, uri))
		return false;

	// skip version
	while (bufsiz && *buf != '\n') {
		buf++;
		bufsiz--;
	}
	if (bufsiz == 0)
		return false;
	buf++;
	bufsiz--;

	// parse headers
	kvlist_init(&req->headers);
	for (;;) {
		if (bufsiz < 2)
			return false;
		if (buf[0] == '\r' && buf[1] == '\n')
			break;

		char *name = buf;
		while (bufsiz && *buf != ':') {
			buf++;
			bufsiz--;
		}
		if (bufsiz == 0)
			return false;
		*buf = '\0';
		buf++;
		bufsiz--;
		makelower(name);

		while (bufsiz && *buf == ' ') {
			buf++;
			bufsiz--;
		}

		char *value = buf;
		while (bufsiz && *buf != '\r') {
			buf++;
			bufsiz--;
		}
		if (bufsiz < 2)
			return false;
		*buf = '\0';
		buf += 2;
		bufsiz -= 2;

		if (strcasecmp(name, "cookie") == 0) {
			if (!parse_cookie(req, value))
				return false;
		} else {
			struct kv *new = kvlist_extend(&req->headers);
			new->name = name;
			new->value = value;
		}
	}

	return true;
}

static void extract_named_segments(struct route *r, struct request *req) {
	assert(r->n_segments == req->n_segments);
	kvlist_init(&req->named_segments);
	for (size_t i = 0; i < r->n_segments; i++) {
		if (r->segments[i].is_glob) {
			struct kv *newseg = kvlist_extend(&req->named_segments);
			newseg->name = r->segments[i].str;
			newseg->value = req->segments[i];
		}
	}
}

static void handle(int fd, struct route *routes, size_t n_routes, sqlite3 *db) {
	struct response res = { .status = STATUS_OK };
	char buf[4096];
	ssize_t nread = recv_until_rnrn(fd, buf, sizeof(buf));
	if (nread == -1) {
		response_set_status(&res, STATUS_BAD_REQUEST);
		response_add_header(&res, "Content-Type", "text/plain");
		response_append_lit(&res, "Request Too Large");

		respond(fd, &res);
		return;
	}

	struct request req = {0};
	if (!parse_request(&req, buf, nread)) {
		bad_request(&res);
		respond(fd, &res);
		return;
	}

	struct route *route = find_route(routes, n_routes, &req);
	if (route == NULL) {
		not_found(&res);
		respond(fd, &res);
		return;
	}
	extract_named_segments(route, &req);

	if (route->spec->filters) {
		for (filter_func_t *f = route->spec->filters; *f != NULL; f++) {
			if ((*f)(&req, &res, db) == FILTER_HALT)
				goto halt;
		}
	}
	route->spec->handler(&req, &res, db);
halt:
	respond(fd, &res);
}

static int tcpsock(uint16_t port) {
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1)
		err(1, "socket");

	int e = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
	if (e == -1)
		err(1, "setsockopt");

	struct sockaddr_in addr;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_family = AF_INET;
	e = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (e == -1)
		err(1, "bind");

	e = listen(fd, 10);
	if (e == -1)
		err(1, "listen");

	return fd;
}

static void parse_route_spec_path(const char *path, struct route *route) {
	if (*path != '/')
		errx(1, "path '%s' does not start with a '/'", path);
	path++;

	while (*path) {
		if (*path == '/')
			errx(1, "empty path segment");

		route->n_segments += 1;
		route->segments = realloc(route->segments, sizeof(route->segments[0]) * route->n_segments);
		if (*path == '{') {
			path++;
			route->segments[route->n_segments - 1].is_glob = true;
			const char *start = path;
			while (*path && *path != '}')
				path++;
			if (*path == 0)
				errx(1, "unclosed '{' in path '%s'", path);
			if (path - start == 0)
				errx(1, "empty glob segment");
			route->segments[route->n_segments - 1].str = strndup(start, path - start);
			path++;
			if (*path == '/')
				path++;
		} else {
			route->segments[route->n_segments - 1].is_glob = false;
			const char *start = path;
			while (*path && *path != '/')
				path++;
			route->segments[route->n_segments - 1].str = strndup(start, path - start);
			if (*path == '/')
				path++;
		}
	}
}

void cweb_run(struct cweb_args *args) {
	struct route *routes = calloc(args->n_route_specs, sizeof(*routes));
	for (size_t i = 0; i < args->n_route_specs; i++) {
		parse_route_spec_path(args->route_specs[i].path, routes + i);
		routes[i].spec = &args->route_specs[i];
	}

	struct sigaction act = {
		.sa_handler = SIG_DFL,
		.sa_flags = SA_NOCLDWAIT,
	};
	if (sigaction(SIGCHLD, &act, NULL))
		err(1, "sigaction");

	int listenfd = tcpsock(args->port);

	for (;;) {
		int connfd = accept(listenfd, NULL, NULL);
		if (connfd == -1) {
			perror("accept");
			continue;
		}

		pid_t pid = fork();
		if (pid == -1) {
			perror("fork");
			close(connfd);
			continue;
		}
		if (pid == 0) {
			sqlite3 *db = NULL;
			if (args->db_path && sqlite3_open(args->db_path, &db) != SQLITE_OK)
				errx(1, "sqlite3_open: %s", sqlite3_errmsg(db));
			sqlite3_busy_timeout(db, 3000);

			handle(connfd, routes, args->n_route_specs, db);

			if (db && sqlite3_close(db) != SQLITE_OK)
				errx(1, "sqlite3_close: %s", sqlite3_errmsg(db));
			exit(0);
		} else {
			close(connfd);
		}
	}
}

char *request_get_query(struct request *req, char *name) {
	return kvlist_get(&req->params, name);
}

char *request_get_segment(struct request *req, char *name) {
	return kvlist_get(&req->named_segments, name);
}

void response_append(struct response *res, const char *stuff, size_t len) {
	if (len == 0)
		return;
	res->body = realloc(res->body, res->body_len + len);
	memcpy(res->body + res->body_len, stuff, len);
	res->body_len += len;
}

void response_append_html_escaped(struct response *res, const char *s) {
	while (*s) {
		const char *runstart = s;
		while (*s && *s != '&' && *s != '<' && *s != '>' && *s != '"' && *s != '\'')
			s++;
		response_append(res, runstart, s - runstart);
		if (*s == '\0')
			break;
		switch (*(s++)) {
		case '&':
			response_append_lit(res, "&amp;");
			break;
		case '<':
			response_append_lit(res, "&lt;");
			break;
		case '>':
			response_append_lit(res, "&gt;");
			break;
		case '"':
			response_append_lit(res, "&#034;");
			break;
		case '\'':
			response_append_lit(res, "&#039;");
			break;
		}
	}
}

void response_add_header(struct response *res, char *name, char *value) {
	struct kv *new = kvlist_extend(&res->headers);
	new->name = strdup(name);
	new->value = strdup(value);
}

void response_set_status(struct response *res, enum status_code status) {
	res->status = status;
}

void response_set_cookie(struct response *res, char *name, char *value) {
	char val[4096];
	int nwrite = snprintf(val, sizeof(val), "%s=%s; Max-Age=2592000", name, value);
	if (nwrite == sizeof(val) - 1) {
		fprintf(stderr, "Cookie \"%s=%s\" too big! Ignoring...\n", name, value);
		return;
	}
	response_add_header(res, "Set-Cookie", val);
}

void response_delete_cookie(struct response *res, char *name) {
	char val[4096];
	int nwrite = snprintf(val, sizeof(val), "%s=x; Max-Age=-1", name);
	if (nwrite == sizeof(val) - 1) {
		fprintf(stderr, "Header to delete cookie \"%s\" too big!", name);
		return;
	}
	response_add_header(res, "Set-Cookie", val);
}

char *request_get_cookie(struct request *req, char *name) {
	return kvlist_get(&req->cookies, name);
}

void not_found(struct response *res) {
	response_set_status(res, STATUS_NOT_FOUND);
	response_add_header(res, "Content-Type", "text/plain");
	response_append_lit(res, "Not Found");
}

void bad_request(struct response *res) {
	response_set_status(res, STATUS_BAD_REQUEST);
	response_add_header(res, "Content-Type", "text/plain");
	response_append_lit(res, "Bad Request");
}

void server_error(struct response *res) {
	response_set_status(res, STATUS_SERVER_ERROR);
	response_add_header(res, "Content-Type", "text/plain");
	response_append_lit(res, "Internal Server Error");
}

void redirect(struct response *res, char *to) {
	response_set_status(res, STATUS_FOUND);
	response_add_header(res, "Location", to);
}
