#include <arpa/inet.h>
#include <fcntl.h>
#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <sys/stat.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>
#include "cweb.h"

#define ARRAY_LEN(arr) (sizeof(arr) / sizeof((arr)[0]))

struct route {
	struct route_spec *spec;
	size_t n_segments;
	struct {
		bool is_glob;
		str_t str;
	} *segments;
};

static ssize_t readall(int fd, char *buf, size_t count) {
	ssize_t nread = 0;
	while (count) {
		ssize_t n = read(fd, buf, count);
		if (n == -1)
			return -1;
		nread += n;
		buf += n;
		count -= n;
	}
	return nread;
}

static str_t *kvlist_get(struct kvlist *kvs, str_t name) {
	for (size_t i = 0; i < kvs->n; i++) {
		if (str_eq(kvs->l[i].name, name))
			return &kvs->l[i].value;
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
		if (dprintf(fd, "%.*s: %.*s\r\n", PRSTR(h->name), PRSTR(h->value)) < 0) {
			perror("dprintf");
			return;
		}
	}
	// Content-Length, end headers
	if (dprintf(fd, "Content-Length: %zu\r\n\r\n", res->body.len) < 0) {
		perror("dprintf");
		return;
	}

	// body
	if (res->body.len)
		write(fd, res->body.ptr, res->body.len);
}

static bool route_matches(struct route *r, struct request *req) {
	if (r->n_segments != req->n_segments)
		return false;

	for (size_t i = 0; i < r->n_segments; i++) {
		if (r->segments[i].is_glob)
			continue;

		if (!str_eq(r->segments[i].str, req->segments[i]))
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

static bool segmentize(str_t path, struct request *req) {
	req->n_segments = 0;
	req->segments = NULL;

	if (path.len == 0 || *path.ptr != '/')
		return false;
	path.len--;
	path.ptr++;

	while (path.len) {
		req->n_segments += 1;
		req->segments = realloc(req->segments, sizeof(req->segments[0]) * req->n_segments);

		size_t seglen = 0;
		const char *start = path.ptr;
		while (path.len && *path.ptr != '/') {
			seglen++;
			path.ptr++;
			path.len--;
		}

		req->segments[req->n_segments - 1].ptr = start;
		req->segments[req->n_segments - 1].len = seglen;

		if (path.len) {
			path.ptr++;
			path.len--;
		}
	}
	return true;
}

static bool parse_uri(struct request *req, str_t uri) {
	if (uri.len == 0)
		return false;

	str_t path = { .ptr = uri.ptr, .len = 0 };
	while (uri.len && *uri.ptr != '?') {
		path.len++;
		uri.ptr++;
		uri.len--;
	}
	// remove a trailing slash
	if (path.len > 1 && path.ptr[path.len - 1] == '/')
		path.len--;
	// skip '?'
	if (uri.len) {
		uri.ptr++;
		uri.len--;
	}

	// query params
	kvlist_init(&req->params);
	while (uri.len) {
		struct kv *q = kvlist_extend(&req->params);

		q->name.ptr = uri.ptr;
		q->name.len = 0;
		while (uri.len && *uri.ptr != '=' && *uri.ptr != '&') {
			q->name.len++;
			uri.ptr++;
			uri.len--;
		}

		q->value.len = 0;
		if (uri.len != 0) {
			if (*uri.ptr == '&') {
				uri.ptr++;
				uri.len--;
			} else { // *uri.ptr == '='
				uri.ptr++;
				uri.len--;
				q->value.ptr = uri.ptr;
				while (uri.len && *uri.ptr != '&') {
					q->value.len++;
					uri.ptr++;
					uri.len--;
				}
			}
		}
	}

	if (!segmentize(path, req))
		return false;
	return true;
}

static bool parse_cookie(struct request *req, str_t str) {
	kvlist_init(&req->cookies);

	while (str.len) {
		struct kv *new = kvlist_extend(&req->cookies);
		new->name.ptr = str.ptr;
		new->name.len = 0;
		while (str.len && *str.ptr != '=') {
			new->name.len++;
			str.len--;
			str.ptr++;
		}
		if (str.len == 0)
			return false;
		str.len--;
		str.ptr++;

		new->value.ptr = str.ptr;
		new->value.len = 0;
		while (str.len && *str.ptr != ';') {
			new->value.len++;
			str.len--;
			str.ptr++;
		}
		if (str.len == 0)
			continue;
		str.len--;
		str.ptr++;

		while (str.len && *str.ptr == ' ') {
			str.len--;
			str.ptr++;
		}
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
	str_t method_str = { .ptr = buf, .len = 0 };
	while (bufsiz && *buf != ' ') {
		method_str.len++;
		buf++;
		bufsiz--;
	}
	if (bufsiz == 0)
		return false;
	// skip ' ' after method
	buf++;
	bufsiz--;

	if (str_eq(method_str, STR("GET")))
		req->method = METHOD_GET;
	else
		return false;

	// extract uri
	req->uri.ptr = buf;
	req->uri.len = 0;
	while (bufsiz && *buf != ' ') {
		req->uri.len++;
		buf++;
		bufsiz--;
	}
	if (bufsiz == 0)
		return false;
	// skip ' '
	buf++;
	bufsiz--;

	if (!parse_uri(req, req->uri))
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

		str_t name = { .ptr = buf, .len = 0 };
		while (bufsiz && *buf != ':') {
			name.len++;
			buf++;
			bufsiz--;
		}
		if (bufsiz == 0)
			return false;
		// skip ':'
		buf++;
		bufsiz--;

		while (bufsiz && *buf == ' ') {
			buf++;
			bufsiz--;
		}

		str_t value = { .ptr = buf, .len = 0 };
		while (bufsiz && *buf != '\r') {
			value.len++;
			buf++;
			bufsiz--;
		}
		if (bufsiz < 2)
			return false;
		// skip "\r\n"
		buf += 2;
		bufsiz -= 2;

		if (str_caseqz(name, "cookie")) {
			if (!parse_cookie(req, value))
				return false;
		}
		struct kv *new = kvlist_extend(&req->headers);
		new->name = name;
		new->value = value;
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
		cweb_set_status(&res, STATUS_BAD_REQUEST);
		cweb_add_header(&res, STR("Content-Type"), STR("text/plain"));
		cweb_append(&res, STR("Request Too Large"));

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
			str_t segname = { .ptr = path, .len = 0 };
			while (*path && *path != '}') {
				segname.len++;
				path++;
			}
			if (*path == '\0')
				errx(1, "unclosed '{' in path '%s'", path);
			if (segname.len == 0)
				errx(1, "empty glob segment");
			route->segments[route->n_segments - 1].str = segname;
			path++;
			if (*path == '/')
				path++;
		} else {
			route->segments[route->n_segments - 1].is_glob = false;
			str_t segname = { .ptr = path, .len = 0 };
			while (*path && *path != '/') {
				segname.len++;
				path++;
			}
			route->segments[route->n_segments - 1].str = segname;
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
	uid_t uid = getuid();
	if (setuid(uid) == -1)
		err(1, "setuid");
	if (uid == 0)
		errx(1, "refusing to run as root");

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

const str_t *cweb_get_query(struct request *req, str_t name) {
	return kvlist_get(&req->params, name);
}

const str_t *cweb_get_segment(struct request *req, str_t name) {
	return kvlist_get(&req->named_segments, name);
}

void cweb_append(struct response *res, str_t stuff) {
	string_append(&res->body, stuff);
}

void cweb_append_html_escaped(struct response *res, str_t s) {
	while (s.len) {
		str_t run = { .ptr = s.ptr, .len = 0 };
		char ch = *s.ptr;
		while (s.len && ch != '&' && ch != '<' && ch != '>' && ch != '"' && ch != '\'') {
			s.ptr++;
			s.len--;
			run.len++;
		}
		cweb_append(res, run);
		if (s.len == 0)
			break;
		switch (*(s.ptr++)) {
		case '&':
			cweb_append(res, STR("&amp;"));
			break;
		case '<':
			cweb_append(res, STR("&lt;"));
			break;
		case '>':
			cweb_append(res, STR("&gt;"));
			break;
		case '"':
			cweb_append(res, STR("&#034;"));
			break;
		case '\'':
			cweb_append(res, STR("&#039;"));
			break;
		}
	}
}

void cweb_add_header(struct response *res, str_t name, str_t value) {
	struct kv *new = kvlist_extend(&res->headers);
	new->name = str_dup(name);
	new->value = str_dup(value);
}

void cweb_set_status(struct response *res, enum status_code status) {
	res->status = status;
}

void cweb_set_cookie(struct response *res, str_t name, str_t value) {
	char val[4096];
	int nwrite = snprintf(val, sizeof(val), "%.*s=%.*s; Max-Age=2592000; Path=/", PRSTR(name), PRSTR(value));
	if (nwrite == sizeof(val) - 1) {
		fprintf(stderr, "Cookie \"%.*s=%.*s\" too big! Ignoring...\n", PRSTR(name), PRSTR(value));
		return;
	}
	str_t valstr = { .ptr = val, .len = nwrite };
	cweb_add_header(res, STR("Set-Cookie"), valstr);
}

void cweb_delete_cookie(struct response *res, str_t name) {
	char val[4096];
	int nwrite = snprintf(val, sizeof(val), "%.*s=x; Max-Age=-1", PRSTR(name));
	if (nwrite == sizeof(val) - 1) {
		fprintf(stderr, "Header to delete cookie \"%.*s\" too big!", PRSTR(name));
		return;
	}
	str_t valstr = { .ptr = val, .len = nwrite };
	cweb_add_header(res, STR("Set-Cookie"), valstr);
}

const str_t *cweb_get_cookie(struct request *req, str_t name) {
	return kvlist_get(&req->cookies, name);
}

void not_found(struct response *res) {
	cweb_set_status(res, STATUS_NOT_FOUND);
	cweb_add_header(res, STR("Content-Type"), STR("text/plain"));
	cweb_append(res, STR("Not Found"));
}

void bad_request(struct response *res) {
	cweb_set_status(res, STATUS_BAD_REQUEST);
	cweb_add_header(res, STR("Content-Type"), STR("text/plain"));
	cweb_append(res, STR("Bad Request"));
}

void server_error(struct response *res) {
	cweb_set_status(res, STATUS_SERVER_ERROR);
	cweb_add_header(res, STR("Content-Type"), STR("text/plain"));
	cweb_append(res, STR("Internal Server Error"));
}

void redirect(struct response *res, str_t to) {
	cweb_set_status(res, STATUS_FOUND);
	cweb_add_header(res, STR("Location"), to);
}

void cweb_static_handler(struct request *req, struct response *res, sqlite3 *db) {
	(void)db;
	str_t fname = req->uri;
	// skip '/'
	fname.len--;
	fname.ptr++;

	char *fnamez = str_dupz(fname);
	struct stat sb;
	if (stat(fnamez, &sb) == -1)
		err(1, "stat(%s)", fnamez);
	int fd = open(fnamez, O_RDONLY);
	if (fd == -1)
		err(1, "open");
	assert(res->body.len == 0);
	string_grow(&res->body, sb.st_size);
	if (readall(fd, res->body.ptr, sb.st_size) == -1)
		err(1, "readall");
	res->body.len = sb.st_size;

	close(fd);
	free(fnamez);
}
