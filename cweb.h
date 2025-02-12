#ifndef __CWEB_H
#define __CWEB_H

#include <stdint.h>
#include <stddef.h>
#include "sqlite3.h"
#include "str.h"

#define FILTERS(...) (filter_func_t[]){ __VA_ARGS__, NULL }

#define render_html(res, basename, ...) \
	do { \
		cweb_add_header(res, STR("Content-Type"), STR("text/html")); \
		__tmplfunc_##basename(res, &(struct __tmplargs_##basename){__VA_ARGS__}); \
	} while (0)

enum method {
	METHOD_GET,
};

struct kv {
	str_t name;
	str_t value;
};

struct kvlist {
	size_t n;
	struct kv *l;
};

struct request {
	enum method method;
	str_t uri;
	size_t n_segments;
	str_t *segments;
	struct kvlist named_segments;
	struct kvlist params;
	struct kvlist headers;
	struct kvlist cookies;
	int64_t uid;
};

enum status_code {
	STATUS_OK = 200,
	STATUS_FOUND = 302,
	STATUS_BAD_REQUEST = 400,
	STATUS_NOT_FOUND = 404,
	STATUS_SERVER_ERROR = 500,
};

struct response {
	enum status_code status;
	struct kvlist headers;
	size_t body_len;
	char *body;
};

enum filter_flow {
	FILTER_CONTINUE,
	FILTER_HALT,
};

typedef void (*handler_func_t)(struct request *req, struct response *res, sqlite3 *db);
typedef enum filter_flow (*filter_func_t)(struct request *req, struct response *res, sqlite3 *db);

struct route_spec {
	char *path;
	handler_func_t handler;
	filter_func_t *filters;
};

struct cweb_args {
	// required:
	size_t n_route_specs;
	struct route_spec *route_specs;
	uint16_t port;

	// optional:
	char *db_path;
	filter_func_t *global_filters;
};

void cweb_run(struct cweb_args *args);

const str_t *cweb_get_query(struct request *req, str_t name);
const str_t *cweb_get_segment(struct request *req, str_t name);
const str_t *cweb_get_cookie(struct request *req, str_t name);

void cweb_add_header(struct response *res, str_t name, str_t value);
void cweb_set_status(struct response *res, enum status_code status);
void cweb_append(struct response *res, str_t stuff);
void cweb_append_html_escaped(struct response *res, str_t s);
void cweb_set_cookie(struct response *res, str_t name, str_t value);
void cweb_delete_cookie(struct response *res, str_t name);

void cweb_static_handler(struct request *req, struct response *res, sqlite3 *db);
void not_found(struct response *res);
void bad_request(struct response *res);
void server_error(struct response *res);
void redirect(struct response *res, str_t to);

#endif
