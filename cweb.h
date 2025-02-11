#ifndef __CWEB_H
#define __CWEB_H

#include <stdint.h>
#include <stddef.h>
#include "sqlite3.h"

#define cweb_append_lit(res, lit) cweb_append(res, ""lit"", sizeof(lit) - 1)

#define FILTERS(...) (filter_func_t[]){ __VA_ARGS__, NULL }

#define render_html(res, basename, ...) \
	do { \
		cweb_add_header(res, "Content-Type", "text/html"); \
		__tmplfunc_##basename(res, &(struct __tmplargs_##basename){__VA_ARGS__}); \
	} while (0)

enum method {
	METHOD_GET,
};

struct kv {
	char *name;
	char *value;
};

struct kvlist {
	size_t n;
	struct kv *l;
};

struct request {
	enum method method;
	char *uri;
	size_t n_segments;
	char **segments;
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

char *cweb_get_query(struct request *req, char *name);
char *cweb_get_segment(struct request *req, char *name);
char *cweb_get_cookie(struct request *req, char *name);

void cweb_add_header(struct response *res, char *name, char *value);
void cweb_set_status(struct response *res, enum status_code status);
void cweb_append(struct response *res, const char *stuff, size_t len);
void cweb_append_html_escaped(struct response *res, const char *s);
void cweb_set_cookie(struct response *res, char *name, char *value);
void cweb_delete_cookie(struct response *res, char *name);

void not_found(struct response *res);
void bad_request(struct response *res);
void server_error(struct response *res);
void redirect(struct response *res, char *to);

#endif
