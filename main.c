#include <curl/curl.h>
#include <assert.h>
#include <err.h>
#include <ldap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cweb.h"
#include "sql_wrappers.h"
#include "tmplfuncs.gen"

#define ARRAY_LEN(arr) (sizeof(arr) / sizeof((arr)[0]))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define SSO_SERVICE "https://fascinating-mochi-9ef846.netlify.app/"

static bool store_user_ldap_info(char *caseid, sqlite3 *db) {
	int e;
	bool ret = false;
	LDAP *ldap = NULL;
	LDAPMessage *resultchain = NULL;
	struct berval **cn_values = NULL;

	e = ldap_initialize(&ldap, "ldaps://ldap.case.edu:636");
	if (e) {
		fprintf(stderr, "ldap_initialize: %s\n", ldap_err2string(e));
		goto out;
	}

	if (ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &(int){3}) != LDAP_OPT_SUCCESS) {
		fprintf(stderr, "ldap_set_option\n");
		goto out;
	}

	char filter[100];
	snprintf(filter, sizeof(filter), "(uid=%s)", caseid);
	char *attrs[] = {"cn", NULL};
	e = ldap_search_ext_s(
		ldap,
		"ou=People,o=cwru.edu,o=isp",
		LDAP_SCOPE_ONELEVEL,
		filter,
		attrs,
		0,
		NULL,
		NULL,
		NULL,
		1,
		&resultchain
	);
	if (e) {
		fprintf(stderr, "ldap_search_ext_s: %s\n", ldap_err2string(e));
		goto out;
	}

	LDAPMessage *fent = ldap_first_entry(ldap, resultchain);
	if (fent == NULL) {
		fprintf(stderr, "ldap search for caseid %s returned no entries\n", caseid);
		goto out;
	}

	cn_values = ldap_get_values_len(ldap, fent, "cn");
	if (*cn_values == NULL) {
		fprintf(stderr, "no cn values for caseid %s\n", caseid);
		goto out;
	}
	struct berval *fcn = *cn_values;

	fprintf(stderr, "TODO: %.*s\n", (int)fcn->bv_len, fcn->bv_val);

	ret = true;
out:
	ldap_value_free_len(cn_values);
	ldap_msgfree(resultchain);
	ldap_unbind_ext_s(ldap, NULL, NULL);
	return ret;
}

static void login_handler(struct request *req, struct response *res, sqlite3 *db) {
	(void)db; (void)req;
	redirect(res, "https://login.case.edu/cas/login?service="SSO_SERVICE);
}

struct auth_callback_userdata {
	size_t len;
	char *ptr;
};

size_t auth_validate_write_callback(char *newdata, size_t size, size_t nmemb, struct auth_callback_userdata *output) {
	(void)size; // always 1
	output->ptr = realloc(output->ptr, output->len + nmemb);
	size_t oldlen = output->len;
	output->len += nmemb;
	memcpy(output->ptr + oldlen, newdata, nmemb);
	return nmemb;
}

static int64_t random_positive_int64(void) {
	int64_t r;
	arc4random_buf(&r, sizeof(r));
	if (r == INT64_MIN)
		r++;
	return labs(r);
}

static int64_t gen_session(sqlite3 *db, char *caseid) {
	int64_t sid = random_positive_int64();
	sqlite3_stmt *del = NULL;
	sqlite3_stmt *ins = NULL;

	sql_prepare_v2(db, "DELETE FROM session WHERE caseid = ?;", -1, &del, NULL);
	sql_bind_text(del, 1, caseid, -1);
	if (sqlite3_step(del) != SQLITE_DONE)
		errx(1, "[%s:%d] %s", __func__, __LINE__, sqlite3_errmsg(db));

	sql_prepare_v2(db, "INSERT INTO session (secret, caseid) VALUES (?, ?);", -1, &ins, NULL);
	sql_bind_int64(ins, 1, sid);
	sql_bind_text(ins, 2, caseid, -1);
	if (sqlite3_step(ins) != SQLITE_DONE)
		errx(1, "[%s:%d] %s", __func__, __LINE__, sqlite3_errmsg(db));

	sqlite3_finalize(del);
	sqlite3_finalize(ins);
	return sid;
}

static void auth_handler(struct request *req, struct response *res, sqlite3 *db) {
	(void)db;
	const char *ticket = request_get_query(req, "ticket");
	if (!ticket) {
		bad_request(res);
		return;
	}

	char url[1024];
	snprintf(url, sizeof(url), "https://login.case.edu/cas/validate?ticket=%s&service="SSO_SERVICE, ticket);

	CURL *c = curl_easy_init();
	struct auth_callback_userdata output = {0};
	curl_easy_setopt(c, CURLOPT_URL, url);
	curl_easy_setopt(c, CURLOPT_HTTPGET, 1L);
	curl_easy_setopt(c, CURLOPT_WRITEDATA, &output);
	curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, auth_validate_write_callback);
	CURLcode err = curl_easy_perform(c);
	if (err != CURLE_OK) {
		fprintf(stderr, "auth validation GET error: %s\n", curl_easy_strerror(err));
		server_error(res);
		goto out;
	}

	if (strncmp(output.ptr, "yes\n", MIN(output.len, 4)) == 0) {
		char *line_ptr = output.ptr + 4;
		size_t line_len = output.len - 4;
		// there's an trailing newline
		if (line_len <= 1) {
			fprintf(stderr, "missing caseid\n");
			server_error(res);
			goto out;
		}
		// replace trailing newline
		line_ptr[line_len - 1] = '\0';
		char *caseid = line_ptr;

		int64_t key = gen_session(db, caseid);
		char sbuf[1024];
		snprintf(sbuf, sizeof(sbuf), "%"PRIx64, key);
		response_set_cookie(res, "s", sbuf);

		char *return_url = request_get_cookie(req, "return");
		if (return_url) {
			redirect(res, return_url);
			response_delete_cookie(res, "return");
		} else {
			redirect(res, "/");
		}
	} else {
		response_add_header(res, "Content-Type", "text/plain");
		response_append_lit(res, "Login failed. Please try again.");
	}

out:
	curl_easy_cleanup(c);
	free(output.ptr);
}

static void logout_handler(struct request *req, struct response *res, sqlite3 *db) {
	(void)req; (void)db;
	response_delete_cookie(res, "s");
	redirect(res, "/");
}

static void index_handler(struct request *req, struct response *res, sqlite3 *db) {
	(void)req; (void)db;
	render_html(res, index, 0);
}

static enum filter_flow require_account(struct request *req, struct response *res, sqlite3 *db) {
	(void)db;
	sqlite3_stmt *uidq = NULL;
	char *sid_str = request_get_cookie(req, "s");
	enum filter_flow ret;
	if (sid_str == NULL || *sid_str == '\0') {
		response_set_cookie(res, "return", req->uri);
		render_html(res, login_prompt, 0);
		ret = FILTER_HALT;
		goto out;
	} else {
		char *endptr;
		int64_t sid = strtol(sid_str, &endptr, 16);
		assert(*endptr == 0);
		int e;

		sql_prepare_v2(
			db,
			"SELECT rowid FROM user\n"
			"JOIN session ON session.caseid = user.caseid\n"
			"WHERE session.secret = ?;",
			-1,
			&uidq,
			NULL
		);
		sql_bind_int64(uidq, 1, sid);

		e = sqlite3_step(uidq);
		if (e == SQLITE_ROW) {
			req->uid = sqlite3_column_int64(uidq, 0);
			ret = FILTER_CONTINUE;
		} else {
			if (e != SQLITE_DONE)
				errx(1, "[%s:%d] %s", __func__, __LINE__, sqlite3_errmsg(db));
			response_delete_cookie(res, "s");
			redirect(res, "/");
			ret = FILTER_HALT;
		}
	}

out:
	sqlite3_finalize(uidq);
	return ret;
}

static void invite_handler(struct request *req, struct response *res, sqlite3 *db) {
	(void)req; (void)db;
	int e;
	sqlite3_stmt *invq = NULL;
	const char *inviter_caseid = NULL;

	const char *refcode = request_get_segment(req, "refcode");
	sql_prepare_v2(
		db,
		"SELECT caseid FROM user WHERE refcode = ?;",
		-1,
		&invq,
		NULL
	);
	sql_bind_text(invq, 1, refcode, -1);
	e = sqlite3_step(invq);
	if (e == SQLITE_ROW) {
		inviter_caseid = (char *)sqlite3_column_text(invq, 0);
	} else {
		if (e != SQLITE_DONE)
			errx(1, "[%s:%d] %s", __func__, __LINE__, sqlite3_errmsg(db));
		response_append_lit(res, "Invalid invite link");
		goto out;
	}

	//////////
	response_append_lit(res, "this is the ref link of: ");
	response_append(res,inviter_caseid,strlen(inviter_caseid));
	goto out;
	//////////

	char *sid_str = request_get_cookie(req, "s");
	if (sid_str == NULL || *sid_str == '\0') {
		response_set_cookie(res, "return", req->uri);
		render_html(
			res,
			invite_login_prompt,
			.inviter_caseid = inviter_caseid,
		);
		goto out;
	}

out:
	sqlite3_finalize(invq);
}

int main(void) {
	struct route_spec routes[] = {
		{ "/", index_handler, FILTERS(require_account) },
		{ "/login", login_handler },
		{ "/logout", logout_handler },
		{ "/auth", auth_handler },
		{ "/join/{refcode}", invite_handler },
	};

	cweb_run(&(struct cweb_args){
		.route_specs = routes,
		.n_route_specs = ARRAY_LEN(routes),
		.port = 8080,
		.db_path = "db.sqlite3"
	});

	return 5;
}
