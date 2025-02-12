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

static bool store_user_ldap_info(str_t caseid, sqlite3 *db) {
	int e;
	bool ret = false;
	LDAP *ldap = NULL;
	LDAPMessage *resultchain = NULL;
	struct berval **cn_values = NULL;
	struct berval **title_values = NULL;
	struct berval **gname_values = NULL;
	sqlite3_stmt *s = NULL;
	str_t fullname = caseid;
	str_t firstname = caseid;

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
	snprintf(filter, sizeof(filter), "(uid=%.*s)", PRSTR(caseid));
	char *attrs[] = {"cn", "title", "givenName", NULL};
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
		-1,
		&resultchain
	);
	if (e) {
		fprintf(stderr, "ldap_search_ext_s: %s\n", ldap_err2string(e));
		goto out;
	}

	LDAPMessage *fent = ldap_first_entry(ldap, resultchain);
	if (fent != NULL) {
		cn_values = ldap_get_values_len(ldap, fent, "cn");
		if (cn_values != NULL && cn_values[0] != NULL) {
			fullname.ptr = cn_values[0]->bv_val;
			fullname.len = cn_values[0]->bv_len;
		}
		gname_values = ldap_get_values_len(ldap, fent, "givenName");
		if (gname_values != NULL && gname_values[0] != NULL) {
			firstname.ptr = gname_values[0]->bv_val;
			firstname.len = gname_values[0]->bv_len;
		}
		title_values = ldap_get_values_len(ldap, fent, "title");
	}

	sql_prepare_v2(
		db,
		"UPDATE user SET fullname = ?, ldap_title = ?, firstname = ? WHERE caseid = ?;",
		-1,
		&s,
		NULL
	);
	sql_bind_text(s, 1, fullname);
	if (title_values && title_values[0] != NULL) {
		str_t tv = {
			.ptr = title_values[0]->bv_val,
			.len = title_values[0]->bv_len,
		};
		sql_bind_text(s, 2, tv);
	}
	sql_bind_text(s, 3, firstname);
	sql_bind_text(s, 4, caseid);
	if (sqlite3_step(s) != SQLITE_DONE)
		errx(1, "[%s:%d] %s", __func__, __LINE__, sqlite3_errmsg(db));

	ret = true;
out:
	sqlite3_finalize(s);
	ldap_value_free_len(cn_values);
	ldap_value_free_len(title_values);
	ldap_value_free_len(gname_values);
	ldap_msgfree(resultchain);
	ldap_unbind_ext_s(ldap, NULL, NULL);
	return ret;
}

static void login_handler(struct request *req, struct response *res, sqlite3 *db) {
	(void)db; (void)req;
	redirect(res, STR("https://login.case.edu/cas/login?service="SSO_SERVICE));
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
	sql_bind_text(del, 1, ztostr(caseid));
	if (sqlite3_step(del) != SQLITE_DONE)
		errx(1, "[%s:%d] %s", __func__, __LINE__, sqlite3_errmsg(db));

	sql_prepare_v2(db, "INSERT INTO session (secret, caseid) VALUES (?, ?);", -1, &ins, NULL);
	sql_bind_int64(ins, 1, sid);
	sql_bind_text(ins, 2, ztostr(caseid));
	if (sqlite3_step(ins) != SQLITE_DONE)
		errx(1, "[%s:%d] %s", __func__, __LINE__, sqlite3_errmsg(db));

	sqlite3_finalize(del);
	sqlite3_finalize(ins);
	return sid;
}

static void auth_handler(struct request *req, struct response *res, sqlite3 *db) {
	(void)db;
	const str_t *ticket = cweb_get_query(req, STR("ticket"));
	if (!ticket) {
		bad_request(res);
		return;
	}

	char url[1024];
	snprintf(url, sizeof(url), "https://login.case.edu/cas/validate?ticket=%.*s&service="SSO_SERVICE, PRSTR(*ticket));

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
		int nwrite = snprintf(sbuf, sizeof(sbuf), "%"PRIx64, key);
		str_t sstr = { .ptr = sbuf, .len = nwrite };
		cweb_set_cookie(res, STR("s"), sstr);

		const str_t *return_url = cweb_get_cookie(req, STR("return"));
		if (return_url) {
			redirect(res, *return_url);
			cweb_delete_cookie(res, STR("return"));
		} else {
			redirect(res, STR("/"));
		}
	} else {
		cweb_add_header(res, STR("Content-Type"), STR("text/plain"));
		cweb_append(res, STR("Login failed. Please try again."));
	}

out:
	curl_easy_cleanup(c);
	free(output.ptr);
}

static void logout_handler(struct request *req, struct response *res, sqlite3 *db) {
	(void)req; (void)db;
	cweb_delete_cookie(res, STR("s"));
	render_html(res, logout, 0);
}

static void index_handler(struct request *req, struct response *res, sqlite3 *db) {
	(void)req; (void)db;
	sqlite3_stmt *q = NULL;

	sql_prepare_v2(
		db,
		"SELECT refcode, firstname FROM user WHERE rowid = ?;",
		-1,
		&q,
		NULL
	);
	sql_bind_int64(q, 1, req->uid);
	if (sqlite3_step(q) != SQLITE_ROW)
		errx(1, "[%s:%d] %s", __func__, __LINE__, sqlite3_errmsg(db));
	str_t refcode = sql_column_str(q, 0);
	str_t firstname = sql_column_str(q, 1);

	render_html(res, index, .refcode = refcode, .myname = firstname);
	sqlite3_finalize(q);
}

static void welcome_handler(struct request *req, struct response *res, sqlite3 *db) {
	(void)req; (void)db;
	sqlite3_stmt *q = NULL;

	sql_prepare_v2(
		db,
		"SELECT firstname FROM user WHERE rowid = ?;",
		-1,
		&q,
		NULL
	);
	sql_bind_int64(q, 1, req->uid);
	if (sqlite3_step(q) != SQLITE_ROW)
		errx(1, "[%s:%d] %s", __func__, __LINE__, sqlite3_errmsg(db));
	str_t firstname = sql_column_str(q, 0);

	render_html(res, welcome, .myname = firstname);
	sqlite3_finalize(q);
}

static int64_t uid_from_sid(sqlite3 *db, int64_t sid) {
	sqlite3_stmt *q = NULL;
	int64_t uid;
	sql_prepare_v2(
		db,
		"SELECT rowid FROM user\n"
		"JOIN session ON session.caseid = user.caseid\n"
		"WHERE session.secret = ?;",
		-1,
		&q,
		NULL
	);
	sql_bind_int64(q, 1, sid);

	int e = sqlite3_step(q);
	if (e == SQLITE_ROW) {
		uid = sqlite3_column_int64(q, 0);
	} else {
		if (e != SQLITE_DONE)
			errx(1, "[%s:%d] %s", __func__, __LINE__, sqlite3_errmsg(db));
		uid = 0;
	}
	sqlite3_finalize(q);
	return uid;
}

static int64_t getsid(struct request *req) {
	const str_t *sid_str = cweb_get_cookie(req, STR("s"));
	if (sid_str == NULL || sid_str->len == 0)
		return -1;

	bool ok;
	int64_t sid = str_toi64(*sid_str, &ok, 16);
	if (!ok)
		return -1;
	return sid;
}

static enum filter_flow require_account(struct request *req, struct response *res, sqlite3 *db) {
	(void)db;
	int64_t sid = getsid(req);
	if (sid == -1) {
		cweb_set_cookie(res, STR("return"), req->uri);
		render_html(res, login_prompt, 0);
		return FILTER_HALT;
	}

	if ((req->uid = uid_from_sid(db, sid)) != 0) {
		return FILTER_CONTINUE;
	} else {
		render_html(res, account_needed, 0);
		return FILTER_HALT;
	}
}

static void create_user(
	sqlite3 *db,
	int64_t inviter_uid,
	int64_t current_sid
) {
	char refcodebuf[100];
	str_t refcodestr = {
		.len = snprintf(refcodebuf, sizeof(refcodebuf), "%"PRIx64, random_positive_int64()),
		.ptr = refcodebuf
	};

	sqlite3_stmt *ins = NULL;
	sql_prepare_v2(
		db,
		"INSERT INTO user (inviter, refcode, caseid)\n"
		"VALUES (?, ?, (SELECT caseid FROM session WHERE secret = ?));",
		-1,
		&ins,
		NULL
	);
	sql_bind_int64(ins, 1, inviter_uid);
	sql_bind_text(ins, 2, refcodestr);
	sql_bind_int64(ins, 3, current_sid);
	if (sqlite3_step(ins) != SQLITE_DONE)
		errx(1, "[%s:%d] %s", __func__, __LINE__, sqlite3_errmsg(db));

	sqlite3_stmt *caseid_q = NULL;
	sql_prepare_v2(
		db,
		"SELECT caseid FROM session WHERE secret = ?;",
		-1,
		&caseid_q,
		NULL
	);
	sql_bind_int64(caseid_q, 1, current_sid);
	if (sqlite3_step(caseid_q) != SQLITE_ROW)
		errx(1, "[%s:%d] %s", __func__, __LINE__, sqlite3_errmsg(db));
	str_t caseid = sql_column_str(caseid_q, 0);

	store_user_ldap_info(caseid, db);

	sqlite3_finalize(ins);
	sqlite3_finalize(caseid_q);
}

static void invite_handler(struct request *req, struct response *res, sqlite3 *db) {
	(void)req; (void)db;
	int e;
	sqlite3_stmt *invq = NULL;
	str_t inviter_name = {0};
	int64_t inviter_uid;

	// check if user already exists
	int64_t sid = getsid(req);
	if (sid != -1 && uid_from_sid(db, sid) != 0) {
		render_html(res, already_joined, 0);
		goto out;
	}

	str_t refcode = *cweb_get_segment(req, STR("refcode"));
	sql_prepare_v2(
		db,
		"SELECT rowid, fullname FROM user WHERE refcode = ?;",
		-1,
		&invq,
		NULL
	);
	sql_bind_text(invq, 1, refcode);
	e = sqlite3_step(invq);
	if (e == SQLITE_ROW) {
		inviter_uid = sqlite3_column_int64(invq, 0);
		inviter_name = sql_column_str(invq, 1);
	} else {
		if (e != SQLITE_DONE)
			errx(1, "[%s:%d] %s", __func__, __LINE__, sqlite3_errmsg(db));
		cweb_append(res, STR("Invalid invite link"));
		goto out;
	}

	if (sid == -1) {
		cweb_set_cookie(res, STR("return"), req->uri);
		render_html(
			res,
			invite_login_prompt,
			.inviter_name = inviter_name,
		);
	} else {
		create_user(db, inviter_uid, sid);
		redirect(res, STR("/welcome"));
	}

out:
	sqlite3_finalize(invq);
}

int main(void) {
	struct route_spec routes[] = {
		{ "/login", login_handler },
		{ "/logout", logout_handler },
		{ "/auth", auth_handler },
		{ "/join/{refcode}", invite_handler },
		{ "/static/style.css", cweb_static_handler },

		{ "/", index_handler, FILTERS(require_account) },
		{ "/welcome", welcome_handler, FILTERS(require_account) },
	};

	cweb_run(&(struct cweb_args){
		.route_specs = routes,
		.n_route_specs = ARRAY_LEN(routes),
		.port = 8080,
		.db_path = "db.sqlite3"
	});

	return 5;
}
