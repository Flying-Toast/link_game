#include <curl/curl.h>
#include <assert.h>
#include <time.h>
#include <err.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <ldap.h>
#include "cweb.h"
#include "sql_wrappers.h"
#include "tmplfuncs.gen"

#define ARRAY_LEN(arr) (sizeof(arr) / sizeof((arr)[0]))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

#ifdef RELEASE_BUILD
#	define PORT 80
#	define SSO_SERVICE "https://symphonious-ganache-5f42c4.netlify.app/"
#else
#	define PORT 8080
#	define SSO_SERVICE "https://fascinating-mochi-9ef846.netlify.app/"
#endif

static const char *w_arg;
static const char *e_arg;
static bool z_flag;

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

	sql_prepare(
		db,
		STR("UPDATE user SET fullname = ?, ldap_title = ?, firstname = ? WHERE caseid = ?;"),
		&s
	);
	sql_bind_str(s, 1, fullname);
	if (title_values && title_values[0] != NULL) {
		str_t tv = {
			.ptr = title_values[0]->bv_val,
			.len = title_values[0]->bv_len,
		};
		sql_bind_str(s, 2, tv);
	}
	sql_bind_str(s, 3, firstname);
	sql_bind_str(s, 4, caseid);
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

// caller frees returned string
static string_t render_tree_data(sqlite3 *db) {
	sqlite3_stmt *s = NULL;
	int e;
	string_t ret = {0};
	string_append(&ret, STR("let inviteData=null;let m=new Map();function a(uid,fullname,inviterUid,caseid){let o={n:fullname,children:[],c:caseid};m.set(uid,o);if(uid==inviterUid){inviteData=o;}else{m.get(inviterUid).children.push(o);}}"));

	sql_prepare(db, STR("SELECT rowid, fullname, inviter, caseid FROM user ORDER BY rowid ASC;"), &s);

	while ((e = sqlite3_step(s)) == SQLITE_ROW) {
		int64_t uid = sqlite3_column_int64(s, 0);
		str_t fullname = sql_column_str(s, 1);
		int64_t inviter = sqlite3_column_int64(s, 2);
		str_t caseid = sql_column_str(s, 3);

		// TODO: escape double quotes and backslashes from fullname
		assert(memchr(fullname.ptr, '"', fullname.len) == NULL);
		assert(memchr(fullname.ptr, '\\', fullname.len) == NULL);

		char buf[4096];
		str_t item = { .ptr = buf };
		item.len = snprintf(
			buf,
			sizeof(buf),
			"a(%"PRId64",\"%.*s\",%"PRId64",\"%.*s\");"
			,uid
			,PRSTR(fullname)
			,inviter
			,PRSTR(caseid)
		);
		assert(item.len < sizeof(buf));
		string_append(&ret, item);
	}
	if (e != SQLITE_DONE)
		errx(1, "[%s:%d] %s", __func__, __LINE__, sqlite3_errmsg(db));

	sqlite3_finalize(s);
	return ret;
}

// pass uid=-1 for global counts
static void refcounts(
	sqlite3 *db,
	int64_t uid,
	int64_t *n_stud,
	int64_t *n_fac,
	int64_t *n_kaler
) {
	sqlite3_stmt *s = NULL;

	sql_prepare(
		db,
		STR("SELECT\n"
			"SUM(CASE WHEN ldap_title IS NULL THEN 1 ELSE 0 END),\n"
			"SUM(CASE WHEN ldap_title IS NOT NULL AND caseid <> 'ewk42' THEN 1 ELSE 0 END),\n"
			"SUM(CASE WHEN caseid = 'ewk42' THEN 1 ELSE 0 END)\n"
			"FROM user WHERE (inviter = ? OR ?) AND inviter <> rowid;"),
		&s
	);
	sql_bind_int64(s, 1, uid);
	sql_bind_int64(s, 2, uid == -1);

	if (sqlite3_step(s) != SQLITE_ROW)
		errx(1, "[%s:%d] %s", __func__, __LINE__, sqlite3_errmsg(db));

	*n_stud = sqlite3_column_int64(s, 0);
	*n_fac = sqlite3_column_int64(s, 1);
	*n_kaler = sqlite3_column_int64(s, 2);

	sqlite3_finalize(s);
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

	sql_prepare(db, STR("DELETE FROM session WHERE caseid = ?;"), &del);
	sql_bind_str(del, 1, ztostr(caseid));
	if (sqlite3_step(del) != SQLITE_DONE)
		errx(1, "[%s:%d] %s", __func__, __LINE__, sqlite3_errmsg(db));

	sql_prepare(db, STR("INSERT INTO session (secret, caseid) VALUES (?, ?);"), &ins);
	sql_bind_int64(ins, 1, sid);
	sql_bind_str(ins, 2, ztostr(caseid));
	if (sqlite3_step(ins) != SQLITE_DONE)
		errx(1, "[%s:%d] %s", __func__, __LINE__, sqlite3_errmsg(db));

	sqlite3_finalize(del);
	sqlite3_finalize(ins);
	return sid;
}

static void auth_handler(struct request *req, struct response *res, sqlite3 *db) {
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

static void tree_handler(struct request *req, struct response *res, sqlite3 *db) {
	(void)req; (void)db;
	render_html(res, tree, 0);
}

static void treedata_handler(struct request *req, struct response *res, sqlite3 *db) {
	(void)req;
	assert(res->body.len == 0);
	res->body = render_tree_data(db);
}

static void index_handler(struct request *req, struct response *res, sqlite3 *db) {
	sqlite3_stmt *q = NULL;
	sqlite3_stmt *recents_q = NULL;

	sql_prepare(
		db,
		STR("SELECT refcode, firstname FROM user WHERE rowid = ?;"),
		&q
	);
	sql_bind_int64(q, 1, req->uid);
	if (sqlite3_step(q) != SQLITE_ROW)
		errx(1, "[%s:%d] %s", __func__, __LINE__, sqlite3_errmsg(db));
	str_t refcode = sql_column_str(q, 0);
	str_t firstname = sql_column_str(q, 1);

	sql_prepare(
		db,
		STR("SELECT joiner.caseid, joiner.fullname, inviter.caseid, inviter.fullname\n"
		"FROM user AS joiner\n"
		"JOIN user AS inviter ON inviter.rowid = joiner.inviter\n"
		"ORDER BY joiner.rowid DESC\n"
		"LIMIT 1"),
		&recents_q
	);
	if (sqlite3_step(recents_q) != SQLITE_ROW)
		errx(1, "[%s:%d] %s", __func__, __LINE__, sqlite3_errmsg(db));
	str_t joinercaseid = sql_column_str(recents_q, 0);
	str_t joinername = sql_column_str(recents_q, 1);
	str_t invitercaseid = sql_column_str(recents_q, 2);
	str_t invitername = sql_column_str(recents_q, 3);

	int64_t my_nstud, my_nfac, my_nkaler;
	int64_t g_nstud, g_nfac, g_nkaler;
	refcounts(db, req->uid, &my_nstud, &my_nfac, &my_nkaler);
	refcounts(db, -1, &g_nstud, &g_nfac, &g_nkaler);

	render_html(
		res,
		index,
		.refcode = refcode,
		.myname = firstname,
		.my_nstud = my_nstud,
		.my_nfac = my_nfac,
		.my_nkaler = my_nkaler,
		.my_total = my_nstud + my_nfac + my_nkaler,
		.g_nstud = g_nstud,
		.g_nfac = g_nfac,
		.g_nkaler = g_nkaler,
		.g_total = g_nstud + g_nfac + g_nkaler,
		.recentinvitercaseid = invitercaseid,
		.recentinvitername = invitername,
		.recentjoinercaseid = joinercaseid,
		.recentjoinername = joinername,
	);
	sqlite3_finalize(q);
	sqlite3_finalize(recents_q);
}

static void welcome_handler(struct request *req, struct response *res, sqlite3 *db) {
	sqlite3_stmt *q = NULL;

	sql_prepare(
		db,
		STR("SELECT firstname FROM user WHERE rowid = ?;"),
		&q
	);
	sql_bind_int64(q, 1, req->uid);
	if (sqlite3_step(q) != SQLITE_ROW)
		errx(1, "[%s:%d] %s", __func__, __LINE__, sqlite3_errmsg(db));
	str_t firstname = sql_column_str(q, 0);

	render_html(res, welcome, .myname = firstname);
	sqlite3_finalize(q);
}

static int64_t sid_valid(sqlite3 *db, int64_t sid) {
	sqlite3_stmt *q = NULL;
	sql_prepare(
		db,
		STR("SELECT count(*) FROM session WHERE secret = ?;"),
		&q
	);
	sql_bind_int64(q, 1, sid);

	int e = sqlite3_step(q);
	if (e != SQLITE_ROW)
		errx(1, "[%s:%d] %s", __func__, __LINE__, sqlite3_errmsg(db));

	int64_t nsessions = sqlite3_column_int64(q, 0);

	sqlite3_finalize(q);
	return nsessions != 0;
}

static int64_t uid_from_sid(sqlite3 *db, int64_t sid) {
	sqlite3_stmt *q = NULL;
	int64_t uid;
	sql_prepare(
		db,
		STR("SELECT rowid FROM user\n"
		"JOIN session ON session.caseid = user.caseid\n"
		"WHERE session.secret = ?;"),
		&q
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

static int64_t getsessid(struct request *req) {
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
	int64_t sid = getsessid(req);
	if (sid == -1) {
		cweb_set_cookie(res, STR("return"), req->uri);
		render_html(res, login_prompt, 0);
		return FILTER_HALT;
	}

	if ((req->uid = uid_from_sid(db, sid)) != 0) {
		return FILTER_CONTINUE;
	} else {
		if (sid_valid(db, sid)) {
			render_html(res, account_needed, 0);
		} else {
			cweb_delete_cookie(res, STR("s"));
			redirect(res, STR("/"));
		}
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
	sql_prepare(
		db,
		STR("INSERT INTO user (inviter, refcode, caseid)\n"
		"VALUES (?, ?, (SELECT caseid FROM session WHERE secret = ?));"),
		&ins
	);
	sql_bind_int64(ins, 1, inviter_uid);
	sql_bind_str(ins, 2, refcodestr);
	sql_bind_int64(ins, 3, current_sid);
	if (sqlite3_step(ins) != SQLITE_DONE)
		errx(1, "[%s:%d] %s", __func__, __LINE__, sqlite3_errmsg(db));

	sqlite3_stmt *caseid_q = NULL;
	sql_prepare(
		db,
		STR("SELECT caseid FROM session WHERE secret = ?;"),
		&caseid_q
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
	int e;
	sqlite3_stmt *invq = NULL;
	str_t inviter_name = {0};
	int64_t inviter_uid;

	str_t refcode = *cweb_get_segment(req, STR("refcode"));
	sql_prepare(
		db,
		STR("SELECT rowid, fullname FROM user WHERE refcode = ?;"),
		&invq
	);
	sql_bind_str(invq, 1, refcode);
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

	// check if user already exists
	int64_t sid = getsessid(req);
	int64_t session_uid = uid_from_sid(db, sid);
	if (sid != -1 && session_uid != 0) {
		if (session_uid == inviter_uid) {
			render_html(res, qrcode, .refcode = refcode, .fullname = inviter_name);
		} else {
			render_html(res, already_joined, 0);
		}
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
		if (sid_valid(db, sid)) {
			create_user(db, inviter_uid, sid);
			redirect(res, STR("/welcome"));
		} else {
			cweb_delete_cookie(res, STR("s"));
			redirect(res, STR("/"));
		}
	}

out:
	sqlite3_finalize(invq);
}

// if uid==-1, shows all events. otherwise, just people invited by `uid`.
static void render_events(struct response *res, sqlite3 *db, int64_t uid) {
	sqlite3_stmt *s = NULL;
	int e;
	sql_prepare(
		db,
		STR("SELECT joiner.caseid, joiner.fullname, joiner.join_time, inviter.fullname\n"
		"FROM user AS joiner\n"
		"JOIN user AS inviter ON inviter.rowid = joiner.inviter\n"
		"WHERE (inviter.rowid = ? OR ?) AND inviter.rowid <> joiner.rowid\n"
		"ORDER BY joiner.rowid ASC;"),
		&s
	);
	sqlite3_bind_int64(s, 1, uid);
	sqlite3_bind_int64(s, 2, uid == -1);

	int64_t n = 1;

	while ((e = sqlite3_step(s)) == SQLITE_ROW) {
		str_t joinercaseid = sql_column_str(s, 0);
		str_t joinername = sql_column_str(s, 1);
		int64_t unixjointime = sqlite3_column_int64(s, 2);
		str_t invitername = sql_column_str(s, 3);
		struct tm *jointime = localtime(&unixjointime);

		char datebuf[1024];
		strftime(datebuf, sizeof(datebuf), "%m/%d/%y %l:%M %p", jointime);

		char buf[1024];
		str_t s = { .ptr = buf };
		s.len = snprintf(
			buf,
			sizeof(buf),
			"%"PRId64": %s - %.*s invited %.*s (%.*s)\n"
			,n++
			,datebuf
			,PRSTR(invitername)
			,PRSTR(joinername)
			,PRSTR(joinercaseid)
		);
		cweb_append(res, s);
	}
	if (e != SQLITE_DONE)
		errx(1, "[%s:%d] %s", __func__, __LINE__, sqlite3_errmsg(db));

	cweb_add_header(res, STR("Content-Type"), STR("text/plain"));
	sqlite3_finalize(s);
}

static void global_events_handler(struct request *req, struct response *res, sqlite3 *db) {
	(void)req;
	render_events(res, db, -1);
}

static int64_t uidfromcaseid(sqlite3 *db, str_t caseid) {
	sqlite3_stmt *s = NULL;
	int64_t ret = -1;

	sql_prepare(db, STR("SELECT rowid FROM user WHERE caseid = ?;"), &s);
	sql_bind_str(s, 1, caseid);

	int e = sqlite3_step(s);
	if (e == SQLITE_DONE) {
		ret = -1;
		goto out;
	} else if (e != SQLITE_ROW) {
		errx(1, "[%s:%d] %s", __func__, __LINE__, sqlite3_errmsg(db));
	}

	ret = sqlite3_column_int64(s, 0);
out:
	sqlite3_finalize(s);
	return ret;
}

static void profile_events_handler(struct request *req, struct response *res, sqlite3 *db) {
	(void)req;

	str_t caseid = *cweb_get_segment(req, STR("caseid"));
	int64_t uid = uidfromcaseid(db, caseid);
	if (uid == -1) {
		not_found(res);
		return;
	}

	render_events(res, db, uid);
}

void profile_handler(struct request *req, struct response *res, sqlite3 *db) {
	sqlite3_stmt *s = NULL;
	str_t caseid = *cweb_get_segment(req, STR("caseid"));

	sql_prepare(
		db,
		STR("SELECT me.rowid, me.fullname, inviter.caseid, inviter.fullname FROM user AS me\n"
		"JOIN user AS inviter ON inviter.rowid = me.inviter\n"
		"WHERE me.caseid = ?;"),
		&s
	);
	sql_bind_str(s, 1, caseid);
	if (sqlite3_step(s) != SQLITE_ROW)
		errx(1, "[%s:%d] %s", __func__, __LINE__, sqlite3_errmsg(db));
	int64_t uid = sqlite3_column_int64(s, 0);
	str_t fullname = sql_column_str(s, 1);
	str_t inviter_caseid = sql_column_str(s, 2);
	str_t inviter_fullname = sql_column_str(s, 3);

	int64_t nstud, nfac, nkaler;
	refcounts(db, uid, &nstud, &nfac, &nkaler);

	render_html(
		res,
		profile,
		.myname = fullname,
		.nstud = nstud,
		.nfac = nfac,
		.nkaler = nkaler,
		.totinvites = nstud + nfac + nkaler,
		.caseid = caseid,
		.inviter_caseid = inviter_caseid,
		.inviter_fullname = inviter_fullname,
	);
	sqlite3_finalize(s);
}

static void opts(int argc, char **argv) {
	int ch;
	while ((ch = getopt(argc, argv, "e:zw:")) != -1) {
		switch (ch) {
		case 'e':
			e_arg = optarg;
			break;
		case 'w':
			w_arg = optarg;
			break;
		case 'z':
			z_flag = true;
			break;
		default:
			errx(1, "unknown flag %c", ch);
			break;
		}
	}
	argc -= optind;
	argv += optind;
}

int main(int argc, char **argv) {
	opts(argc, argv);

	if (w_arg == NULL)
		errx(1, "missing -d working_dir");
	if (chdir(w_arg) == -1)
		err(1, "chdir");

	if (z_flag && daemon(1, 1))
		err(1, "daemon");

	if (e_arg) {
		int efd = open(e_arg, O_WRONLY | O_CREAT, 0644);
		if (efd == -1)
			err(1, "open(e_arg)");
		if (dup2(efd, 2) == -1)
			err(1, "dup2(efd)");
	}

	int static_dir = open("static", O_DIRECTORY);
	if (static_dir == -1)
		err(1, "open(\"static\")");

#ifdef __OpenBSD__
	if (unveil(".", "rwc") == -1
		|| unveil("/etc/resolv.conf", "r") == -1
		|| unveil("/etc/ssl", "r") == -1
		|| unveil(NULL, NULL) == -1
	) {
		err(1, "unveil");
	}
	if (pledge("wpath rpath cpath flock stdio proc id inet dns", "") == -1)
		err(1, "pledge");
#endif

	struct route_spec routes[] = {
		{ "/login", login_handler },
		{ "/logout", logout_handler },
		{ "/auth", auth_handler },
		{ "/join/{refcode}", invite_handler },
		{ "/style.css", cweb_static_handler },
		{ "/d3.js", cweb_static_handler },
		{ "/qr.js", cweb_static_handler },

		{ "/", index_handler, FILTERS(require_account) },
		{ "/welcome", welcome_handler, FILTERS(require_account) },
		{ "/tree", tree_handler, FILTERS(require_account) },
		{ "/treedata.js", treedata_handler, FILTERS(require_account) },
		{ "/profile/{caseid}", profile_handler, FILTERS(require_account) },
		{ "/profile/{caseid}/events", profile_events_handler, FILTERS(require_account) },
		{ "/events", global_events_handler, FILTERS(require_account) },
	};

	cweb_run(&(struct cweb_args){
		.route_specs = routes,
		.n_route_specs = ARRAY_LEN(routes),
		.port = PORT,
		.db_path = "db.sqlite3",
		.static_dir = static_dir,
	});

	return 5;
}
