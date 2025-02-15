#ifndef __SQL_WRAPPERS_H
#define __SQL_WRAPPERS_H

#include <err.h>
#include <inttypes.h>
#include "str.h"

static inline void sql_prepare(
	sqlite3 *db,
	str_t zSql,
	sqlite3_stmt **ppStmt
) {
	int err = sqlite3_prepare_v2(db, zSql.ptr, (int)zSql.len, ppStmt, NULL);
	if (err != SQLITE_OK)
		errx(1, "Error in query \"%.*s\": %s", PRSTR(zSql), sqlite3_errmsg(db));
}

static inline void sql_bind_int64(sqlite3_stmt *s, int idx, sqlite3_int64 x) {
	int err = sqlite3_bind_int64(s, idx, x);
	if (err != SQLITE_OK)
		errx(1, "sql_bind_int64(idx = %d, x = %lld): %s", idx, x, sqlite3_errstr(err));
}

static inline void sql_bind_str(
	sqlite3_stmt *s,
	int idx,
	str_t text
) {
	int err = sqlite3_bind_text(s, idx, text.ptr, text.len, SQLITE_STATIC);
	if (err != SQLITE_OK)
		errx(1, "sql_bind_text(idx = %d, text = %.*s): %s", idx, PRSTR(text), sqlite3_errstr(err));
}

static inline str_t sql_column_str(
	sqlite3_stmt *s,
	int iCol
) {
	str_t ret = {
		.ptr = (char *)sqlite3_column_text(s, iCol),
		.len = sqlite3_column_bytes(s, iCol),
	};
	return ret;
}

#endif
