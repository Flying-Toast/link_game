#ifndef __STR_H
#define __STR_H

#include <stddef.h>
#include <stdbool.h>

#define PRSTR(s) (int)(s).len, (s).ptr
#define STR(lit) (str_t){ .ptr = ""lit"", .len = sizeof(lit) - 1 }

typedef struct {
	size_t len;
	const char *ptr;
} str_t;

typedef struct {
	size_t cap;
	size_t len;
	char *ptr;
} string_t;

static inline str_t string2str(string_t s) {
	str_t ret = {
		.ptr = s.ptr,
		.len = s.len,
	};
	return ret;
}

bool str_eq(str_t a, str_t b);
bool str_eqz(str_t a, const char *b);
bool str_caseqz(str_t a, const char *b);
str_t str_dup(str_t s);
char *str_dupz(str_t s);
int64_t str_toi64(str_t s, bool *ok_out, unsigned base);

void string_append(string_t *s, str_t stuff);
void string_grow(string_t *s, size_t newcap);

#endif
