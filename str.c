#include <ctype.h>
#include <stdlib.h>
#include <err.h>
#include <stdint.h>
#include "str.h"

bool str_eq(str_t a, str_t b) {
	if (a.len != b.len)
		return false;
	for (size_t i = 0; i < a.len; i++) {
		if (a.ptr[i] != b.ptr[i])
			return false;
	}
	return true;
}

bool str_eqz(str_t a, const char *b) {
	for (size_t i = 0; i < a.len; i++) {
		if (b[i] == '\0' || a.ptr[i] != b[i])
			return false;
	}
	return true;
}

bool str_caseqz(str_t a, const char *b) {
	for (size_t i = 0; i < a.len; i++) {
		if (b[i] == '\0' || tolower(a.ptr[i]) != tolower(b[i]))
			return false;
	}
	return true;
}

str_t str_dup(str_t s) {
	str_t ret = { .ptr = malloc(s.len), .len = s.len };
	memcpy((char *)ret.ptr, s.ptr, s.len);
	return ret;
}

char *str_dupz(str_t s) {
	char *ret = malloc(s.len + 1);
	memcpy(ret, s.ptr, s.len);
	ret[s.len] = '\0';
	return ret;
}

int64_t str_toi64(str_t s, bool *ok_out, unsigned base) {
	if (base != 10 && base != 16)
		errx(1, "%s: unsupported base %u", __func__, base);

	int64_t ret = 0;
	*ok_out = false;

	if (s.len == 0)
		goto out;

	if (*s.ptr == '-') {
		ret = -1;
		s.ptr++;
		s.len--;
	}

	if (s.len == 0)
		goto out;

	int64_t place = 1;
	size_t i = s.len - 1;
	for (;;) {
		char ch = tolower(s.ptr[i]);

		if (isdigit(ch)) {
			ret += place * (ch - '0');
		} else if (base == 16 && ch >= 'a' && ch <= 'f') {
			ret += place * (10 + (ch - 'a'));
		} else {
			goto out;
		}

		if (i--)
			place *= base;
		else
			break;
	}

	*ok_out = true;
out:
	return ret;
}

void string_grow(string_t *s, size_t newcap) {
	if (newcap <= s->cap)
		return;
	s->cap = newcap;
	s->ptr = realloc(s->ptr, newcap);
}

void string_append(string_t *s, str_t stuff) {
	size_t newcap = s->cap == 0 ? stuff.len : s->cap;
	while (newcap < s->len + stuff.len)
		newcap *= 2;
	string_grow(s, newcap);
	memcpy(s->ptr + s->len, stuff.ptr, stuff.len);
	s->len += stuff.len;
}

void string_free(string_t *s) {
	free(s->ptr);
	s->len = 0;
	s->ptr = NULL;
	s->cap = 0;
}
