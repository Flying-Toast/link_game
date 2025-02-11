#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <err.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include "str.h"

#define ARRAY_LEN(arr) (sizeof(arr) / sizeof((arr)[0]))

const struct {
	const char *fmt;
	const char *type;
} specspecs[] = {
	{ "d", "int " },
	{ "s", "str_t " },
};

static const char *spectype(str_t fmt) {
	for (size_t i = 0; i < ARRAY_LEN(specspecs); i++) {
		if (strncmp(specspecs[i].fmt, fmt.ptr, fmt.len) == 0)
			return specspecs[i].type;
	}
	return NULL;
}

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

static size_t next_placeholder(const char *ptr) {
	ssize_t dist = 0;
	while (ptr[dist] && strncmp(ptr + dist, "<%", 2) != 0)
		dist++;
	return dist;
}

static size_t parse_placeholder(
	char *placeholder_start,
	// borrowed from buf
	str_t *spec_out,
	// borrowed from buf
	str_t *name_out
) {
	char *ptr = placeholder_start;
	assert(*(ptr++) == '<');
	assert(*(ptr++) == '%');

	spec_out->ptr = ptr;
	while (*ptr != ' ')
		assert(*(ptr++) != '\0');
	spec_out->len = ptr - spec_out->ptr;
	assert(*(ptr++) == ' ');

	name_out->ptr = ptr;
	while (*ptr != '>')
		assert(*(ptr++) != '\0');
	name_out->len = ptr - name_out->ptr;
	assert(*(ptr++) == '>');

	return ptr - placeholder_start;
}

static void print_strlit(const char *ptr, size_t len) {
	putchar('"');
	for (size_t i = 0; i < len; i++) {
		switch (ptr[i]) {
		case '\n':
			printf("\\n");
			break;
		case '\t':
			printf("\\t");
			break;
		case '"':
			printf("\\\"");
			break;
		case '?':
			// stupid trigraphs
			printf("\"\"?\"\"");
			break;
		case '\\':
			printf("\\");
			break;
		default:
			putchar(ptr[i]);
			break;
		}
	}
	putchar('"');
}

static void append_arg(str_t spec, str_t name) {
	if (strncmp("s", spec.ptr, spec.len) == 0) {
		printf(
			"\tcweb_append_html_escaped(res, args->%.*s);\n"
			,(int)name.len
			,name.ptr
		);
	} else {
		printf("\t{\n");
		printf("\t\tchar buf[1024];\n");
		printf(
			"\t\tint nwrite = snprintf(buf, sizeof(buf), \"%%%.*s\", args->%.*s);\n"
			,(int)spec.len
			,spec.ptr
			,(int)name.len
			,name.ptr
		);
		printf("\t\tassert((size_t)nwrite < sizeof(buf));\n");
		printf("\t\tcweb_append(res, buf, nwrite);\n");
		printf("\t}\n");
	}
}

static bool strvec_contains(const str_t *haystack, size_t n, str_t needle) {
	for (size_t i = 0; i < n; i++) {
		str_t cur = haystack[i];
		if (needle.len == cur.len && strncmp(cur.ptr, needle.ptr, cur.len) == 0)
			return true;
	}
	return false;
}

static void do_args(const char *basename, char *buf) {
	size_t nargs = 0;
	str_t *seen_args = NULL;
	printf("struct __tmplargs_%s {\n", basename);

	while (*buf) {
		buf += next_placeholder(buf);
		if (*buf == 0)
			break;
		str_t spec, name;
		buf += parse_placeholder(buf, &spec, &name);

		if (strvec_contains(seen_args, nargs, name))
			continue;
		seen_args = realloc(seen_args, sizeof(*seen_args) * (nargs + 1));
		seen_args[nargs] = name;

		const char *type = spectype(spec);
		if (!type)
			errx(1, "no specspec for %%%.*s", (int)spec.len, spec.ptr);
		printf("\t%s%.*s;\n", type, (int)name.len, name.ptr);
		nargs++;
	}
	if (nargs == 0)
		printf("\tint __unused;\n");
	printf("};\n");

	free(seen_args);
}

static void do_func(const char *basename, char *buf) {
	printf(
		"static void __tmplfunc_%s(struct response *res, const struct __tmplargs_%s *args) {\n"
		,basename
		,basename
	);
	printf("\t(void)args;\n");

	while (*buf) {
		const char *runstart = buf;
		buf += next_placeholder(buf);

		printf("\tcweb_append(res, STR(");
		print_strlit(runstart, buf - runstart);
		printf("));\n");

		if (*buf == 0)
			break;

		str_t spec, name;
		buf += parse_placeholder(buf, &spec, &name);
		append_arg(spec, name);
	}
	printf("}\n");
}

int main(int argc, char **argv) {
	char *buf = NULL;
	off_t cap = 0;

	for (int i = 1; i < argc; i++) {
		struct stat statbuf;
		char *fname = argv[i];
		if (stat(fname, &statbuf) == -1)
			err(1, "stat");

		off_t needcap = statbuf.st_size + 1;
		if (needcap > cap) {
			free(buf);
			buf = malloc(needcap);
			cap = needcap;
		}

		int fd = open(fname, O_RDONLY);
		if (fd == -1)
			err(1, "open");
		readall(fd, buf, statbuf.st_size);
		buf[statbuf.st_size] = '\0';
		if (statbuf.st_size > 1 && buf[statbuf.st_size - 1] == '\n')
			buf[statbuf.st_size - 1] = '\0';
		close(fd);

		const char *basename = fname + strlen(fname);
		while (basename > fname && basename[-1] != '/')
			basename--;

		do_args(basename, buf);
		do_func(basename, buf);

		if (i != argc - 1)
			puts("");
	}
}
