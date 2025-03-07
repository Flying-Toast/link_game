#include <string.h>
#include <inttypes.h>
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

static const struct spec {
	const char *placeholder_fmt;
	const char *printf_fmt;
	const char *type;
} specs[] = {
	// NULL because str is special-cased to escape HTML
	{ "str", NULL, "str_t " },
	{ "i64", PRId64, "int64_t " },
};

static const struct spec *getspec(str_t fmt) {
	for (size_t i = 0; i < ARRAY_LEN(specs); i++) {
		if (strncmp(specs[i].placeholder_fmt, fmt.ptr, fmt.len) == 0)
			return &specs[i];
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

char *read_file(const char *fname) {
	struct stat sb;
	if (stat(fname, &sb) == -1)
		err(1, "stat(%s)", fname);
	int fd = open(fname, O_RDONLY);
	if (fd == -1)
		err(1, "open");
	char *buf = malloc(sb.st_size + 1);
	if (readall(fd, buf, sb.st_size) == -1)
		err(1, "readall");
	buf[sb.st_size] = '\0';
	close(fd);
	return buf;
}

static size_t next_placeholder(const char *ptr) {
	size_t dist = 0;
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

static void append_arg(str_t specname, str_t name) {
	const struct spec *spec = getspec(specname);
	if (!spec)
		errx(1, "No spec for %%%.*s", PRSTR(specname));

	if (strncmp("str", specname.ptr, specname.len) == 0) {
		printf(
			"\tcweb_append_html_escaped(res, args->%.*s);\n"
			,PRSTR(name)
		);
	} else {
		printf("\t{\n");
		printf("\t\tchar buf[1024];\n");
		printf("\t\tstr_t str = { .ptr = buf };\n");
		printf(
			"\t\tstr.len = snprintf(buf, sizeof(buf), \"%%%s\", args->%.*s);\n"
			,spec->printf_fmt
			,PRSTR(name)
		);
		printf("\t\tassert(str.len < sizeof(buf));\n");
		printf("\t\tcweb_append(res, str);\n");
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

static void include(str_t fname) {
	char *fname_cstr = malloc(fname.len + 1);
	fname_cstr[fname.len] = '\0';
	memcpy(fname_cstr, fname.ptr, fname.len);
	char *buf = read_file(fname_cstr);

	printf("\tcweb_append(res, STR(");
	print_strlit(buf, strlen(buf));
	printf("));\n");

	free(buf);
	free(fname_cstr);
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

		if (str_eq(spec, STR("include")))
			continue;

		if (strvec_contains(seen_args, nargs, name))
			continue;
		seen_args = realloc(seen_args, sizeof(*seen_args) * (nargs + 1));
		seen_args[nargs] = name;

		const struct spec *specspec = getspec(spec);
		if (!specspec)
			errx(1, "no specspec for %%%.*s", PRSTR(spec));
		const char *type = getspec(spec)->type;
		printf("\t%s%.*s;\n", type, PRSTR(name));
		nargs++;
	}
	if (nargs == 0)
		printf("\tint __tmpl_unused;\n");
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

		if (buf - runstart > 0) {
			printf("\tcweb_append(res, STR(");
			print_strlit(runstart, buf - runstart);
			printf("));\n");
		}

		if (*buf == 0)
			break;

		str_t spec, name;
		buf += parse_placeholder(buf, &spec, &name);

		if (str_eq(spec, STR("include")))
			include(name);
		else
			append_arg(spec, name);
	}
	printf("}\n");
}

int main(int argc, char **argv) {
	for (int i = 1; i < argc; i++) {
		char *fname = argv[i];
		char *buf = read_file(fname);
		char *basename = fname + strlen(fname);
		while (basename > fname && basename[-1] != '/') {
			if (*basename == '.')
				*basename = '\0';
			basename--;
		}

		do_args(basename, buf);
		do_func(basename, buf);

		if (i != argc - 1)
			puts("");
		free(buf);
	}
}
