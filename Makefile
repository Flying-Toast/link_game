CC=clang
CFLAGS=-Wall -Wextra -Wpedantic -Wno-missing-field-initializers -std=c99 -g \
       -D _POSIX_C_SOURCE=200809L -D _DEFAULT_SOURCE -fsanitize=undefined
LIBS=-lcurl -lldap
TEMPLATES:=tmpl/views/*
OBJECTS=cweb.o main.o str.o
HEADERS=cweb.h sql_wrappers.h str.h

.PHONY: run
run: main
	./main

$(OBJECTS): $(HEADERS)

main.o: tmplfuncs.gen

main: $(OBJECTS) sqlite3.o
	$(CC) $(CFLAGS) $(LIBS) -o main $(OBJECTS) sqlite3.o

tmplc: tmplc.o str.o
	$(CC) $(CFLAGS) tmplc.o str.o -o tmplc

tmplfuncs.gen: $(TEMPLATES) tmplc tmpl/head tmpl/foot
	./tmplc $(TEMPLATES) >tmplfuncs.gen

.PHONY: clean
clean:
	rm -f $(OBJECTS)
	rm -f tmplc.o
	rm -f tmplc
	rm -f main
	rm -f *.gen
