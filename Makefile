CC=clang
CFLAGS=-Wall -Wextra -Wpedantic -Wno-missing-field-initializers -Wno-overlength-strings \
       -std=c99 -g -D _POSIX_C_SOURCE=200809L -D _DEFAULT_SOURCE -fsanitize=undefined
LIBS=-lcurl -lldap
SERVEREXE=linkserver
TEMPLATES!=echo views/*.html
OBJECTS=cweb.o main.o str.o
HEADERS=cweb.h sql_wrappers.h str.h

.PHONY: run
run: $(SERVEREXE)
	./$(SERVEREXE)

.PHONY: release
release:
	rm -f *.o
	make $(SERVEREXE) CFLAGS="$(CFLAGS) -O2 -D RELEASE_BUILD"
	chown root $(SERVEREXE)
	chmod u+s $(SERVEREXE)

$(OBJECTS): $(HEADERS)

main.o: tmplfuncs.gen

$(SERVEREXE): $(OBJECTS) sqlite3.o
	$(CC) $(CFLAGS) $(LIBS) -o $(SERVEREXE) $(OBJECTS) sqlite3.o

tmplc: tmplc.o str.o
	$(CC) $(CFLAGS) tmplc.o str.o -o tmplc

tmplfuncs.gen: $(TEMPLATES) tmplc views/head views/foot
	./tmplc $(TEMPLATES) >tmplfuncs.gen

.PHONY: clean
clean:
	rm -f $(OBJECTS)
	rm -f tmplc.o
	rm -f tmplc
	rm -f $(SERVEREXE)
	rm -f *.gen
