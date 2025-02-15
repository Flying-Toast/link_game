CC=clang
LIBS=ldap libcurl sqlite3
CFLAGS=-Wall -Wextra -Wpedantic -Wno-missing-field-initializers -Wno-overlength-strings -g \
       `pkg-config --cflags $(LIBS)`
SERVEREXE=linkserver
TEMPLATES!=echo views/*.html
OBJECTS=cweb.o main.o str.o
HEADERS=cweb.h sql_wrappers.h str.h

.PHONY: run
run: $(SERVEREXE)
	./$(SERVEREXE) -w .

.PHONY: install
install: release
	mv -f linkserver ../prod_links/
	cp -r static ../prod_links/
	rcctl restart linkserver

.PHONY: release
release:
	rm -f *.o
	make $(SERVEREXE) CFLAGS="$(CFLAGS) -O2 -D RELEASE_BUILD"
	chown root $(SERVEREXE)
	chmod u+s $(SERVEREXE)

$(OBJECTS): $(HEADERS)

main.o: tmplfuncs.gen

$(SERVEREXE): $(OBJECTS)
	$(CC) $(CFLAGS) `pkg-config --libs $(LIBS)` -o $(SERVEREXE) $(OBJECTS)

tmplc: tmplc.o str.o
	$(CC) $(CFLAGS) tmplc.o str.o -o tmplc

tmplfuncs.gen: $(TEMPLATES) tmplc views/head views/foot
	./tmplc $(TEMPLATES) >tmplfuncs.gen

.PHONY: clean
clean:
	rm -f *.o
	rm -f tmplc
	rm -f $(SERVEREXE)
	rm -f *.gen
