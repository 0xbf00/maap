PROGRAMS = xpc_vuln_checker plist_sanitizer jtool

all: $(PROGRAMS)

xpc_vuln_checker: xpc_vuln_checker.c
	$(CC) -o xpc_vuln_checker xpc_vuln_checker.c

plist_sanitizer: plist_sanitizer.m
	$(CC) -o plist_sanitizer plist_sanitizer.m -framework Foundation

jtool:
	curl -O http://www.newosxbook.com/tools/jtool.tar
	tar -xzf jtool.tar jtool
	rm jtool.tar

clean:
	rm $(PROGRAMS)