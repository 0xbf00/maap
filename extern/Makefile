PROGRAMS = xpc_vuln_checker plist_sanitizer jtool simbple sandbox_check sandbox_status sandbox_container_path_for_pid

all: $(PROGRAMS)

xpc_vuln_checker: xpc_vuln_checker.c
	$(CC) -o xpc_vuln_checker xpc_vuln_checker.c

plist_sanitizer: plist_sanitizer.m
	$(CC) -o plist_sanitizer plist_sanitizer.m -framework Foundation

jtool:
	curl -O http://www.newosxbook.com/tools/jtool.tar
	tar -xzf jtool.tar jtool
	rm jtool.tar

simbple:
	curl -L -O https://github.com/0xbf00/simbple/releases/download/v0.9-catalina/simbple
	chmod +x simbple

sandbox_check: sandbox_check.c
	$(CC) -o sandbox_check sandbox_check.c

sandbox_status: sandbox_status.c apple_sandbox.h
	$(CC) -o sandbox_status sandbox_status.c -std=c11

sandbox_container_path_for_pid: sandbox_container_path_for_pid.c apple_sandbox.h
	$(CC) -o sandbox_container_path_for_pid sandbox_container_path_for_pid.c -std=c11

clean:
	rm $(PROGRAMS)
