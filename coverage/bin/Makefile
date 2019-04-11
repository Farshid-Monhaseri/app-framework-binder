
.PHONY: clean binaries

heredir = .
basedir = ../..

bindings = \
	hi3.so \
	hello.so \
	salut.so \
	salam.so \
	shalom.so \
	demat.so \
	hellov2.so

bugs = $(foreach i,\
	1 2 3 4 5 6 7 8 9 \
	10 11 12 13 14 15 16 17 18 19 \
	20 21, \
	bugs/bug$i.so)

tests = \
	test-apiset \
	test-session \
	test-wrap-json

targets = \
	afb-daemon-cov \
	afb-client \
	$(tests) \
	$(bindings) \
	$(bugs)

binaries: $(targets)

clean:
	@echo remove all binaries
	@rm $(targets) *.gcno *.gcda *.o  2>/dev/null || true

#======================================================================================
# definitions
#======================================================================================

incdir = $(basedir)/include
srcdir = $(basedir)/src
tstdir = $(basedir)/src/tests
samdir = $(basedir)/bindings/samples

bindir = $(heredir)/bin

deps = openssl libmicrohttpd json-c libsystemd uuid

ccflags = \
	-g \
	-I$(incdir) \
	$(shell pkg-config --cflags $(deps))

ldflags = -ldl -lrt -lpthread \
	$(shell pkg-config --libs $(deps))

cflags = $(ccflags) $(ldflags)

defs = 	-DAGL_DEVEL=1 \
	-DWITH_MONITORING_OPTION \
	-DAFB_VERSION=\"cov\" \
	-DUSE_SIG_MONITOR_DUMPSTACK=1 \
	-DUSE_SIG_MONITOR_SIGNALS=1 \
	-DUSE_SIG_MONITOR_FOR_CALL=1 \
	-DUSE_SIG_MONITOR_TIMERS=1 \
	-DWITH_AFB_HOOK=1 \
	-DWITH_AFB_TRACE=1 \
	-DWITH_LEGACY_BINDING_V1=0 \
	-DWITH_LEGACY_BINDING_V2=1 \
	-DWITH_LEGACY_BINDING_VDYN=0 \
	-DWITH_DBUS_TRANSPARENCY=0 \
	-DWITH_SUPERVISION=0 \
	-DWITH_DYNAMIC_BINDING=1 \
	-DBINDING_INSTALL_DIR=\"$(shell pwd)/fake\"

afb_lib_src = $(shell ls $(srcdir)/*.c | egrep -v '/afs-|/main-|/fdev-epoll.c|/afb-ws-client.c' )
afb_lib_obj = $(patsubst $(srcdir)/%.c,%.o,$(afb_lib_src))
afb_lib = afb-lib.a
afb_lib_defs = $(defs)

afb_daemon_srcs = $(srcdir)/main-afb-daemon.c $(afb_lib_obj)
afb_daemon_defs = $(afb_lib_defs)

afb_client_srcs = $(srcdir)/main-afb-client-demo.c $(srcdir)/afb-ws-client.c $(afb_lib_src)
afb_client_defs = $(defs)

tst_defs = $(defs)
tst_flags = $(cflags) \
	-I$(srcdir) \
	$(shell pkg-config --cflags --libs check)

tst_defs = '-DAFB_VERSION="cov"' '-DBINDING_INSTALL_DIR="fake"'
tst_flags = $(cflags) \
	-I$(srcdir) \
	$(shell pkg-config --cflags --libs check)

hello2_src = $(samdir)/hello2.c
hello3_src = $(samdir)/hello3.c
hi_src = $(samdir)/hi3.c
binding_flags = -shared -fPIC -Wl,--version-script=$(samdir)/export.map

#======================================================================================
# creates the targets
#======================================================================================

%.o: $(srcdir)/%.c
	@echo creation of $@
	@gcc -c -o $@ $< --coverage $(afb_lib_defs) $(ccflags)

afb-daemon-cov: $(afb_daemon_srcs)
	@echo creation of $@
	@gcc -o $@ $(afb_daemon_srcs) --coverage $(afb_daemon_defs) $(cflags)

afb-client: $(afb_client_srcs)
	@echo creation of $@
	@gcc -o $@ $(afb_client_srcs) $(afb_client_defs) $(cflags)

#======================================================================================
# create test
#======================================================================================

test-apiset: $(tstdir)/apiset/test-apiset.c $(afb_lib_obj)
	@echo creation of $@
	@gcc -o $@ $(tstdir)/apiset/test-apiset.c $(afb_lib_obj) --coverage $(tst_defs) $(tst_flags)

test-session: $(tstdir)/session/test-session.c $(afb_lib_obj)
	@echo creation of $@
	@gcc -o $@ $(tstdir)/session/test-session.c $(afb_lib_obj) --coverage $(tst_defs) $(tst_flags)

test-wrap-json: $(tstdir)/session/test-session.c $(afb_lib_obj)
	@echo creation of $@
	@gcc -o $@ $(tstdir)/wrap-json/test-wrap-json.c $(afb_lib_obj) --coverage $(tst_defs) $(tst_flags)

#======================================================================================
# create bindings
#======================================================================================

hi3.so: $(hi3_src)
	@echo creation of $@
	@gcc -o $@ $(hi3_src) $(binding_flags) $(cflags)

hello.so: $(hello3_src)
	@echo creation of $@
	@gcc -o $@ $(hello3_src) '-DAPINAME="hello"' '-DPREINIT_PROVIDE_CLASS="class1 class2"' $(binding_flags) $(cflags)

salut.so: $(hello3_src)
	@echo creation of $@
	@gcc -o $@ $(hello3_src) '-DAPINAME="salut"' '-DPREINIT_REQUIRE_CLASS="class2"' $(binding_flags) $(cflags)

salam.so: $(hello3_src)
	@echo creation of $@
	@gcc -o $@ $(hello3_src) '-DAPINAME="salam"' '-DINIT_REQUIRE_API="hello salut"' $(binding_flags) $(cflags)

shalom.so: $(hello3_src)
	@echo creation of $@
	@gcc -o $@ $(hello3_src) '-DAPINAME="shalom"' $(binding_flags) $(cflags)

demat.so: $(hello3_src)
	@echo creation of $@
	@gcc -o $@ $(hello3_src) '-DAPINAME="demat"' $(binding_flags) $(cflags)

hellov2.so: $(hello2_src)
	@echo creation of $@
	@gcc -o $@ $(hello2_src) '-DAPINAME="hello-v2"' $(binding_flags) $(cflags)

#======================================================================================
# create bugs
#======================================================================================

bugs:
	@echo creation of directory bugs
	@mkdir bugs

bugs/bug%.so: bug.c bugs
	@echo creation of $@
	@gcc -o $@ bug.c $(binding_flags) $(cflags) -D$(patsubst bugs/bug%.so,BUG%,$@)
