# vmsnotify, Linux side.
#
#   make            build the agent and the tests
#   make check      run them: rules, throttle, formatting, the endpoint
#                   encoders against tests/golden/, the configuration
#                   (with the shipped example), the HTTP response parser;
#                   the golden payloads through tools/fake_endpoints.py's
#                   validators; then the agent end to end against
#                   tools/fake_endpoints.py (tools/agent_test.py)
#   make check also runs tools/check_build_files.py: Makefile, build_vms.com and
#                   descrip.mms must list the same sources and flags
#   make golden     rewrite tests/golden/ from the encoders; read the diff
#                   before committing it
#
#   build/vmsnotify           the agent, with the fake log source
#   build/vmsnotify_tls       the same with TLS (OpenSSL)
#   build/vmsnotify_vmsstub   the agent with the VMS log reader, against
#                             stub/vmsstub.c: its logic, not VMS's behaviour

CC      ?= cc
STRICT  = -std=c99 -pedantic -Wall -Wextra -Werror
# '$' in identifiers is the one extension VMS code cannot avoid, and
# -pedantic has no switch for it alone, so the VMS sources drop -pedantic
# and keep the rest (as in vmsotel).
VMSISH  = -std=c99 -Wall -Wextra -Werror -fdollars-in-identifiers -Istub

PYTHON ?= python3

B = build
INC = -Isrc/model -Isrc/notify -Isrc/platform -Isrc/transport -Isrc/sources \
      -Isrc/agent -Itests
CFLAGS_ = $(STRICT) $(INC)
HDRS = $(wildcard src/*/*.h) $(wildcard tests/*.h)

CORE_OBJ = $(B)/vn_types.o $(B)/logparse.o $(B)/rules.o $(B)/throttle.o \
           $(B)/json.o $(B)/format.o $(B)/endpoint.o $(B)/config.o

TESTS = $(B)/test_types $(B)/test_logs $(B)/test_rules $(B)/test_endpoint \
        $(B)/test_config $(B)/test_http

# What every agent links besides its log source and its HTTP.
AGENT_OBJ = $(CORE_OBJ) $(B)/queue.o $(B)/platform_posix.o
AGENTS = $(B)/vmsnotify $(B)/vmsnotify_tls $(B)/vmsnotify_vmsstub \
         $(B)/vmsnotify_launch_vmsstub

all: $(TESTS) $(AGENTS)

$(B):
	mkdir -p $(B)

$(B)/vn_types.o: src/model/vn_types.c $(HDRS) | $(B)
	$(CC) $(CFLAGS_) -c -o $@ $<
$(B)/logparse.o: src/model/logparse.c $(HDRS) | $(B)
	$(CC) $(CFLAGS_) -c -o $@ $<
$(B)/rules.o: src/model/rules.c $(HDRS) | $(B)
	$(CC) $(CFLAGS_) -c -o $@ $<
$(B)/throttle.o: src/model/throttle.c $(HDRS) | $(B)
	$(CC) $(CFLAGS_) -c -o $@ $<
$(B)/json.o: src/notify/json.c $(HDRS) | $(B)
	$(CC) $(CFLAGS_) -c -o $@ $<
$(B)/format.o: src/notify/format.c $(HDRS) | $(B)
	$(CC) $(CFLAGS_) -c -o $@ $<
$(B)/endpoint.o: src/notify/endpoint.c $(HDRS) | $(B)
	$(CC) $(CFLAGS_) -c -o $@ $<
$(B)/config.o: src/agent/config.c $(HDRS) | $(B)
	$(CC) $(CFLAGS_) -c -o $@ $<

$(B)/queue.o: src/transport/queue.c $(HDRS) | $(B)
	$(CC) $(CFLAGS_) -c -o $@ $<
$(B)/platform_posix.o: src/platform/platform_posix.c $(HDRS) | $(B)
	$(CC) $(CFLAGS_) -c -o $@ $<
$(B)/fake_logs.o: src/sources/fake/fake_logs.c $(HDRS) | $(B)
	$(CC) $(CFLAGS_) -c -o $@ $<

# The two that change with TLS.
$(B)/http.o: src/transport/http.c $(HDRS) | $(B)
	$(CC) $(CFLAGS_) -c -o $@ $<
$(B)/agent.o: src/agent/agent.c $(HDRS) | $(B)
	$(CC) $(CFLAGS_) -c -o $@ $<
$(B)/http_tls.o: src/transport/http.c $(HDRS) | $(B)
	$(CC) $(CFLAGS_) -DVN_WITH_TLS -c -o $@ $<
$(B)/agent_tls.o: src/agent/agent.c $(HDRS) | $(B)
	$(CC) $(CFLAGS_) -DVN_WITH_TLS -c -o $@ $<
$(B)/tls.o: src/transport/tls.c $(HDRS) | $(B)
	$(CC) $(CFLAGS_) -DVN_WITH_TLS -c -o $@ $<

# The VMS log reader and what it needs of the system, against the stub.
$(B)/vms_logs.o: src/sources/vms/vms_logs.c $(HDRS) stub/*.h | $(B)
	$(CC) $(VMSISH) $(INC) -c -o $@ $<
$(B)/vms_sys.o: src/sources/vms/vms_sys.c $(HDRS) stub/*.h | $(B)
	$(CC) $(VMSISH) $(INC) -c -o $@ $<
$(B)/vmsstub.o: stub/vmsstub.c stub/*.h | $(B)
	$(CC) $(VMSISH) -c -o $@ stub/vmsstub.c

$(B)/vmsnotify: $(B)/agent.o $(B)/http.o $(B)/fake_logs.o $(AGENT_OBJ)
	$(CC) -o $@ $^
$(B)/vmsnotify_tls: $(B)/agent_tls.o $(B)/http_tls.o $(B)/tls.o $(B)/fake_logs.o $(AGENT_OBJ)
	$(CC) -o $@ $^ -lssl -lcrypto
$(B)/vmsnotify_vmsstub: $(B)/agent.o $(B)/http.o $(B)/vms_logs.o $(B)/vms_sys.o $(B)/vmsstub.o $(AGENT_OBJ)
	$(CC) -o $@ $^

# The kit's launcher (src/launch), copied from vmsotel: VMS system
# services, so against the stub, which knows one account, VMSNOTIFY, and
# prints the process it is asked to create. OpenSSL for --password.
$(B)/launch.o: src/launch/launch.c stub/*.h | $(B)
	$(CC) $(VMSISH) -c -o $@ $<
$(B)/vmsnotify_launch_vmsstub: $(B)/launch.o $(B)/vmsstub.o
	$(CC) -o $@ $^ -lcrypto

# The test compares the formatter with glibc's snprintf, whose output gcc
# thinks may be truncated; it is the point of the test.
$(B)/test_types: tests/test_types.c $(B)/vn_types.o
	$(CC) $(CFLAGS_) -Wno-format-truncation -o $@ $< $(B)/vn_types.o
$(B)/test_logs: tests/test_logs.c $(B)/logparse.o $(B)/vn_types.o
	$(CC) $(CFLAGS_) -o $@ $< $(B)/logparse.o $(B)/vn_types.o
$(B)/test_rules: tests/test_rules.c $(CORE_OBJ)
	$(CC) $(CFLAGS_) -o $@ $< $(CORE_OBJ)
$(B)/test_endpoint: tests/test_endpoint.c $(CORE_OBJ)
	$(CC) $(CFLAGS_) -o $@ $< $(CORE_OBJ)
$(B)/test_config: tests/test_config.c $(CORE_OBJ)
	$(CC) $(CFLAGS_) -o $@ $< $(CORE_OBJ)

$(B)/test_http: tests/test_http.c $(B)/http.o $(B)/platform_posix.o $(B)/vn_types.o
	$(CC) $(CFLAGS_) -o $@ $< $(B)/http.o $(B)/platform_posix.o $(B)/vn_types.o

golden: $(B)/test_endpoint
	$(B)/test_endpoint tests/golden --write

check: all
	$(B)/test_types
	$(B)/test_logs
	$(B)/test_rules
	$(B)/test_endpoint tests/golden
	$(B)/test_config vmsnotify.conf.example
	$(B)/test_http
	$(PYTHON) -I tools/check_build_files.py Makefile build_vms.com descrip.mms
	$(PYTHON) -I tools/check_kit.py
	$(B)/vmsnotify_launch_vmsstub VMSNOTIFY DKA0:[X.COM]R.COM DKA0:[X.LOG]R.LOG vmsnotify > $(B)/launch.out
	grep -q 'as persona 7, input DKA0:\[X.COM\]R.COM, output DKA0:\[X.LOG\]R.LOG, error DKA0:\[X.LOG\]R.LOG, name VMSNOTIFY, priority 4, flags 0x200, quotas 1=100 3=200000 12=500 6=100 2=100 5=100 7=300000 9=20 10=4096 11=16384 13=32768$$' $(B)/launch.out
	grep -q '^vmsnotify_launch: process 02001234 started as VMSNOTIFY$$' $(B)/launch.out
	! $(B)/vmsnotify_launch_vmsstub vmsnotify_x a.com a.log vmsnotify > $(B)/launch.out
	grep -q 'cannot take on the account VMSNOTIFY_X' $(B)/launch.out
	! STUB_CREPRC_FAIL=1 $(B)/vmsnotify_launch_vmsstub vmsnotify a.com a.log vmsnotify > $(B)/launch.out
	grep -q 'cannot create the process as VMSNOTIFY' $(B)/launch.out
	! $(B)/vmsnotify_launch_vmsstub vmsnotify a.com a.log process_name_too_long > /dev/null
	$(B)/vmsnotify_launch_vmsstub --password > $(B)/launch.out
	$(B)/vmsnotify_launch_vmsstub --password >> $(B)/launch.out
	test "$$(grep -cxE '[A-Z0-9]{32}' $(B)/launch.out)" = 2
	test "$$(sort -u $(B)/launch.out | wc -l)" = 2
	$(PYTHON) -I tools/fake_endpoints.py --validate tests/golden/*.txt
	$(B)/vmsnotify --version | grep -qx 'vmsnotify 0.1.0'
	! grep -n 'snprintf' src/agent/*.c src/transport/*.c src/sources/*/*.c src/platform/*.c | grep -v 'vn_v*snprintf'
	$(PYTHON) -I tools/agent_test.py $(B)/vmsnotify $(B)/vmsnotify_tls $(B)/vmsnotify_vmsstub

clean:
	rm -rf $(B)

.PHONY: all check golden clean
