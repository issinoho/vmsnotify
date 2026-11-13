# vmsnotify, Linux side.
#
#   make            build the tests
#   make check      run them: rules, throttle, formatting, the endpoint
#                   encoders against tests/golden/, the configuration
#                   (with the shipped example); the golden payloads through
#                   tools/fake_endpoints.py's validators; the VMS log reader
#                   compiled against stub/
#   make golden     rewrite tests/golden/ from the encoders; read the diff
#                   before committing it
#
# The agent itself comes in phase 2 (docs/design.md, "Phases").

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
        $(B)/test_config

all: $(TESTS) $(B)/vms_logs.o

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

# The VMS log reader, against the stub: it must at least compile here.
$(B)/vms_logs.o: src/sources/vms/vms_logs.c $(HDRS) stub/*.h | $(B)
	$(CC) $(VMSISH) $(INC) -c -o $@ $<

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

golden: $(B)/test_endpoint
	$(B)/test_endpoint tests/golden --write

check: all
	$(B)/test_types
	$(B)/test_logs
	$(B)/test_rules
	$(B)/test_endpoint tests/golden
	$(B)/test_config vmsnotify.conf.example
	$(PYTHON) -I tools/fake_endpoints.py --validate tests/golden/*.txt

clean:
	rm -rf $(B)

.PHONY: all check golden clean
