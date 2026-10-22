# Host-side unit tests. These run on the developer's machine (not the
# Retro68 PowerPC target) so failing tests don't require launching an
# emulator. Add new test_* binaries here as the suite grows.
CC = cc
CFLAGS = -Wall -Wextra -O2 -std=c99
BEARSSL_INC = ../../bearssl/inc
BEARSSL_SRC = ../../bearssl/src
SRC = ../../src

# BearSSL source files needed for key schedule tests
BEARSSL_OBJS = \
	$(BEARSSL_SRC)/hash/sha2small.c \
	$(BEARSSL_SRC)/hash/sha2big.c \
	$(BEARSSL_SRC)/hash/md5.c \
	$(BEARSSL_SRC)/hash/dig_oid.c \
	$(BEARSSL_SRC)/hash/dig_size.c \
	$(BEARSSL_SRC)/mac/hmac.c \
	$(BEARSSL_SRC)/kdf/hkdf.c \
	$(BEARSSL_SRC)/codec/dec32be.c \
	$(BEARSSL_SRC)/codec/dec32le.c \
	$(BEARSSL_SRC)/codec/dec64be.c \
	$(BEARSSL_SRC)/codec/enc32be.c \
	$(BEARSSL_SRC)/codec/enc32le.c \
	$(BEARSSL_SRC)/codec/enc64be.c

# Full host build of BearSSL, shared by the entropy and record-boundary
# tests, which link the real handshake and pump code (X25519, X.509, AEAD,
# DRBG, ...).
BEARSSL_ALL = $(wildcard $(BEARSSL_SRC)/*/*.c) $(BEARSSL_SRC)/settings.c
BEARSSL_HOST_OBJS = $(patsubst $(BEARSSL_SRC)/%.c,obj/%.o,$(BEARSSL_ALL))
BEARSSL_LIB = libbearssl_host.a
STUBS = stubs

# Record-boundary tests; `make asan` runs them under ASan+UBSan.
RECORD_TESTS = test_record test_record_handshake test_record_app
RECORD_HDRS = record_helpers.h $(SRC)/tls13_record.h $(SRC)/tls13_record.c \
              $(SRC)/tls13_handshake.h
SAN_FLAGS = -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1

# Native Certainly client: the production pump and TLS code compiled against
# the stub Mac headers, with platform/ standing in for Open Transport, the
# Memory Manager, TickCount and OS randomness. -DHOST_PLATFORM switches the
# stubs from inline fakes to those adapters.
PLATFORM = platform
PLATFORM_CFLAGS = -Wall -Wextra -O2 -std=gnu99 -DHOST_PLATFORM $(EXTRA_CFLAGS) \
                  -I$(STUBS) -I$(BEARSSL_INC) -I$(SRC) -I../../include -I$(PLATFORM)
LIB_CFLAGS = $(CFLAGS) -DHOST_PLATFORM $(EXTRA_CFLAGS) \
             -I$(STUBS) -I$(BEARSSL_INC) -I$(SRC) -I../../include
LIB_SRCS = certainly entropy tls13_handshake tls13_keysched tls13_record ca_roots
LIB_OBJS = $(patsubst %,obj/certainly/%.o,$(LIB_SRCS))
PLATFORM_OBJS = $(patsubst %,obj/platform/%.o,host_ticks host_alloc host_entropy host_transport)
CONF = ../conformance
CONF_OUT = ../../build/conformance
ANVIL_PYTHON ?= python3
ANVIL_ARGS ?=
BEARSSL_TOOLS = ../../bearssl/tools

.PHONY: all clean clean-client test asan conformance-client conformance-check \
        conformance-anvil conformance-anvil-reference conformance-runner-check

all: test_keysched test_http test_entropy $(RECORD_TESTS) test_host_transport

test_keysched: test_keysched.c $(SRC)/tls13_keysched.c $(SRC)/tls13_keysched.h
	$(CC) $(CFLAGS) -I$(BEARSSL_INC) -I$(BEARSSL_SRC) -I$(SRC) \
		-o $@ test_keysched.c $(SRC)/tls13_keysched.c $(BEARSSL_OBJS)

obj/%.o: $(BEARSSL_SRC)/%.c
	@mkdir -p $(dir $@)
	$(CC) -O2 -std=c99 -I$(BEARSSL_INC) -I$(BEARSSL_SRC) -c -o $@ $<

$(BEARSSL_LIB): $(BEARSSL_HOST_OBJS)
	rm -f $@
	ar rcs $@ $^

test_entropy: test_entropy.c $(SRC)/entropy.c $(SRC)/entropy.h \
              $(SRC)/tls13_handshake.c $(SRC)/tls13_keysched.c \
              $(SRC)/tls13_record.c $(BEARSSL_LIB)
	$(CC) $(CFLAGS) -I$(BEARSSL_INC) -I$(BEARSSL_SRC) -I$(SRC) \
		-o $@ test_entropy.c $(SRC)/entropy.c $(SRC)/tls13_handshake.c \
		$(SRC)/tls13_keysched.c $(SRC)/tls13_record.c $(BEARSSL_LIB)

test: test_keysched test_http test_entropy $(RECORD_TESTS) test_host_transport
	./test_keysched
	./test_http
	./test_entropy
	./test_record
	./test_record_handshake
	./test_record_app
	./test_host_transport

test_record: test_record.c $(RECORD_HDRS) $(BEARSSL_LIB)
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -I$(BEARSSL_INC) -I$(SRC) \
		-o $@ test_record.c $(SRC)/tls13_record.c $(BEARSSL_LIB)

test_record_handshake: test_record_handshake.c $(RECORD_HDRS) \
                       $(SRC)/tls13_handshake.c $(SRC)/tls13_keysched.c $(BEARSSL_LIB)
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -I$(BEARSSL_INC) -I$(SRC) \
		-o $@ test_record_handshake.c $(SRC)/tls13_record.c \
		$(SRC)/tls13_keysched.c $(BEARSSL_LIB)

# Compiles the production pump (certainly.c) against stub Mac headers.
test_record_app: test_record_app.c $(RECORD_HDRS) $(SRC)/certainly.c \
                 $(SRC)/certainly_internal.h $(SRC)/tls13_handshake.c \
                 $(SRC)/tls13_keysched.c $(BEARSSL_LIB) $(wildcard $(STUBS)/*.h)
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -I$(STUBS) -I$(BEARSSL_INC) -I$(SRC) \
		-I../../include \
		-o $@ test_record_app.c $(SRC)/tls13_record.c \
		$(SRC)/tls13_handshake.c $(SRC)/tls13_keysched.c $(BEARSSL_LIB)

obj/certainly/%.o: $(SRC)/%.c $(wildcard $(SRC)/*.h) $(wildcard $(STUBS)/*.h)
	@mkdir -p $(dir $@)
	$(CC) $(LIB_CFLAGS) -c -o $@ $<

obj/platform/%.o: $(PLATFORM)/%.c $(PLATFORM)/host_platform.h \
                  $(wildcard $(STUBS)/*.h) $(SRC)/ot_transport.h
	@mkdir -p $(dir $@)
	$(CC) $(PLATFORM_CFLAGS) -c -o $@ $<

# The adapter's error semantics (would-block vs EOF vs reset) against a
# loopback peer.
test_host_transport: test_host_transport.c $(PLATFORM)/host_platform.h \
                     obj/platform/host_ticks.o obj/platform/host_alloc.o \
                     obj/platform/host_transport.o
	$(CC) $(PLATFORM_CFLAGS) -o $@ test_host_transport.c \
		obj/platform/host_ticks.o obj/platform/host_alloc.o \
		obj/platform/host_transport.o

# Conformance client (see ../conformance/README.md); lands under ignored
# build output.
conformance-client: $(CONF_OUT)/certainly_client

$(CONF_OUT)/certainly_client: $(CONF)/certainly_client.c $(CONF)/trust_anchors.c \
                              $(CONF)/trust_anchors.h $(LIB_OBJS) $(PLATFORM_OBJS) \
                              $(BEARSSL_LIB) $(BEARSSL_TOOLS)/errors.c
	@mkdir -p $(CONF_OUT)
	$(CC) $(PLATFORM_CFLAGS) -I$(BEARSSL_TOOLS) -I$(CONF) -o $@ \
		$(CONF)/certainly_client.c $(CONF)/trust_anchors.c \
		$(BEARSSL_TOOLS)/errors.c \
		$(LIB_OBJS) $(PLATFORM_OBJS) $(BEARSSL_LIB)

clean-client:
	rm -rf obj/certainly obj/platform $(CONF_OUT)/certainly_client

conformance-check: conformance-client
	$(CONF)/check-client.sh

conformance-anvil:
	ANVIL_PYTHON="$(ANVIL_PYTHON)" $(CONF)/run-anvil.sh $(ANVIL_ARGS)

conformance-anvil-reference:
	ANVIL_PYTHON="$(ANVIL_PYTHON)" $(CONF)/run-anvil.sh --backend openssl $(ANVIL_ARGS)

conformance-runner-check:
	$(ANVIL_PYTHON) $(CONF)/test_controller.py

# Rebuild and run the record tests with AddressSanitizer and UBSan. The
# conformance client takes the same flags:
#   make clean-client conformance-check EXTRA_CFLAGS="$(SAN_FLAGS)"
asan:
	rm -rf $(RECORD_TESTS) *.dSYM
	$(MAKE) $(RECORD_TESTS) EXTRA_CFLAGS="$(SAN_FLAGS)"
	for t in $(RECORD_TESTS); do ./$$t || exit 1; done
	rm -rf $(RECORD_TESTS) *.dSYM

test_http: test_http.c ../../examples/postman/http.c \
           ../../examples/postman/http.h
	$(CC) $(CFLAGS) -I../../examples/postman \
		-o $@ test_http.c ../../examples/postman/http.c

test_http_run: test_http
	./test_http

clean:
	rm -rf test_keysched test_http test_entropy test_host_transport \
		$(RECORD_TESTS) $(BEARSSL_LIB) obj $(CONF_OUT) *.dSYM
