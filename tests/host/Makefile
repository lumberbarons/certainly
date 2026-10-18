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

# Full BearSSL, built once into build/ for the record-boundary tests, which
# link the real handshake and pump code (X25519, X.509, AEAD, DRBG, ...).
BEARSSL_ALL_SRC = $(wildcard $(BEARSSL_SRC)/*/*.c)
BEARSSL_LIB = build/libbearssl.a
STUBS = stubs

# Record-boundary tests; `make asan` runs them under ASan+UBSan.
RECORD_TESTS = test_record test_record_handshake test_record_app
RECORD_HDRS = record_helpers.h $(SRC)/tls13_record.h $(SRC)/tls13_record.c \
              $(SRC)/tls13_handshake.h
SAN_FLAGS = -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1

.PHONY: all clean test asan

all: test_keysched test_http $(RECORD_TESTS)

test_keysched: test_keysched.c $(SRC)/tls13_keysched.c $(SRC)/tls13_keysched.h
	$(CC) $(CFLAGS) -I$(BEARSSL_INC) -I$(BEARSSL_SRC) -I$(SRC) \
		-o $@ test_keysched.c $(SRC)/tls13_keysched.c $(BEARSSL_OBJS)

test: test_keysched test_http $(RECORD_TESTS)
	./test_keysched
	./test_http
	./test_record
	./test_record_handshake
	./test_record_app

$(BEARSSL_LIB): $(BEARSSL_ALL_SRC) $(wildcard $(BEARSSL_INC)/*.h) $(BEARSSL_SRC)/inner.h
	@mkdir -p build/obj
	@for f in $(BEARSSL_ALL_SRC); do \
		o=build/obj/$$(echo $$f | sed 's|.*/src/||; s|/|_|g; s|\.c$$|.o|'); \
		$(CC) -O2 -w -I$(BEARSSL_INC) -I$(BEARSSL_SRC) -c $$f -o $$o || exit 1; \
	done
	ar rcs $@ build/obj/*.o

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

# Rebuild and run the record tests with AddressSanitizer and UBSan.
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
	rm -rf test_keysched test_http $(RECORD_TESTS) build *.dSYM
