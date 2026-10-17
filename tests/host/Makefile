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

# The entropy tests exercise the real BearSSL engine and the TLS 1.3
# ClientHello, so they link a host build of all of BearSSL.
BEARSSL_ALL = $(wildcard $(BEARSSL_SRC)/*/*.c) $(BEARSSL_SRC)/settings.c
BEARSSL_HOST_OBJS = $(patsubst $(BEARSSL_SRC)/%.c,obj/%.o,$(BEARSSL_ALL))

.PHONY: all clean test

all: test_keysched test_http test_entropy

test_keysched: test_keysched.c $(SRC)/tls13_keysched.c $(SRC)/tls13_keysched.h
	$(CC) $(CFLAGS) -I$(BEARSSL_INC) -I$(BEARSSL_SRC) -I$(SRC) \
		-o $@ test_keysched.c $(SRC)/tls13_keysched.c $(BEARSSL_OBJS)

obj/%.o: $(BEARSSL_SRC)/%.c
	@mkdir -p $(dir $@)
	$(CC) -O2 -std=c99 -I$(BEARSSL_INC) -I$(BEARSSL_SRC) -c -o $@ $<

libbearssl_host.a: $(BEARSSL_HOST_OBJS)
	rm -f $@
	ar rcs $@ $^

test_entropy: test_entropy.c $(SRC)/entropy.c $(SRC)/entropy.h \
              $(SRC)/tls13_handshake.c $(SRC)/tls13_keysched.c \
              $(SRC)/tls13_record.c libbearssl_host.a
	$(CC) $(CFLAGS) -I$(BEARSSL_INC) -I$(BEARSSL_SRC) -I$(SRC) \
		-o $@ test_entropy.c $(SRC)/entropy.c $(SRC)/tls13_handshake.c \
		$(SRC)/tls13_keysched.c $(SRC)/tls13_record.c libbearssl_host.a

test: test_keysched test_http test_entropy
	./test_keysched
	./test_http
	./test_entropy

test_http: test_http.c ../../examples/postman/http.c \
           ../../examples/postman/http.h
	$(CC) $(CFLAGS) -I../../examples/postman \
		-o $@ test_http.c ../../examples/postman/http.c

test_http_run: test_http
	./test_http

clean:
	rm -rf test_keysched test_http test_entropy libbearssl_host.a obj
