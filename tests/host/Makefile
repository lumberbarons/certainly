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

.PHONY: all clean test

all: test_keysched test_http test_closure

test_keysched: test_keysched.c $(SRC)/tls13_keysched.c $(SRC)/tls13_keysched.h
	$(CC) $(CFLAGS) -I$(BEARSSL_INC) -I$(BEARSSL_SRC) -I$(SRC) \
		-o $@ test_keysched.c $(SRC)/tls13_keysched.c $(BEARSSL_OBJS)

test: test_keysched test_http test_closure
	./test_keysched
	./test_http
	./test_closure

test_http: test_http.c ../../examples/postman/http.c \
           ../../examples/postman/http.h
	$(CC) $(CFLAGS) -I../../examples/postman \
		-o $@ test_http.c ../../examples/postman/http.c

test_http_run: test_http
	./test_http

# test_closure builds src/certainly.c against the fake Mac headers in fake/
# and links the whole of BearSSL, compiled once into obj/.
BEARSSL_ALL = $(wildcard $(BEARSSL_SRC)/*/*.c)
BEARSSL_OBJ = $(patsubst $(BEARSSL_SRC)/%.c,obj/bearssl/%.o,$(BEARSSL_ALL))
BEARSSL_LIB = obj/libbearssl.a
CLOSURE_SRCS = $(SRC)/certainly.c $(SRC)/tls13_handshake.c \
	$(SRC)/tls13_keysched.c $(SRC)/tls13_record.c $(SRC)/ca_roots.c

obj/bearssl/%.o: $(BEARSSL_SRC)/%.c
	@mkdir -p $(dir $@)
	$(CC) -O1 -I$(BEARSSL_INC) -I$(BEARSSL_SRC) -c $< -o $@

$(BEARSSL_LIB): $(BEARSSL_OBJ)
	rm -f $@
	@ar rcs $@ $(BEARSSL_OBJ)

test_closure: test_closure.c fake/OpenTransport.h $(CLOSURE_SRCS) \
              $(SRC)/certainly_internal.h $(BEARSSL_LIB)
	$(CC) $(CFLAGS) -Ifake -I$(BEARSSL_INC) -I$(SRC) -I../../include \
		-o $@ test_closure.c $(CLOSURE_SRCS) $(BEARSSL_LIB)

clean:
	rm -rf obj test_closure
	rm -f test_keysched test_http
