/*
 * test_http.c — host-side unit tests for examples/postman/http.c
 *
 * Build and run:
 *   cd tests/host && make test_http && ./test_http
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "../../examples/postman/http.h"

static int failures = 0;
static int passes   = 0;

#define EXPECT_EQ_INT(name, expected, actual) do {                    \
    long _e = (long)(expected), _a = (long)(actual);                  \
    if (_e == _a) { passes++; printf("PASS: %s\n", name); }           \
    else { failures++; printf("FAIL: %s expected=%ld actual=%ld\n",   \
                              name, _e, _a); }                        \
} while (0)

#define EXPECT_EQ_STR(name, expected, actual) do {                    \
    if (strcmp((expected), (actual)) == 0) {                          \
        passes++; printf("PASS: %s\n", name);                         \
    } else {                                                          \
        failures++;                                                   \
        printf("FAIL: %s\n  expected: %s\n  actual:   %s\n",          \
               name, (expected), (actual));                           \
    }                                                                 \
} while (0)

#define EXPECT_EQ_MEM(name, expected, actual, len) do {               \
    if (memcmp((expected), (actual), (len)) == 0) {                   \
        passes++; printf("PASS: %s\n", name);                         \
    } else {                                                          \
        failures++; printf("FAIL: %s (memory mismatch)\n", name);     \
    }                                                                 \
} while (0)

static void test_smoke(void)
{
    /* Placeholder so the harness builds and runs before Task 3. */
    printf("=== test_http smoke ===\n");
    EXPECT_EQ_INT("harness runs", 1, 1);
}

int main(void)
{
    test_smoke();

    printf("\n%d passed, %d failed\n", passes, failures);
    return failures == 0 ? 0 : 1;
}
