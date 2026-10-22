/*
 * trust_anchors.h — load PEM certificates as BearSSL trust anchors.
 *
 * The conformance client trusts only the fixture CA it is given; the
 * generated production roots in src/ca_roots.c are never involved.
 */

#ifndef CERTAINLY_CONFORMANCE_TRUST_ANCHORS_H
#define CERTAINLY_CONFORMANCE_TRUST_ANCHORS_H

#include <bearssl.h>
#include <stddef.h>

typedef struct {
    br_x509_trust_anchor *tas;
    size_t                count;
} ta_set;

/*
 * Decode every CERTIFICATE block in the PEM file at `path`. Returns 0 on
 * success with at least one anchor; otherwise non-zero with a reason in
 * `err`. Release with ta_free().
 */
int  ta_load_pem_file(const char *path, ta_set *out, char *err, size_t errlen);
void ta_free(ta_set *set);

#endif /* CERTAINLY_CONFORMANCE_TRUST_ANCHORS_H */
