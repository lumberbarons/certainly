#!/usr/bin/env bash
# Generate the conformance fixtures into a directory (default
# build/conformance/fixtures). Everything produced here is disposable test
# material: keys and certificates are never committed and never touch the
# production roots in src/ca_roots.c.
#
#   ca.pem / ca.key              trusted by the client under test
#   server.pem / server.key      leaf for conformance.test, signed by ca.pem
#   other-ca.pem                 an issuer the client does NOT trust
#   other-server.pem / .key      same name, signed by other-ca.pem
#   validation_time              unix time inside the certificates' validity
#   line.txt, line.expected      one line and its `s_server -rev` reply
#   big.txt                      several TLS records of known text
#
# Needs OpenSSL with `s_server -ciphersuites` (1.1.1 or later, not LibreSSL).

set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
out=${1:-$here/../../../build/conformance/fixtures}
mkdir -p "$out"
out=$(cd "$out" && pwd)
cd "$out"

openssl=${OPENSSL:-openssl}
name=conformance.test
days=3650

make_leaf() {   # make_leaf <issuer-prefix> <leaf-prefix>
    "$openssl" ecparam -name prime256v1 -genkey -noout -out "$2.key" 2>/dev/null
    "$openssl" req -new -key "$2.key" -subj "/CN=$name" -out "$2.csr"
    "$openssl" x509 -req -in "$2.csr" -CA "$1.pem" -CAkey "$1.key" \
        -CAcreateserial -days "$days" -sha256 -extfile leaf.ext \
        -out "$2.pem" 2>/dev/null
    rm -f "$2.csr"
}

make_ca() {   # make_ca <prefix> <common name>
    "$openssl" ecparam -name prime256v1 -genkey -noout -out "$1.key" 2>/dev/null
    "$openssl" req -new -x509 -key "$1.key" -sha256 -days "$days" \
        -subj "/CN=$2" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -out "$1.pem"
}

cat > leaf.ext <<EXT
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:$name
EXT

make_ca ca "Certainly Conformance CA"
make_leaf ca server
make_ca other-ca "Certainly Untrusted CA"
make_leaf other-ca other-server
rm -f leaf.ext ./*.srl

# One day past issuance: comfortably inside the validity window, and fixed
# so a run is unaffected by when it happens.
echo $(( $(date +%s) + 86400 )) > validation_time

printf 'certainly conformance payload\n' > line.txt
printf 'daolyap ecnamrofnoc ylniatrec\n' > line.expected

# Deterministic text spanning several full TLS records.
awk 'BEGIN { for (i = 0; i < 4000; i++) printf "line %05d: certainly conformance filler\n", i }' > big.txt
