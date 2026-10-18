#!/bin/sh
# Create a seed file for the Certainly example apps from the host's
# cryptographic RNG. Usage: tools/make_seed.sh [output-file]
#
# Copy the result into the application's folder on the Mac, named
# "Certainly Seed". The apps overwrite it with a fresh seed each time they
# run, so provision a new file if you restore the folder from a backup or
# duplicate it onto another machine: reusing a seed repeats key material.
# Treat the file as a secret.
set -eu
out=${1:-"Certainly Seed"}
umask 077
head -c 64 /dev/urandom > "$out"
echo "wrote $out"
