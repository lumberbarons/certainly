#!/bin/sh
set -eu
exec "${ANVIL_PYTHON:-python3}" "$(dirname "$0")/controller.py" "$@"
