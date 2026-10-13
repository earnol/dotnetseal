#!/bin/bash
# setup.sh — create the key material the test suite expects: a signing key plus
# epochs E1 and E2. e2e.sh needs both, E1 for the pages it seals and E2 to prove a
# key from one epoch cannot open another's page.
#
#   test/setup.sh            create whatever is missing, then publish the table
#   test/setup.sh --force    throw the key store away and build it again
#
# This is separate from e2e.sh for two reasons. Publishing the table derives every
# epoch's public half, one G2 multiply apiece, which cost the suite about 14
# seconds on every run. And a test run should not quietly rewrite your keys.
set -u

cd "$(dirname "$0")/.."
ROOT=$PWD

if [ -f test/env.sh ]; then
  . test/env.sh
else
  load_php() { :; }
fi
load_php

force=0
for arg in "$@"; do
  case $arg in
    --force) force=1 ;;
    *) echo "usage: test/setup.sh [--force]" >&2; exit 2 ;;
  esac
done

if [ "$force" -eq 1 ]; then
  echo "removing the existing key store"
  rm -rf keys/private keys/epochs.json keys/signpublic.pem keys/issued.log
fi

# The first run creates the signing key as well; the second adds the epoch.
php php/setup.php           >/dev/null || { echo "setup failed for E1" >&2; exit 1; }
php php/setup.php --epoch E2 >/dev/null || { echo "setup failed for E2" >&2; exit 1; }

python3 - <<'PY'
import json, os, sys
table = json.load(open('keys/epochs.json'))
epochs = list(table['epochs'])
print('epochs published :', ', '.join(epochs))
print('verification key :', 'keys/signpublic.pem', f"({os.path.getsize('keys/signpublic.pem')} bytes)")
print('private material :', ', '.join(sorted(os.listdir('keys/private'))))
if 'E1' not in epochs or 'E2' not in epochs:
    print('ERROR: the suite needs both E1 and E2', file=sys.stderr)
    sys.exit(1)
PY
