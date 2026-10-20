#!/bin/bash
# setup.sh — create the key material the test suite expects: a signing key plus
# epochs E1, E2 and E3. E1 seals most pages, E2 proves a key from one epoch cannot
# open another's, and E3 lets the suite seal a page under E1+E3 and check that a
# perfectly valid E2 key is still refused.
#
#   test/setup.sh            create whatever is missing, then publish the table
#   test/setup.sh --force    throw the key store away and build it again
#
# Keys are encrypted at rest, so the suite needs their passwords. These are
# throwaway development keys, so this script keeps the passwords it generates in
# out/fixture-passwords (mode 0600, ignored by git) for e2e.sh to read. Deleting
# out/ loses them, and the next run of this script rebuilds the key store. Nothing in
# php/ ever writes a password down; this file exists only for the test fixtures.
set -u

cd "$(dirname "$0")/.."
FIXTURE=out/fixture-passwords

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

if [ "$force" -eq 1 ] || [ ! -f "$FIXTURE" ]; then
  [ "$force" -eq 1 ] && echo "removing the existing key store"
  # without the fixture file the suite cannot unlock existing keys, so start over
  rm -rf keys/private keys/epochs.json keys/signpublic.pem keys/issued.log "$FIXTURE"
fi

signing=""
declare -A epoch_pw=()
if [ -f "$FIXTURE" ]; then
  while IFS='=' read -r name value; do
    case $name in
      SIGN) signing=$value ;;
      E*)   epoch_pw[$name]=$value ;;
    esac
  done < "$FIXTURE"
fi
if [ -z "$signing" ]; then
  # letters and digits only, so the value needs no quoting anywhere
  signing="Test$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
fi

for epoch in E1 E2 E3; do
  out=$(php php/setup.php --epoch "$epoch" --signing-password "$signing" 2>&1) \
    || { echo "setup failed for $epoch:" >&2; echo "$out" >&2; exit 1; }
  generated=$(sed -n "s/^  Password for epoch $epoch: //p" <<<"$out")
  [ -n "$generated" ] && epoch_pw[$epoch]=$generated
done

umask 077
mkdir -p out
{
  echo "SIGN=$signing"
  for epoch in E1 E2 E3; do echo "$epoch=${epoch_pw[$epoch]:-}"; done
} > "$FIXTURE"
chmod 600 "$FIXTURE"

python3 - <<'PY'
import json, os, sys
table = json.load(open('keys/epochs.json'))
epochs = list(table['epochs'])
print('epochs published :', ', '.join(epochs))
print('table signed     :', 'yes' if table.get('signature') else 'NO')
print('private material :', ', '.join(sorted(os.listdir('keys/private'))))
missing = [e for e in ('E1', 'E2', 'E3') if e not in epochs]
if missing:
    print('ERROR: the suite needs ' + ', '.join(missing), file=sys.stderr)
    sys.exit(1)
PY
for epoch in E1 E2 E3; do
  [ -n "${epoch_pw[$epoch]:-}" ] || { echo "ERROR: no password recorded for $epoch; run test/setup.sh --force" >&2; exit 1; }
done
