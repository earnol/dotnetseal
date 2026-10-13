#!/bin/bash
# End-to-end test: PHP issues keys, .NET seals a page, real Chrome decrypts it
# from a file:// URL. Each case appends a small driver script to a copy of the
# generated page, then dumps the resulting DOM.
set -u

cd "$(dirname "$0")/.."
ROOT=$PWD
OUT=$ROOT/out
WORK=$OUT/test
mkdir -p "$WORK"

pass=0
fail=0

# The page shows expiry in the reader's own time zone, so the expected strings are
# computed here rather than hardcoded; otherwise these checks would only pass in
# whatever zone the test machine happens to sit in.
local_moment() {
  python3 -c "
import sys, datetime
utc = datetime.datetime.strptime(sys.argv[1], '%Y-%m-%dT%H:%M:%SZ').replace(
    tzinfo=datetime.timezone.utc)
print(utc.astimezone().strftime('%Y-%m-%d %H:%M'))" "$1"
}

# How the toolchain gets onto PATH is machine-specific, so it lives in env.sh,
# which is not version controlled. Without it the suite expects php, dotnet and a
# Chrome binary to be on PATH already. See env.sh.example.
if [ -f "$ROOT/test/env.sh" ]; then
  . "$ROOT/test/env.sh"
else
  load_php()    { :; }
  load_dotnet() { :; }
  load_chrome() { :; }
fi

# ---------------------------------------------------------------- build inputs
load_php

# Key material is a fixture, built by test/setup.sh. Creating it here would cost
# about 14 seconds a run and would rewrite whatever is in keys/.
python3 - <<'PYEOF' || { echo "run test/setup.sh first"; exit 1; }
import json, sys
try:
    epochs = json.load(open('keys/epochs.json'))['epochs']
except (OSError, KeyError, ValueError):
    print('keys/epochs.json is missing or unreadable', file=sys.stderr)
    sys.exit(1)
missing = [e for e in ('E1', 'E2') if e not in epochs]
if missing:
    print('key table has no epoch ' + ', '.join(missing), file=sys.stderr)
    sys.exit(1)
PYEOF

PAGE=DOC-1234
OTHER=DOC-5678
TOKEN=$(php php/issue.php --epoch E1 --page $PAGE --kid acct-4471 --extra '{"tier":"gold"}')
TOKEN_EXPIRED=$(php php/issue.php --epoch E1 --page $PAGE --kid old-key --exp 2020-03-01)
TOKEN_FUTURE=$(php php/issue.php --epoch E1 --page $PAGE --kid new-key --exp 2099-12-31)
TOKEN_RANDOMKID=$(php php/issue.php --epoch E1 --page $PAGE)
TOKEN_UI=$(php php/issue.php --epoch E1 --page $PAGE --kid acct-4471 --exp 2027-01-31 \
    --name 'A. Example' --institution 'Example Institute')
TOKEN_BLANK=$(php php/issue.php --epoch E1 --page $PAGE --exp 9999-12-31 --name unknown --institution unknown)
TOKEN_OTHERPAGE=$(php php/issue.php --epoch E1 --page $OTHER --kid wrong-page)
EXP_PAST=$(local_moment 2020-03-01T00:00:00Z)
EXP_FUTURE=$(local_moment 2099-12-31T00:00:00Z)
EXP_UI=$(local_moment 2027-01-31T00:00:00Z)
EXP_NEVER=$(local_moment 9999-12-31T00:00:00Z)
TOKEN_E2=$(php php/issue.php --epoch E2 --page $PAGE --kid wrong-epoch)
TOKEN_E2_OWN=$(php php/issue.php --epoch E2 --page $PAGE --kid e2-user)


load_dotnet
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
(cd dotnet/ReportSeal.Generator && dotnet build -v q --nologo >/dev/null 2>&1) || { echo "build failed"; exit 1; }
(cd dotnet/ReportSeal.Generator && dotnet run --no-build -- \
    --table "$ROOT/keys/epochs.json" --epoch E1 --page $PAGE \
    --hidden "$ROOT/samples/hidden.html" --header "$ROOT/samples/header.html" \
    --title "Quarterly Summary" --out "$OUT/page.html" >/dev/null 2>&1) \
  || { echo "generate failed"; exit 1; }

echo "== library self-test (pairing constant, stepwise sealing, thread safety)"
(cd dotnet/ReportSeal.SelfTest && dotnet build -v q --nologo >/dev/null 2>&1) \
  || { echo "  FAIL self-test would not build"; fail=$((fail+1)); }
SELFTEST=$(cd dotnet/ReportSeal.SelfTest && dotnet run --no-build 2>/dev/null | tail -1)
if [ "${SELFTEST#*, }" = "0 failed" ]; then
  pass=$((pass+1)); echo "  ok   $SELFTEST"
else
  fail=$((fail+1)); echo "  FAIL $SELFTEST"
fi

load_chrome
CHROME=$(command -v google-chrome || command -v chrome || command -v google-chrome-stable)
[ -z "$CHROME" ] && { echo "no chrome binary found"; exit 1; }

# ------------------------------------------------------------------- harnesses
# $1 = case name, $2 = token to type. Prints the final DOM.
run_case() {
  local name=$1 token=$2 page=$WORK/$1.html
  cp "$OUT/page.html" "$page"
  TOKEN_VALUE="$token" python3 - "$page" <<'PY'
import os, sys, json
p = sys.argv[1]
# The unlock script builds its own form, so drive it through the rendered UI.
driver = ("\n<script>\n"
          "document.querySelector('.reportseal-form textarea').value = %s;\n"
          "document.querySelector('.reportseal-form')"
          ".dispatchEvent(new Event('submit', {cancelable:true}));\n"
          "</script>\n") % json.dumps(os.environ['TOKEN_VALUE'])
html = open(p, encoding='utf-8').read().replace('</body>', driver + '</body>')
open(p, 'w', encoding='utf-8').write(html)
PY
  "$CHROME" --headless=new --no-sandbox --disable-gpu --disable-dev-shm-usage \
      --user-data-dir="$WORK/profile-$name" --virtual-time-budget=8000 \
      --dump-dom "file://$page" 2>/dev/null \
    | python3 -c "import sys,re; sys.stdout.write(re.sub(r'(?s)<script.*?</script>','',sys.stdin.read()))"
}

check() { # name, dom, expected substring, should_be_present(y/n)
  local name=$1 dom=$2 needle=$3 want=$4
  if grep -qF -- "$needle" <<<"$dom"; then found=y; else found=n; fi
  if [ "$found" = "$want" ]; then
    pass=$((pass+1)); printf '  ok   %s\n' "$name"
  else
    fail=$((fail+1)); printf '  FAIL %s (expected present=%s for "%s")\n' "$name" "$want" "$needle"
  fi
}

# Runs one Chrome session against a copy of the page with a custom driver script
# appended. Everything a case needs to observe must happen inside that one session:
# launching a second browser against the same profile races profile locking and
# storage flushing, which made earlier versions of these tests flaky.
run_driver() {
  local name=$1 driver=$2 page=$WORK/$1.html
  cp "$OUT/page.html" "$page"
  DRIVER="$driver" python3 - "$page" <<'PY'
import os, sys
p = sys.argv[1]
original = open(p, encoding='utf-8').read()
block = "\n<script>\n" + os.environ['DRIVER'] + "\n</script>\n"
open(p, 'w', encoding='utf-8').write(original.replace('</body>', block + '</body>'))
PY
  "$CHROME" --headless=new --no-sandbox --disable-gpu --disable-dev-shm-usage \
      --user-data-dir="$WORK/profile-$name" --virtual-time-budget=15000 \
      --dump-dom "file://$page" 2>/dev/null \
    | python3 -c "import sys,re; sys.stdout.write(re.sub(r'(?s)<script.*?</script>','',sys.stdin.read()))"
}

# Removes the page and epoch checks from a copy of the page, leaving only the
# cryptography to refuse a key meant for somewhere else.
run_driver_on_patched() {
  local token=$1 page=$WORK/patched.html
  TOKEN_VALUE="$token" python3 - "$OUT/page.html" "$page" <<'PYEOF'
import os, sys, json
src, out = sys.argv[1], sys.argv[2]
html = open(src, encoding='utf-8').read()
html = html.replace("if (payload.page !== d.page) {", "if (false) {")
html = html.replace("if (payload.epoch !== d.epoch) {", "if (false) {")
driver = ("\n<script>\ndocument.querySelector('.reportseal-form textarea').value = %s;\n"
          "document.querySelector('.reportseal-form')"
          ".dispatchEvent(new Event('submit', {cancelable:true}));\n</script>\n"
          ) % json.dumps(os.environ['TOKEN_VALUE'])
open(out, 'w', encoding='utf-8').write(html.replace('</body>', driver + '</body>'))
PYEOF
  "$CHROME" --headless=new --no-sandbox --disable-gpu --disable-dev-shm-usage \
      --user-data-dir="$WORK/profile-patched" --virtual-time-budget=20000 \
      --dump-dom "file://$page" 2>/dev/null \
    | python3 -c "import sys,re; sys.stdout.write(re.sub(r'(?s)<script.*?</script>','',sys.stdin.read()))"
}

# Generates a page under a given epoch with extra generator flags, then drives one
# token against it.
# $1 = variant name, $2 = epoch, $3 = generator flags, $4 = token
run_variant() {
  local name=$1 epoch=$2 flags=$3 token=$4 page=$WORK/$1.html
  load_dotnet
  (cd dotnet/ReportSeal.Generator && dotnet run --no-build -- \
      --table "$ROOT/keys/epochs.json" --epoch $epoch --page $PAGE $flags \
      --hidden "$ROOT/samples/hidden.html" --header "$ROOT/samples/header.html" \
      --title "Quarterly Summary" --out "$page" >/dev/null 2>&1) \
    || { echo "  FAIL could not generate $name"; fail=$((fail+1)); return; }
  load_chrome
  TOKEN_VALUE="$token" python3 - "$page" <<'PYEOF'
import os, sys, json
p = sys.argv[1]
original = open(p, encoding='utf-8').read()
driver = ("\n<script>\ndocument.querySelector('.reportseal-form textarea').value = %s;\n"
          "document.querySelector('.reportseal-form')"
          ".dispatchEvent(new Event('submit', {cancelable:true}));\n</script>\n"
          ) % json.dumps(os.environ['TOKEN_VALUE'])
open(p, 'w', encoding='utf-8').write(original.replace('</body>', driver + '</body>'))
PYEOF
  "$CHROME" --headless=new --no-sandbox --disable-gpu --disable-dev-shm-usage \
      --user-data-dir="$WORK/profile-$name" --virtual-time-budget=20000 \
      --dump-dom "file://$page" 2>/dev/null \
    | python3 -c "import sys,re; sys.stdout.write(re.sub(r'(?s)<script.*?</script>','',sys.stdin.read()))"
}

# Reports what is in localStorage by appending it to the document.
STORAGE_DUMP='
function dumpStorage() {
  var items = [];
  try {
    for (var i = 0; i < localStorage.length; i++) {
      var k = localStorage.key(i);
      items.push(k + "=" + localStorage.getItem(k).slice(0, 4));
    }
  } catch (e) { items.push("unavailable"); }
  var p = document.createElement("p");
  p.textContent = "STORAGE:[" + items.join(",") + "]";
  document.body.appendChild(p);
}
function afterUnlock(fn) {
  var t = setInterval(function () {
    var st = document.querySelector(".reportseal-status");
    if (st && /Unlocked/.test(st.textContent)) { clearInterval(t); fn(); }
  }, 50);
}
function submitKey(token) {
  document.querySelector(".reportseal-form textarea").value = token;
  document.querySelector(".reportseal-form")
    .dispatchEvent(new Event("submit", { cancelable: true }));
}
'

echo "== generated page does not leak the plaintext"
check "ciphertext only" "$(cat "$OUT/page.html")" "SEALED-SAMPLE-OK" n
check "no marker string" "$(cat "$OUT/page.html")" "1 234 units" n

echo "== valid key unlocks in Chrome on file://"
DOM=$(run_case valid "$TOKEN")
check "status ok"        "$DOM" "Unlocked."                    y
check "content revealed" "$DOM" "SEALED-SAMPLE-OK"              y
check "table decrypted"  "$DOM" "2 345 units"                   y
check "key id not shown" "$DOM" "acct-4471"                   n
check "extra json shown" "$DOM" "gold"                        y
check "locked notice hidden" "$DOM" 'reportseal-locked" hidden'    y
check "ciphertext div stays hidden" "$DOM" 'hidden="" data-epoch' y

echo "== key issued without --kid gets a unique id"
DOM=$(run_case randomkid "$TOKEN_RANDOMKID")
check "random kid accepted" "$DOM" "Unlocked."           y
check "content revealed"    "$DOM" "SEALED-SAMPLE-OK"       y
KIDPAT=$(python3 -c "
import base64, json, sys
p = sys.argv[1].split('.')[1]
print(json.loads(base64.urlsafe_b64decode(p + '=='))['extra']['kid'])" "$TOKEN_RANDOMKID")
if [[ $KIDPAT =~ ^K-[0-9A-F]{8}$ ]]; then pass=$((pass+1)); echo "  ok   generated kid is random"; 
else fail=$((fail+1)); echo "  FAIL generated kid is random (got $KIDPAT)"; fi

echo "== expiry is reported, never enforced"
DOM=$(run_case expired "$TOKEN_EXPIRED")
check "expiry reported"      "$DOM" "This key expired on $EXP_PAST"  y
check "notice-only wording"  "$DOM" "expiry is a notice only"        y
check "flagged as expired"   "$DOM" 'class="reportseal-expiry expired"'  y
check "content still shown"  "$DOM" "SEALED-SAMPLE-OK"                y
check "date in header"       "$DOM" "valid until $EXP_PAST"         y

DOM=$(run_case future "$TOKEN_FUTURE")
check "validity reported"    "$DOM" "valid until $EXP_FUTURE" y
check "not flagged expired"  "$DOM" 'reportseal-expiry expired'  n
check "content shown"        "$DOM" "SEALED-SAMPLE-OK"        y

DOM=$(run_case noexp "$TOKEN")
check "no expiry banner when absent" "$DOM" 'class="reportseal-expiry" role="note" hidden' y

echo "== the key is remembered, and a revisit needs no key"
DOM=$(run_driver remember "$STORAGE_DUMP
if (location.hash !== '#again') {
  afterUnlock(function () { location.hash = '#again'; location.reload(); });
  submitKey($(printf '%s' "$TOKEN" | python3 -c 'import sys,json;print(json.dumps(sys.stdin.read()))'));
} else {
  setTimeout(dumpStorage, 1000);   // second pass: no key typed, storage must carry it
}")
check "stored under page id"    "$DOM" "STORAGE:[reportseal/v2/E1/$PAGE=" y
check "stored value is a token" "$DOM" "=NO1."                          y
check "auto-unlocked"           "$DOM" "Unlocked with a remembered key." y
check "content revealed"        "$DOM" "SEALED-SAMPLE-OK"                 y
check "entry form hidden"       "$DOM" 'reportseal-form" autocomplete="off" hidden' y

echo "== forgetting the key re-locks the page"
DOM=$(run_driver forget "$STORAGE_DUMP
if (location.hash === '') {
  afterUnlock(function () { location.hash = '#stored'; location.reload(); });
  submitKey($(printf '%s' "$TOKEN" | python3 -c 'import sys,json;print(json.dumps(sys.stdin.read()))'));
} else if (location.hash === '#stored') {
  var t = setInterval(function () {
    var note = document.querySelector('.reportseal-remembered');
    if (note && !note.hidden) {
      clearInterval(t);
      location.hash = '#forgotten';
      document.querySelector('.reportseal-forget').click();
    }
  }, 50);
} else {
  setTimeout(dumpStorage, 1000);   // third pass: entry must be gone
}")
check "storage emptied"                "$DOM" "STORAGE:[]"     y
check "page locked again after forget" "$DOM" "SEALED-SAMPLE-OK" n
check "entry form offered again"       "$DOM" "Decryption key" y

echo "== storage being unavailable does not block unlocking"
BLOCKED=$WORK/blocked.html
TOKEN_VALUE="$TOKEN" python3 - "$BLOCKED" "$OUT/page.html" <<'PY'
import os, sys, json
out, src = sys.argv[1], sys.argv[2]
deny = ("\n<script>\nObject.defineProperty(window, 'localStorage', "
        "{ get: function () { throw new Error('denied'); } });\n</script>\n")
driver = ("\n<script>\ndocument.querySelector('.reportseal-form textarea').value = %s;\n"
          "document.querySelector('.reportseal-form')"
          ".dispatchEvent(new Event('submit', {cancelable:true}));\n</script>\n"
          ) % json.dumps(os.environ['TOKEN_VALUE'])
html = open(src, encoding='utf-8').read()
html = html.replace('<body>', '<body>' + deny, 1).replace('</body>', driver + '</body>')
open(out, 'w', encoding='utf-8').write(html)
PY
DOM=$("$CHROME" --headless=new --no-sandbox --disable-gpu --disable-dev-shm-usage \
      --user-data-dir="$WORK/profile-blocked" --virtual-time-budget=8000 \
      --dump-dom "file://$BLOCKED" 2>/dev/null \
    | python3 -c "import sys,re; sys.stdout.write(re.sub(r'(?s)<script.*?</script>','',sys.stdin.read()))")
check "still unlocks"            "$DOM" "Unlocked."                       y
check "no remembered claim made" "$DOM" 'class="reportseal-remembered" hidden' y

echo "== attribution from the key is printed in the page header"
DOM=$(run_case attributed "$TOKEN_UI")
check "user name in header"    "$DOM" "Issued to A. Example"            y
check "institution in header"  "$DOM" "Example Institute"           y
check "expiry in header"       "$DOM" "valid until $EXP_UI"             y
check "in the header element"  "$DOM" 'data-reportseal-attribution'     y
check "key id not displayed"   "$DOM" "acct-4471"                       n
check "no empty key data list" "$DOM" 'reportseal-keydata" hidden'      y

echo "== blank fields fall back to unknown and year 9999"
DOM=$(run_case defaults "$TOKEN_BLANK")
check "user unknown"        "$DOM" "Issued to unknown · unknown" y
check "expiry year 9999"    "$DOM" "valid until $EXP_NEVER"      y
check "content revealed"    "$DOM" "SEALED-SAMPLE-OK"             y
check "no expiry warning"   "$DOM" 'reportseal-expiry expired'   n

echo "== attribution can be switched off at generation time"
DOM=$(run_variant noattr E1 --no-attribution "$TOKEN_UI")
check "content revealed"        "$DOM" "SEALED-SAMPLE-OK"       y
check "no attribution printed"  "$DOM" "Issued to A. Example" n
DOM=$(run_variant withattr E1 "" "$TOKEN_UI")
check "shown by default"        "$DOM" "Issued to A. Example" y

echo "== expiry can be \"enforced\" at generation time"
DOM=$(run_variant enforced E1 --enforce-expiry "$TOKEN_EXPIRED")
check "expired key refused"     "$DOM" "set to refuse expired keys" y
check "content withheld"        "$DOM" "SEALED-SAMPLE-OK"             n
DOM=$(run_variant enforced-ok E1 --enforce-expiry "$TOKEN_FUTURE")
check "live key still opens it" "$DOM" "SEALED-SAMPLE-OK"             y

echo "== a demo page can ship with the key already in the box"
# BeginSealInternal is internal, so the attribute is injected the way it would emit
# it; what is under test is the browser half.
PREFILL=$WORK/prefill.html
TOKEN_VALUE="$TOKEN" python3 - "$OUT/page.html" "$PREFILL" <<'PYEOF'
import os, sys, json
src, out = sys.argv[1], sys.argv[2]
html = open(src, encoding='utf-8').read()
assert ' hidden data-epoch=' in html
html = html.replace(' hidden data-epoch=',
                    ' hidden data-debug-key="%s" data-epoch=' % os.environ['TOKEN_VALUE'], 1)
driver = ("\n<script>\nvar v = document.querySelector('.reportseal-form textarea').value;\n"
          "var p = document.createElement('p');\n"
          "p.textContent = 'PREFILL_LEN:' + v.length;\n"
          "document.body.appendChild(p);\n"
          "document.querySelector('.reportseal-form')"
          ".dispatchEvent(new Event('submit', {cancelable:true}));\n</script>\n")
open(out, 'w', encoding='utf-8').write(html.replace('</body>', driver + '</body>'))
PYEOF
DOM=$("$CHROME" --headless=new --no-sandbox --disable-gpu --disable-dev-shm-usage \
      --user-data-dir="$WORK/profile-prefill" --virtual-time-budget=20000 \
      --dump-dom "file://$PREFILL" 2>/dev/null \
    | python3 -c "import sys,re; sys.stdout.write(re.sub(r'(?s)<script.*?</script>','',sys.stdin.read()))")
check "entry box was pre-filled" "$DOM" "PREFILL_LEN:0" n
check "and it opens the page"    "$DOM" "SEALED-SAMPLE-OK" y
check "normal pages are not"     "$(cat "$OUT/page.html")" "data-debug-key" n

echo "== compression is on by default and independent of the key"
check "default page is compressed" "$(cat "$OUT/page.html")" 'data-encoding="gzip"' y
DOM=$(run_variant uncompressed E1 --no-compress "$TOKEN")
check "same token opens it uncompressed" "$DOM" "SEALED-SAMPLE-OK"  y
check "and that page declares no encoding" "$DOM" "data-encoding" n
DOM=$(run_variant compressed E1 "" "$TOKEN")
check "same token opens it compressed"  "$DOM" "SEALED-SAMPLE-OK"   y
check "and that page declares gzip"     "$DOM" 'data-encoding="gzip"' y

echo "== tampered key is rejected"
BAD=$(python3 - "$TOKEN" <<'PY'
import sys
t = sys.argv[1]; p = t.split('.')
mid = len(p[1]) // 2
p[1] = p[1][:mid] + ('B' if p[1][mid] != 'B' else 'C') + p[1][mid+1:]
print('.'.join(p))
PY
)
DOM=$(run_case tampered "$BAD")
check "signature refused" "$DOM" "signature is not valid" y
check "content stays hidden" "$DOM" "SEALED-SAMPLE-OK"      n

echo "== a page sealed under a different epoch opens with that epoch's key"
DOM=$(run_variant epoch2 E2 "" "$TOKEN_E2_OWN")
check "E2 page opens with E2 key" "$DOM" "SEALED-SAMPLE-OK" y
DOM=$(run_variant epoch2b E2 "" "$TOKEN")
check "E2 page refuses E1 key"   "$DOM" "SEALED-SAMPLE-OK" n

echo "== a key for another page is rejected"
DOM=$(run_case wrongpage "$TOKEN_OTHERPAGE")
check "page mismatch reported" "$DOM" "was issued for page 'DOC-5678'" y
check "content stays hidden"   "$DOM" "SEALED-SAMPLE-OK"                n

echo "== a key from another epoch is rejected"
DOM=$(run_case wrongepoch "$TOKEN_E2")
check "epoch mismatch reported" "$DOM" "this page was sealed under 'E1'" y
check "content stays hidden"    "$DOM" "SEALED-SAMPLE-OK"                n

echo "== the binding holds with the checks patched out"
DOM=$(run_driver_on_patched "$TOKEN_OTHERPAGE")
check "cryptography refuses it" "$DOM" "did not authenticate" y
check "content stays hidden"    "$DOM" "SEALED-SAMPLE-OK"       n

echo "== garbage input is rejected"
DOM=$(run_case garbage "not-a-key")
check "malformed reported"   "$DOM" "does not look like a key" y
check "content stays hidden" "$DOM" "SEALED-SAMPLE-OK"           n

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
