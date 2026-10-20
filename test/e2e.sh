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

# Keys are encrypted at rest; test/setup.sh records the fixture passwords here.
FIXTURE=$ROOT/out/fixture-passwords
[ -f "$FIXTURE" ] || { echo "no $FIXTURE — run test/setup.sh first"; exit 1; }
declare -A FIXTURE_PW=()
while IFS='=' read -r name value; do FIXTURE_PW[$name]=$value; done < "$FIXTURE"

# php/issue.php with the fixture passwords for whichever --epoch the call names.
issue() {
  local epoch="" a
  local -a args=("$@")
  for ((a = 0; a < ${#args[@]}; a++)); do
    [ "${args[$a]}" = "--epoch" ] && epoch=${args[$((a + 1))]}
  done
  php php/issue.php "$@" --signing-password "${FIXTURE_PW[SIGN]}" \
                         --epoch-password "${FIXTURE_PW[$epoch]:-}"
}

TABLE_FILE=$ROOT/keys/epochs.json
TABLE=file://$TABLE_FILE

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
missing = [e for e in ('E1', 'E2', 'E3') if e not in epochs]
if missing:
    print('key table has no epoch ' + ', '.join(missing), file=sys.stderr)
    sys.exit(1)
PYEOF

PAGE=DOC-1234
OTHER=DOC-5678
TOKEN=$(issue --epoch E1 --page $PAGE --kid acct-4471 --extra '{"tier":"gold"}')
TOKEN_EXPIRED=$(issue --epoch E1 --page $PAGE --kid old-key --exp 2020-03-01)
TOKEN_FUTURE=$(issue --epoch E1 --page $PAGE --kid new-key --exp 2099-12-31)
TOKEN_RANDOMKID=$(issue --epoch E1 --page $PAGE)
TOKEN_UI=$(issue --epoch E1 --page $PAGE --kid acct-4471 --exp 2027-01-31 \
    --name 'A. Example' --institution 'Example Institute')
TOKEN_BLANK=$(issue --epoch E1 --page $PAGE --exp 9999-12-31 --name unknown --institution unknown)
TOKEN_OTHERPAGE=$(issue --epoch E1 --page $OTHER --kid wrong-page)
UNIPAGE='DOC-Årsrapport-Übersicht'
TOKEN_UNICODE=$(issue --epoch E1 --page "$UNIPAGE" --kid 'nyckel-Åsa' \
    --name 'Åsa Müller-Désirée' --institution 'Universität Göttingen' 2>/dev/null)
EXP_PAST=$(local_moment 2020-03-01T00:00:00Z)
EXP_FUTURE=$(local_moment 2099-12-31T00:00:00Z)
EXP_UI=$(local_moment 2027-01-31T00:00:00Z)
EXP_NEVER=$(local_moment 9999-12-31T00:00:00Z)
TOKEN_E2=$(issue --epoch E2 --page $PAGE --kid wrong-epoch)
TOKEN_E2_OWN=$(issue --epoch E2 --page $PAGE --kid e2-user)
TOKEN_E3_OWN=$(issue --epoch E3 --page $PAGE --kid e3-user)


load_dotnet
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
(cd dotnet/ReportSeal.Generator && dotnet build -v q --nologo >/dev/null 2>&1) || { echo "build failed"; exit 1; }
{
  echo '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
  echo '<title>Quarterly Summary</title></head><body>'
  echo '<header><h1>Quarterly Summary</h1>'
  echo '<p class="muted" data-reportseal-attribution hidden></p></header>'
  echo "<!-- ReportSeal PageID: $PAGE, Epoch: E1, Compress: true,"
  echo "     EnforceExpiry: false, ShowAttribution: true, Table: $TABLE -->"
  cat "$ROOT/samples/fragment-to-seal.html"
  echo '<!-- EndOfReportSeal -->'
  echo '</body></html>'
} > "$OUT/page-src.html"
(cd dotnet/ReportSeal.Generator && dotnet run --no-build -- \
    --in "$OUT/page-src.html" \
    --out "$OUT/page.html" >/dev/null 2>&1) \
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
for old, new in (("if (slot < 0) {", "if (slot < 0) { slot = 0; }\n    if (false) {"),
                 ("if (payload.page !== group.page) {", "if (false) {")):
    assert old in html, 'guard not found: ' + old
    html = html.replace(old, new, 1)
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

# Seals a one-fragment page with the given marker attributes, then drives one token
# against it.
# $1 name, $2 epoch, $3 compress, $4 enforce expiry, $5 show attribution, $6 token
run_variant() {
  local name=$1 epoch=$2 compress=$3 enforce=$4 attribution=$5 token=$6 page=$WORK/$1.html
  write_and_seal "$name" "$PAGE" "$epoch" "$compress" "$enforce" "$attribution" >/dev/null \
    || return
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

# Drives one token against a page that has already been generated.
# $1 page file, $2 token, $3 profile tag, $4 "patched" to strip the epoch and page
# checks so only the cryptography can refuse the key.
drive_file() {
  local src=$1 token=$2 tag=$3 mode=${4:-plain} page=$WORK/drive-$3.html
  TOKEN_VALUE="$token" MODE="$mode" python3 - "$src" "$page" <<'PYEOF'
import os, sys, json
src, out = sys.argv[1], sys.argv[2]
html = open(src, encoding='utf-8').read()
if os.environ['MODE'] == 'patched':
    # force the first C1 and skip the refusals, leaving AES-GCM as the only gate
    for old, new in (("if (slot < 0) {", "if (slot < 0) { slot = 0; }\n    if (false) {"),
                     ("if (payload.page !== group.page) {", "if (false) {")):
        assert old in html, 'guard not found: ' + old
        html = html.replace(old, new, 1)
driver = ("\n<script>\ndocument.querySelector('.reportseal-form textarea').value = %s;\n"
          "document.querySelector('.reportseal-form')"
          ".dispatchEvent(new Event('submit', {cancelable:true}));\n</script>\n"
          ) % json.dumps(os.environ['TOKEN_VALUE'])
open(out, 'w', encoding='utf-8').write(html.replace('</body>', driver + '</body>'))
PYEOF
  "$CHROME" --headless=new --no-sandbox --disable-gpu --disable-dev-shm-usage \
      --user-data-dir="$WORK/profile-$tag" --virtual-time-budget=25000 \
      --dump-dom "file://$page" 2>/dev/null \
    | python3 -c "import sys,re; sys.stdout.write(re.sub(r'(?s)<script.*?</script>','',sys.stdin.read()))"
}

# Writes a complete page carrying one ReportSeal marker, then seals it. The page
# now says what to seal, so the old generator flags are gone and these are marker
# attributes instead.
# $1 name, $2 page id, $3 epoch (or E1+E3), $4 compress, $5 enforce expiry,
# $6 show attribution
write_and_seal() {
  local name=$1 pageid=$2 epoch=$3 compress=$4 enforce=$5 attribution=$6
  local src=$WORK/$name-src.html out=$WORK/$name.html
  {
    echo '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
    echo "<title>Quarterly Summary</title></head><body>"
    echo '<header><h1>Quarterly Summary</h1>'
    echo '<p class="muted" data-reportseal-attribution hidden></p></header>'
    echo "<!-- ReportSeal PageID: $pageid, Epoch: $epoch, Compress: $compress,"
    echo "     EnforceExpiry: $enforce, ShowAttribution: $attribution, Table: $TABLE -->"
    cat "$ROOT/samples/fragment-to-seal.html"
    echo '<!-- EndOfReportSeal -->'
    echo '</body></html>'
  } > "$src"
  load_dotnet
  (cd dotnet/ReportSeal.Generator && dotnet run --no-build -- \
      --in "$src" --out "$out" >/dev/null 2>&1) \
    || { echo "  FAIL could not seal $name"; fail=$((fail+1)); return 1; }
  echo "$out"
}

# Seals a page read from stdin and expects the generator to refuse it.
# $1 tag, $2 description
expect_markup_error() {
  local tag=$1 desc=$2 src=$WORK/bad-$1.html
  sed "s|@TABLE@|$TABLE|g" > "$src"
  load_dotnet
  if (cd dotnet/ReportSeal.Generator && dotnet run --no-build -- \
        --in "$src" \
        --out "$WORK/bad-$1-out.html" >/dev/null 2>&1); then
    fail=$((fail+1)); printf '  FAIL %s was accepted\n' "$desc"
  else
    pass=$((pass+1)); printf '  ok   %s refused\n' "$desc"
  fi
}

# Drives a token into one specific entry box, for pages whose fragments fall into
# more than one group and therefore show more than one box.
# $1 page file, $2 token, $3 tag, $4 box index
drive_nth() {
  local src=$1 token=$2 tag=$3 index=$4 page=$WORK/drive-$3.html
  TOKEN_VALUE="$token" INDEX="$index" python3 - "$src" "$page" <<'PYEOF'
import os, sys, json
src, out = sys.argv[1], sys.argv[2]
html = open(src, encoding='utf-8').read()
driver = ("\n<script>\n"
          "var f = document.querySelectorAll('.reportseal-form')[%s];\n"
          "f.querySelector('textarea').value = %s;\n"
          "f.dispatchEvent(new Event('submit', {cancelable:true}));\n</script>\n"
          ) % (os.environ['INDEX'], json.dumps(os.environ['TOKEN_VALUE']))
open(out, 'w', encoding='utf-8').write(html.replace('</body>', driver + '</body>'))
PYEOF
  "$CHROME" --headless=new --no-sandbox --disable-gpu --disable-dev-shm-usage \
      --user-data-dir="$WORK/profile-$tag" --virtual-time-budget=30000 \
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
check "ciphertext div stays hidden" "$DOM" 'hidden="" data-reportseal' y

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
check "no empty key data list" "$DOM" 'class="reportseal-keydata"'      n

echo "== blank fields fall back to unknown and year 9999"
DOM=$(run_case defaults "$TOKEN_BLANK")
check "user unknown"        "$DOM" "Issued to unknown · unknown" y
check "expiry year 9999"    "$DOM" "valid until $EXP_NEVER"      y
check "content revealed"    "$DOM" "SEALED-SAMPLE-OK"             y
check "no expiry warning"   "$DOM" 'reportseal-expiry expired'   n

echo "== attribution can be switched off at generation time"
DOM=$(run_variant noattr E1 true false false "$TOKEN_UI")
check "content revealed"        "$DOM" "SEALED-SAMPLE-OK"       y
check "no attribution printed"  "$DOM" "Issued to A. Example" n
DOM=$(run_variant withattr E1 true false true "$TOKEN_UI")
check "shown by default"        "$DOM" "Issued to A. Example" y

echo "== expiry can be \"enforced\" at generation time"
DOM=$(run_variant enforced E1 true true true "$TOKEN_EXPIRED")
check "expired key refused"     "$DOM" "set to refuse expired keys" y
check "content withheld"        "$DOM" "SEALED-SAMPLE-OK"             n
DOM=$(run_variant enforced-ok E1 true true true "$TOKEN_FUTURE")
check "live key still opens it" "$DOM" "SEALED-SAMPLE-OK"             y

echo "== a demo page can ship with the key already in the box"
# BeginSealInternal is internal, so the attribute is injected the way it would emit
# it; what is under test is the browser half.
PREFILL=$WORK/prefill.html
TOKEN_VALUE="$TOKEN" python3 - "$OUT/page.html" "$PREFILL" <<'PYEOF'
import os, sys, json
src, out = sys.argv[1], sys.argv[2]
html = open(src, encoding='utf-8').read()
assert ' hidden data-reportseal' in html
html = html.replace(' hidden data-reportseal',
                    ' hidden data-debug-key="%s" data-reportseal' % os.environ['TOKEN_VALUE'], 1)
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
check "prefill probe ran"        "$DOM" "PREFILL_LEN:"  y
check "entry box was pre-filled" "$DOM" "PREFILL_LEN:0" n
check "and it opens the page"    "$DOM" "SEALED-SAMPLE-OK" y
check "normal pages are not"     "$(cat "$OUT/page.html")" "data-debug-key" n

echo "== compression is on by default and independent of the key"
check "default page is compressed" "$(cat "$OUT/page.html")" 'data-encoding="gzip"' y
DOM=$(run_variant uncompressed E1 false false true "$TOKEN")
check "same token opens it uncompressed" "$DOM" "SEALED-SAMPLE-OK"  y
check "and that page declares no encoding" "$DOM" "data-encoding" n
DOM=$(run_variant compressed E1 true false true "$TOKEN")
check "same token opens it compressed"  "$DOM" "SEALED-SAMPLE-OK"   y
check "and that page declares gzip"     "$DOM" 'data-encoding="gzip"' y

echo "== accented text survives the whole chain"
write_and_seal unicode "$UNIPAGE" E1 true false true >/dev/null || true
UNIPAGEFILE=$WORK/unicode.html
load_chrome
TOKEN_VALUE="$TOKEN_UNICODE" python3 - "$UNIPAGEFILE" <<'PYEOF'
import os, sys, json
p = sys.argv[1]
original = open(p, encoding='utf-8').read()
driver = ("\n<script>\ndocument.querySelector('.reportseal-form textarea').value = %s;\n"
          "document.querySelector('.reportseal-form')"
          ".dispatchEvent(new Event('submit', {cancelable:true}));\n</script>\n"
          ) % json.dumps(os.environ['TOKEN_VALUE'])
open(p, 'w', encoding='utf-8').write(original.replace('</body>', driver + '</body>'))
PYEOF
DOM=$("$CHROME" --headless=new --no-sandbox --disable-gpu --disable-dev-shm-usage \
      --user-data-dir="$WORK/profile-unicode" --virtual-time-budget=25000 \
      --dump-dom "file://$UNIPAGEFILE" 2>/dev/null \
    | python3 -c "import sys,re; sys.stdout.write(re.sub(r'(?s)<script.*?</script>','',sys.stdin.read()))")
check "accented page id unlocks"  "$DOM" "SEALED-SAMPLE-OK"                y
check "accented name in header"   "$DOM" "Åsa Müller-Désirée"              y
check "accented institution"      "$DOM" "Universität Göttingen"           y

# The two sides print a fingerprint of the identity so a page id that differs only
# by Unicode composition is visible. They must agree, or the hint misleads.
load_php
PHP_FP=$(issue --epoch E1 --page "$UNIPAGE" --kid fp-probe 2>&1 >/dev/null \
         | grep -o 'page identity [0-9a-f]*' | awk '{print $3}')
load_dotnet
GEN_FP=$(cd dotnet/ReportSeal.Generator && dotnet run --no-build -- \
    --in "$WORK/unicode-src.html" \
    --out "$WORK/fp.html" 2>/dev/null \
  | grep -o 'identity [0-9a-f]*' | head -1 | awk '{print $2}')
if [ -n "$PHP_FP" ] && [ "$PHP_FP" = "$GEN_FP" ]; then
  pass=$((pass+1)); echo "  ok   both sides fingerprint the identity alike ($PHP_FP)"
else
  fail=$((fail+1)); echo "  FAIL fingerprints differ: php=$PHP_FP generator=$GEN_FP"
fi
load_chrome

echo "== several fragments on one page"
MULTI=$WORK/multi.html
load_dotnet
(cd dotnet/ReportSeal.Generator && dotnet run --no-build -- \
    --in "$ROOT/samples/page-one-document.html" \
    --out "$MULTI" >/dev/null 2>&1) \
  || { echo "  FAIL could not seal the sample page"; fail=$((fail+1)); }
SRC=$(cat "$MULTI")
check "markers are consumed"        "$SRC" "<!-- ReportSeal"     n
check "unsealed text is kept"       "$SRC" "never sealed"          y
check "curve library inlined once"  "$(grep -c 'noble-curves' "$MULTI")" "1" y
check "neither fragment leaks"      "$SRC" "SEALED-SAMPLE-OK"      n
check "nor the second"              "$SRC" "SEALED-SECOND-OK"      n
load_chrome
DOM=$(drive_file "$MULTI" "$TOKEN_FUTURE" multi-live)
check "one key opens both"          "$DOM" "SEALED-SAMPLE-OK"      y
check "and the second section"      "$DOM" "SEALED-SECOND-OK"      y
check "a single entry box"          "$(grep -c 'class="reportseal-form"' <<<"$DOM")" "1" y
check "count is reported"           "$DOM" "2 of 2 sections"       y

echo "== per-fragment EnforceExpiry is honoured independently"
# the sample sets EnforceExpiry false on the first region and true on the second,
# so one expired key must open one and be turned away by the other
DOM=$(drive_file "$MULTI" "$TOKEN_EXPIRED" multi-expired)
check "lenient section opens"       "$DOM" "SEALED-SAMPLE-OK"      y
check "strict section withheld"     "$DOM" "SEALED-SECOND-OK"      n
check "partial count reported"      "$DOM" "1 of 2 sections"       y
check "refusal explained"           "$DOM" "refuses expired keys"  y

echo "== malformed markers are refused"
expect_markup_error unterminated "an unclosed ReportSeal" <<'EOF'
<!DOCTYPE html><html><head><title>x</title></head><body>
<!-- ReportSeal PageID: DOC-1234, Epoch: E1, Compress: true, EnforceExpiry: false, ShowAttribution: true, Table: @TABLE@ -->
<p>SEALED</p>
</body></html>
EOF
expect_markup_error orphan "an EndOfReportSeal with no opener" <<'EOF'
<!DOCTYPE html><html><head><title>x</title></head><body>
<p>text</p>
<!-- EndOfReportSeal -->
</body></html>
EOF
expect_markup_error nested "a nested ReportSeal" <<'EOF'
<!DOCTYPE html><html><head><title>x</title></head><body>
<!-- ReportSeal PageID: DOC-1234, Epoch: E1, Compress: true, EnforceExpiry: false, ShowAttribution: true, Table: @TABLE@ -->
<!-- ReportSeal PageID: DOC-5678, Epoch: E1, Compress: true, EnforceExpiry: false, ShowAttribution: true, Table: @TABLE@ -->
<p>SEALED</p>
<!-- EndOfReportSeal -->
</body></html>
EOF
expect_markup_error unknownkey "an unknown marker key" <<'EOF'
<!DOCTYPE html><html><head><title>x</title></head><body>
<!-- ReportSeal PageID: DOC-1234, Epcoh: E1, Compress: true, EnforceExpiry: false, ShowAttribution: true, Table: @TABLE@ -->
<p>SEALED</p>
<!-- EndOfReportSeal -->
</body></html>
EOF
expect_markup_error missingkey "a marker missing a key" <<'EOF'
<!DOCTYPE html><html><head><title>x</title></head><body>
<!-- ReportSeal PageID: DOC-1234, Epoch: E1, Compress: true -->
<p>SEALED</p>
<!-- EndOfReportSeal -->
</body></html>
EOF
expect_markup_error badbool "a non-boolean flag" <<'EOF'
<!DOCTYPE html><html><head><title>x</title></head><body>
<!-- ReportSeal PageID: DOC-1234, Epoch: E1, Compress: yes, EnforceExpiry: false, ShowAttribution: true, Table: @TABLE@ -->
<p>SEALED</p>
<!-- EndOfReportSeal -->
</body></html>
EOF
expect_markup_error unknownepoch "an epoch the table lacks" <<'EOF'
<!DOCTYPE html><html><head><title>x</title></head><body>
<!-- ReportSeal PageID: DOC-1234, Epoch: E9, Compress: true, EnforceExpiry: false, ShowAttribution: true, Table: @TABLE@ -->
<p>SEALED</p>
<!-- EndOfReportSeal -->
</body></html>
EOF
expect_markup_error badpageid "a page id with a forbidden character" <<'EOF'
<!DOCTYPE html><html><head><title>x</title></head><body>
<!-- ReportSeal PageID: DOC|1234, Epoch: E1, Compress: true, EnforceExpiry: false, ShowAttribution: true, Table: @TABLE@ -->
<p>SEALED</p>
<!-- EndOfReportSeal -->
</body></html>
EOF
expect_markup_error nomarkers "a page with no markers at all" <<'EOF'
<!DOCTYPE html><html><head><title>x</title></head><body>
<p>nothing to seal here</p>
</body></html>
EOF
expect_markup_error nohead "a page with no head for the styles" <<'EOF'
<html><body>
<!-- ReportSeal PageID: DOC-1234, Epoch: E1, Compress: true, EnforceExpiry: false, ShowAttribution: true, Table: @TABLE@ -->
<p>SEALED</p>
<!-- EndOfReportSeal -->
</body></html>
EOF

echo "== one page carrying two page ids"
# samples/page-two-documents.html seals DOC-1234 and DOC-5678 side by side, so the
# fragments fall into two groups and each gets its own entry box
# Its markers name http://127.0.0.1:8765/epochs.json, so serve a copy of the table
# there; only the table, never the rest of keys/.
TWODOC=$WORK/twodoc.html
mkdir -p "$WORK/served"; cp "$TABLE_FILE" "$WORK/served/epochs.json"
if curl -s -o /dev/null "http://127.0.0.1:8765/" 2>/dev/null; then
  echo "  FAIL port 8765 is already in use; the two-document sample needs it"; fail=$((fail+1))
fi
(cd "$WORK/served" && exec python3 -m http.server 8765 --bind 127.0.0.1) >/dev/null 2>&1 & SAMPLE_HTTP_PID=$!
for i in 1 2 3 4 5 6 7 8 9 10; do curl -sf http://127.0.0.1:8765/epochs.json >/dev/null && break; sleep 0.5; done
load_dotnet
TWODOC_OUT=$(cd dotnet/ReportSeal.Generator && dotnet run --no-build -- \
    --in "$ROOT/samples/page-two-documents.html" --out "$TWODOC" 2>&1) \
  || { echo "  FAIL could not seal the two-document page: $TWODOC_OUT"; fail=$((fail+1)); }
kill "$SAMPLE_HTTP_PID" 2>/dev/null; wait "$SAMPLE_HTTP_PID" 2>/dev/null
check "its table came over http" "$TWODOC_OUT" "table   : http://127.0.0.1:8765/epochs.json (signature verified" y
check "neither document leaks" "$(cat "$TWODOC")" "SEALED-FIRST-DOC-OK"  n
check "nor the other"          "$(cat "$TWODOC")" "SEALED-SECOND-DOC-OK" n
load_chrome
DOM=$(drive_nth "$TWODOC" "$TOKEN" twodoc-first 0)
check "two entry boxes"            "$(grep -c 'class="reportseal-form"' <<<"$DOM")" "2" y
check "its own document opens"     "$DOM" "SEALED-FIRST-DOC-OK"  y
check "the other stays sealed"     "$DOM" "SEALED-SECOND-DOC-OK" n
DOM=$(drive_nth "$TWODOC" "$TOKEN_OTHERPAGE" twodoc-second 1)
check "the other document opens"   "$DOM" "SEALED-SECOND-DOC-OK" y
check "and the first stays sealed" "$DOM" "SEALED-FIRST-DOC-OK"  n
DOM=$(drive_nth "$TWODOC" "$TOKEN" twodoc-cross 1)
check "a key in the wrong box is refused" "$DOM" "was issued for page 'DOC-1234'" y
check "and reveals nothing"               "$DOM" "SEALED-SECOND-DOC-OK"           n

echo "== a page may supply its own controls, wording and styles"
CUSTOM=$WORK/custom.html
load_dotnet
CUSTOM_OUT=$(cd dotnet/ReportSeal.Generator && dotnet run --no-build -- \
    --in "$ROOT/samples/page-custom-layout.html" \
    --out "$CUSTOM" 2>&1) \
  || { echo "  FAIL could not seal the custom page"; fail=$((fail+1)); }
check "defaults left out"        "$CUSTOM_OUT" "the page's own"        y
check "no default style rules"   "$(cat "$CUSTOM")" "reportseal-locked {" n
load_chrome
TOKEN_TIER=$(load_php; issue --epoch E1 --page $PAGE --kid tiered \
    --exp 2027-01-31 --name 'A. Example' --institution 'Example Institute' \
    --extra '{"tier":"gold"}' 2>/dev/null)
load_chrome
TOKEN_VALUE="$TOKEN_TIER" python3 - "$CUSTOM" "$WORK/custom-run.html" <<'PYEOF'
import os, sys, json
src, out = sys.argv[1], sys.argv[2]
html = open(src, encoding='utf-8').read()
driver = ("\n<script>\ndocument.getElementById('mykey').value = %s;\n"
          "document.querySelector('[data-reportseal-unlock]').click();\n</script>\n"
          ) % json.dumps(os.environ['TOKEN_VALUE'])
open(out, 'w', encoding='utf-8').write(html.replace('</body>', driver + '</body>'))
PYEOF
DOM=$("$CHROME" --headless=new --no-sandbox --disable-gpu --disable-dev-shm-usage \
      --user-data-dir="$WORK/profile-custom" --virtual-time-budget=30000 \
      --dump-dom "file://$WORK/custom-run.html" 2>/dev/null \
    | python3 -c "import sys,re; sys.stdout.write(re.sub(r'(?s)<script.*?</script>','',sys.stdin.read()))")
check "the supplied box is used"   "$DOM" 'class="reportseal-form"'  n
check "content revealed"           "$DOM" "SEALED-CUSTOM-OK"         y
check "\$\$reportseal-name\$\$ works"  "$DOM" "A. Example"               y
check "institution token too"      "$DOM" "Example Institute"        y
check "extra:tier token too"       "$DOM" "Tier: gold"               y
check "no token markers left"      "$DOM" '$$reportseal-name$$'      n
check "unprefixed text untouched"  "$DOM" '$$name$$'                 n
check "host classes kept"          "$DOM" 'class="reportseal-status ok"' y

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

echo "== a page sealed under two epochs opens with a key from either"
DOM=$(run_variant bothepochs "E1+E2" true false true "$TOKEN")
check "E1 key opens it"        "$DOM" "SEALED-SAMPLE-OK"          y
check "page lists both epochs" "$DOM" 'data-epochs="E1+E2"'       y
DOM=$(run_variant bothepochs2 "E1+E2" true false true "$TOKEN_E2_OWN")
check "E2 key opens it too"    "$DOM" "SEALED-SAMPLE-OK"          y
DOM=$(run_variant bothepochs3 "E1+E2" true false true "$TOKEN_OTHERPAGE")
check "wrong page still refused" "$DOM" "SEALED-SAMPLE-OK"        n

echo "== a page sealed under a different epoch opens with that epoch's key"
DOM=$(run_variant epoch2 E2 true false true "$TOKEN_E2_OWN")
check "E2 page opens with E2 key" "$DOM" "SEALED-SAMPLE-OK" y
DOM=$(run_variant epoch2b E2 true false true "$TOKEN")
check "E2 page refuses E1 key"   "$DOM" "SEALED-SAMPLE-OK" n

echo "== a page sealed under E1+E3 refuses a valid E2 key"
E1E3=$(write_and_seal e1e3 "$PAGE" "E1+E3" true false true) || true
E1E3=$WORK/e1e3.html
load_chrome
check "page lists only E1+E3" "$(cat "$E1E3")" 'data-epochs="E1+E3"' y
# positive first, so the refusals below cannot pass just because the page is broken
DOM=$(drive_file "$E1E3" "$TOKEN" e1e3-e1)
check "E1 key opens it"       "$DOM" "SEALED-SAMPLE-OK" y
DOM=$(drive_file "$E1E3" "$TOKEN_E3_OWN" e1e3-e3)
check "E3 key opens it"       "$DOM" "SEALED-SAMPLE-OK" y
DOM=$(drive_file "$E1E3" "$TOKEN_E2_OWN" e1e3-e2)
check "valid E2 key refused"  "$DOM" "Key belongs to epoch 'E2'" y
check "and content withheld"  "$DOM" "SEALED-SAMPLE-OK"          n
# the refusal must not depend on the JavaScript check
DOM=$(drive_file "$E1E3" "$TOKEN_E2_OWN" e1e3-patched patched)
check "cryptography refuses E2 too" "$DOM" "did not authenticate" y
check "still no content"            "$DOM" "SEALED-SAMPLE-OK"     n

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

echo "== the key table named by the markers"
# Table: is required, read and signature-checked by ReportSeal.Pages itself.
TT=$WORK/tables; mkdir -p "$TT"
cp "$TABLE_FILE" "$TT/epochs.json"
python3 - "$TT" <<'PYEOF'
import json, sys
d = sys.argv[1]
t = json.load(open(d + '/epochs.json'))
# same content, different layout: the canonical form must still verify
json.dump(t, open(d + '/reformatted.json', 'w'), indent=3, sort_keys=False)
x = dict(t); x['epochs'] = dict(t['epochs']); x['epochs']['E1'] = t['epochs']['E2']
json.dump(x, open(d + '/tampered.json', 'w'))
x = dict(t); x['epochs'] = dict(t['epochs']); x['epochs']['E9'] = t['epochs']['E1']
json.dump(x, open(d + '/added-epoch.json', 'w'))
x = dict(t); del x['signature']
json.dump(x, open(d + '/unsigned.json', 'w'))
PYEOF
# $1 tag, $2 Table: value for every marker, optional $3 Table: for a second marker
table_page() {
  local src=$TT/$1-src.html
  {
    echo '<!DOCTYPE html><html><head><title>x</title></head><body>'
    echo "<!-- ReportSeal PageID: $PAGE, Epoch: E1, Compress: true, EnforceExpiry: false, ShowAttribution: true, Table: $2 -->"
    echo '<p>SEALED-TABLE-OK</p><!-- EndOfReportSeal -->'
    if [ -n "${3:-}" ]; then
      echo "<!-- ReportSeal PageID: $PAGE, Epoch: E1, Compress: true, EnforceExpiry: false, ShowAttribution: true, Table: $3 -->"
      echo '<p>SECOND</p><!-- EndOfReportSeal -->'
    fi
    echo '</body></html>'
  } > "$src"
  echo "$src"
}
# $1 tag, $2 description, $3 expected substring in the generator's output, then table_page args
expect_table() {
  local tag=$1 desc=$2 want=$3; shift 3
  local src out
  src=$(table_page "$tag" "$@")
  out=$(cd dotnet/ReportSeal.Generator && dotnet run --no-build -- \
        --in "$src" --out "$TT/$tag.html" 2>&1)
  if grep -qF -- "$want" <<<"$out"; then
    pass=$((pass+1)); printf '  ok   %s\n' "$desc"
  else
    fail=$((fail+1)); printf '  FAIL %s: expected "%s", got: %s\n' "$desc" "$want" "$(tr '\n' ' ' <<<"$out" | cut -c1-200)"
  fi
}
load_dotnet
expect_table barepath  "a path without file:// is refused"        "has no scheme"        "$TT/epochs.json"
expect_table barerel   "a relative path without file:// is refused" "has no scheme"      "../../../../../keys/epochs.json"
expect_table fileuri   "a file:// URI is read"                    "signature verified"   "file://$TT/epochs.json"
expect_table relpath   "a relative file:// path is taken from the executable" "signature verified" "file://../../../../../keys/epochs.json"
expect_table layout    "a re-laid-out table still verifies"       "signature verified"   "file://$TT/reformatted.json"
expect_table tampered  "a table with an altered epoch is refused" "does not verify"      "file://$TT/tampered.json"
expect_table added     "a table with an added epoch is refused"   "does not verify"      "file://$TT/added-epoch.json"
expect_table unsigned  "an unsigned table is refused"             "is not signed"        "file://$TT/unsigned.json"
expect_table missing   "a missing table is refused"               "could not read the key table" "file://$TT/nope.json"
expect_table ftp       "an ftp: location is refused"              "only https://, http:// and file://" "ftp://127.0.0.1/epochs.json"
expect_table mixed     "two tables on one page are refused"       "must use the same table" "file://$TT/epochs.json" "file://$TT/reformatted.json"
expect_table samefile  "one table spelled two ways is accepted"   "signature verified"   "file://$TT/epochs.json" "file://$TT/../tables/epochs.json"
grep -q 'SEALED-TABLE-OK' "$TT/tampered.html" 2>/dev/null \
  && { fail=$((fail+1)); echo "  FAIL a refused table still produced a page"; } \
  || { pass=$((pass+1)); echo "  ok   a refused table writes no page"; }

# over the network, from a local Python server
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
(cd "$TT" && exec python3 -m http.server "$PORT" --bind 127.0.0.1) >/dev/null 2>&1 & HTTP_PID=$!
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj /CN=127.0.0.1 \
  -addext subjectAltName=IP:127.0.0.1 -keyout "$TT/tls.key" -out "$TT/tls.crt" >/dev/null 2>&1
SPORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
python3 - "$TT" "$SPORT" >/dev/null 2>&1 <<'PYEOF' & HTTPS_PID=$!
import http.server, os, ssl, sys
d, port = sys.argv[1], int(sys.argv[2])
os.chdir(d)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(d + '/tls.crt', d + '/tls.key')
srv = http.server.HTTPServer(('127.0.0.1', port), http.server.SimpleHTTPRequestHandler)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
PYEOF
for i in 1 2 3 4 5 6 7 8 9 10; do
  curl -sf "http://127.0.0.1:$PORT/epochs.json" >/dev/null && curl -sfk "https://127.0.0.1:$SPORT/epochs.json" >/dev/null && break
  sleep 0.5
done
if curl -sf "http://127.0.0.1:$PORT/epochs.json" >/dev/null && curl -sfk "https://127.0.0.1:$SPORT/epochs.json" >/dev/null; then
  pass=$((pass+1)); echo "  ok   the http and https test servers are up"
else
  fail=$((fail+1)); echo "  FAIL the http or https test server did not start"
fi
expect_table http      "an http:// URL is fetched"                "signature verified"   "http://127.0.0.1:$PORT/epochs.json"
expect_table http404   "an http:// URL that is not there is refused" "could not read the key table" "http://127.0.0.1:$PORT/nope.json"
expect_table httptamp  "a tampered table over http is refused"    "does not verify"      "http://127.0.0.1:$PORT/tampered.json"
# the throwaway certificate is trusted for this one run only
SSL_CERT_FILE=$TT/tls.crt expect_table https "an https:// URL is fetched" "signature verified" "https://127.0.0.1:$SPORT/epochs.json"
expect_table httpsbad  "an https:// server with an untrusted certificate is refused" "could not read the key table" "https://127.0.0.1:$SPORT/epochs.json"
kill "$HTTP_PID" "$HTTPS_PID" 2>/dev/null; wait "$HTTP_PID" "$HTTPS_PID" 2>/dev/null

echo "== the Unity WebGL signature bridge, run in the browser"
# unity/ReportSealEcdsa.jslib with Unity's heap, string marshalling and SendMessage
# simulated, checking a table PHP signed. Unity itself is not involved.
load_php
php -r 'require "php/lib/reportseal.php";
$t = json_decode(file_get_contents($argv[1]), true); $sig = $t["signature"]; unset($t["signature"]);
echo json_encode(["data" => base64_encode(canonical_json($t)), "x" => $t["signpublic"]["x"],
                  "y" => $t["signpublic"]["y"], "sig" => $sig]);' "$TABLE_FILE" > "$TT/bridge-input.json"
python3 - "$ROOT/unity/ReportSealEcdsa.jslib" "$TT/bridge-input.json" "$TT/bridge.html" <<'PYEOF'
import sys
lib, data, out = (open(sys.argv[1]).read(), open(sys.argv[2]).read(), sys.argv[3])
open(out, 'w').write('''<!DOCTYPE html><html><body><pre id="out"></pre><script>
var LibraryManager = { library: {} };
function mergeInto(target, fns) { Object.assign(target, fns); }
''' + lib + '''
var lib = LibraryManager.library, input = ''' + data + ''';
var HEAPU8 = new Uint8Array(1 << 16), heapTop = 8;
function put(bytes) { var at = heapTop; HEAPU8.set(bytes, at); heapTop += bytes.length + 8; return at; }
function cstr(s) { return put(new TextEncoder().encode(s + "\\0")); }
function UTF8ToString(p) { var e = p; while (HEAPU8[e]) e++; return new TextDecoder().decode(HEAPU8.subarray(p, e)); }
function b64u(s) { var b = atob(s.replace(/-/g, "+").replace(/_/g, "/")); return Uint8Array.from(b, function (c) { return c.charCodeAt(0); }); }
var data = Uint8Array.from(atob(input.data), function (c) { return c.charCodeAt(0); });
var altered = new TextEncoder().encode(new TextDecoder().decode(data).replace('"E1"', '"E9"'));
var key = new Uint8Array(65); key[0] = 4; key.set(b64u(input.x), 1); key.set(b64u(input.y), 33);
var cases = [["valid", data, key], ["altered", altered, key], ["badkey", data, new Uint8Array(65).fill(7)]];
var replies = 0;
var unityInstance = { SendMessage: function (o, m, msg) {
  document.getElementById("out").textContent += "BRIDGE " + o + "." + m + " " + msg + "\\n"; } };
cases.forEach(function (c, i) {
  var sig = b64u(input.sig), kp = put(c[2]), sp = put(sig), dp = put(c[1]);
  lib.ReportSealVerifyEcdsa(kp, c[2].length, sp, sig.length, dp, c[1].length, cstr("Verifier"), cstr("OnReportSealVerified"), i + 1);
  HEAPU8.fill(0xEE, kp, heapTop);  // the bridge must already have copied its inputs
});
</script></body></html>''')
PYEOF
load_chrome
DOM=$("$CHROME" --headless=new --no-sandbox --disable-gpu --disable-dev-shm-usage \
      --user-data-dir="$WORK/profile-bridge" --virtual-time-budget=5000 \
      --dump-dom "file://$TT/bridge.html" 2>/dev/null | grep -o 'BRIDGE [^<]*' | tr '\n' ' ')
check "PHP's signature verifies in WebCrypto" "$DOM" "Verifier.OnReportSealVerified 1:OK:true"  y
check "an altered table does not"             "$DOM" "OnReportSealVerified 2:OK:false"          y
check "an unusable key reports an error"      "$DOM" "OnReportSealVerified 3:ERR:"              y

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
