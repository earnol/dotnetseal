# .NET sealer - Proof of Concept

A .NET generator seals part of a web page; a PHP issuer mints unlimited keys that
open it; the browser decrypts on `file://` with WebCrypto and no dependencies.

The two halves never talk to each other. The .NET side holds only a **public**
key, so it can seal pages but cannot mint keys. The PHP side holds the private
halves and is the only place keys can be created.

## Layout

```
keys/signpublic.pem       signature verification key, in PEM for openssl and people
keys/epochs.json          published table: epoch id -> master public key, + the same verify key
keys/private/             PHP only: signprivate.pem (signing), master-<epoch>.key (master scalar)
keys/issued.log           append-only record of what the web UI issued (never the key itself)
php/setup.php             create signing key + epoch master scalars, publish public halves
php/issue.php             mint one signed token for one page
php/lib/bls12381.php      BLS12-381 G1/G2 arithmetic on bcmath, issuer side only
php/web/index.php         key issuing UI
dotnet/ReportSeal.Sealing/    netstandard2.1 library: encryption + the three page parts
dotnet/ReportSeal.Pages/      netstandard2.1 library: ReportSeal markers, whole-page sealing
dotnet/ReportSeal.Sealing/assets/  unlock.js and unlock.css, embedded as resources
dotnet/ReportSeal.Generator/  runnable CLI host (net10.0): I/O, key table, page assembly
dotnet/ReportSeal.SelfTest/   pairing constant, stepwise sealing and thread-safety checks
samples/fragment-to-seal.html    a bare fragment, used by the suite to build pages
samples/page-one-document.html   one page id, two fragments, differing EnforceExpiry
samples/page-two-documents.html  two page ids on one page, a key box for each
samples/page-custom-layout.html  host-supplied controls, $$reportseal-tokens$$, styles
unity/                    UNTESTED Unity WebGL bridge: AES-GCM via the browser's WebCrypto
test/setup.sh             build the key fixtures the suite needs (epochs E1, E2 and E3)
test/e2e.sh               full pipeline verified in headless Chrome on file://
```

`keys/epochs.json` stands in for the future read-only SQL table. Swap the file
read in `Program.Run`/`publish_table()` for a query and nothing else changes.

## The .NET side

`ReportSeal.Sealing` targets **netstandard2.1**. Its one dependency is
`Neo.Cryptography.BLS12_381`, a pure managed MIT implementation with a
netstandard2.1 target, used instead of hand-writing tower field arithmetic. `Sealer.Seal` encrypts the fragment and
returns the three parts a page needs, nothing more:

| `SealedFragment` member | What it is |
|---|---|
| `Markup` | hidden `div` with a random id, ciphertext as its text, public unlock values as `data-` attributes |
| `Styles` | CSS for the unlock UI, all rules scoped to `.reportseal*`, no `<style>` wrapper |
| `Script` | unlock code, no `<script>` wrapper |
| `ElementId` | the generated element id, for logging |

`Sealer.Seal` takes an optional `SealOptions`:

| `SealOptions` member | Default | Effect |
|---|---|---|
| `Compress` | `true` | gzip the fragment before encrypting it |
| `ShowAttribution` | `true` | print who the key was issued to once the page unlocks |
| `EnforceExpiry` | `false` | refuse to reveal the content past the key's `exp` |
| `Cipher` | `null` | the AES-GCM implementation; null means the runtime's own (see *Supplying AES-GCM*) |

When sealing a whole page, the first three come from each fragment's `ReportSeal`
marker, as described under *Pages seal themselves*.

### Compression

HTML compresses 5–7×, and because the ciphertext is base64 in the page, every byte
removed before encryption saves 1.33 in the file. Measured on report-shaped HTML:

| Fragment | Page uncompressed | Page gzipped | Saved |
|---|---|---|---|
| 10 KB | 103 KB | 91 KB | 11% |
| 21 KB | 116 KB | 93 KB | 20% |
| 51 KB | 156 KB | 99 KB | 37% |

The floor is the ~74 KB curve library, which dominates a small page regardless.

Compression is **independent of the key**: it happens inside the AES-GCM payload, so
a token carries no knowledge of it and one token opens a compressed and an
uncompressed page alike. The page declares its own encoding with
`data-encoding="gzip"`, and the suite unlocks both kinds with the same token.

The cost is a narrower browser floor. Inflating needs `DecompressionStream` —
Chrome 80+, Firefox 113+, Safari 16.4+ — whereas the rest of the page works in much
older engines. There is no graceful degradation: such a browser can verify the token
and derive the key but not inflate the result, so it reports that plainly. Seal with
`Compress = false` where that matters.

### Sealing without blocking

`Sealer.Seal` does everything in one call and takes 43–68 ms on this machine,
almost all of it three group operations. Where a caller cannot block that long —
a game loop, or a single-threaded host such as Unity WebGL — `Sealer.BeginSeal`
returns a `SealOperation` that does one step per `MoveNext`:

```csharp
var op = Sealer.BeginSeal(bytes, epochs, pageId, signX, signY);   // epochs: EpochKey[]
while (op.MoveNext()) { yield return null; }   // one slice per frame
var fragment = op.Result;
```

It implements `IEnumerator` with a null `Current`, which is what a Unity coroutine
consumes, so it can also be handed straight to `StartCoroutine`. `Seal` is itself a
loop over `BeginSeal`, so both paths run the same code and the whole test suite
covers both. `StepCount` and `StepsCompleted` are there if a host wants a progress
indicator.

The step boundaries are the group operations, so the longest stall is the Gt
exponentiation at 17–27 ms — about one frame instead of three or four. Slicing
finer would mean driving the scalar ladders ourselves, which the curve library does
not expose. `dotnet run --project dotnet/ReportSeal.SelfTest` prints the per-step
cost on your hardware.

Nothing in the library has thread affinity, so hosts that do have threads can
offload the whole of `Seal` instead. There is no `SealAsync` on purpose: no step
waits on I/O, so an async wrapper would allocate a state machine and free no
thread.

### Demo pages

`Sealer.BeginSealInternal` and `SealInternal` take one extra argument the public
entry points do not: a signed token to pre-fill the key entry box with, so a demo
page opens without pasting anything. `BeginSeal` and `Seal` pass null.

Nothing is bypassed. The token lands in a `data-debug-key` attribute, the script
copies it into the entry field, and pressing Unlock runs every check a typed key
runs — signature, epoch, page. A token for the wrong page is refused exactly as
before. The library only checks the token's *shape*, and rejects a malformed one at
the call rather than emitting a page whose box is pre-filled with something the
browser will only reject.

A page built this way carries a working key, so anyone holding the file can read the
sealed content. That is why these entry points are `internal` and no CLI flag
exposes them; make them public in your own build if you want them.

### Assets and layout

The library never dictates layout. With `ReportSeal.Pages` the input page is the
layout, and only the marked regions change; with `Sealer.Seal` the caller places
the three parts itself. The generator does file I/O and reads the key table,
nothing more.

The browser code is not a C# string. `assets/unlock.js` and `assets/unlock.css`
are ordinary files, embedded as resources and read at generation time, so they can
be linted and diffed like any other source. To inline a vendored library — a curve
implementation, say — drop the `.js` beside them, add it to `EmbeddedResource` in
the csproj and to `UnlockAssets.ScriptFiles`, and it is concatenated ahead of the
unlock code. Nothing else changes.

One copy of the script serves every fragment on a page: it finds them by their
`data-reportseal` attribute and groups them by page id and epoch set. For each
group it builds an entry box, status line and notices beside the first fragment,
unless the page supplies its own — see *Letting the page own the furniture*.

### Platform requirements

The sealing libraries target netstandard2.1. Run them on **.NET Core 3.0+ or .NET
5+**, which is what they are tested on. Elsewhere:

- **.NET Framework** cannot load netstandard2.1 assemblies. Not supported.
- **Mono 6.12** loads them, but `AesGcm` throws `PlatformNotSupportedException`
  the first time a page is sealed. Measured. Not supported as shipped.
- **Unity** with the .NET Standard 2.1 API compatibility level loads them, and
  `GZipStream` works under IL2CPP including WebGL. Two dependencies remain
  unverified there — see below. WebGL is also single-threaded: seal with
  `Sealer.BeginSeal` driven from a coroutine rather than with `Sealer.Seal`, as
  described under *Sealing without blocking*.

The curve arithmetic is managed code and runs anywhere netstandard2.1 does.
SHA-256, HMAC-SHA256 and the random generator worked when measured on Mono, and
gzip is reported to work on Unity IL2CPP.

#### Before shipping on a new runtime, verify these two

Off .NET Core, two calls are at risk, and they fail differently.

| Call | Used for | If unsupported |
|---|---|---|
| `AesGcm` | encrypting each fragment, in `PlatformAesGcm`, the default `IAesGcm` | **fails loudly**: an exception on the first seal |
| `RandomNumberGenerator.Fill` | the ephemeral scalar, the IV, the element id | **may fail silently**: a weak generator still returns bytes |

Take the second seriously. The ephemeral scalar is what keeps a page's content key
private; a predictable generator would let anyone reproduce it and decrypt the
page with no key at all. Confirm that the runtime's `RandomNumberGenerator` is a
cryptographic generator — on WebGL, that it is backed by the browser's
`crypto.getRandomValues` — rather than only that the call succeeds.

`AesGcm` is a hard requirement of the default build. Where a runtime lacks it, supply
another implementation instead — see *Supplying AES-GCM* below.

### Supplying AES-GCM

Encryption goes through `IAesGcm`. The default, `PlatformAesGcm`, wraps the
runtime's `AesGcm`; pass another through `SealOptions.Cipher` where that is missing.
An implementation receives the key, nonce, plaintext and associated data, and returns
an `AesGcmJob` holding the ciphertext followed by the 16-byte tag.

A job may finish at once or later, so an implementation can be asynchronous — a
browser call, for instance. `Sealer.BeginSeal` handles that: the step that starts the
encryption repeats on each `MoveNext` until the job finishes, yielding meanwhile. The
synchronous `Sealer.Seal` and `PageSealer.Seal` cannot wait for one on a
single-threaded host, so they refuse it with an error pointing at `BeginSeal` rather
than hanging. A result of the wrong length is rejected too, which catches an
implementation that drops the tag before it becomes a page no key can open.

Two rules for an implementation, both easy to get wrong:

- **Pass the associated data through.** Each fragment is sealed with
  `aad = "<epochs>|<pageId>"` and the page decrypts with the same value, so
  ciphertext produced without it can never be opened.
- **Copy inputs before going asynchronous** if they come from memory that may move,
  such as a WASM heap.

`unity/` holds a bridge for Unity WebGL that routes the call to WebCrypto:
`WebGLAesGcm.cs` and `ReportSealAesGcm.jslib`. **It has never been run in Unity.** It
type-checks against the library with Unity's types stubbed, and the JavaScript
parses, but treat it as a starting point and test it before relying on it.

### How the design's needs are met

| Need | Met by | Where |
|---|---|---|
| HKDF-SHA256 that matches WebCrypto byte for byte | two `HMACSHA256` calls: extract keyed by 32 zero bytes, then expand one block as `HMAC(prk, info ‖ 0x01)`. Written out because the `HKDF` class exists only from .NET 5 | `Sealer.DeriveKey` |
| Curve arithmetic for BLS12-381 | `Neo.Cryptography.BLS12_381`, managed, MIT, with a netstandard2.1 target | `ReportSeal.Sealing.csproj` |
| A pairing result both sides hash identically | Neo and @noble/curves order the twelve 48-byte blocks of that result oppositely; they are reversed before hashing | `Sealer.Canonicalise` |
| Compression the browser can undo | `GZipStream`, read by `DecompressionStream("gzip")` | `Sealer.Gzip` |

The 32 zero bytes are what make the derivation agree with the browser. WebCrypto
runs HKDF with an empty salt, and the HKDF specification treats an empty salt as a
zero key of the hash's length, so both sides extract the same key.

Every row is exercised by each run of `test/e2e.sh` rather than tested on its own,
because a fault in any of them has one symptom: no page decrypts.

## Requirements

| | Version | Needed for |
|---|---|---|
| PHP | 8.1+ with `openssl` and `bcmath` | issuing keys; bcmath carries the curve arithmetic |
| .NET SDK | 10 | the generator; the library itself targets netstandard2.1 |
| Chrome | 80+, headless | `test/e2e.sh` only |

Nothing else: no Composer, no npm, and the one NuGet package restores from
nuget.org. How those tools get onto `PATH` is up to your machine — the test suite
reads `test/env.sh` if you provide one, as described in `test/env.sh.example`.

To run the tests:

```bash
test/setup.sh      # once: signing key plus epochs E1, E2 and E3
test/e2e.sh        # the suite; refuses to run until the fixtures exist
```

`setup.sh --force` throws the key store away and rebuilds it. Keeping this out of
`e2e.sh` saves about 14 seconds a run, since publishing the table derives every
epoch's public half, and means a test run never rewrites your keys.

Browsers opening a sealed page need WebCrypto and, unless every fragment was
sealed with `Compress: false`, `DecompressionStream`: Chrome 80+, Firefox 113+, Safari 16.4+.

## Usage

```bash
php php/setup.php                 # signing key + master scalar for epoch E1
php php/issue.php --epoch E1 --page DOC-1234 --kid acct-4471 --name 'A. Example'

cd dotnet/ReportSeal.Generator
dotnet run -- --in ../../samples/page-one-document.html --out ../../out/page.html
```

Open `out/page.html` from disk and paste the key. The key must name an epoch the
page was sealed under — the sample uses `E1` — so give `--epoch` explicitly:
without it `issue.php` takes the last epoch in the table, which after
`test/setup.sh` is `E3`.

### Pages seal themselves

The generator takes one complete HTML page and returns the same page with the
marked regions sealed. Everything about a fragment is stated in its marker, with
no defaults to inherit:

```html
<!-- ReportSeal PageID: DOC-1234, Epoch: E1+E3, Compress: true,
     EnforceExpiry: false, ShowAttribution: true -->
  …content to seal…
<!-- EndOfReportSeal -->
```

All five keys are required; an unknown or repeated key, a missing one, a
non-boolean flag, an epoch the table does not publish, a page id with a forbidden
character, an unclosed or nested marker, a stray `EndOfReportSeal`, or a page
with no `</head>` all abort the run rather than emitting a half-sealed page.

A page may carry **several fragments**, and they need not belong to the same
document. Fragments are grouped by page id and epoch set: those sharing both are
opened together by one key under a single entry box, reporting "2 of 2 sections
unlocked", while a page mixing page ids offers one box per group and a key opens
only its own group. `samples/page-two-documents.html` carries `DOC-1234` and
`DOC-5678` side by side, which is how one file can hold material a reader is only
partly entitled to. Each fragment keeps its own `Compress` and
`EnforceExpiry`, so one expired key can open a lenient region and be turned away
by a strict one on the same page — which is what `samples/page-one-document.html` demonstrates.
Unsealed markup is passed through untouched, and the styles and the curve library
are injected once however many fragments there are.

The marker comments are removed from the output; the hidden div carries the page id
anyway.

### Letting the page own the furniture

By default the script builds the entry box, status line and attribution itself. A
page that wants its own layout, wording or translation marks the elements and the
script fills them in instead:

```html
<p class="receipt" data-reportseal-attribution="DOC-1234">
  Prepared for <strong>$$reportseal-name$$</strong> of <em>$$reportseal-institution$$</em>.
  Valid until $$reportseal-exp$$. Tier: $$reportseal-extra:tier$$.
</p>

<textarea data-reportseal-key="DOC-1234"></textarea>
<button type="button" data-reportseal-unlock="DOC-1234">Open the report</button>
<p data-reportseal-status="DOC-1234"></p>
```

The attribute value names the page id the control belongs to, which is what makes
this work on a page carrying several documents; it may be left empty when there is
only one group. Anything not supplied is generated as before, so a page can hand
over as much or as little as it likes. A supplied element keeps its own classes —
only `ok` and `err` are toggled on the status line.

Inside an attribution element, placeholders are filled in from the key:
`$$reportseal-name$$`, `$$reportseal-institution$$`, `$$reportseal-exp$$` (in the
reader's time zone), `$$reportseal-page$$`, `$$reportseal-epoch$$`, and
`$$reportseal-extra:KEY$$` for anything else the issuer signed into it. Text without
the `reportseal-` prefix is never touched, and a prefixed placeholder that names
nothing is left standing, so a typo shows rather than silently blanking.
Substitution happens in text nodes, never through `innerHTML`, so a value cannot
bring markup of its own into the page. An attribution element left empty gets the
default `Issued to … · … · valid until …` line.

Styles follow the same principle but all or nothing: if the page carries any
`.reportseal-` rule it owns the appearance and the defaults are left out entirely.
The generator reports which happened.

### Two levels of interface

`ReportSeal.Pages` is the page-level interface and sits on top of
`ReportSeal.Sealing`. `PageSealer.Seal` takes the markup as a **string** and
returns the sealed markup plus an account of each fragment; it does no file I/O.
A caller that would rather lay the page out itself can reference
`ReportSeal.Sealing` alone and keep using `Sealer.Seal`, which takes one fragment
and returns the three parts.

Keys are minted one at a time, each with its own data block. A caller issuing
keys programmatically should skip the CLI and call the library directly:

```php
require 'php/lib/reportseal.php';
$token = mint_token('E1', 'DOC-1234', ['kid' => 'acct-4471', 'name' => 'A. Example']);
```

## The scheme

Keys are **identity-based**: a key opens exactly the page it was issued for, and
that boundary is cryptographic rather than a check the page performs. This is
Sakai-Kasahara over BLS12-381, with the ECDSA signature layer on P-256 because
WebCrypto verifies that natively.

An epoch is one master keypair. The master scalar `s` never leaves
`keys/private/`; only `X = s*G2` is published. The identity of a page is
`id = SHA-256("reportseal/v2|" + pageId) mod r`, which all three sides derive
independently — that tagged string is the one thing they must agree on exactly.

**Issuing (PHP, master scalar).** The element for a page is `sk = (1/(s+id))*G1`,
48 compressed bytes. Nothing public relates one page's element to another's, so a
holder cannot turn their key into a key for a different page. A token is

```
NO1.<base64url(payload)>.<base64url(r||s)>
payload = {"v":2,"epoch":"E1","page":"DOC-1234","sk":"<page element>",
           "extra":{"kid":"K-000001","name":"A. Example",
                    "institution":"Example Institute","exp":"2027-01-31T00:00:00Z"}}
```

signed with ECDSA-P256-SHA256 by a **separate** signing key. Only `epoch`, `page`
and `sk` are crypto; everything else is metadata in `extra`. The page shows
`name`, `institution` and `exp` in its attribution line — the page's own
`data-reportseal-attribution` element if it has one, otherwise a line above the
entry box — hides `kid`, and lists anything else at the end of the page. About 414 characters; minting one takes ~1 s,
almost all of it the G1 multiply.

**Sealing (.NET, public key only).** `Sealer.Seal` takes an `EpochKey[]` — a name
and that epoch's `X` together, at least one entry — and a key issued for **any**
listed epoch opens the page. Pick an ephemeral `k`, emit `C1 = k*(X + id*G2)` per
epoch, and derive the content key from `e(G1,G2)^k`. Note where the
epoch lives: `X` appears only in `C1`, computed fresh every time from the published
table. The shared value is `e(G1,G2)^k`, which contains no epoch and no page — the
`(s+id)` factors cancel in `e(sk, C1)` — so `e(G1,G2)` is a constant of the curve
itself and is embedded rather than computed. Rotating an epoch changes `X` and
therefore `C1`; it cannot change that constant. It is also why several epochs share
one ciphertext: the shared value is the same for all of them, so only `C1` is
per-epoch. The page carries `data-epochs="E1+E2"` and a matching `+`-joined list of
`C1` values, and the browser uses the one at its token's position. For a single
epoch the derivation string is byte-identical to the one-epoch form, so nothing
changes for pages sealed under one.

Listing an old epoch beside a new one keeps old keys working **for that page** —
useful as a transition window, and the opposite of what rotation is for. A
`ReportSeal` marker may list at most three epochs
(`PageSealer.MaxEpochsPerFragment`), to catch mistakes.

The suite keeps this honest from both directions: it seals a page under `E1+E2` and
opens it with a key from either, and seals one under `E1+E3` where a perfectly
valid `E2` key is refused — by the page's own check, and with that check patched
out, by AES-GCM failing to authenticate. Key derivation is
`HKDF-SHA256(info = "reportseal/v2|<epochs>|<pageId>")`, then AES-256-GCM with
`aad = "<epochs>|<pageId>"`, where `<epochs>` is the page's sorted epoch ids joined
with `+`. Sealing performs **no pairing at all**; the browser performs exactly one
per fragment.

**Unlocking (browser).** Verify the signature against the verification key baked
into the page, check that the token's epoch is one the page lists and its page id
matches, then one pairing per fragment:
`e(sk, C1) = e(G1,G2)^k`. HKDF, AES-GCM decrypt, inject, append the signed
metadata. An element issued for another page yields a different value, so
stripping the epoch and page checks out of the JavaScript changes nothing — the
suite tests exactly that.

Both sides serialise the pairing result to 576 bytes, but Neo orders the twelve
48-byte coefficient blocks opposite to @noble/curves. `Sealer.Canonicalise`
reverses them. Three tests guard the agreement, each at a different layer:
`test/bls-vectors.php` checks the PHP curve arithmetic against values captured from
@noble/curves and Neo; `ReportSeal.SelfTest` checks that the embedded pairing
constant still equals Neo's computed one; and `test/e2e.sh` runs all three
implementations together on every run, which is the only check that would catch
the block order going wrong.

**Remembering the key.** After a successful unlock the token is written to
`localStorage` under `reportseal/v2/<epochs>/<pageId>`, so a revisit opens the page
with no interaction. A "Forget key" control clears it. If a remembered key stops
working it is discarded and the entry form returns with an explanation — except a
key refused only for being past its date, which is kept, since it is still a valid
key the page is declining. Every
storage access is wrapped: where storage is missing or throws, unlocking still
works and the page simply does not offer to remember anything.

The token is a decryption key sitting in plaintext on disk, and all `file://`
pages share one storage area per browser profile, so any other local HTML file
the user opens can read it. Now that keys are page-scoped this leaks one page
rather than an epoch, but it is still worth knowing.

**Expiry is reporting by default.** A page decrypts if the signature checks out
and the key is for that page. `exp` is shown in the header and, past it, in a
banner.

Tokens carry `exp` as a UTC instant, but the page renders it in the **reader's own
time zone** to the minute — `2027-01-31T15:04:00Z` reads as
`valid until 2027-01-31 16:04 GMT+2` in central Europe. Only the presentation is
local; the comparison and the stored value are UTC. The test suite computes the
expected strings from the local zone for that reason, and passes from UTC-8 to
UTC+14.

Sealing a fragment with `EnforceExpiry: true` makes the page refuse it instead: it checks the date
before decrypting and never injects the fragment. Be clear-eyed about what that
buys. The holder's element still works, so they can decrypt the ciphertext with
forty lines of noble-curves and never load your page; and the check itself is a
`Date` comparison in JavaScript they could edit out. It communicates intent to
honest readers and nothing more. Rotating the epoch is the only real withdrawal.

## Issuing keys

There is a web UI for issuing. It reads the private keys, so keep it on loopback:

```bash
php -S 127.0.0.1:8080 -t php/web
```

It has **no access control at all** — anyone who can load it can mint a key for any
page id, and so open any page sealed under the chosen epoch. Do not put it on a
shared interface.

The form takes an epoch, page id, user name, user institution, expiry date and
key id. What each one does:

| Field | In the key | Shown on the page |
|---|---|---|
| User name | `extra.name` | yes, in the header |
| User institution | `extra.institution` | yes, in the header |
| Expiry date and time | `exp` | yes, in the header |
| Page id | `page` | no, but it is what the key opens |
| Key id | `kid` | no |

Blank name or institution becomes `unknown`. Blank key id generates a random
`K-xxxxxxxx`.

Expiry is a **UTC moment**, entered as a date plus an hours-and-minutes time. Both
default to two months from the instant the form loads, carrying the time of day
with them: a key minted at 15:04 UTC expires at 15:04 UTC. Enter `9999-12-31` for
a key that never expires. The time field is `type="time"` with `step="60"`, so
seconds are never offered, and it carries `lang="en-GB"` because HTML has no
attribute that forces 24-hour display and Chrome takes the format from the
element's language. The submitted value is `HH:MM` on a 24-hour clock regardless,
and anything else is rejected.

### Characters

Page ids and key ids are a whitelist: letters, digits and combining marks in any
script, plus `_ . : -`. Everything else is refused, including whitespace and
`% & * ' " + | < > / \ ? # = ;`. `|` and `+` separate fields in the derivation
string, and the rest have no business in an identifier. Both the issuer and the
generator apply the same rule, so a page cannot be sealed under an id no key could
be issued for. Names and institutions are free text and take anything.

Names, institutions, page ids and key ids take letters in any script, so
`Åsa Müller-Désirée` of `Universität Göttingen` with a page id of
`DOC-Årsrapport` works end to end and into the page header. Tokens carry them as
UTF-8 rather than `\uXXXX` escapes, which costs an accented letter 2 bytes instead
of 6 characters — 43 characters off a token carrying those names.

Epoch ids stay ASCII (`A-Za-z0-9_.-`) on purpose: one names a file in
`keys/private/`, and they are joined with `+` into the derivation string.

The page id is hashed into the page's identity, so **both sides must use the same
bytes, not merely the same-looking text**. `Å` as one code point and as `A` plus a
combining ring are different identities, and PHP cannot normalise them because no
build here carries `intl`. So `issue.php` and the generator both print a
fingerprint of the identity:

```
page identity dc565b4f8e4e for 'DOC-Årsrapport-Übersicht'
```

Compare them if a key ever refuses its page — the decomposed spelling of that same
id fingerprints as `30cd64970f7b`. Page ids that come from one source, a database
column rather than two keyboards, cannot drift this way.

Once unlocked, the page prints `Issued to <name> · <institution> · valid until
<date>` in its attribution line, or the page's own wording if it supplies one. The key id is never displayed, though it sits in the
signed payload and anyone who decodes their own key can read it — it buys
attribution in `keys/issued.log`, not secrecy.

Every key the web UI issues is appended to `keys/issued.log` with a timestamp; the
command line and `mint_token` do not log. The token itself is never logged, because
it is the decryption key.

The same thing from the command line, or from your own PHP:

```bash
php php/issue.php --page DOC-1234 --kid acct-4471 --exp 2027-01-31 --name 'A. Example'
```

```php
require 'php/lib/reportseal.php';
$token = mint_token('E1', 'DOC-1234', ['kid' => 'acct-4471', 'name' => 'A. Example',
                                       'institution' => 'Example Institute']);
```

## Generating keypairs

There are two kinds of key, both created by `setup.php`. Nothing private ever
leaves `keys/private/`.

| Keypair | Private half | Public half | Replacing it |
|---|---|---|---|
| **Signing** (ECDSA P-256, signs keys) | `keys/private/signprivate.pem` | `keys/signpublic.pem` and `signpublic` in `keys/epochs.json` | invalidates *every* key ever issued |
| **Epoch master** (BLS12-381, opens pages) | `keys/private/master-<epoch>.key` | `epochs.<id>` in `keys/epochs.json` | old keys stop opening newly sealed pages |

First run — creates the signing key and the first epoch master scalar:

```bash
php php/setup.php
```

Add a new epoch (the normal path; keeps the old one working):

```bash
php php/setup.php --epoch E2
```

Replace an existing key in place. Both refuse without `--force`, because each
throws away already-issued keys:

```bash
php php/setup.php --epoch E2 --force    # new master scalar for E2
php php/setup.php --issuer --force      # new signing key: all keys become unusable
```

Every run rebuilds `keys/epochs.json` from whatever private material is present,
so the table always matches the key store. Deriving each public half is one G2
multiply, a couple of seconds apiece. Copy that one file to the .NET side after
any of these commands — it holds public halves only.

Inspect the verification key with plain openssl, without touching anything private:

```bash
openssl ec -pubin -in keys/signpublic.pem -text -noout
```

`keys/signpublic.pem` and the `signpublic` entry in `keys/epochs.json` are the same
key in two shapes — a PEM for tooling and people, raw `x`/`y` because that is what
the generator hands to WebCrypto. Both are rewritten from the private key on every
`setup.php` run, so they cannot drift.

## Rotation

Rotation is the expiry mechanism, and it is cryptographically hard: pages sealed
under a new epoch cannot be opened by any previously issued key.

```bash
php php/setup.php --epoch E2         # new master scalar, republishes the table
# ship keys/epochs.json to the .NET side, set Epoch: E2 in the pages'
# ReportSeal markers, and regenerate
php php/issue.php --epoch E2 --page DOC-1234 --kid acct-4471
```

Old pages stay readable by old keys, because each page names the epoch it was
sealed under. To make old *pages* unreadable as well, re-seal them under the new
epoch and replace the published files.

## What this does and does not protect

By design, any key holder can extract the plaintext of the page their key opens
and reshare it, and every key issued for one page carries the same element, so a
leak is attributable only through what the issuer logged. What a leak does *not*
give away is any other page: the element is bound to one page id and the master
scalar cannot be recovered from it. There is no offline revocation — rotation is
the only withdrawal mechanism.

What does hold: only the issuer can produce a token the page will accept, a key
cannot be moved to another page, and the metadata block cannot be altered by its
holder.

Decrypted HTML is injected with `innerHTML`. It is authenticated by AES-GCM
under a key only reachable through a signed token, so the trust boundary is the
generator's input; values from `extra` are rendered with `textContent`.
