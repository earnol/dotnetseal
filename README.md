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
dotnet/ReportSeal.Sealing/assets/  unlock.js and unlock.css, embedded as resources
dotnet/ReportSeal.Generator/  runnable CLI host (net10.0): I/O, key table, page assembly
dotnet/ReportSeal.SelfTest/   pairing constant, stepwise sealing and thread-safety checks
samples/                  example header and hidden fragment
test/setup.sh             build the key fixtures the suite needs (epochs E1 and E2)
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

`Sealer.Seal` takes an optional `SealOptions` controlling two things about the
finished page:

| `SealOptions` member | Default | Effect |
|---|---|---|
| `Compress` | `true` | gzip the fragment before encrypting it |
| `ShowAttribution` | `true` | print `Issued to …` once the page unlocks |
| `EnforceExpiry` | `false` | refuse to reveal the content past the key's `exp` |

The CLI exposes them as `--no-compress`, `--no-attribution` and `--enforce-expiry`.

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
var op = Sealer.BeginSeal(bytes, epoch, pageId, mpk, signX, signY);
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

Nothing in the library has thread affinity, so hosts that do have threads can
offload the whole of `Seal` instead. There is no `SealAsync` on purpose: no step
waits on I/O, so an async wrapper would allocate a state machine and free no
thread.

`Program.cs` owns everything else: the HTML skeleton, the title, the visible
header, its own page CSS, and the merge. So the library never dictates layout,
and a different host can lay the page out however it likes.

The browser code is not a C# string. `assets/unlock.js` and `assets/unlock.css`
are ordinary files, embedded as resources and read at generation time, so they can
be linted and diffed like any other source. To inline a vendored library — a curve
implementation, say — drop the `.js` beside them, add it to `EmbeddedResource` in
the csproj and to `UnlockAssets.ScriptFiles`, and it is concatenated ahead of the
unlock code. Nothing else changes.

The script builds its own entry form, status line and output containers next to
the hidden div, which means the host page shares **no element-id contract** with
the library — it only has to place the three parts. The element id is random per
page, so nothing in the page has a predictable hook.

Two consequences of the netstandard2.1 constraint, both already handled:

- There is no `HKDF` class before .NET 5, so extraction uses
  `ECDiffieHellman.DeriveKeyFromHmac`, which computes HMAC-SHA256 over the raw
  ECDH agreement and *is* HKDF-Extract. Expansion for one 32-byte block is
  `HMAC(prk, info || 0x01)`. This is byte-identical to `HKDF.DeriveKey`, verified
  against it, so pages and keys are interchangeable with the earlier build.
- **Mono cannot run this.** Mono 6.12 compiles against netstandard2.1 but throws
  at runtime: `ECDiffieHellman.Create` raises `NotImplementedException` and
  `AesGcm` raises `PlatformNotSupportedException`. Only `HMACSHA256`, `SHA256`
  and the RNG work. Supporting Mono means replacing the BCL crypto with a managed
  implementation such as BouncyCastle. The library needs .NET Core 3.0+ or
  .NET 5+.

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
test/setup.sh      # once: signing key plus epochs E1 and E2
test/e2e.sh        # the suite; refuses to run until the fixtures exist
```

`setup.sh --force` throws the key store away and rebuilds it. Keeping this out of
`e2e.sh` saves about 14 seconds a run, since publishing the table derives every
epoch's public half, and means a test run never rewrites your keys.

Browsers opening a sealed page need WebCrypto and, unless it was sealed with
`--no-compress`, `DecompressionStream`: Chrome 80+, Firefox 113+, Safari 16.4+.

## Usage

```bash
php php/setup.php                 # signing key + master scalar for epoch E1
php php/issue.php --page DOC-1234 --kid acct-4471 --name 'A. Example'

cd dotnet/ReportSeal.Generator
dotnet run -- --page DOC-1234 --hidden ../../samples/hidden.html \
              --header ../../samples/header.html \
              --title "Quarterly Summary" --out ../../out/page.html
```

Open `out/page.html` from disk and paste any issued key.

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
`name`, `institution` and `exp` in its header, hides `kid`, and lists anything
else beneath the content. About 414 characters; minting one takes ~1 s,
almost all of it the G1 multiply.

**Sealing (.NET, public key only).** Pick an ephemeral `k`, emit
`C1 = k*(X + id*G2)`, and derive the content key from `e(G1,G2)^k`. Note where the
epoch lives: `X` appears only in `C1`, computed fresh every time from the published
table. The shared value is `e(G1,G2)^k`, which contains no epoch and no page — the
`(s+id)` factors cancel in `e(sk, C1)` — so `e(G1,G2)` is a constant of the curve
itself and is embedded rather than computed. Rotating an epoch changes `X` and
therefore `C1`; it cannot change that constant. The suite seals under a second
epoch and opens it to keep that honest. Key derivation is
`HKDF-SHA256(info = "reportseal/v2|<epoch>|<pageId>")`, then AES-256-GCM with
`aad = "<epoch>|<pageId>"`. Sealing performs **no pairing at all**; the browser
performs exactly one.

**Unlocking (browser).** Verify the signature against the verification key baked
into the page, check the epoch and page match, then one pairing:
`e(sk, C1) = e(G1,G2)^k`. HKDF, AES-GCM decrypt, inject, append the signed
metadata. An element issued for another page yields a different value, so
stripping the epoch and page checks out of the JavaScript changes nothing — the
suite tests exactly that.

Both sides serialise the pairing result to 576 bytes, but Neo orders the twelve
48-byte coefficient blocks opposite to @noble/curves. `Sealer.Canonicalise`
reverses them; `test/bls-vectors.php` pins all three implementations to captured
vectors.

**Remembering the key.** After a successful unlock the token is written to
`localStorage` under `reportseal/v2/<epoch>/<pageId>`, so a revisit opens the page
with no interaction. A "Forget key" control clears it. If a remembered key stops
working it is discarded and the entry form returns with an explanation. Every
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

Sealing with `--enforce-expiry` makes the page refuse instead: it checks the date
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

It has **no access control at all** — anyone who can load it can mint a key that
opens every sealed page of the chosen epoch. Do not put it on a shared interface.

The form takes an epoch, page id, user name, user institution, expiry date and
key id. What each one does:

| Field | In the key | Shown on the page |
|---|---|---|
| User name | `extra.name` | yes, in the header |
| User institution | `extra.institution` | yes, in the header |
| Expiry date | `exp` | yes, in the header |
| Page id | `page` | no, but it is what the key opens |
| Key id | `kid` | no |

Blank name or institution becomes `unknown`; a blank expiry becomes `9999-12-31`,
which reads as "does not expire". Blank key id generates a random `K-xxxxxxxx`.

Once unlocked, the page prints `Issued to <name> · <institution> · valid until
<date>` into its header. The key id is never displayed, though it sits in the
signed payload and anyone who decodes their own key can read it — it buys
attribution in `keys/issued.log`, not secrecy.

Every issue is appended to `keys/issued.log` with a timestamp. The token itself is
never logged, because it is the decryption key.

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

First run — creates the issuer key and the first epoch master scalar:

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
# ship keys/epochs.json to the .NET side, then generate with --epoch E2
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
