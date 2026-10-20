<?php
/**
 * Shared helpers for the PHP (private-key) side.
 *
 * Where things live is set in config (see config.php); the defaults are:
 *   keys/private/signprivate.pem.enc  ECDSA P-256 signing key, encrypted under the
 *                                     password chosen at setup
 *   keys/private/master-<epoch>.key.enc  BLS12-381 master scalar, encrypted under a
 *                                     password generated for that epoch and shown once
 *   keys/private/master-<epoch>.pub   that epoch's public half, so the table can be
 *                                     published without any epoch password
 *   keys/signpublic.pem               signature verification key, for openssl and people
 *   keys/epochs.json                  the published table, signed over its own content
 */

declare(strict_types=1);

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/keystore.php';
require_once __DIR__ . '/recorder.php';
require_once __DIR__ . '/bls12381.php';

/** The signing key stays on P-256: WebCrypto verifies it natively. */
const CURVE = 'prime256v1';

function table_path(): string
{
    return config()['table'];
}

function signpublic_path(): string
{
    return config()['signpublic'];
}

function private_dir(): string
{
    return config()['private_dir'];
}

function signing_key_path(): string
{
    return private_dir() . '/signprivate.pem.enc';
}

function master_path(string $epoch): string
{
    return private_dir() . '/master-' . $epoch . '.key.enc';
}

function master_public_path(string $epoch): string
{
    return private_dir() . '/master-' . $epoch . '.pub';
}

/** Writes private material readable by its owner only. */
function write_private(string $path, string $content): void
{
    $dir = dirname($path);
    if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) {
        throw new RuntimeException("cannot create $dir");
    }
    @chmod($dir, 0700);
    $old = umask(0077);
    try {
        if (file_put_contents($path, $content) === false) {
            throw new RuntimeException("cannot write $path");
        }
    } finally {
        umask($old);
    }
    chmod($path, 0600);
}

function b64u(string $raw): string
{
    return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
}

function b64u_decode(string $s): string
{
    $s = strtr($s, '-_', '+/');
    $pad = strlen($s) % 4;
    if ($pad !== 0) {
        $s .= str_repeat('=', 4 - $pad);
    }
    $out = base64_decode($s, true);
    if ($out === false) {
        throw new RuntimeException('invalid base64url');
    }
    return $out;
}

/** Generate a fresh P-256 keypair and return it as a PEM private key. */
function new_ec_key(): string
{
    $k = openssl_pkey_new([
        'private_key_type' => OPENSSL_KEYTYPE_EC,
        'curve_name'       => CURVE,
    ]);
    if ($k === false) {
        throw new RuntimeException('openssl_pkey_new failed: ' . openssl_error_string());
    }
    if (!openssl_pkey_export($k, $pem)) {
        throw new RuntimeException('openssl_pkey_export failed: ' . openssl_error_string());
    }
    return $pem;
}

/** The matching public key, as a PEM anyone can inspect with openssl. */
function public_pem(string $privatePem): string
{
    $k = openssl_pkey_get_private($privatePem);
    if ($k === false) {
        throw new RuntimeException('cannot read signing key: ' . openssl_error_string());
    }
    $details = openssl_pkey_get_details($k);
    if ($details === false || !isset($details['key'])) {
        throw new RuntimeException('cannot export public key');
    }
    return $details['key'];
}

/** @return array{d:string,x:string,y:string} raw 32-byte big-endian values */
function ec_parts(string $pem): array
{
    $k = openssl_pkey_get_private($pem);
    if ($k === false) {
        throw new RuntimeException('cannot read private key: ' . openssl_error_string());
    }
    $d = openssl_pkey_get_details($k);
    if ($d === false || !isset($d['ec'])) {
        throw new RuntimeException('key is not an EC key');
    }
    return [
        'd' => pad32($d['ec']['d']),
        'x' => pad32($d['ec']['x']),
        'y' => pad32($d['ec']['y']),
    ];
}

/** OpenSSL strips leading zero bytes; P-256 field elements must be exactly 32 bytes. */
function pad32(string $raw): string
{
    if (strlen($raw) > 32) {
        throw new RuntimeException('field element longer than 32 bytes');
    }
    return str_pad($raw, 32, "\0", STR_PAD_LEFT);
}

/**
 * Sign with ECDSA-P256-SHA256 and return the raw 64-byte r||s form that
 * WebCrypto expects (openssl_sign emits DER).
 */
function ecdsa_sign_raw(string $data, string $pem): string
{
    $k = openssl_pkey_get_private($pem);
    if ($k === false) {
        throw new RuntimeException('cannot read signing key: ' . openssl_error_string());
    }
    if (!openssl_sign($data, $der, $k, OPENSSL_ALGO_SHA256)) {
        throw new RuntimeException('openssl_sign failed: ' . openssl_error_string());
    }
    return der_sig_to_raw($der);
}

/** SEQUENCE { INTEGER r, INTEGER s } -> r||s, 32 bytes each. */
function der_sig_to_raw(string $der): string
{
    $off = 0;
    $expect = static function (string $der, int &$off, int $tag): int {
        if (ord($der[$off++]) !== $tag) {
            throw new RuntimeException('unexpected DER tag');
        }
        $len = ord($der[$off++]);
        if ($len & 0x80) {
            $n = $len & 0x7f;
            $len = 0;
            for ($i = 0; $i < $n; $i++) {
                $len = ($len << 8) | ord($der[$off++]);
            }
        }
        return $len;
    };
    $expect($der, $off, 0x30);
    $rl = $expect($der, $off, 0x02);
    $r = substr($der, $off, $rl);
    $off += $rl;
    $sl = $expect($der, $off, 0x02);
    $s = substr($der, $off, $sl);

    return pad32(ltrim_zeros($r)) . pad32(ltrim_zeros($s));
}

function ltrim_zeros(string $raw): string
{
    $out = ltrim($raw, "\0");
    return $out === '' ? "\0" : $out;
}

/** @return array{seeds:array<string,array{x:string,y:string}>,issuer:array{x:string,y:string}} */
function load_table(): array
{
    $p = table_path();
    if (!is_file($p)) {
        throw new RuntimeException("key table not found at $p — run setup.php first");
    }
    $t = json_decode((string) file_get_contents($p), true, 512, JSON_THROW_ON_ERROR);
    return $t;
}

/** Anything strtotime() reads, normalised to a UTC instant the browser can parse. */
function normalise_exp(string $exp): string
{
    $ts = strtotime($exp);
    if ($ts === false) {
        throw new RuntimeException("not a date I can read: $exp");
    }
    return gmdate('Y-m-d\TH:i:s\Z', $ts);
}

function random_kid(): string
{
    return 'K-' . strtoupper(bin2hex(random_bytes(4)));
}

// ---------------------------------------------------------------------------
// Identity-based keys. One master scalar per epoch; rotation mints a new one and
// leaves the old in place, so pages already published keep working.
// ---------------------------------------------------------------------------

/**
 * The identity a page is sealed under, derived from its assigned page id. All
 * three sides compute this, so the tagged string below is the one thing that
 * must agree character for character across PHP, .NET and the browser.
 */
function page_identity(string $pageId): string
{
    return Bls12381::scalarFromBytes(hash('sha256', 'reportseal/v2|' . $pageId, true));
}

/**
 * Short fingerprint of the exact bytes a page id hashes to.
 *
 * There is no intl extension here, so this side cannot normalise Unicode. Two page
 * ids that look identical but differ in composition — "Å" as one code point or as
 * A plus a combining ring — hash to different identities, and the only symptom
 * would be a key that refuses to open its page. Both the issuer and the generator
 * print this, so a mismatch is obvious before anyone goes hunting.
 */
function page_fingerprint(string $pageId): string
{
    return substr(hash('sha256', 'reportseal/v2|' . $pageId), 0, 12);
}

/** Epoch ids that currently have a published public half. */
function available_epochs(): array
{
    $ids = [];
    foreach (glob(private_dir() . '/master-*.pub') ?: [] as $file) {
        $ids[] = preg_replace('/^master-|\.pub$/', '', basename($file));
    }
    sort($ids);
    return $ids;
}

function assert_epoch_id(string $epoch): void
{
    // Deliberately ASCII: this names a file and is joined with '+' into the
    // derivation string.
    if (!preg_match('/^[A-Za-z0-9_.-]{1,32}$/', $epoch)) {
        throw new RuntimeException('invalid epoch id (allowed: A-Za-z0-9_.- up to 32 chars)');
    }
}

// ---------------------------------------------------------------- signing key

/** Creates the signing key, encrypted under a password the caller chose. */
function create_signing_key(string $password): void
{
    $problem = password_problem($password);
    if ($problem !== null) {
        throw new RuntimeException($problem);
    }
    $pem = new_ec_key();
    write_private(signing_key_path(), seal_secret($pem, $password, 'signing key'));
    file_put_contents(signpublic_path(), public_pem($pem));
}

function unlock_signing_key(string $password): string
{
    $path = signing_key_path();
    if (!is_file($path)) {
        throw new RuntimeException("no signing key at $path — run setup.php first");
    }
    return open_secret((string) file_get_contents($path), $password, 'signing key');
}

// ------------------------------------------------------------- epoch masters

/** A fresh master scalar. 384 random bits reduced mod r leaves negligible bias. */
function new_master(): string
{
    return Bls12381::scalarToHex(Bls12381::scalarFromBytes(random_bytes(48)));
}

/**
 * Creates an epoch and returns its password. The password is generated here, is
 * not kept anywhere, and is the only way to use the epoch afterwards: the caller
 * must show it once, and whoever runs setup must record it.
 */
function create_epoch(string $epoch): string
{
    assert_epoch_id($epoch);
    $scalarHex = new_master();
    $public = Bls12381::compressG2(Bls12381::g2Mul(Bls12381::scalarFromHex($scalarHex)));
    $password = generate_password();
    write_private(master_path($epoch), seal_secret($scalarHex, $password, "master scalar for epoch $epoch"));
    // Public, so it needs no password: publishing the table reads only these.
    file_put_contents(master_public_path($epoch), b64u($public) . "\n");
    return $password;
}

/**
 * Creates an epoch and re-signs the published table with it, as one action: the
 * signing password is checked before anything is written, so a wrong one leaves no
 * epoch behind that the table omits. Serialised by locking the private key
 * directory, so two callers cannot create the same epoch at once.
 *
 * Refuses an existing epoch unless $replace, because replacing one stops keys
 * issued under it from opening newly sealed pages.
 *
 * @return array{password:string, table:array, replaced:bool} the epoch's generated
 *         password — shown once by the caller, stored nowhere — and the new table
 */
function add_epoch(string $epoch, string $signingPassword, bool $replace = false): array
{
    assert_epoch_id($epoch);
    unlock_signing_key($signingPassword);

    $dir = private_dir();
    if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) {
        throw new RuntimeException("cannot create $dir");
    }
    // The directory itself is the lock: it always exists and is never replaced, so
    // nothing is created or left behind, and the lock ends with the process.
    // fopen, not opendir: PHP's flock accepts only a stream, and on Linux a
    // directory opens read-only as one.
    $lock = fopen($dir, 'r');
    if ($lock === false || !flock($lock, LOCK_EX)) {
        throw new RuntimeException('could not lock the key store');
    }
    try {
        $exists = is_file(master_path($epoch)) || is_file(master_public_path($epoch));
        if ($exists && !$replace) {
            throw new RuntimeException("epoch $epoch already exists; replacing it invalidates "
                . "keys issued under it (setup.php --epoch $epoch --force)");
        }
        $password = create_epoch($epoch);
        $table = publish_table($signingPassword);
    } finally {
        flock($lock, LOCK_UN);
        fclose($lock);
    }
    return ['password' => $password, 'table' => $table, 'replaced' => $exists];
}

function unlock_master(string $epoch, string $password): string
{
    assert_epoch_id($epoch);
    $path = master_path($epoch);
    if (!is_file($path)) {
        throw new RuntimeException("no master scalar for epoch '$epoch' — run: php setup.php --epoch $epoch");
    }
    $hex = open_secret((string) file_get_contents($path), $password, "master scalar for epoch $epoch");
    return Bls12381::scalarFromHex(trim($hex));
}

/** The epoch's public half, X = s * G2, as 96 compressed bytes. */
function master_public(string $epoch): string
{
    $path = master_public_path($epoch);
    if (!is_file($path)) {
        throw new RuntimeException("no public half for epoch '$epoch' at $path");
    }
    return b64u_decode(trim((string) file_get_contents($path)));
}

// ------------------------------------------------------------------- issuing

/**
 * Decrypts what minting needs: the signing key and one epoch's master scalar. Do
 * it once and mint as many tokens as you like with the result.
 *
 * @return array{epoch:string,sign:string,master:string}
 */
function unlock_issuer(string $epoch, string $signingPassword, string $epochPassword): array
{
    return [
        'epoch'  => $epoch,
        'sign'   => unlock_signing_key($signingPassword),
        'master' => unlock_master($epoch, $epochPassword),
    ];
}

/**
 * The private element for one page: sk = (1/(s + id)) * G1, 48 compressed bytes.
 *
 * This is the only operation that needs the master scalar. The result opens
 * exactly the pages sealed under this epoch with this page id: nothing public
 * relates one page's element to another's, so a holder cannot move their key to a
 * different page.
 */
function page_key(string $master, string $pageId): string
{
    $inv = Bls12381::scalarInv(Bls12381::scalarAdd($master, page_identity($pageId)));
    return Bls12381::compressG1(Bls12381::g1Mul($inv));
}

/**
 * Mint one decryption token for one page.
 *
 * Only what the crypto needs sits at the top level: which epoch and page the key
 * belongs to, and the private element itself. Everything else is descriptive
 * metadata in "extra", where the page decides how to treat each field.
 *
 * Recognised options, all optional:
 *   kid          key id for your logs; a random K-xxxxxxxx when omitted
 *   exp          anything strtotime() reads, normalised to a UTC instant
 *   name         user name, shown on the page
 *   institution  user institution, shown on the page
 *   extra        further caller fields, merged in and listed by the page
 *
 * @param array{epoch:string,sign:string,master:string} $issuer from unlock_issuer()
 * @param array<string,mixed> $opts
 */
function mint_token(array $issuer, string $pageId, array $opts = []): string
{
    $unknown = array_diff(array_keys($opts), ['kid', 'exp', 'name', 'institution', 'extra']);
    if ($unknown !== []) {
        throw new RuntimeException('unknown option(s): ' . implode(', ', $unknown));
    }
    $epoch = $issuer['epoch'];
    assert_epoch_id($epoch);
    if (!preg_match('/^[\p{L}\p{N}\p{M}_.:-]+$/u', $pageId) || mb_strlen($pageId) > 64) {
        throw new RuntimeException(
            'invalid page id (allowed: letters, digits and _.:- up to 64 characters)');
    }

    $kid = (string) ($opts['kid'] ?? '');
    if ($kid === '') {
        $kid = random_kid();
    }
    if (!preg_match('/^[\p{L}\p{N}\p{M}_.:-]+$/u', $kid) || mb_strlen($kid) > 40) {
        throw new RuntimeException(
            'invalid key id (allowed: letters, digits and _.:- up to 40 characters)');
    }

    // Descriptive fields first, then any caller extras, so the well-known keys
    // keep a stable position in the token.
    $extra = ['kid' => $kid];
    foreach (['name', 'institution'] as $k) {
        if (isset($opts[$k]) && $opts[$k] !== '') {
            $extra[$k] = (string) $opts[$k];
        }
    }
    if (isset($opts['exp']) && $opts['exp'] !== '') {
        $extra['exp'] = normalise_exp((string) $opts['exp']);
    }
    foreach ((array) ($opts['extra'] ?? []) as $k => $v) {
        $extra[$k] = $v;
    }

    $payload = [
        'v'     => 2,
        'epoch' => $epoch,
        'page'  => $pageId,
        'sk'    => b64u(page_key($issuer['master'], $pageId)),
        'extra' => $extra,
    ];

    // UTF-8 rather than \uXXXX escapes: an accented letter then costs its 2 UTF-8
    // bytes instead of 6 characters, and the browser parses either form.
    $p64 = b64u(json_encode(
        $payload,
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR
    ));
    return "NO1.$p64." . b64u(ecdsa_sign_raw($p64, $issuer['sign']));
}

// ------------------------------------------------------------- the table

/**
 * RFC 8785 canonical JSON, for the types the table holds: objects, lists,
 * strings, integers, booleans and null. Keys are sorted, there is no whitespace,
 * and strings escape only what JSON requires. Written out rather than left to
 * json_encode, because the .NET side reproduces it byte for byte and both must
 * agree without depending on either serialiser's habits. Object keys must be
 * ASCII, which keeps byte order and RFC 8785's UTF-16 order the same.
 */
function canonical_json($value): string
{
    if ($value === null) { return 'null'; }
    if (is_bool($value)) { return $value ? 'true' : 'false'; }
    if (is_int($value)) { return (string) $value; }
    if (is_string($value)) { return canonical_string($value); }
    if ($value instanceof stdClass) { $value = (array) $value; $object = true; }
    if (!is_array($value)) {
        throw new RuntimeException('canonical_json: unsupported value type ' . gettype($value));
    }
    if (empty($object) && $value !== [] && array_is_list($value)) {
        return '[' . implode(',', array_map('canonical_json', $value)) . ']';
    }
    $keys = array_map('strval', array_keys($value));
    sort($keys, SORT_STRING);
    $parts = [];
    foreach ($keys as $key) {
        if (preg_match('/[^\x20-\x7e]/', $key)) {
            throw new RuntimeException('canonical_json: object keys must be printable ASCII');
        }
        $parts[] = canonical_string($key) . ':' . canonical_json($value[$key]);
    }
    return '{' . implode(',', $parts) . '}';
}

function canonical_string(string $s): string
{
    $out = '"';
    for ($i = 0, $n = strlen($s); $i < $n; $i++) {
        $c = $s[$i];
        $o = ord($c);
        if ($c === '"') { $out .= '\\"'; }
        elseif ($c === '\\') { $out .= '\\\\'; }
        elseif ($o === 0x08) { $out .= '\\b'; }
        elseif ($o === 0x09) { $out .= '\\t'; }
        elseif ($o === 0x0a) { $out .= '\\n'; }
        elseif ($o === 0x0c) { $out .= '\\f'; }
        elseif ($o === 0x0d) { $out .= '\\r'; }
        elseif ($o < 0x20) { $out .= sprintf('\\u%04x', $o); }
        else { $out .= $c; }
    }
    return $out . '"';
}

/**
 * Rebuilds and signs the published table. It needs the signing password, but no
 * epoch password: every epoch's public half was stored when the epoch was made.
 *
 * The signature covers the whole table except the signature itself: remove the
 * "signature" member, serialise what remains as canonical JSON, and verify
 * ECDSA-P256-SHA256 over those bytes.
 */
function publish_table(string $signingPassword): array
{
    $signPem = unlock_signing_key($signingPassword);

    // The verification key, written twice on purpose: as a PEM that openssl and a
    // human can read, and as raw x/y in the table because that is the shape the
    // generator hands to WebCrypto. Both come from the one private key.
    file_put_contents(signpublic_path(), public_pem($signPem));
    $sign = ec_parts($signPem);

    $epochs = [];
    foreach (available_epochs() as $epoch) {
        $epochs[$epoch] = b64u(master_public($epoch));
    }
    $table = [
        'version'    => 2,
        'signpublic' => ['x' => b64u($sign['x']), 'y' => b64u($sign['y'])],
        'epochs'     => $epochs === [] ? new stdClass() : $epochs,
    ];
    $table['signature'] = b64u(ecdsa_sign_raw(canonical_json($table), $signPem));

    file_put_contents(
        table_path(),
        json_encode($table, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n"
    );
    return $table;
}

/** Verifies the table's signature against its own verification key. */
function table_signature_ok(array $table): bool
{
    if (!isset($table['signature'], $table['signpublic']['x'], $table['signpublic']['y'])) {
        return false;
    }
    $signature = b64u_decode($table['signature']);
    unset($table['signature']);
    if (isset($table['epochs']) && $table['epochs'] === []) {
        $table['epochs'] = new stdClass();
    }
    $der = raw_sig_to_der($signature);
    $pem = ec_public_pem(b64u_decode($table['signpublic']['x']), b64u_decode($table['signpublic']['y']));
    return openssl_verify(canonical_json($table), $der, $pem, OPENSSL_ALGO_SHA256) === 1;
}

function raw_sig_to_der(string $raw): string
{
    if (strlen($raw) !== 64) {
        throw new RuntimeException('signature must be 64 bytes');
    }
    $int = static function (string $v): string {
        $v = ltrim($v, "\0");
        if ($v === '' || (ord($v[0]) & 0x80)) { $v = "\0" . $v; }
        return "\x02" . chr(strlen($v)) . $v;
    };
    $body = $int(substr($raw, 0, 32)) . $int(substr($raw, 32));
    return "\x30" . chr(strlen($body)) . $body;
}

/** A P-256 public key as PEM, from its raw coordinates. */
function ec_public_pem(string $x, string $y): string
{
    // SubjectPublicKeyInfo for id-ecPublicKey / prime256v1, then the uncompressed point.
    $prefix = hex2bin('3059301306072a8648ce3d020106082a8648ce3d030107034200');
    return "-----BEGIN PUBLIC KEY-----\n"
        . chunk_split(base64_encode($prefix . "\x04" . pad32($x) . pad32($y)), 64, "\n")
        . "-----END PUBLIC KEY-----\n";
}
