<?php
/**
 * Shared helpers for the PHP (private-key) side of the POC.
 *
 * Layout:
 *   keys/private/signprivate.pem    ECDSA P-256 signing key  (PHP only, never published)
 *   keys/private/master-<epoch>.key BLS12-381 master scalar   (PHP only, never published)
 *   keys/signpublic.pem             signature verification key, for openssl and people
 *   keys/epochs.json                epoch public keys + the same verification key,
 *                                   in the JWK-shaped form the generator wants
 *
 * keys/epochs.json stands in for the future read-only SQL seed table. It maps a
 * seed id to the public half of the epoch keypair. Rotation = add a new seed row.
 */

declare(strict_types=1);

require_once __DIR__ . '/bls12381.php';

/** The issuer signing key stays on P-256: WebCrypto verifies it natively. */
const CURVE = 'prime256v1';

function repo_root(): string
{
    return dirname(__DIR__, 2);
}

function keys_dir(): string
{
    return repo_root() . '/keys';
}

function table_path(): string
{
    return keys_dir() . '/epochs.json';
}

function signpublic_path(): string
{
    return keys_dir() . '/signpublic.pem';
}

function private_path(string $name): string
{
    return keys_dir() . '/private/' . $name . '.pem';
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

function master_path(string $epoch): string
{
    return keys_dir() . '/private/master-' . $epoch . '.key';
}

/** Epoch ids that currently have a master scalar. */
function available_epochs(): array
{
    $ids = [];
    foreach (glob(keys_dir() . '/private/master-*.key') ?: [] as $file) {
        $ids[] = preg_replace('/^master-|\.key$/', '', basename($file));
    }
    sort($ids);
    return $ids;
}

function read_master(string $epoch): string
{
    $p = master_path($epoch);
    if (!is_file($p)) {
        throw new RuntimeException("no master scalar for epoch '$epoch' — run: php setup.php --epoch $epoch");
    }
    return Bls12381::scalarFromHex(trim((string) file_get_contents($p)));
}

/** A fresh master scalar. 384 random bits reduced mod r leaves negligible bias. */
function new_master(): string
{
    return Bls12381::scalarToHex(Bls12381::scalarFromBytes(random_bytes(48)));
}

/** The epoch's public half, X = s * G2, as 96 compressed bytes. */
function master_public(string $epoch): string
{
    return Bls12381::compressG2(Bls12381::g2Mul(read_master($epoch)));
}

/**
 * The private element for one page: sk = (1/(s + id)) * G1, 48 compressed bytes.
 *
 * This is the only operation that needs the master scalar, and the only reason
 * the issuer exists. The result opens exactly the pages sealed under this epoch
 * with this page id: nothing public relates one page's element to another's, so
 * a holder cannot move their key to a different page.
 */
function page_key(string $epoch, string $pageId): string
{
    $inv = Bls12381::scalarInv(
        Bls12381::scalarAdd(read_master($epoch), page_identity($pageId))
    );
    return Bls12381::compressG1(Bls12381::g1Mul($inv));
}

/**
 * Mint one decryption token for one page of one epoch.
 *
 * Only what the crypto needs sits at the top level: which epoch and page the key
 * belongs to, and the private element itself. Everything else is descriptive
 * metadata in "extra", where the page decides how to treat each field.
 *
 * Recognised options, all optional:
 *   kid          key id for your logs; a random K-xxxxxxxx when omitted
 *   exp          anything strtotime() reads, normalised to a UTC instant
 *   name         user name, shown in the page header
 *   institution  user institution, shown in the page header
 *   extra        further caller fields, merged in and listed by the page
 *
 * @param array<string,mixed> $opts
 */
function mint_token(string $epoch, string $pageId, array $opts = []): string
{
    $unknown = array_diff(array_keys($opts), ['kid', 'exp', 'name', 'institution', 'extra']);
    if ($unknown !== []) {
        throw new RuntimeException('unknown option(s): ' . implode(', ', $unknown));
    }
    if (!preg_match('/^[A-Za-z0-9_.-]{1,32}$/', $epoch)) {
        throw new RuntimeException('invalid epoch id (allowed: A-Za-z0-9_.- up to 32 chars)');
    }
    if (!preg_match('/^[A-Za-z0-9_.:-]{1,64}$/', $pageId)) {
        throw new RuntimeException('invalid page id (allowed: A-Za-z0-9_.:- up to 64 chars)');
    }

    $kid = (string) ($opts['kid'] ?? '');
    if ($kid === '') {
        $kid = random_kid();
    }
    if (!preg_match('/^[A-Za-z0-9_.:-]{1,40}$/', $kid)) {
        throw new RuntimeException('invalid key id (allowed: A-Za-z0-9_.:- up to 40 chars)');
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
        'sk'    => b64u(page_key($epoch, $pageId)),
        'extra' => $extra,
    ];

    $p64 = b64u(json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
    $sig = b64u(ecdsa_sign_raw($p64, (string) file_get_contents(private_path('signprivate'))));

    return "NO1.$p64.$sig";
}

/**
 * Rebuild keys/epochs.json from whatever private material exists. Public halves
 * only: the master scalars never leave keys/private/.
 */
function publish_table(): array
{
    $signPem = (string) file_get_contents(private_path('signprivate'));

    // The verification key, written twice on purpose: as a PEM that openssl and a
    // human can read, and as raw x/y in the table because that is the shape the
    // generator hands to WebCrypto. Both are derived here from the one private
    // key, so they cannot drift apart.
    file_put_contents(signpublic_path(), public_pem($signPem));

    $sign = ec_parts($signPem);
    $epochs = [];
    foreach (available_epochs() as $epoch) {
        $epochs[$epoch] = b64u(master_public($epoch));
    }
    $table = [
        'version'    => 2,
        'signpublic' => ['x' => b64u($sign['x']), 'y' => b64u($sign['y'])],
        'epochs'     => $epochs,
    ];
    file_put_contents(
        table_path(),
        json_encode($table, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n"
    );
    return $table;
}
