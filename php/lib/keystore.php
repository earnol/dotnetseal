<?php
/**
 * keystore.php — passwords, and private keys encrypted at rest.
 *
 * A key file is a small JSON envelope: Argon2id stretches the password into a
 * 256-bit key, and AES-256-GCM encrypts the secret under it. The Argon2id
 * parameters and salt travel in the envelope, so changing the configured
 * parameters later never strands a file written under the old ones. GCM's tag
 * means a wrong password is detected rather than yielding garbage.
 *
 * Argon2id comes from the OpenSSL 3.2+ command line, because neither PHP nor the
 * OpenSSL it links against here offers it. That command takes the password only
 * as an argument, so for the second or so it runs, the password — passed as hex —
 * is in the process's argument list. See "Deployment checks" in README.md for what
 * that means on the issuing server. It is never written to disk, a log or the
 * database.
 */

declare(strict_types=1);

require_once __DIR__ . '/config.php';

/** Symbols a password may use besides letters and digits: typeable on any keyboard. */
const PASSWORD_SYMBOLS = '-_.,!@#%=:{}[]()';
const PASSWORD_MIN_LENGTH = 12;

/** Why a password is unacceptable, or null when it is fine. */
function password_problem(string $password): ?string
{
    if (strlen($password) < PASSWORD_MIN_LENGTH) {
        return 'a password needs at least ' . PASSWORD_MIN_LENGTH . ' characters';
    }
    for ($i = 0, $n = strlen($password); $i < $n; $i++) {
        $c = $password[$i];
        if (!ctype_alnum($c) && strpos(PASSWORD_SYMBOLS, $c) === false) {
            return 'a password may use letters, digits and ' . PASSWORD_SYMBOLS . ' only';
        }
    }
    return null;
}

/**
 * A password for a new epoch: 20 characters, about 116 bits. It is written down
 * once by a person, so characters that are easy to misread — 0 O o 1 l I — are
 * left out, and so are symbols.
 */
function generate_password(int $length = 20): string
{
    $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789';
    $out = '';
    for ($i = 0; $i < $length; $i++) {
        $out .= $alphabet[random_int(0, strlen($alphabet) - 1)];
    }
    return $out;
}

/**
 * Reads one password: from the terminal without echo, or a line from stdin when
 * that is a pipe, which is how scripts and the test suite supply one. Never from
 * the command line, which ends up in shell history.
 */
function read_password(string $prompt): string
{
    // Decided once, before anything is read: asking again after PHP has buffered
    // stdin makes it warn about the buffered bytes.
    static $tty = null;
    if ($tty === null) {
        $tty = stream_isatty(STDIN);
    }
    if ($tty) {
        fwrite(STDERR, $prompt);
        shell_exec('stty -echo');
        $line = fgets(STDIN);
        shell_exec('stty echo');
        fwrite(STDERR, "\n");
    } else {
        $line = fgets(STDIN);
    }
    if ($line === false) {
        throw new RuntimeException('no password was supplied');
    }
    return rtrim($line, "\r\n");
}

/** Argon2id through the OpenSSL command line; returns 32 raw bytes. */
function argon2id(string $password, string $salt, int $memcost, int $iter, int $lanes): string
{
    // An argument array, so no shell is involved: nothing to quote and nothing
    // in shell history. Hex makes every character of the password inert.
    $command = [
        config()['openssl'], 'kdf', '-keylen', '32',
        '-kdfopt', 'hexpass:' . bin2hex($password),
        '-kdfopt', 'hexsalt:' . bin2hex($salt),
        '-kdfopt', 'iter:' . $iter,
        '-kdfopt', 'memcost:' . $memcost,
        '-kdfopt', 'lanes:' . $lanes,
        // The CLI never enables threading, and asking for more than one fails.
        '-kdfopt', 'threads:1',
        '-binary', 'ARGON2ID',
    ];
    $process = proc_open($command, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    if (!is_resource($process)) {
        throw new RuntimeException('could not run ' . config()['openssl']);
    }
    $key = stream_get_contents($pipes[1]);
    $errors = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $status = proc_close($process);

    if ($status !== 0 || strlen((string) $key) !== 32) {
        // The arguments are deliberately left out of this message: they hold the
        // password.
        throw new RuntimeException(
            'Argon2id failed; the "openssl" setting must name an OpenSSL 3.2 or newer binary ('
            . trim(strtok((string) $errors, "\n") ?: 'no detail') . ')');
    }
    return $key;
}

/** Encrypts a secret under a password, for one stated purpose. */
function seal_secret(string $secret, string $password, string $purpose): string
{
    $p = config()['argon2'];
    $salt = random_bytes(16);
    $nonce = random_bytes(12);
    $key = argon2id($password, $salt, $p['memcost'], $p['iter'], $p['lanes']);

    // The purpose is authenticated, so an epoch file cannot be passed off as the
    // signing key file or the other way round.
    $tag = '';
    $ciphertext = openssl_encrypt($secret, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, $purpose, 16);
    if ($ciphertext === false) {
        throw new RuntimeException('encryption failed: ' . openssl_error_string());
    }
    return json_encode([
        'format'  => 'reportseal-key-1',
        'purpose' => $purpose,
        'kdf'     => 'argon2id',
        'memcost' => $p['memcost'],
        'iter'    => $p['iter'],
        'lanes'   => $p['lanes'],
        'salt'    => b64u($salt),
        'nonce'   => b64u($nonce),
        'data'    => b64u($ciphertext . $tag),
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
}

/** Decrypts an envelope written by seal_secret. A wrong password is an error. */
function open_secret(string $envelope, string $password, string $purpose): string
{
    $e = json_decode($envelope, true);
    if (!is_array($e) || ($e['format'] ?? '') !== 'reportseal-key-1' || ($e['kdf'] ?? '') !== 'argon2id') {
        throw new RuntimeException('not a key file this version understands');
    }
    if (($e['purpose'] ?? '') !== $purpose) {
        throw new RuntimeException("this key file holds '" . ($e['purpose'] ?? '?') . "', not '$purpose'");
    }
    $key = argon2id($password, b64u_decode($e['salt']), (int) $e['memcost'], (int) $e['iter'], (int) $e['lanes']);
    $data = b64u_decode($e['data']);
    $secret = openssl_decrypt(
        substr($data, 0, -16), 'aes-256-gcm', $key, OPENSSL_RAW_DATA,
        b64u_decode($e['nonce']), substr($data, -16), $purpose);
    if ($secret === false) {
        throw new RuntimeException("wrong password for the $purpose");
    }
    return $secret;
}
