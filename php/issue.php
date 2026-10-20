<?php
/**
 * issue.php — mint one decryption token for one page.
 *
 *   php issue.php --page DOC-1234 --epoch E1
 *   php issue.php --page DOC-1234 --epoch E1 --kid acct-4471 --name 'A. Example'
 *   php issue.php --page DOC-1234 --epoch E1 --exp 2027-01-31 --extra '{"tier":"gold"}'
 *
 * Needs the signing key password and the epoch's password. Each comes from
 * --signing-password / --epoch-password if given, otherwise from the terminal
 * without echo, or a line on stdin when that is a pipe (signing password first).
 * A password on the command line is visible in the process list while this runs
 * and lands in shell history unless the shell is told otherwise.
 *
 * Each issued key is recorded in the log and, if configured, the database before
 * the token is printed; if recording fails, no token is printed.
 *
 * Without --epoch the last epoch in the table is used, which is rarely what a page
 * was sealed under, so passing it is advisable.
 */

declare(strict_types=1);
require __DIR__ . '/lib/reportseal.php';

$epoch = null;
$pageId = null;
$opts = [];
$signingPassword = null;
$epochPassword = null;

for ($i = 1; $i < $argc; $i++) {
    switch ($argv[$i]) {
        case '--epoch':            $epoch = $argv[++$i] ?? ''; break;
        case '--page':             $pageId = $argv[++$i] ?? ''; break;
        case '--kid':              $opts['kid'] = $argv[++$i] ?? ''; break;
        case '--exp':              $opts['exp'] = $argv[++$i] ?? ''; break;
        case '--name':             $opts['name'] = $argv[++$i] ?? ''; break;
        case '--institution':      $opts['institution'] = $argv[++$i] ?? ''; break;
        case '--signing-password': $signingPassword = $argv[++$i] ?? ''; break;
        case '--epoch-password':   $epochPassword = $argv[++$i] ?? ''; break;
        case '--extra':
            $opts['extra'] = json_decode($argv[++$i] ?? '{}', true, 512, JSON_THROW_ON_ERROR);
            break;
        default:
            fwrite(STDERR, "unknown argument: {$argv[$i]}\n");
            fwrite(STDERR, "usage: issue.php --page <id> [--epoch E1] [--kid <id>] [--exp <date>]\n"
                         . "                 [--name <text>] [--institution <text>] [--extra <json>]\n"
                         . "                 [--signing-password <pw>] [--epoch-password <pw>]\n");
            exit(1);
    }
}

try {
    if ($pageId === null || $pageId === '') {
        throw new RuntimeException('--page is required: a key opens exactly one page');
    }
    if ($epoch === null || $epoch === '') {
        $epochs = available_epochs();
        if ($epochs === []) {
            throw new RuntimeException('no epochs exist yet — run: php setup.php');
        }
        $epoch = end($epochs);
    }

    $issuer = unlock_issuer(
        $epoch,
        $signingPassword ?? read_password('Signing key password: '),
        $epochPassword ?? read_password("Password for epoch $epoch: ")
    );
    if (!isset($opts['kid']) || $opts['kid'] === '') {
        $opts['kid'] = random_kid();
    }
    $token = mint_token($issuer, $pageId, $opts);

    record_issue([
        'kid'         => $opts['kid'],
        'epoch'       => $epoch,
        'page'        => $pageId,
        'name'        => (string) ($opts['name'] ?? 'unknown'),
        'institution' => (string) ($opts['institution'] ?? 'unknown'),
        'exp'         => isset($opts['exp']) && $opts['exp'] !== '' ? normalise_exp($opts['exp']) : null,
    ], 'cli');

    echo $token, "\n";
    // on stderr so stdout stays exactly the token
    fwrite(STDERR, 'page identity ' . page_fingerprint($pageId) . " for '$pageId'\n");
} catch (RuntimeException $e) {
    fwrite(STDERR, 'error: ' . $e->getMessage() . "\n");
    exit(1);
}
