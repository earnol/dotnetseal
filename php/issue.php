<?php
/**
 * issue.php — mint one decryption token. This is the only place the epoch private
 * key and the issuer signing key are ever read.
 *
 *   php issue.php --page DOC-1234
 *   php issue.php --page DOC-1234 --kid acct-4471 --name 'A. Example' --institution 'Example Institute'
 *   php issue.php --page DOC-1234 --exp 2027-01-31   # reported, never enforced
 *   php issue.php --page DOC-1234 --extra '{"tier":"gold"}'
 *
 * One key per invocation, each with its own data block. Callers that issue keys
 * programmatically should require lib/reportseal.php and call mint_token() directly.
 *
 * Token format:  NO1.<base64url(payload)>.<base64url(r||s)>
 *   payload = {"v":2,"epoch":...,"page":...,"sk":<page private element>,
 *              "extra":{"kid":...,"name":...,"institution":...,"exp":...}}
 *
 * Only the epoch, page and element are crypto; everything else is metadata in
 * "extra". The element opens exactly this page: a key for another page cannot be
 * turned into a key for this one. The ECDSA signature is what stops a holder from
 * editing their own metadata or minting tokens of their own.
 *
 * "exp" is a signed notice only: the page still decrypts and simply reports that
 * the key is past its date. Withdrawal is done by rotating the epoch.
 */

declare(strict_types=1);
require __DIR__ . '/lib/reportseal.php';

$epoch = null;
$pageId = null;
$opts = [];

for ($i = 1; $i < $argc; $i++) {
    switch ($argv[$i]) {
        case '--epoch':       $epoch = $argv[++$i] ?? ''; break;
        case '--page':        $pageId = $argv[++$i] ?? ''; break;
        case '--kid':         $opts['kid'] = $argv[++$i] ?? ''; break;
        case '--exp':         $opts['exp'] = $argv[++$i] ?? ''; break;
        case '--name':        $opts['name'] = $argv[++$i] ?? ''; break;
        case '--institution': $opts['institution'] = $argv[++$i] ?? ''; break;
        case '--extra':
            // decoded as an array so it merges into the metadata block
            $opts['extra'] = json_decode($argv[++$i] ?? '{}', true, 512, JSON_THROW_ON_ERROR);
            break;
        default:
            fwrite(STDERR, "unknown argument: {$argv[$i]}\n");
            fwrite(STDERR, "usage: issue.php --page <id> [--epoch E1] [--kid <id>] [--exp <date>]\n"
                         . "                 [--name <text>] [--institution <text>] [--extra <json>]\n");
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
    echo mint_token($epoch, $pageId, $opts), "\n";
    // on stderr so stdout stays exactly the token
    fwrite(STDERR, 'page identity ' . page_fingerprint($pageId) . " for '$pageId'\n");
} catch (RuntimeException $e) {
    fwrite(STDERR, 'error: ' . $e->getMessage() . "\n");
    exit(1);
}
