<?php
/**
 * setup.php — create the signing key and epoch master scalars, encrypted at rest,
 * and publish the signed table of public halves.
 *
 *   php setup.php                     # first run: signing key, then epoch E1
 *   php setup.php --epoch E2          # add an epoch
 *   php setup.php --epoch E2 --force  # replace E2's master scalar
 *   php setup.php --issuer --force    # replace the signing key
 *   php setup.php --publish           # re-sign and republish the table only
 *
 * The signing key's password is chosen by you and needed on every run, because
 * every run re-signs the table. Each epoch's password is generated, shown once,
 * and kept nowhere: record it, or the epoch can never issue a key.
 *
 * The signing password comes from --signing-password if given, otherwise from the
 * terminal without echo, or a line on stdin when that is a pipe. A password on the
 * command line is visible in the process list while this runs and lands in shell
 * history unless the shell is told otherwise.
 */

declare(strict_types=1);
require __DIR__ . '/lib/reportseal.php';

$epoch = 'E1';
$force = false;
$newIssuer = false;
$publishOnly = false;
$givenPassword = null;
for ($i = 1; $i < $argc; $i++) {
    switch ($argv[$i]) {
        case '--epoch':            $epoch = $argv[++$i] ?? ''; break;
        case '--force':            $force = true; break;
        case '--issuer':           $newIssuer = true; break;
        case '--publish':          $publishOnly = true; break;
        case '--signing-password': $givenPassword = $argv[++$i] ?? ''; break;
        default:
            fwrite(STDERR, "unknown argument: {$argv[$i]}\n");
            exit(2);
    }
}

try {
    assert_epoch_id($epoch);
    $tty = stream_isatty(STDIN);

    if (!is_file(signing_key_path()) || ($newIssuer && $force)) {
        $replacing = is_file(signing_key_path());
        if ($givenPassword !== null) {
            $signingPassword = $givenPassword;
        } else {
            fwrite(STDERR, 'A password for the signing key: at least ' . PASSWORD_MIN_LENGTH
                . ' characters of letters, digits and ' . PASSWORD_SYMBOLS . "\n");
            $signingPassword = read_password('New signing key password: ');
            if ($tty && read_password('Repeat it: ') !== $signingPassword) {
                throw new RuntimeException('the two passwords differ');
            }
        }
        $problem = password_problem($signingPassword);
        if ($problem !== null) {
            throw new RuntimeException($problem);
        }
        create_signing_key($signingPassword);
        echo ($replacing
            ? 'REPLACED the signing key: every key issued until now no longer works'
            : 'created signing key: ' . signing_key_path()) . "\n";
    } elseif ($newIssuer) {
        throw new RuntimeException('a signing key exists; add --force to replace it, which invalidates every issued key');
    } else {
        // Checked before anything changes, so a mistyped password cannot leave a
        // new epoch behind in an unsigned table.
        $signingPassword = $givenPassword ?? read_password('Signing key password: ');
        unlock_signing_key($signingPassword);
    }

    $epochPassword = null;
    if (!$publishOnly && (!is_file(master_path($epoch)) || $force)) {
        echo "creating epoch $epoch (deriving its public half takes a few seconds)\n";
        $added = add_epoch($epoch, $signingPassword, $force);
        $epochPassword = $added['password'];
        $table = $added['table'];
        if ($added['replaced']) {
            echo "REPLACED epoch $epoch: keys issued under it no longer open newly sealed pages\n";
        }
    } else {
        if (!$publishOnly) {
            echo "epoch $epoch already present (add --force to replace it)\n";
        }
        $table = publish_table($signingPassword);
    }
    echo 'published and signed ' . table_path() . ' with epochs: '
        . implode(', ', array_keys((array) $table['epochs'])) . "\n";

    if ($epochPassword !== null) {
        $bar = str_repeat('=', 72);
        echo "\n$bar\n";
        echo "  Password for epoch $epoch: $epochPassword\n";
        echo "  Shown this once and stored nowhere. Without it, epoch $epoch cannot\n";
        echo "  issue keys, and the only remedy is a new epoch.\n";
        echo "$bar\n";
    }
} catch (RuntimeException $e) {
    fwrite(STDERR, 'error: ' . $e->getMessage() . "\n");
    exit(1);
}
