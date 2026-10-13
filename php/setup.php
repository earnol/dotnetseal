<?php
/**
 * setup.php — create the signing key and the epoch master scalars, then publish
 * the public halves to keys/signpublic.pem and keys/epochs.json.
 *
 *   php setup.php                     # first run: issuer key + master scalar for E1
 *   php setup.php --epoch E2          # rotation: a new master scalar, old one kept
 *   php setup.php --epoch E2 --force  # replace E2's master scalar
 *   php setup.php --issuer --force    # replace the signing key
 *
 * Existing keys are never overwritten without --force, because replacing one
 * invalidates every key already issued under it.
 *
 * Private material stays in keys/private/ and is never written to the table.
 */

declare(strict_types=1);
require __DIR__ . '/lib/reportseal.php';

$epoch = 'E1';
$force = false;
$newIssuer = false;
for ($i = 1; $i < $argc; $i++) {
    switch ($argv[$i]) {
        case '--epoch':  $epoch = $argv[++$i] ?? ''; break;
        case '--force':  $force = true; break;
        case '--issuer': $newIssuer = true; break;
        default:
            fwrite(STDERR, "unknown argument: {$argv[$i]}\n");
            exit(1);
    }
}
if (!preg_match('/^[A-Za-z0-9_.-]{1,32}$/', $epoch)) {
    fwrite(STDERR, "invalid --epoch (allowed: A-Za-z0-9_.- up to 32 chars)\n");
    exit(1);
}

@mkdir(keys_dir() . '/private', 0700, true);
@chmod(keys_dir() . '/private', 0700);

$signPem = private_path('signprivate');
if (!is_file($signPem)) {
    file_put_contents($signPem, new_ec_key());
    chmod($signPem, 0600);
    echo "created signing key: $signPem\n";
} elseif ($newIssuer && $force) {
    file_put_contents($signPem, new_ec_key());
    chmod($signPem, 0600);
    echo "REPLACED signing key: every key issued before now is now unusable\n";
} elseif ($newIssuer) {
    fwrite(STDERR, "signing key exists; add --force to replace it (invalidates all issued keys)\n");
    exit(1);
} else {
    echo "signing key already present\n";
}

$masterFile = master_path($epoch);
if (!is_file($masterFile)) {
    file_put_contents($masterFile, new_master() . "\n");
    chmod($masterFile, 0600);
    echo "created master scalar for epoch '$epoch': $masterFile\n";
} elseif ($force) {
    file_put_contents($masterFile, new_master() . "\n");
    chmod($masterFile, 0600);
    echo "REPLACED master scalar for epoch '$epoch': keys issued under it no longer open new pages\n";
} else {
    echo "master scalar for epoch '$epoch' already present (add --force to replace it)\n";
}

// Deriving each public half is one G2 multiply, a couple of seconds apiece.
echo "computing public halves...\n";
$table = publish_table();

echo 'wrote ' . signpublic_path() . "\n";
echo 'published epochs: ' . implode(', ', array_keys($table['epochs'])) . "\n";
echo 'table: ' . table_path() . "\n";
echo "next: copy that table to the .NET side, then generate pages against epoch $epoch\n";
