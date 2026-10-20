<?php
/**
 * recorder.php — the record of which keys were issued, to whom.
 *
 * Every issued key is written to the log file and, when a database is configured,
 * to a table as well. The token itself is never recorded: it is the decryption
 * key. Neither are passwords.
 *
 * Recording happens before the token is shown. If any configured destination
 * fails, the issuer refuses to hand the key over, so a key never exists without a
 * record of it.
 *
 * The database layer is written for MariaDB through PDO and has NOT been run
 * against a real server: no PHP build on the development machine carries
 * pdo_mysql. php/sql/mariadb.sql creates the table it expects.
 */

declare(strict_types=1);

require_once __DIR__ . '/config.php';

/**
 * @param array{kid:string,epoch:string,page:string,name:string,institution:string,exp:?string} $entry
 * @param string $source where the key was issued from, e.g. "web" or "cli"
 */
function record_issue(array $entry, string $source): void
{
    $cfg = config();
    $row = [
        'issued_at'   => gmdate('Y-m-d\TH:i:s\Z'),
        'source'      => $source,
        'kid'         => $entry['kid'],
        'epoch'       => $entry['epoch'],
        'page'        => $entry['page'],
        'name'        => $entry['name'],
        'institution' => $entry['institution'],
        'exp'         => $entry['exp'],
    ];

    if ($cfg['issued_log'] !== null) {
        $line = $row['issued_at'] . "\t"
            . json_encode($row, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR) . "\n";
        if (@file_put_contents($cfg['issued_log'], $line, FILE_APPEND | LOCK_EX) === false) {
            throw new RuntimeException('could not append to ' . $cfg['issued_log']);
        }
    }

    if ($cfg['db'] !== null) {
        record_issue_db($cfg['db'], $row);
    }
}

/** @param array<string,mixed> $db */
function record_issue_db(array $db, array $row): void
{
    foreach (['dsn', 'user'] as $required) {
        if (empty($db[$required])) {
            throw new RuntimeException("setting db.$required is required when db is configured");
        }
    }
    $table = $db['table'] ?? 'issued_keys';
    if (!preg_match('/^[A-Za-z0-9_]{1,64}$/', $table)) {
        throw new RuntimeException('setting db.table must be a plain table name');
    }

    // The database password comes from the environment, never the config file, so
    // it is not stored on disk alongside the settings.
    $password = '';
    if (!empty($db['password_env'])) {
        $value = getenv((string) $db['password_env']);
        if ($value === false) {
            throw new RuntimeException('environment variable ' . $db['password_env'] . ' is not set');
        }
        $password = $value;
    }

    try {
        $pdo = new PDO((string) $db['dsn'], (string) $db['user'], $password, [
            PDO::ATTR_ERRMODE          => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
        $statement = $pdo->prepare(
            "INSERT INTO `$table` (issued_at, source, kid, epoch, page, name, institution, exp) "
            . 'VALUES (:issued_at, :source, :kid, :epoch, :page, :name, :institution, :exp)');
        $statement->execute([
            ':issued_at'   => substr(str_replace('T', ' ', $row['issued_at']), 0, 19),
            ':source'      => $row['source'],
            ':kid'         => $row['kid'],
            ':epoch'       => $row['epoch'],
            ':page'        => $row['page'],
            ':name'        => $row['name'],
            ':institution' => $row['institution'],
            ':exp'         => $row['exp'] === null ? null : substr(str_replace('T', ' ', $row['exp']), 0, 19),
        ]);
    } catch (PDOException $e) {
        // PDO messages can carry the DSN; they never carry the password.
        throw new RuntimeException('could not record the key in the database: ' . $e->getMessage());
    }
}
