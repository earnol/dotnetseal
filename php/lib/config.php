<?php
/**
 * config.php — where things live, and the few settings that differ between
 * machines.
 *
 * Every setting has a default that reproduces the repository layout, so a config
 * file is optional. To change any of them, copy config/reportseal.example.php to
 * config/reportseal.php, or point REPORTSEAL_CONFIG at a file elsewhere. Relative
 * paths are taken from the repository root.
 */

declare(strict_types=1);

/** @return array<string,mixed> */
function config(): array
{
    static $config = null;
    if ($config !== null) {
        return $config;
    }

    $root = dirname(__DIR__, 2);
    $defaults = [
        'table'       => 'keys/epochs.json',
        'signpublic'  => 'keys/signpublic.pem',
        'private_dir' => 'keys/private',
        'issued_log'  => 'keys/issued.log',     // null: no log file
        'openssl'     => 'openssl',             // an OpenSSL 3.2+ binary, for Argon2id
        'argon2'      => ['memcost' => 65536, 'iter' => 3, 'lanes' => 4],
        'db'          => null,                  // see config/reportseal.example.php
    ];

    $named = getenv('REPORTSEAL_CONFIG');
    $file = ($named !== false && $named !== '') ? $named : $root . '/config/reportseal.php';
    $given = [];
    if (is_file($file)) {
        $given = require $file;
        if (!is_array($given)) {
            throw new RuntimeException("$file must return an array of settings");
        }
    } elseif ($named !== false && $named !== '') {
        throw new RuntimeException("REPORTSEAL_CONFIG names $file, which does not exist");
    }

    $unknown = array_diff(array_keys($given), array_keys($defaults));
    if ($unknown !== []) {
        throw new RuntimeException("unknown setting(s) in $file: " . implode(', ', $unknown));
    }

    $config = array_replace($defaults, $given);
    foreach (['table', 'signpublic', 'private_dir', 'issued_log'] as $key) {
        if ($config[$key] !== null) {
            $path = (string) $config[$key];
            $config[$key] = ($path !== '' && $path[0] === '/') ? $path : $root . '/' . $path;
        }
    }
    foreach (['memcost', 'iter', 'lanes'] as $key) {
        $v = $config['argon2'][$key] ?? null;
        if (!is_int($v) || $v < 1) {
            throw new RuntimeException("setting argon2.$key must be a positive integer");
        }
    }
    return $config;
}
