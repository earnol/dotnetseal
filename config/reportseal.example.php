<?php
// Copy to config/reportseal.php, or point REPORTSEAL_CONFIG at a copy elsewhere.
// Every setting is optional; the values shown are the defaults. Relative paths are
// taken from the repository root.
return [
    // The published table. On a deployment, point this inside the web server's
    // document root so the .NET build machine can fetch it.
    'table'       => 'keys/epochs.json',
    'signpublic'  => 'keys/signpublic.pem',

    // Encrypted signing key, encrypted epoch scalars and epoch public halves.
    'private_dir' => 'keys/private',

    // One JSON line per issued key; null turns the file off.
    'issued_log'  => 'keys/issued.log',

    // An OpenSSL 3.2 or newer binary, which provides Argon2id.
    'openssl'     => 'openssl',

    // Applied to newly written key files; existing files keep the parameters they
    // were written with. memcost is in KiB: 65536 is 64 MiB.
    'argon2'      => ['memcost' => 65536, 'iter' => 3, 'lanes' => 4],

    // Record issued keys in MariaDB as well as the log (php/sql/mariadb.sql makes
    // the table). The password is read from the named environment variable and is
    // never kept in this file.
    'db'          => null,
    // 'db' => [
    //     'dsn'          => 'mysql:host=127.0.0.1;port=3306;dbname=reportseal;charset=utf8mb4',
    //     'user'         => 'reportseal',
    //     'password_env' => 'REPORTSEAL_DB_PASSWORD',
    //     'table'        => 'issued_keys',
    // ],
];
