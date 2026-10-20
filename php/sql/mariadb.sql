-- The table php/lib/recorder.php writes one row per issued key into.
-- Never holds a token or a password. UNTESTED against a real MariaDB server.
--
--   mysql -u <admin> -p <database> < php/sql/mariadb.sql
--
-- The issuer only ever inserts, so its account needs INSERT on this table and
-- nothing else:
--   GRANT INSERT ON <database>.issued_keys TO 'reportseal'@'localhost';

CREATE TABLE IF NOT EXISTS issued_keys (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    issued_at   DATETIME        NOT NULL COMMENT 'UTC',
    source      VARCHAR(16)     NOT NULL COMMENT 'web or cli',
    kid         VARCHAR(40)     NOT NULL,
    epoch       VARCHAR(32)     NOT NULL,
    page        VARCHAR(64)     NOT NULL,
    name        VARCHAR(255)    NOT NULL,
    institution VARCHAR(255)    NOT NULL,
    exp         DATETIME        NULL     COMMENT 'UTC; NULL when the key has no expiry',
    PRIMARY KEY (id),
    KEY ix_page (page),
    KEY ix_kid (kid),
    KEY ix_issued_at (issued_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
