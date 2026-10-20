<?php
/**
 * index.php — key issuing UI. Reads the epoch private key and the issuer signing
 * key, so this must never be reachable from an untrusted network. Start it bound
 * to the loopback interface only:
 *
 *   php -S 127.0.0.1:8080 -t php/web
 *
 * It asks for the signing password on every request and holds no password between
 * requests, but has no access control of its own: anyone who can reach it and knows
 * the passwords can mint keys and create epochs.
 *
 * Two forms post here: issuing a key (action=issue) and creating an epoch
 * (action=create_epoch). A new epoch's password is shown once in the response and
 * kept nowhere.
 */

declare(strict_types=1);
require dirname(__DIR__) . '/lib/reportseal.php';

const UNKNOWN = 'unknown';

/** Default validity for a new key, resolved afresh on every request. */
const DEFAULT_VALIDITY = '+2 months';

/**
 * The default expiry moment: the same time of day, two months out. A key minted
 * at 15:04 UTC expires at 15:04 UTC. Everything here is UTC; the form says so,
 * because a bare HH:MM carries no zone of its own.
 *
 * @return array{date:string,time:string}
 */
function default_expiry(): array
{
    $ts = strtotime(DEFAULT_VALIDITY);
    return ['date' => gmdate('Y-m-d', $ts), 'time' => gmdate('H:i', $ts)];
}

/** Trim, collapse whitespace and cap length, so a field cannot bloat the token. */
function field(string $name, int $max = 80): string
{
    $raw = (string) ($_POST[$name] ?? '');
    $clean = trim(preg_replace('/\s+/u', ' ', $raw) ?? '');
    return mb_substr($clean, 0, $max);
}

function h(string $s): string
{
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/** The next free id of the form E<n>, as a suggestion for a new epoch. */
function next_epoch_id(array $epochs): string
{
    $n = 0;
    foreach ($epochs as $e) {
        if (preg_match('/^E(\d+)$/', $e, $m)) {
            $n = max($n, (int) $m[1]);
        }
    }
    return 'E' . ($n + 1);
}

// A response may carry a token or a new epoch password: never cache it.
header('Cache-Control: no-store');
header('Pragma: no-cache');

$epochs = available_epochs();
$token = null;
$error = null;
$issued = [];
$posted = $_SERVER['REQUEST_METHOD'] === 'POST';
$action = $posted ? (string) ($_POST['action'] ?? 'issue') : '';

// Epoch creation. Only adds: replacing an epoch invalidates keys issued under it,
// which stays a deliberate command-line step (setup.php --epoch X --force).
$created = null;          // ['epoch' => …, 'password' => …] once, in this response
$epochError = null;
$newEpoch = $action === 'create_epoch' ? field('new_epoch', 32) : next_epoch_id($epochs);
if ($action === 'create_epoch') {
    try {
        // One action: create the epoch and re-sign the table, with the signing
        // password held in this request only.
        $added = add_epoch($newEpoch, (string) ($_POST['signing_password'] ?? ''));
        $created = ['epoch' => $newEpoch, 'password' => $added['password']];
        $epochs = available_epochs();
        $newEpoch = next_epoch_id($epochs);
    } catch (Throwable $e) {
        $epochError = $e->getMessage();
    }
}

// Sticky values, so a rejected form comes back filled in.
$in = [
    'epoch'       => $action === 'issue' ? field('epoch', 32)
                     : ($created['epoch'] ?? (end($epochs) ?: '')),
    'page_id'     => field('page_id', 64),
    'name'        => field('name'),
    'institution' => field('institution'),
    'exp'         => $posted ? field('exp', 40) : default_expiry()['date'],
    'exp_time'    => $posted ? field('exp_time', 5) : default_expiry()['time'],
    'kid'         => field('kid', 40),
];

if ($action === 'issue') {
    try {
        if ($epochs === []) {
            throw new RuntimeException('no epochs exist yet — run: php php/setup.php');
        }
        if (!in_array($in['epoch'], $epochs, true)) {
            throw new RuntimeException('unknown epoch');
        }
        if ($in['page_id'] === '') {
            throw new RuntimeException('a page id is required: a key opens exactly one page');
        }

        // Everything the operator left blank gets an explicit stand-in, so the
        // signed payload always carries a value and the page never has to guess.
        $name = $in['name'] !== '' ? $in['name'] : UNKNOWN;
        $institution = $in['institution'] !== '' ? $in['institution'] : UNKNOWN;
        // Date and time-of-day are separate fields; together they are one UTC moment.
        $expDate = $in['exp'] !== '' ? $in['exp'] : default_expiry()['date'];
        $expTime = $in['exp_time'] !== '' ? $in['exp_time'] : default_expiry()['time'];
        if (!preg_match('/^([01][0-9]|2[0-3]):[0-5][0-9]$/', $expTime)) {
            throw new RuntimeException('expiry time must be HH:MM on a 24-hour clock');
        }
        $exp = $expDate . 'T' . $expTime . ':00Z';
        $kid = $in['kid'] !== '' ? $in['kid'] : random_kid();

        // Passwords are read straight from the request and never kept: not in the
        // sticky form values, not in the log, not in the database, not in errors.
        $issuer = unlock_issuer(
            $in['epoch'],
            (string) ($_POST['signing_password'] ?? ''),
            (string) ($_POST['epoch_password'] ?? '')
        );
        $token = mint_token($issuer, $in['page_id'], [
            'kid'         => $kid,
            'exp'         => $exp,
            'name'        => $name,
            'institution' => $institution,
        ]);

        // Recorded before the token is shown; if recording fails, no token is.
        record_issue([
            'kid'         => $kid,
            'epoch'       => $in['epoch'],
            'page'        => $in['page_id'],
            'name'        => $name,
            'institution' => $institution,
            'exp'         => normalise_exp($exp),
        ], 'web');

        $issued = [
            'Key id'      => $kid,
            'Epoch'       => $in['epoch'],
            'Page id'     => $in['page_id'],
            'Page identity' => page_fingerprint($in['page_id']),
            'User'        => $name,
            'Institution' => $institution,
            'Expires'     => normalise_exp($exp),
            'Length'      => strlen($token) . ' characters',
        ];
    } catch (Throwable $e) {
        $error = $e->getMessage();
        $token = null;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>reportseal — issue a key</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 16px/1.5 system-ui, sans-serif; margin: 0 auto; max-width: 44rem; padding: 2rem 1rem; }
  h1 { font-size: 1.5rem; margin: 0 0 .25rem; }
  .muted { color: #8a8a8a; font-size: .875rem; }
  .warn { border-left: 3px solid #b7950b; background: #b7950b1a; padding: .6rem .8rem;
          margin: 1rem 0 1.5rem; font-size: .9375rem; }
  .err { border-left: 3px solid #c0392b; background: #c0392b1a; padding: .6rem .8rem;
         margin: 1rem 0; }
  form { display: grid; gap: 1rem; margin: 1.5rem 0; }
  label { display: grid; gap: .25rem; font-weight: 600; }
  label span { font-weight: 400; color: #8a8a8a; font-size: .8125rem; }
  input, select { font: inherit; padding: .4rem; box-sizing: border-box; width: 100%; }
  button { justify-self: start; font: inherit; padding: .5rem 1.25rem; cursor: pointer; }
  .key { font: 13px/1.5 ui-monospace, monospace; word-break: break-all; background: #8881;
         padding: .75rem; border: 1px solid #8884; }
  dl { display: grid; grid-template-columns: max-content 1fr; gap: .25rem 1rem; margin: 1rem 0; }
  dt { font-weight: 600; }
  dd { margin: 0; font-family: ui-monospace, monospace; }
  .secret { border: 2px solid #b7950b; padding: .75rem 1rem; margin: 1rem 0; }
  .secret .key { font-size: 1.25rem; letter-spacing: .05em; user-select: all; }
  section + section { border-top: 1px solid #8884; margin-top: 2.5rem; padding-top: 1rem; }
</style>
</head>
<body>

<h1>Issue a decryption key</h1>
<p class="muted">Each key opens exactly one page. A key issued for one page id
cannot open another, and that boundary is cryptographic.</p>

<p class="warn">This page reads the private keys. Keep it on loopback only —
anyone who can load it and knows the passwords can mint keys.</p>

<?php if ($created !== null): ?>
  <div class="secret" role="alert">
    <h2>Epoch <?= h($created['epoch']) ?> created</h2>
    <p>Its password:</p>
    <p class="key"><?= h($created['password']) ?></p>
    <p><strong>Record it now.</strong> It is shown this once and stored nowhere —
    not on disk, not in a log. Without it, epoch <?= h($created['epoch']) ?> cannot
    issue keys, and the only remedy is a new epoch.</p>
    <p class="muted">The key table has been re-signed with <?= h($created['epoch']) ?>
    in it. Publish it where the pages' <code>Table:</code> points.</p>
  </div>
<?php endif; ?>

<section>

<?php if ($error !== null): ?>
  <p class="err"><?= h($error) ?></p>
<?php endif; ?>

<?php if ($token !== null): ?>
  <h2>Key issued</h2>
  <p class="key"><?= h($token) ?></p>
  <dl>
    <?php foreach ($issued as $k => $v): ?>
      <dt><?= h((string) $k) ?></dt><dd><?= h((string) $v) ?></dd>
    <?php endforeach; ?>
  </dl>
  <p class="muted">The user pastes this into that page. Their name, institution
  and expiry date are signed into it and will be shown in the page header once it
  unlocks. The key id and document id are not displayed by the page.</p>
  <hr>
  <h2>Issue another</h2>
<?php endif; ?>

<form method="post">
  <input type="hidden" name="action" value="issue">
  <label>Epoch
    <span>Which master keypair the key belongs to.</span>
    <select name="epoch" required>
      <?php foreach ($epochs as $e): ?>
        <option value="<?= h($e) ?>"<?= $e === $in['epoch'] ? ' selected' : '' ?>><?= h($e) ?></option>
      <?php endforeach; ?>
      <?php if ($epochs === []): ?><option value="">(run setup.php first)</option><?php endif; ?>
    </select>
  </label>

  <label>Page id
    <span>The page this key opens. Must match the id the page was generated with,
    character for character.</span>
    <input name="page_id" value="<?= h($in['page_id']) ?>" autocomplete="off" required
           maxlength="64">
  </label>

  <label>User name
    <span>Shown in the page header. Blank becomes “<?= h(UNKNOWN) ?>”.</span>
    <input name="name" value="<?= h($in['name']) ?>" autocomplete="off">
  </label>

  <label>User institution
    <span>Shown in the page header. Blank becomes “<?= h(UNKNOWN) ?>”.</span>
    <input name="institution" value="<?= h($in['institution']) ?>" autocomplete="off">
  </label>

  <label>Expiry date (UTC)
    <span>Defaults to two months from now. Use 9999-12-31 for a key that never
    expires. Reported only, unless the page was sealed with --enforce-expiry.</span>
    <input name="exp" type="date" value="<?= h($in['exp']) ?>" lang="en-GB">
  </label>

  <label>Expiry time (UTC, 24-hour)
    <span>Hours and minutes. Defaults to the time of day the key is issued, so a key
    minted at 15:04 expires at 15:04.</span>
    <input name="exp_time" type="time" step="60" value="<?= h($in['exp_time']) ?>"
           lang="en-GB" pattern="([01][0-9]|2[0-3]):[0-5][0-9]" required>
  </label>

  <label>Key id
    <span>For your logs. Not shown on the page. Blank generates a random one.</span>
    <input name="kid" value="<?= h($in['kid']) ?>" autocomplete="off" maxlength="40">
  </label>

  <label>Signing key password
    <span>Chosen when the key store was set up.</span>
    <input name="signing_password" type="password" autocomplete="off" required>
  </label>

  <label>Password for the epoch
    <span>Shown once when the epoch was created.</span>
    <input name="epoch_password" type="password" autocomplete="off" required>
  </label>

  <button type="submit">Issue key</button>
</form>
</section>

<section>
<h2>Create an epoch</h2>
<p class="muted">A new master keypair. Keys issued under other epochs do not open
pages sealed only under it. Its password is generated and shown once.</p>

<?php if ($epochError !== null): ?>
  <p class="err"><?= h($epochError) ?></p>
<?php endif; ?>

<form method="post">
  <input type="hidden" name="action" value="create_epoch">
  <label>Epoch id
    <span>Letters, digits and <code>_ . -</code>, up to 32 characters. Existing:
    <?= $epochs === [] ? 'none' : h(implode(', ', $epochs)) ?>.</span>
    <input name="new_epoch" value="<?= h($newEpoch) ?>" autocomplete="off" required
           maxlength="32" pattern="[A-Za-z0-9_.\-]{1,32}">
  </label>

  <label>Signing key password
    <span>Needed to re-sign the key table with the new epoch in it.</span>
    <input name="signing_password" type="password" autocomplete="off" required>
  </label>

  <button type="submit">Create epoch</button>
  <span class="muted">Takes a few seconds.</span>
</form>
</section>

</body>
</html>
