<?php
/**
 * index.php — key issuing UI. Reads the epoch private key and the issuer signing
 * key, so this must never be reachable from an untrusted network. Start it bound
 * to the loopback interface only:
 *
 *   php -S 127.0.0.1:8080 -t php/web
 *
 * There is deliberately no access control here: anyone who can reach this page can
 * mint a key that opens every sealed page of the selected epoch.
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

$epochs = available_epochs();
$token = null;
$error = null;
$issued = [];
$posted = $_SERVER['REQUEST_METHOD'] === 'POST';

// Sticky values, so a rejected form comes back filled in.
$in = [
    'epoch'       => $posted ? field('epoch', 32) : (end($epochs) ?: ''),
    'page_id'     => field('page_id', 64),
    'name'        => field('name'),
    'institution' => field('institution'),
    'exp'         => $posted ? field('exp', 40) : default_expiry()['date'],
    'exp_time'    => $posted ? field('exp_time', 5) : default_expiry()['time'],
    'kid'         => field('kid', 40),
];

if ($posted) {
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

        $token = mint_token($in['epoch'], $in['page_id'], [
            'kid'         => $kid,
            'exp'         => $exp,
            'name'        => $name,
            'institution' => $institution,
        ]);

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

        // Issuing log. Never records the token itself: that is the decryption key.
        @file_put_contents(
            dirname(__DIR__, 2) . '/keys/issued.log',
            gmdate('c') . "\t" . json_encode([
                'kid'         => $kid,
                'epoch'       => $in['epoch'],
                'page'        => $in['page_id'],
                    'name'        => $name,
                'institution' => $institution,
                'exp'         => normalise_exp($exp),
            ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n",
            FILE_APPEND | LOCK_EX
        );
    } catch (Throwable $e) {
        $error = $e->getMessage();
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
</style>
</head>
<body>

<h1>Issue a decryption key</h1>
<p class="muted">Each key opens exactly one page. A key issued for one page id
cannot open another, and that boundary is cryptographic.</p>

<p class="warn">This page reads the private keys. Keep it on loopback only —
anyone who can load it can mint keys.</p>

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

  <button type="submit">Issue key</button>
</form>

</body>
</html>
