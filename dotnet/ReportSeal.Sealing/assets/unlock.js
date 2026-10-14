(function () {
  "use strict";

  var box = document.getElementById("__ID__");
  if (!box) { return; }

  var d = box.dataset;
  var ct = (box.textContent || "").replace(/\s+/g, "");
  var showAttribution = !("noAttribution" in d);
  var enforceExpiry = "enforceExpiry" in d;
  var enc = new TextEncoder();

  var ui = document.createElement("div");
  ui.innerHTML =
    '<form class="reportseal-form" autocomplete="off">' +
      '<label for="key-__ID__">Decryption key</label>' +
      '<textarea id="key-__ID__" spellcheck="false" ' +
        'placeholder="Paste a key (NO1.…) — any valid key opens this page"></textarea>' +
      '<button type="submit">Unlock</button>' +
      '<p class="reportseal-status" role="status" aria-live="polite"></p>' +
    '</form>' +
    '<p class="reportseal-locked">The remainder of this page is encrypted.</p>' +
    '<p class="reportseal-remembered" hidden>This key is remembered on this device. ' +
      '<button type="button" class="reportseal-forget">Forget key</button></p>' +
    '<p class="reportseal-expiry" role="note" hidden></p>' +
    '<section class="reportseal-content" hidden></section>' +
    '<section class="reportseal-keydata" hidden><h2>Key data</h2><dl></dl></section>';
  box.parentNode.insertBefore(ui, box.nextSibling);

  var form = ui.querySelector(".reportseal-form");
  var input = ui.querySelector("textarea");
  var statusEl = ui.querySelector(".reportseal-status");

  // A demo page may ship with a key already in the box. It still has to pass every
  // check a typed key does; this only saves the paste.
  if (d.debugKey) { input.value = d.debugKey; }

  // Remembering the key. Scoped to this page id so two documents opened from the
  // same machine never pick up each other's key. Every access is guarded: storage
  // can be absent or throw outright, and that must never stop a manual unlock.
  var storeKey = "reportseal/v2/" + d.epochs + "/" + d.page;

  function recall() {
    try { return window.localStorage.getItem(storeKey); } catch (e) { return null; }
  }

  function remember(token) {
    try { window.localStorage.setItem(storeKey, token); return true; } catch (e) { return false; }
  }

  function forget() {
    try { window.localStorage.removeItem(storeKey); } catch (e) { /* nothing to do */ }
  }

  function hasWebCrypto() {
    return !!(window.crypto && window.crypto.subtle);
  }

  function say(msg, cls) {
    statusEl.textContent = msg;
    statusEl.className = "reportseal-status" + (cls ? " " + cls : "");
  }

  function b64uToBytes(s) {
    s = String(s).replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) { s += "="; }
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) { out[i] = bin.charCodeAt(i); }
    return out;
  }

  // Any key issued for this page opens it; a key for another page cannot.
  // Returns { html, payload }.
  async function unlock(token) {
    var m = /^NO1\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/.exec(token.trim());
    if (!m) { throw new Error("That does not look like a key (expected NO1.\u2026.\u2026)."); }
    var p64 = m[1], s64 = m[2];

    // 1. The signature is the only hard gate: it proves the key server issued
    //    this key and that nobody edited its data block.
    var verifyKey = await crypto.subtle.importKey(
      "jwk", { kty: "EC", crv: "P-256", x: d.signX, y: d.signY },
      { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    var sigOk = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" }, verifyKey, b64uToBytes(s64), enc.encode(p64));
    if (!sigOk) { throw new Error("Key rejected: signature is not valid."); }

    var payload = JSON.parse(new TextDecoder().decode(b64uToBytes(p64)));
    if (payload.v !== 2) {
      throw new Error("Key format v" + payload.v + " is not one this page understands.");
    }
    // A page may be sealed under several epochs; a key from any of them opens it.
    // The epoch list and the C1 list are in the same order, so the token's epoch
    // picks which C1 to pair with its element.
    var epochs = String(d.epochs).split("+");
    var slot = epochs.indexOf(payload.epoch);
    if (slot < 0) {
      throw new Error("Key belongs to epoch '" + payload.epoch +
                      "'; this page was sealed under '" + epochs.join("', '") + "'.");
    }
    if (payload.page !== d.page) {
      throw new Error("Key was issued for page '" + payload.page +
                      "'; this page is '" + d.page + "'.");
    }

    // 2. Optionally refuse a key that is past its date. This happens before any
    //    decryption, but it is a courtesy rather than a control: the holder's
    //    element still works, so anyone determined can decrypt without this page.
    if (enforceExpiry && payload.extra && payload.extra.exp) {
      var until = new Date(payload.extra.exp);
      if (!isNaN(until.getTime()) && until.getTime() < Date.now()) {
        var refusal = new Error("This key expired on " + fmt(until) +
                                ", and this page is set to refuse expired keys.");
        refusal.expired = true;
        throw refusal;
      }
    }

    // 3. One pairing recovers the shared value. The key carries this page's
    //    private element, the page carries the generator's ephemeral point, and
    //    e(sk, C1) = e(G1, G2)^k, the value the generator sealed with. An element
    //    issued for another page gives a different result, so the binding is
    //    cryptographic rather than a check that could be patched out.
    var B = window.bls12_381;
    if (!B) { throw new Error("The curve library did not load, so this page cannot be decrypted."); }
    var sk, c1;
    try {
      sk = B.G1.Point.fromBytes(b64uToBytes(payload.sk));
      c1 = B.G2.Point.fromBytes(b64uToBytes(String(d.c1).split("+")[slot]));
    } catch (e) {
      throw new Error("Key rejected: its page element is malformed.");
    }
    var shared = B.fields.Fp12.toBytes(B.pairing(sk, c1));

    // 4. HKDF binds the content key to this epoch and page.
    var ikm = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"]);
    var kBits = await crypto.subtle.deriveBits({
      name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0),
      info: enc.encode("reportseal/v2|" + d.epochs + "|" + d.page)
    }, ikm, 256);
    var key = await crypto.subtle.importKey("raw", kBits, "AES-GCM", false, ["decrypt"]);

    var plain = await crypto.subtle.decrypt({
      name: "AES-GCM", iv: b64uToBytes(d.iv), tagLength: 128,
      additionalData: enc.encode(d.epochs + "|" + d.page)
    }, key, b64uToBytes(ct));

    // 5. The fragment may have been compressed before it was encrypted. That is a
    //    property of the page, not of the key: the same key opens either kind.
    var bytes = new Uint8Array(plain);
    if (d.encoding === "gzip") { bytes = await inflate(bytes); }

    return { html: new TextDecoder().decode(bytes), payload: payload, token: token.trim() };
  }

  async function inflate(bytes) {
    if (typeof DecompressionStream !== "function") {
      throw new Error("This page's content is compressed and this browser cannot " +
                      "decompress it. Chrome 80+, Firefox 113+ or Safari 16.4+ can.");
    }
    var stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("gzip"));
    return new Uint8Array(await new Response(stream).arrayBuffer());
  }

  // Expiry is a signed notice, never a gate: the content has already been
  // decrypted by the time this runs. The banner only appears when something is
  // wrong with the date; the header line carries the normal case. Real withdrawal
  // is done by rotating the epoch keypair, which no issued key can follow.
  function reportExpiry(exp) {
    if (!exp) { return; }
    var el = ui.querySelector(".reportseal-expiry");
    var when = new Date(exp);
    if (isNaN(when.getTime())) {
      el.textContent = "This key carries an expiry value this page cannot read (" +
                       exp + "). The content below was decrypted anyway.";
    } else if (when.getTime() < Date.now()) {
      el.textContent = "This key expired on " + fmt(when) +
                       ". The content below was still decrypted — expiry is a notice only.";
    } else {
      return;
    }
    el.className = "reportseal-expiry expired";
    el.hidden = false;
  }

  // Expiry moments are shown in the reader's own time zone, to minutes. The token
  // carries UTC; only the presentation is local.
  function fmt(dt) {
    function pad(n) { return (n < 10 ? "0" : "") + n; }
    return dt.getFullYear() + "-" + pad(dt.getMonth() + 1) + "-" + pad(dt.getDate()) +
           " " + pad(dt.getHours()) + ":" + pad(dt.getMinutes()) + " " + zone();
  }

  function zone() {
    try {
      var parts = new Intl.DateTimeFormat(undefined, { timeZoneName: "short" })
        .formatToParts(new Date());
      for (var i = 0; i < parts.length; i++) {
        if (parts[i].type === "timeZoneName") { return parts[i].value; }
      }
    } catch (e) { /* fall through */ }
    return "local time";
  }

  // Who the key was issued to, written into the host page's header if it offers a
  // [data-reportseal-attribution] element, otherwise shown above the content. The
  // key id and document id are deliberately left out.
  function attribute(meta) {
    var when = meta.exp ? new Date(meta.exp) : null;
    var line = "Issued to " + (meta.name || "unknown") +
               " · " + (meta.institution || "unknown") +
               " · valid until " +
               (when && !isNaN(when.getTime()) ? fmt(when) : "unknown");

    var target = document.querySelector("[data-reportseal-attribution]");
    if (!target) {
      target = document.createElement("p");
      target.className = "reportseal-attribution";
      ui.insertBefore(target, ui.firstChild);
    }
    target.textContent = line;
    target.hidden = false;
  }

  function reveal(result, fromStore) {
    var content = ui.querySelector(".reportseal-content");
    content.innerHTML = result.html;
    content.hidden = false;
    ui.querySelector(".reportseal-locked").hidden = true;

    // All metadata travels in the token's "extra" block. Three fields have meaning
    // to this page, the key id is the issuer's bookkeeping and is never shown, and
    // anything else is listed underneath the content as-is.
    var meta = result.payload.extra || {};
    reportExpiry(meta.exp);
    if (showAttribution) { attribute(meta); }

    // Keep the key for next time, so this page opens without retyping it.
    var kept = fromStore || remember(result.token);
    if (kept) {
      var note = ui.querySelector(".reportseal-remembered");
      note.hidden = false;
      note.querySelector(".reportseal-forget").addEventListener("click", function () {
        forget();
        location.reload();
      });
    }

    var handled = { name: 1, institution: 1, exp: 1, kid: 1 };
    var dl = ui.querySelector(".reportseal-keydata dl");
    var rows = [];
    Object.keys(meta).forEach(function (k) {
      if (handled[k]) { return; }
      rows.push([k, typeof meta[k] === "object" ? JSON.stringify(meta[k]) : String(meta[k])]);
    });
    rows.forEach(function (row) {
      var dt = document.createElement("dt");
      dt.textContent = row[0];
      var dd = document.createElement("dd");
      dd.textContent = row[1];
      dl.appendChild(dt);
      dl.appendChild(dd);
    });
    ui.querySelector(".reportseal-keydata").hidden = rows.length === 0;

    window.reportseal = { payload: result.payload, extra: meta };
    // Deliberately no key id here: it is for the issuer's logs, not the reader.
    say(fromStore ? "Unlocked with a remembered key." : "Unlocked.", "ok");
    form.hidden = true;
  }

  function fail(err) {
    var msg = err && err.message ? err.message : String(err);
    // AES-GCM failures surface as a bare OperationError.
    if (!msg || err.name === "OperationError") {
      msg = "Key rejected: the encrypted section did not authenticate.";
    }
    say(msg, "err");
  }

  form.addEventListener("submit", function (ev) {
    ev.preventDefault();
    if (!hasWebCrypto()) {
      say("This browser exposes no WebCrypto here, so the page cannot be decrypted.", "err");
      return;
    }
    say("Checking key…");
    unlock(input.value).then(function (r) { reveal(r, false); }).catch(fail);
  });

  // A key remembered from an earlier visit opens the page with no interaction. If
  // it no longer works — the epoch was rotated, or the entry was tampered with —
  // discard it and fall back to the form.
  if (!hasWebCrypto()) {
    say("This browser exposes no WebCrypto here, so the page cannot be decrypted.", "err");
  } else {
    var saved = recall();
    if (saved) {
      say("Unlocking with a remembered key…");
      unlock(saved).then(function (r) { reveal(r, true); }).catch(function (err) {
        if (err && err.expired) {
          // Still a valid key, just past its date: keep it and say so.
          fail(err);
          return;
        }
        forget();
        say("The remembered key no longer opens this page, so it was discarded.", "err");
      });
    }
  }
})();
