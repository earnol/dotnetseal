(function () {
  "use strict";

  var sealed = document.querySelectorAll("[data-reportseal]");
  if (!sealed.length) { return; }

  var enc = new TextEncoder();
  var dec = new TextDecoder();

  // Fragments are grouped by the epoch set and page id they were sealed under, so
  // one key entry serves every fragment it can actually open. A page whose
  // fragments all share a page id therefore shows a single box.
  var groups = [];
  var byKey = {};
  for (var i = 0; i < sealed.length; i++) {
    var el = sealed[i];
    var id = el.dataset.epochs + "|" + el.dataset.page;
    if (!byKey[id]) {
      byKey[id] = { epochs: el.dataset.epochs, page: el.dataset.page, items: [], ui: null };
      groups.push(byKey[id]);
    }
    byKey[id].items.push(el);
  }

  // A page may supply its own controls instead of letting the script build them.
  // A hook is claimed by the group whose page id it names; an unnamed hook belongs
  // to whichever group asks first, which is unambiguous on a single-group page.
  function claim(name, group) {
    var all = document.querySelectorAll("[data-reportseal-" + name + "]");
    for (var i = 0; i < all.length; i++) {
      if (all[i].reportsealClaimed) { continue; }
      var want = (all[i].getAttribute("data-reportseal-" + name) || "").trim();
      if (want === "" || want === group.page) {
        all[i].reportsealClaimed = true;
        return all[i];
      }
    }
    return null;
  }

  function claimAll(name, group) {
    var found = [], one;
    while ((one = claim(name, group)) !== null) { found.push(one); }
    return found;
  }

  function hasWebCrypto() {
    return !!(window.crypto && window.crypto.subtle);
  }

  function b64uToBytes(s) {
    s = String(s).replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) { s += "="; }
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var j = 0; j < bin.length; j++) { out[j] = bin.charCodeAt(j); }
    return out;
  }

  async function inflate(bytes) {
    if (typeof DecompressionStream !== "function") {
      throw new Error("This page's content is compressed and this browser cannot " +
                      "decompress it. Chrome 80+, Firefox 113+ or Safari 16.4+ can.");
    }
    var stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("gzip"));
    return new Uint8Array(await new Response(stream).arrayBuffer());
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
      for (var k = 0; k < parts.length; k++) {
        if (parts[k].type === "timeZoneName") { return parts[k].value; }
      }
    } catch (e) { /* fall through */ }
    return "local time";
  }

  // ---------------------------------------------------------------- per group UI

  function buildUi(group, index) {
    group.input = claim("key", group);
    group.statusEl = claim("status", group);
    group.button = claim("unlock", group);
    group.attribution = claimAll("attribution", group);

    // Only the missing pieces are generated, so a page can hand over as much or as
    // little of the furniture as it likes.
    var inputId = "reportseal-key-" + index;
    var parts = [];
    if (!group.input) {
      parts.push(
        '<form class="reportseal-form" autocomplete="off">' +
          '<label for="' + inputId + '">Decryption key</label>' +
          '<textarea id="' + inputId + '" spellcheck="false" ' +
            'placeholder="Paste a key (NO1.…) — any valid key opens this page"></textarea>' +
          '<button type="submit">Unlock</button>' +
          (group.statusEl ? "" :
            '<p class="reportseal-status" role="status" aria-live="polite"></p>') +
        '</form>');
    } else if (!group.statusEl) {
      parts.push('<p class="reportseal-status" role="status" aria-live="polite"></p>');
    }
    parts.push('<p class="reportseal-locked">The remainder of this page is encrypted.</p>');
    parts.push('<p class="reportseal-remembered" hidden>This key is remembered on this ' +
               'device. <button type="button" class="reportseal-forget">Forget key</button></p>');
    parts.push('<p class="reportseal-expiry" role="note" hidden></p>');

    var ui = document.createElement("div");
    ui.innerHTML = parts.join("");
    var first = group.items[0];
    first.parentNode.insertBefore(ui, first);
    group.ui = ui;

    if (!group.input) {
      group.input = ui.querySelector("textarea");
      group.form = ui.querySelector(".reportseal-form");
    } else {
      group.form = group.input.form;
    }
    if (!group.statusEl) { group.statusEl = ui.querySelector(".reportseal-status"); }
    if (!group.form && !group.button) {
      // an entry box was supplied with nothing to submit it; give it a button
      var fallback = document.createElement("button");
      fallback.type = "button";
      fallback.textContent = "Unlock";
      group.input.parentNode.insertBefore(fallback, group.input.nextSibling);
      group.button = fallback;
    }
    return ui;
  }

  // A host-supplied element keeps whatever classes the page gave it; only the
  // state classes are toggled.
  function say(group, msg, cls) {
    group.statusEl.textContent = msg;
    group.statusEl.classList.remove("ok", "err");
    group.statusEl.classList.add("reportseal-status");
    if (cls) { group.statusEl.classList.add(cls); }
  }

  // Remembering the key, scoped to the epoch set and page id so two documents
  // opened from the same machine never pick up each other's key. Every access is
  // guarded: storage can be absent or throw, and that must never stop an unlock.
  function storeKey(group) {
    return "reportseal/v2/" + group.epochs + "/" + group.page;
  }

  function recall(group) {
    try { return window.localStorage.getItem(storeKey(group)); } catch (e) { return null; }
  }

  function remember(group, token) {
    try { window.localStorage.setItem(storeKey(group), token); return true; }
    catch (e) { return false; }
  }

  function forget(group) {
    try { window.localStorage.removeItem(storeKey(group)); } catch (e) { /* nothing to do */ }
  }

  // ------------------------------------------------------------------- unlocking

  // Checks the token itself: signature first, then that it is for this group.
  // Returns the parsed payload and the slot its epoch occupies in the page's list.
  async function checkToken(group, token) {
    var m = /^NO1\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/.exec(token.trim());
    if (!m) { throw new Error("That does not look like a key (expected NO1.….…)."); }
    var p64 = m[1], s64 = m[2];
    var first = group.items[0];

    // The signature is the only hard gate: it proves the key server issued this
    // key and that nobody edited its data block.
    var verifyKey = await crypto.subtle.importKey(
      "jwk", { kty: "EC", crv: "P-256", x: first.dataset.signX, y: first.dataset.signY },
      { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    var sigOk = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" }, verifyKey, b64uToBytes(s64), enc.encode(p64));
    if (!sigOk) { throw new Error("Key rejected: signature is not valid."); }

    var payload = JSON.parse(dec.decode(b64uToBytes(p64)));
    if (payload.v !== 2) {
      throw new Error("Key format v" + payload.v + " is not one this page understands.");
    }
    var epochs = String(group.epochs).split("+");
    var slot = epochs.indexOf(payload.epoch);
    if (slot < 0) {
      throw new Error("Key belongs to epoch '" + payload.epoch +
                      "'; this page was sealed under '" + epochs.join("', '") + "'.");
    }
    if (payload.page !== group.page) {
      throw new Error("Key was issued for page '" + payload.page +
                      "'; this page is '" + group.page + "'.");
    }

    return { payload: payload, slot: slot };
  }

  // One fragment: one pairing, then HKDF and AES-GCM. Each fragment carries its own
  // ephemeral point and IV, so this runs per fragment even for a shared key.
  async function openFragment(el, payload, slot) {
    var B = window.bls12_381;
    if (!B) { throw new Error("The curve library did not load, so this page cannot be decrypted."); }

    var sk, c1;
    try {
      sk = B.G1.Point.fromBytes(b64uToBytes(payload.sk));
      c1 = B.G2.Point.fromBytes(b64uToBytes(String(el.dataset.c1).split("+")[slot]));
    } catch (e) {
      throw new Error("Key rejected: its page element is malformed.");
    }
    var shared = B.fields.Fp12.toBytes(B.pairing(sk, c1));

    var ikm = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"]);
    var kBits = await crypto.subtle.deriveBits({
      name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0),
      info: enc.encode("reportseal/v2|" + el.dataset.epochs + "|" + el.dataset.page)
    }, ikm, 256);
    var key = await crypto.subtle.importKey("raw", kBits, "AES-GCM", false, ["decrypt"]);

    var plain = await crypto.subtle.decrypt({
      name: "AES-GCM", iv: b64uToBytes(el.dataset.iv), tagLength: 128,
      additionalData: enc.encode(el.dataset.epochs + "|" + el.dataset.page)
    }, key, b64uToBytes((el.textContent || "").replace(/\s+/g, "")));

    var bytes = new Uint8Array(plain);
    if (el.dataset.encoding === "gzip") { bytes = await inflate(bytes); }
    return dec.decode(bytes);
  }

  function reveal(el, html) {
    var section = document.createElement("section");
    section.className = "reportseal-content";
    section.innerHTML = html;
    el.parentNode.insertBefore(section, el.nextSibling);
    el.setAttribute("data-reportseal-open", "");
  }

  // Expiry notice and attribution are page level: with several groups the last
  // unlock wins, which is fine.
  function reportExpiry(group, exp) {
    if (!exp) { return; }
    var el = group.ui.querySelector(".reportseal-expiry");
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
    el.classList.add("reportseal-expiry", "expired");
    el.hidden = false;
  }

  // Values a page may interpolate with $$reportseal-token$$. Beyond these,
  // $$reportseal-extra:KEY$$ reaches any field the issuer put in the key. The
  // prefix keeps a page's own $$...$$ text out of the way, and an unknown token is
  // left as it stands so a typo is visible rather than silently blank.
  function tokenValue(name, group, payload, meta) {
    if (name === "page") { return group.page; }
    if (name === "epoch") { return payload.epoch; }
    if (name === "exp") {
      var when = meta.exp ? new Date(meta.exp) : null;
      return when && !isNaN(when.getTime()) ? fmt(when) : "unknown";
    }
    if (name.indexOf("extra:") === 0) {
      var key = name.slice(6);
      return key in meta ? String(meta[key]) : "unknown";
    }
    if (name in meta) { return String(meta[name]); }
    return null;
  }

  // Substitution happens in text nodes, never through innerHTML, so a value can
  // never bring markup of its own into the page.
  function substitute(root, group, payload, meta) {
    var walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null, false);
    var nodes = [], node;
    while ((node = walker.nextNode()) !== null) { nodes.push(node); }
    var found = false;
    nodes.forEach(function (text) {
      if (text.nodeValue.indexOf("$$reportseal-") < 0) { return; }
      text.nodeValue = text.nodeValue.replace(/\$\$reportseal-([A-Za-z0-9_.:-]+)\$\$/g,
        function (whole, name) {
          var value = tokenValue(name, group, payload, meta);
          if (value === null) { return whole; }
          found = true;
          return value;
        });
    });
    return found;
  }

  function attribute(group, meta, payload) {
    var first = group.items[0];
    if (first.hasAttribute("data-no-attribution")) { return; }

    var when = meta.exp ? new Date(meta.exp) : null;
    var line = "Issued to " + (meta.name || "unknown") +
               " · " + (meta.institution || "unknown") +
               " · valid until " +
               (when && !isNaN(when.getTime()) ? fmt(when) : "unknown");

    if (group.attribution.length) {
      // The page owns the wording. Where it wrote $$tokens$$ those are filled in;
      // where it left the element empty it gets the default line.
      group.attribution.forEach(function (target) {
        if (!substitute(target, group, payload, meta) && !target.textContent.trim()) {
          target.textContent = line;
        }
        target.hidden = false;
      });
      return;
    }

    var generated = document.createElement("p");
    generated.className = "reportseal-attribution";
    generated.textContent = line;
    group.ui.insertBefore(generated, group.ui.firstChild);
  }

  function keyData(group, meta) {
    var handled = { name: 1, institution: 1, exp: 1, kid: 1 };
    var rows = Object.keys(meta).filter(function (k) { return !handled[k]; });
    if (!rows.length) { return; }
    var section = document.createElement("section");
    section.className = "reportseal-keydata";
    section.innerHTML = "<h2>Key data</h2><dl></dl>";
    var dl = section.querySelector("dl");
    rows.forEach(function (k) {
      var dt = document.createElement("dt");
      dt.textContent = k;
      var dd = document.createElement("dd");
      dd.textContent = typeof meta[k] === "object" ? JSON.stringify(meta[k]) : String(meta[k]);
      dl.appendChild(dt);
      dl.appendChild(dd);
    });
    group.ui.parentNode.appendChild(section);
  }

  // Each fragment decides for itself whether an expired key is enough, so one key
  // can open some regions of a page and be turned away by others. A courtesy rather
  // than a control either way: the holder's element still works, so anyone
  // determined can decrypt without this page.
  function expiredFor(el, payload) {
    if (!el.hasAttribute("data-enforce-expiry")) { return false; }
    var exp = payload.extra && payload.extra.exp;
    if (!exp) { return false; }
    var until = new Date(exp);
    return !isNaN(until.getTime()) && until.getTime() < Date.now();
  }

  async function unlockGroup(group, token, fromStore) {
    var checked = await checkToken(group, token);
    var opened = [];
    var refused = 0;
    for (var n = 0; n < group.items.length; n++) {
      if (expiredFor(group.items[n], checked.payload)) {
        opened.push(null);
        refused++;
        continue;
      }
      opened.push(await openFragment(group.items[n], checked.payload, checked.slot));
    }

    if (refused === group.items.length) {
      var until = new Date(checked.payload.extra.exp);
      var all = new Error("This key expired on " + fmt(until) +
                          ", and this page is set to refuse expired keys.");
      all.expired = true;
      throw all;
    }

    for (var m = 0; m < opened.length; m++) {
      if (opened[m] !== null) { reveal(group.items[m], opened[m]); }
    }

    var meta = checked.payload.extra || {};
    reportExpiry(group, meta.exp);
    attribute(group, meta, checked.payload);
    keyData(group, meta);
    group.ui.querySelector(".reportseal-locked").hidden = true;

    var kept = fromStore || remember(group, token.trim());
    if (kept) {
      var note = group.ui.querySelector(".reportseal-remembered");
      note.hidden = false;
      note.querySelector(".reportseal-forget").addEventListener("click", function () {
        forget(group);
        location.reload();
      });
    }

    window.reportseal = { payload: checked.payload, extra: meta };
    var head = fromStore ? "Unlocked with a remembered key." : "Unlocked.";
    var detail = "";
    if (group.items.length > 1 || refused) {
      detail = " " + (group.items.length - refused) + " of " + group.items.length +
               " sections unlocked.";
    }
    if (refused) {
      detail += " " + refused + (refused === 1 ? " section refuses" : " sections refuse") +
                " expired keys.";
    }
    say(group, head + detail, "ok");
    if (group.form) { group.form.hidden = true; }
    else if (group.input) { group.input.hidden = true; if (group.button) { group.button.hidden = true; } }
  }

  function fail(group, err) {
    var msg = err && err.message ? err.message : String(err);
    // AES-GCM failures surface as a bare OperationError.
    if (!msg || err.name === "OperationError") {
      msg = "Key rejected: the encrypted section did not authenticate.";
    }
    say(group, msg, "err");
  }

  groups.forEach(function (group, index) {
    buildUi(group, index);

    function submitted(ev) {
      if (ev) { ev.preventDefault(); }
      if (!hasWebCrypto()) {
        say(group, "This browser exposes no WebCrypto here, so the page cannot be decrypted.", "err");
        return;
      }
      say(group, "Checking key…");
      unlockGroup(group, group.input.value, false).catch(function (err) { fail(group, err); });
    }

    if (group.form) { group.form.addEventListener("submit", submitted); }
    if (group.button) { group.button.addEventListener("click", submitted); }

    // A demo page may ship with a key already in the box. It still has to pass
    // every check a typed key does; this only saves the paste.
    var debugKey = group.items[0].dataset.debugKey;
    if (debugKey) { group.input.value = debugKey; }

    if (!hasWebCrypto()) {
      say(group, "This browser exposes no WebCrypto here, so the page cannot be decrypted.", "err");
      return;
    }

    // A key remembered from an earlier visit opens the page with no interaction. If
    // it no longer works the entry form comes back; an expired key is kept, since
    // it is still a valid key the page is declining.
    var saved = recall(group);
    if (saved) {
      say(group, "Unlocking with a remembered key…");
      unlockGroup(group, saved, true).catch(function (err) {
        if (err && err.expired) { fail(group, err); return; }
        forget(group);
        say(group, "The remembered key no longer opens this page, so it was discarded.", "err");
      });
    }
  });
})();
