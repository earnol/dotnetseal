// UNTESTED. The browser half of WebGLAesGcm.cs; place it in a Plugins folder.
//
// Encryption only. ReportSeal never decrypts on the generating side — sealed pages
// carry their own unlock code — so no decrypt function is needed here.

mergeInto(LibraryManager.library, {

  ReportSealAesGcmEncrypt: function (keyPtr, keyLen, noncePtr, nonceLen,
                                     plainPtr, plainLen, aadPtr, aadLen,
                                     objectNamePtr, methodNamePtr, jobId) {
    var objectName = UTF8ToString(objectNamePtr);
    var methodName = UTF8ToString(methodNamePtr);

    // Copy now, before anything asynchronous. The pointers are only valid for the
    // duration of this call, and if the WASM heap grows while WebCrypto works, every
    // view onto the old buffer is detached. slice() copies; a plain view would not.
    var key   = HEAPU8.slice(keyPtr,   keyPtr   + keyLen);
    var nonce = HEAPU8.slice(noncePtr, noncePtr + nonceLen);
    var plain = HEAPU8.slice(plainPtr, plainPtr + plainLen);
    var aad   = HEAPU8.slice(aadPtr,   aadPtr   + aadLen);

    function reply(status, value) {
      // SendMessage carries one string, so the job id travels inside it.
      // Assumes the template exposes unityInstance; adjust for your Unity version.
      unityInstance.SendMessage(objectName, methodName, jobId + ":" + status + ":" + value);
    }

    // btoa over String.fromCharCode.apply(null, bytes) passes every byte as an argument,
    // which overflows the engine's argument limit on a large fragment. Chunked instead.
    function toBase64(bytes) {
      var text = "";
      for (var i = 0; i < bytes.length; i += 0x8000) {
        text += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
      }
      return btoa(text);
    }

    crypto.subtle.importKey("raw", key, { name: "AES-GCM" }, false, ["encrypt"])
      .then(function (cryptoKey) {
        // additionalData is required: the page decrypts with the same value, and
        // ciphertext produced without it can never be opened.
        return crypto.subtle.encrypt(
          { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 },
          cryptoKey, plain);
      })
      .then(function (buffer) {
        // WebCrypto appends the 16-byte tag, which is the layout ReportSeal expects.
        reply("OK", toBase64(new Uint8Array(buffer)));
      })
      .catch(function (err) {
        reply("ERR", (err && err.message) ? err.message : String(err));
      });
  }
});
