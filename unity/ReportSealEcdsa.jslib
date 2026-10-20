// UNTESTED in Unity. The browser half of WebGLEcdsaVerifier.cs; place it in a
// Plugins folder. The function itself is exercised by the test suite against a real
// signed table, with Unity's heap and SendMessage simulated.

mergeInto(LibraryManager.library, {

  ReportSealVerifyEcdsa: function (publicKeyPtr, publicKeyLen, signaturePtr, signatureLen,
                                   dataPtr, dataLen, objectNamePtr, methodNamePtr, jobId) {
    var objectName = UTF8ToString(objectNamePtr);
    var methodName = UTF8ToString(methodNamePtr);

    // Copy now, before anything asynchronous. The pointers are only valid for the
    // duration of this call, and if the WASM heap grows while WebCrypto works, every
    // view onto the old buffer is detached. slice() copies; a plain view would not.
    var publicKey = HEAPU8.slice(publicKeyPtr, publicKeyPtr + publicKeyLen);
    var signature = HEAPU8.slice(signaturePtr, signaturePtr + signatureLen);
    var data      = HEAPU8.slice(dataPtr,      dataPtr      + dataLen);

    function reply(status, value) {
      // SendMessage carries one string, so the job id travels inside it.
      // Assumes the template exposes unityInstance; adjust for your Unity version.
      unityInstance.SendMessage(objectName, methodName, jobId + ":" + status + ":" + value);
    }

    // publicKey is 0x04 || X || Y, WebCrypto's "raw" form for an EC public key, and
    // signature is r || s, which is the form WebCrypto's ECDSA verify expects.
    crypto.subtle.importKey("raw", publicKey, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"])
      .then(function (key) {
        return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, signature, data);
      })
      .then(function (valid) {
        reply("OK", valid ? "true" : "false");
      })
      .catch(function (err) {
        reply("ERR", (err && err.message) ? err.message : String(err));
      });
  }
});
