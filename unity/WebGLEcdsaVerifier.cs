// UNTESTED. Written to Unity's WebGL plugin conventions, but never built or run in
// Unity. Treat it as a starting point and verify it before relying on it.
//
// Routes the key table's signature check to the browser's WebCrypto under Unity
// WebGL, where System.Security.Cryptography.ECDsa may be unavailable. Pair it with
// ReportSealEcdsa.jslib, placed in a Plugins folder. Elsewhere — the editor, desktop
// players — leave PageSealOptions.Verifier null for the runtime's own ECDsa.
//
// WebCrypto answers through a Promise, so the result cannot be returned from the
// DllImport call itself; it comes back through SendMessage, and the sealing operation
// polls for it. That also means the synchronous PageSealer.Seal refuses this verifier.
//
//     var options = new PageSealOptions
//     {
//         TableSource = new UnityTableSource(),
//         Verifier = gameObject.AddComponent<WebGLEcdsaVerifier>(),
//         Cipher = gameObject.AddComponent<WebGLAesGcm>(),
//     };
//     var op = PageSealer.BeginSeal(html, options);
//     while (op.MoveNext()) { yield return null; }

#if UNITY_WEBGL && !UNITY_EDITOR
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using ReportSeal.Pages;
using UnityEngine;

public sealed class WebGLEcdsaVerifier : MonoBehaviour, IEcdsaVerifier
{
    [DllImport("__Internal")]
    private static extern void ReportSealVerifyEcdsa(
        byte[] publicKey, int publicKeyLength,
        byte[] signature, int signatureLength,
        byte[] data, int dataLength,
        string objectName, string methodName, int jobId);

    private readonly Dictionary<int, Pending<bool>> pending = new Dictionary<int, Pending<bool>>();
    private int nextId;

    public Pending<bool> Verify(byte[] publicKey, byte[] signature, byte[] data)
    {
        var id = ++nextId;
        var result = new Pending<bool>();
        pending[id] = result;

        // The JavaScript side copies every buffer before returning, because these
        // arrays are only guaranteed to stay put for the duration of this call.
        ReportSealVerifyEcdsa(
            publicKey, publicKey.Length,
            signature, signature.Length,
            data, data.Length,
            gameObject.name, nameof(OnReportSealVerified), id);
        return result;
    }

    // Called from JavaScript through SendMessage, which carries a single string:
    // "<id>:OK:true", "<id>:OK:false" or "<id>:ERR:<message>".
    public void OnReportSealVerified(string message)
    {
        var first = message.IndexOf(':');
        var second = first < 0 ? -1 : message.IndexOf(':', first + 1);
        if (first < 0 || second < 0 || !int.TryParse(message.Substring(0, first), out var id)
            || !pending.TryGetValue(id, out var result))
        {
            Debug.LogError("ReportSeal: unexpected reply from the WebCrypto bridge: " + message);
            return;
        }
        pending.Remove(id);

        var status = message.Substring(first + 1, second - first - 1);
        var body = message.Substring(second + 1);
        if (status == "OK")
        {
            result.Complete(body == "true");
        }
        else
        {
            result.Fail(new InvalidOperationException("WebCrypto could not verify: " + body));
        }
    }
}
#endif
