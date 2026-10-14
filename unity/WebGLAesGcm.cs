// UNTESTED. Written to Unity's WebGL plugin conventions, but never built or run in
// Unity. Treat it as a starting point and verify it before relying on it.
//
// Routes ReportSeal's AES-GCM to the browser's WebCrypto under Unity WebGL, where the
// runtime's own System.Security.Cryptography.AesGcm may be unavailable. Pair it with
// ReportSealAesGcm.jslib, placed in a Plugins folder.
//
// Usage, from a coroutine — the browser answers asynchronously, so the synchronous
// Sealer.Seal refuses this cipher by design:
//
//     var cipher = gameObject.AddComponent<WebGLAesGcm>();
//     var op = Sealer.BeginSeal(bytes, epochs, pageId, signX, signY,
//                               new SealOptions { Cipher = cipher });
//     while (op.MoveNext()) { yield return null; }
//     var fragment = op.Result;

#if UNITY_WEBGL && !UNITY_EDITOR
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using ReportSeal.Sealing;
using UnityEngine;

public sealed class WebGLAesGcm : MonoBehaviour, IAesGcm
{
    [DllImport("__Internal")]
    private static extern void ReportSealAesGcmEncrypt(
        byte[] key, int keyLength,
        byte[] nonce, int nonceLength,
        byte[] plaintext, int plaintextLength,
        byte[] associatedData, int associatedDataLength,
        string objectName, string methodName, int jobId);

    private readonly Dictionary<int, AesGcmJob> pending = new Dictionary<int, AesGcmJob>();
    private int nextId;

    public AesGcmJob Encrypt(byte[] key, byte[] nonce, byte[] plaintext, byte[] associatedData)
    {
        var id = ++nextId;
        var job = new AesGcmJob();
        pending[id] = job;

        // The JavaScript side copies every buffer before returning, because these
        // arrays are only guaranteed to stay put for the duration of this call.
        ReportSealAesGcmEncrypt(
            key, key.Length,
            nonce, nonce.Length,
            plaintext, plaintext.Length,
            associatedData, associatedData.Length,
            gameObject.name, nameof(OnReportSealEncrypted), id);
        return job;
    }

    // Called from JavaScript through SendMessage, which carries a single string:
    // "<id>:OK:<base64 ciphertext and tag>" or "<id>:ERR:<message>".
    public void OnReportSealEncrypted(string message)
    {
        var first = message.IndexOf(':');
        var second = first < 0 ? -1 : message.IndexOf(':', first + 1);
        if (first < 0 || second < 0 || !int.TryParse(message.Substring(0, first), out var id)
            || !pending.TryGetValue(id, out var job))
        {
            Debug.LogError("ReportSeal: unexpected reply from the WebCrypto bridge: " + message);
            return;
        }
        pending.Remove(id);

        var status = message.Substring(first + 1, second - first - 1);
        var body = message.Substring(second + 1);
        if (status == "OK")
        {
            job.Complete(Convert.FromBase64String(body));
        }
        else
        {
            job.Fail(new InvalidOperationException("WebCrypto refused to encrypt: " + body));
        }
    }
}
#endif
