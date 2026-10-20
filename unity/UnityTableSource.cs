// UNTESTED. Written to Unity's conventions, but never built or run in Unity. Treat
// it as a starting point and verify it before relying on it.
//
// Fetches the key table with UnityWebRequest, which works on every Unity platform,
// WebGL included, where HttpClient has no sockets to use. Ships as source rather than
// inside the library: UNITY_* symbols exist only when Unity compiles the file itself.
//
// Usage, from a coroutine — the request answers through a callback, so the
// synchronous PageSealer.Seal refuses this source by design:
//
//     var options = new PageSealOptions { TableSource = new UnityTableSource() };
//     var op = PageSealer.BeginSeal(html, options);
//     while (op.MoveNext()) { yield return null; }
//     var page = op.Result;
//
// On WebGL a file:// location cannot be read, and the request is subject to
// the browser's CORS rules, so serve the table over https from a host that allows it.
// A relative file:// path is resolved against AppContext.BaseDirectory, as everywhere
// else; what that directory is under a Unity player is unverified.

#if UNITY_2020_2_OR_NEWER
using System;
using ReportSeal.Pages;
using UnityEngine.Networking;

public sealed class UnityTableSource : ITableSource
{
    public Pending<string> Fetch(Uri location)
    {
        var pending = new Pending<string>();
        var request = UnityWebRequest.Get(location.AbsoluteUri);
        request.SendWebRequest().completed += _ =>
        {
            try
            {
                if (request.result == UnityWebRequest.Result.Success)
                {
                    pending.Complete(request.downloadHandler.text);
                }
                else
                {
                    pending.Fail(new InvalidOperationException(
                        request.error + (request.responseCode > 0 ? " (HTTP " + request.responseCode + ")" : "")));
                }
            }
            finally
            {
                request.Dispose();
            }
        };
        return pending;
    }
}
#endif
