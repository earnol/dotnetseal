using System;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace ReportSeal.Pages
{
    /// <summary>
    /// Fetches a key table's text. The location has already been checked and resolved
    /// by <see cref="TableLocation.Resolve"/>, so an implementation sees only
    /// <c>https</c>, <c>http</c> and <c>file</c> URIs. The default is
    /// <see cref="DefaultTableSource"/>; a host whose runtime has no usable
    /// <see cref="HttpClient"/> — Unity WebGL — supplies its own.
    /// </summary>
    public interface ITableSource
    {
        Pending<string> Fetch(Uri location);
    }

    /// <summary>
    /// Checks one ECDSA P-256 / SHA-256 signature. The default is
    /// <see cref="PlatformEcdsaVerifier"/>; Unity WebGL routes it to WebCrypto instead.
    /// </summary>
    public interface IEcdsaVerifier
    {
        /// <param name="publicKey">65 bytes: 0x04, then X and Y, 32 bytes each — WebCrypto's "raw" form.</param>
        /// <param name="signature">64 bytes: r then s, 32 bytes each — WebCrypto's own form.</param>
        /// <param name="data">The signed bytes; hashed with SHA-256 by the verifier.</param>
        /// <returns>True if the signature is valid. An error is for a verifier that could not run.</returns>
        Pending<bool> Verify(byte[] publicKey, byte[] signature, byte[] data);
    }

    /// <summary>Where a marker's <c>Table:</c> value points.</summary>
    public static class TableLocation
    {
        private static readonly Regex Scheme = new Regex("^([A-Za-z][A-Za-z0-9+.-]*):", RegexOptions.CultureInvariant);
        private static readonly Regex DriveAfterSlash = new Regex("^/[A-Za-z]:[/\\\\]", RegexOptions.CultureInvariant);

        private const string FilePrefix = "file://";

        /// <summary>
        /// The location must carry a scheme: <c>https://</c>, <c>http://</c> or
        /// <c>file://</c>. Anything else, a bare path included, is refused.
        ///
        /// After <c>file://</c> comes a path. One starting with <c>/</c>
        /// (<c>file:///srv/keys/epochs.json</c>, <c>file:///C:/keys/epochs.json</c>) is
        /// absolute; any other (<c>file://../keys/epochs.json</c>) is taken from the
        /// directory of the running executable (<see cref="AppContext.BaseDirectory"/>),
        /// not the working directory or the page. Percent-escapes are decoded.
        /// </summary>
        public static Uri Resolve(string location)
        {
            if (string.IsNullOrWhiteSpace(location))
            {
                throw new KeyTableException("the key table location is empty");
            }
            location = location.Trim();

            var scheme = Scheme.Match(location);
            if (!scheme.Success)
            {
                throw new KeyTableException(
                    "the key table location '" + location + "' has no scheme; write https://… for a URL " +
                    "or file://… for a file (a relative file:// path is taken from the executable's directory)");
            }

            var name = scheme.Groups[1].Value.ToLowerInvariant();
            if (name == "file")
            {
                if (!location.StartsWith(FilePrefix, StringComparison.OrdinalIgnoreCase))
                {
                    throw new KeyTableException(
                        "the key table location '" + location + "' should start with file://");
                }
                var path = Uri.UnescapeDataString(location.Substring(FilePrefix.Length));
                if (path.Length == 0)
                {
                    throw new KeyTableException("the key table location '" + location + "' names no file");
                }
                if (DriveAfterSlash.IsMatch(path))
                {
                    path = path.Substring(1); // file:///C:/… on Windows
                }
                var full = path.StartsWith("/", StringComparison.Ordinal) || Path.IsPathRooted(path)
                    ? path
                    : Path.Combine(AppContext.BaseDirectory, path);
                return new Uri(Path.GetFullPath(full));
            }

            if (name != "https" && name != "http")
            {
                throw new KeyTableException(
                    "the key table location '" + location + "' uses '" + name +
                    ":'; only https://, http:// and file:// are accepted");
            }
            if (!Uri.TryCreate(location, UriKind.Absolute, out var uri))
            {
                throw new KeyTableException("the key table location '" + location + "' is not a valid URI");
            }
            return uri;
        }
    }

    /// <summary>
    /// Reads files directly and fetches URLs with <see cref="HttpClient"/>. A fetch
    /// completes on a thread-pool thread, so <see cref="PageSealer.Seal"/> may wait
    /// for it; <see cref="PageSealer.BeginSeal"/> just polls.
    /// </summary>
    public sealed class DefaultTableSource : ITableSource
    {
        public static readonly DefaultTableSource Instance = new DefaultTableSource();

        private static readonly Lazy<HttpClient> Client = new Lazy<HttpClient>(
            () => new HttpClient { Timeout = TimeSpan.FromSeconds(30) });

        private DefaultTableSource() { }

        public Pending<string> Fetch(Uri location)
        {
            if (location.IsFile)
            {
                try
                {
                    return Pending<string>.Completed(File.ReadAllText(location.LocalPath));
                }
                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
                {
                    return Pending<string>.Failed(ex);
                }
            }
            return Pending<string>.FromTask(Client.Value.GetStringAsync(location));
        }
    }

    /// <summary>
    /// The runtime's own ECDSA. Finishes synchronously. Supported on .NET Core 3.0+ and
    /// .NET 5+; unverified on Mono and Unity outside WebGL.
    /// </summary>
    public sealed class PlatformEcdsaVerifier : IEcdsaVerifier
    {
        public static readonly PlatformEcdsaVerifier Instance = new PlatformEcdsaVerifier();

        private PlatformEcdsaVerifier() { }

        public Pending<bool> Verify(byte[] publicKey, byte[] signature, byte[] data)
        {
            try
            {
                var x = new byte[32];
                var y = new byte[32];
                Array.Copy(publicKey, 1, x, 0, 32);
                Array.Copy(publicKey, 33, y, 0, 32);
                using (var ecdsa = ECDsa.Create(new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    Q = new ECPoint { X = x, Y = y },
                }))
                {
                    // the base class takes r||s, the same fixed-width form WebCrypto uses
                    return Pending<bool>.Completed(ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256));
                }
            }
            catch (CryptographicException ex)
            {
                return Pending<bool>.Failed(ex);
            }
        }
    }
}
