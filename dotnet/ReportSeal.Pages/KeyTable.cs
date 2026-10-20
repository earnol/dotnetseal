using System;
using System.Collections.Generic;
using System.Text;
using ReportSeal.Sealing;

namespace ReportSeal.Pages
{
    /// <summary>Raised when the key table cannot be read, is malformed, or fails its signature.</summary>
    public sealed class KeyTableException : Exception
    {
        public KeyTableException(string message) : base(message) { }

        public KeyTableException(string message, Exception inner) : base(message, inner) { }
    }

    /// <summary>
    /// A published key table whose signature has been checked: the epochs it offers and
    /// the key that verifies tokens.
    ///
    /// The signature covers the whole table except the <c>signature</c> member: remove
    /// that member, write the rest as RFC 8785 canonical JSON, and verify
    /// ECDSA-P256-SHA256 over those bytes with the table's own <c>signpublic</c> key.
    /// php/lib/reportseal.php produces the same bytes, which is what lets the two agree
    /// however the file is laid out. An unsigned table is refused.
    ///
    /// Checking against the key inside the table proves the table is intact and was
    /// signed by whoever holds that key. It does not prove who that is; transport
    /// security has to.
    /// </summary>
    public sealed class KeyTable
    {
        private KeyTable(Uri location, EpochKey[] epochs, string signX, string signY)
        {
            Location = location;
            Epochs = epochs;
            SignX = signX;
            SignY = signY;
        }

        public Uri Location { get; }

        public IReadOnlyList<EpochKey> Epochs { get; }

        /// <summary>Token verification key X, base64url.</summary>
        public string SignX { get; }

        /// <summary>Token verification key Y, base64url.</summary>
        public string SignY { get; }

        /// <summary>A table that is well formed but whose signature is still to be checked.</summary>
        internal sealed class Unverified
        {
            public KeyTable Table;
            public byte[] SignedBytes;
            public byte[] PublicKey;
            public byte[] Signature;
        }

        internal static Unverified Read(string json, Uri location)
        {
            object root;
            try
            {
                root = CanonicalJson.Parse(json);
            }
            catch (FormatException ex)
            {
                throw Problem(location, "is not valid JSON: " + ex.Message);
            }
            var table = root as Dictionary<string, object>
                ?? throw Problem(location, "is not a JSON object");

            if (!table.TryGetValue("version", out var version) || !(version is long v) || v != 2)
            {
                throw Problem(location, "is not a version 2 key table");
            }
            if (!table.TryGetValue("signature", out var signatureValue))
            {
                throw Problem(location, "is not signed; republish it with php/setup.php --publish");
            }
            var signature = Bytes(location, signatureValue, 64, "signature");

            var signpublic = table.TryGetValue("signpublic", out var sp) ? sp as Dictionary<string, object> : null;
            if (signpublic == null)
            {
                throw Problem(location, "has no signpublic key");
            }
            signpublic.TryGetValue("x", out var xValue);
            signpublic.TryGetValue("y", out var yValue);
            var x = Bytes(location, xValue, 32, "signpublic.x");
            var y = Bytes(location, yValue, 32, "signpublic.y");

            var published = table.TryGetValue("epochs", out var ep) ? ep as Dictionary<string, object> : null;
            if (published == null || published.Count == 0)
            {
                throw Problem(location, "publishes no epochs");
            }
            var epochs = new List<EpochKey>();
            var names = new List<string>(published.Keys);
            names.Sort(string.CompareOrdinal);
            foreach (var name in names)
            {
                var key = Bytes(location, published[name], 96, "epochs." + name);
                try
                {
                    epochs.Add(new EpochKey(name, key));
                }
                catch (ArgumentException ex)
                {
                    throw Problem(location, "has an unusable epoch '" + name + "': " + ex.Message);
                }
            }

            var unsigned = new Dictionary<string, object>(table, StringComparer.Ordinal);
            unsigned.Remove("signature");

            var publicKey = new byte[65];
            publicKey[0] = 0x04;
            Array.Copy(x, 0, publicKey, 1, 32);
            Array.Copy(y, 0, publicKey, 33, 32);

            return new Unverified
            {
                Table = new KeyTable(location, epochs.ToArray(), (string)xValue, (string)yValue),
                SignedBytes = Encoding.UTF8.GetBytes(CanonicalJson.Write(unsigned)),
                PublicKey = publicKey,
                Signature = signature,
            };
        }

        internal static KeyTableException Problem(Uri location, string what) =>
            new KeyTableException("the key table at " + Describe(location) + " " + what);

        internal static string Describe(Uri location) => location.IsFile ? location.LocalPath : location.AbsoluteUri;

        private static byte[] Bytes(Uri location, object value, int length, string member)
        {
            if (!(value is string text))
            {
                throw Problem(location, "has no " + member);
            }
            byte[] bytes;
            try
            {
                bytes = Base64Url.Decode(text);
            }
            catch (FormatException)
            {
                throw Problem(location, "has a " + member + " that is not base64url");
            }
            if (bytes.Length != length)
            {
                throw Problem(location, "has a " + member + " of " + bytes.Length + " bytes; expected " + length);
            }
            return bytes;
        }
    }
}
