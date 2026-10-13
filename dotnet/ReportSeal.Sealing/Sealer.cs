using System;
using System.Collections;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using Neo.Cryptography.BLS12_381;

namespace ReportSeal.Sealing
{
    /// <summary>
    /// The three page parts produced by <see cref="Sealer.Seal"/>. The caller drops
    /// them into a page of its own making: <see cref="Styles"/> in a style element,
    /// <see cref="Markup"/> anywhere in the body, <see cref="Script"/> in a script
    /// element after it.
    /// </summary>
    public sealed class SealedFragment
    {
        internal SealedFragment(string elementId, string markup, string styles, string script)
        {
            ElementId = elementId;
            Markup = markup;
            Styles = styles;
            Script = script;
        }

        /// <summary>Random id of the hidden element, regenerated for every page.</summary>
        public string ElementId { get; }

        /// <summary>Hidden div holding the ciphertext, with the public unlock values as data attributes.</summary>
        public string Markup { get; }

        /// <summary>CSS for the unlock UI, without a style element around it.</summary>
        public string Styles { get; }

        /// <summary>Unlock code, without a script element around it.</summary>
        public string Script { get; }
    }

    /// <summary>How the sealed page should behave once a key opens it.</summary>
    public sealed class SealOptions
    {
        /// <summary>
        /// Print "Issued to &lt;name&gt; · &lt;institution&gt; · valid until &lt;date&gt;"
        /// once the page unlocks. On by default.
        /// </summary>
        public bool ShowAttribution { get; set; } = true;

        /// <summary>
        /// Gzip the fragment before encrypting it. On by default: HTML compresses
        /// 5-7x, and since the ciphertext is base64 in the page, every byte removed
        /// before encryption saves 1.33 in the file.
        ///
        /// This is independent of the key. Compression happens inside the encrypted
        /// payload, so a token carries no knowledge of it and the same token opens a
        /// compressed and an uncompressed page alike; the page says which it is.
        ///
        /// Turning it off widens browser support: decompression needs Chrome 80+,
        /// Firefox 113+ or Safari 16.4+, whereas everything else the page does works
        /// in far older engines.
        /// </summary>
        public bool Compress { get; set; } = true;

        /// <summary>
        /// Refuse to reveal the content when the key's expiry date has passed,
        /// instead of decrypting and noting it. Off by default.
        ///
        /// This is a courtesy, not a control. The holder's key still works: they
        /// can decrypt the fragment with the element in their token and never load
        /// this page. Anyone who wants the content past the date will get it, so
        /// treat this as a way of communicating intent to honest readers. Rotating
        /// the epoch is the only real withdrawal.
        /// </summary>
        public bool EnforceExpiry { get; set; }
    }

    /// <summary>
    /// Seals a fragment to one page id under one epoch's *public* key, using
    /// Sakai-Kasahara identity-based encryption over BLS12-381.
    ///
    /// The generator holds no secret: the epoch public key is enough to seal, and
    /// only the issuer's master scalar can produce the element that opens a page.
    /// Because that element is tied to the page's identity, a key for one page
    /// cannot be turned into a key for another.
    ///
    /// Sealing needs no pairing — the shared value is the fixed constant
    /// e(G1, G2) raised to the ephemeral scalar, which the browser recovers with a
    /// single pairing against its page element.
    ///
    /// <para><b>Cost and scheduling.</b> Sealing is CPU-bound and took 43-68 ms on
    /// the machine this was built on, nearly all of it in three group operations —
    /// run ReportSeal.SelfTest for the figures on yours. <see cref="Seal"/> does
    /// the lot in one call. Where blocking for that long is not acceptable — a game
    /// loop, or any single-threaded host such as Unity WebGL — use
    /// <see cref="BeginSeal"/>, which returns an <see cref="IEnumerator"/> that
    /// performs one step per <c>MoveNext</c> and can be driven a frame at a time:</para>
    ///
    /// <code>
    /// var op = Sealer.BeginSeal(bytes, epoch, pageId, mpk, x, y);
    /// while (op.MoveNext()) { yield return null; }   // one slice per frame
    /// var fragment = op.Result;
    /// </code>
    ///
    /// <para>The heaviest single slice is the Gt exponentiation, 17-27 ms measured,
    /// so this bounds a stall at roughly one frame rather than three or four. Going
    /// finer would mean driving the scalar ladders step by step ourselves, which the
    /// underlying library does not expose.</para>
    ///
    /// <para>This type is thread-safe and has no thread affinity, so hosts that do
    /// have threads can simply offload the whole of <see cref="Seal"/> instead.
    /// There is no asynchronous overload on purpose: nothing here waits on I/O, so
    /// one would allocate a state machine and free no thread.</para>
    /// </summary>
    public static class Sealer
    {
        /// <summary>Domain tag for the page identity. PHP and the browser use the same string.</summary>
        private const string IdentityTag = "reportseal/v2|";

        /// <summary>
        /// e(G1, G2), the value every sealing raises to its ephemeral scalar. It
        /// depends only on the curve generators, so it is a fixed public constant
        /// rather than something to compute at startup: embedding it keeps the first
        /// seal as quick as the thousandth, and removes the only pairing this side
        /// would otherwise perform. ReportSeal.SelfTest asserts it still equals
        /// Bls12.Pairing(G1Affine.Generator, G2Affine.Generator).
        /// </summary>
        private const string PairingConstantBase64 =
            "D0HlhmO/CM8GhnLL0Bp+xzuspNcsqTVE3v9oa/1t9UPUjqokr+R+Hv3kSTg7Z2YxBMWBI00IapkCJJtkco/9IaGJ6Hk1" +
            "qVQFHHzbp7OHJimk+vwFBmJFy5EI8CQtD+PvAzUPVaeu/NPDG0/LbOV3HMag6XhqtZczIMgGrTYIKRB7qBDFoJ/92b4i" +
            "kaDCWpmiEbi0JM1Ivzj872gIOwsOxcgak7Mw7hpnfQ0V/3uYTol470iIHjL6yRuTtHMz4rpXBvuiPrfFrw2fgJQMp3G2" +
            "/9WFe6ryIuuVp9KAnWG/4C4b/Rto/wLwuBAq4cLV1asaGfJjN9IF+0ac1r0Vw9WgTciHhPuz0LLb3qVNQ7K3Pyy7EtWD" +
            "hqhwPg+UgibkfuidAYEHFU8lp2S9PHmTekW4RUbaY0uPa+FKgGHlXM66R4sj99rKo1yMp4vq6WJARbS2AbL1Ikc9FxOR" +
            "EluoTcQAfPvy+Np1L3x0GFID/MpYmscZw03/u6rYQx2tHB+1l6qlGTUCuG7biFfCc/oHWlBRKTfgeU4eZadhfJDYvWYG" +
            "Wx//5R16V5lzsTFQIew8GZNPE2i7RFx8LSCXA/I5aJzjTAN4po5yprOyFtoOIqUDG1Td/1cwk5azjIgcTISewj6HCJoc" +
            "W0blEQuGdQ7GpTI0iGioQEVIPJK3r1r2iUUur6vxqJQ+UEOfHVmIKpjqoBcPElDr2HH8CpKnstgxaNDXJyctRBvvoVxQ" +
            "PdjpDOmNs+e20ZT2CDnFCKhDBarKF4m2";

        private static readonly Gt PairingConstant =
            Gt.FromBytes(Convert.FromBase64String(PairingConstantBase64));

        /// <param name="plaintext">The hidden fragment, as UTF-8 HTML.</param>
        /// <param name="epoch">Epoch id, mixed into the key derivation and the AEAD tag.</param>
        /// <param name="pageId">Assigned page id; the identity a key must match.</param>
        /// <param name="masterPublicKey">The epoch's public half, 96 compressed bytes.</param>
        /// <param name="signX">Signature verification key X, base64url, from the key table.</param>
        /// <param name="signY">Signature verification key Y, base64url, from the key table.</param>
        /// <param name="options">Page behaviour; defaults to attribution shown, expiry not enforced.</param>
        public static SealedFragment Seal(
            byte[] plaintext,
            string epoch,
            string pageId,
            byte[] masterPublicKey,
            string signX,
            string signY,
            SealOptions options = null)
        {
            return SealInternal(plaintext, epoch, pageId, masterPublicKey, signX, signY, options, null);
        }

        /// <summary>
        /// Begins a sealing operation without doing any of the work. Each
        /// <c>MoveNext</c> performs one step and returns true while more remain;
        /// <see cref="SealOperation.Result"/> is set once it returns false.
        /// Arguments are validated here, so mistakes surface immediately rather
        /// than on the first step.
        /// </summary>
        /// <inheritdoc cref="Seal" path="/param"/>
        public static SealOperation BeginSeal(
            byte[] plaintext,
            string epoch,
            string pageId,
            byte[] masterPublicKey,
            string signX,
            string signY,
            SealOptions options = null)
        {
            return BeginSealInternal(plaintext, epoch, pageId, masterPublicKey, signX, signY, options, null);
        }

        /// <summary>
        /// One-shot sealing with the debug seam. <see cref="Seal"/> is this with a
        /// null <paramref name="debugToken"/>.
        /// </summary>
        /// <inheritdoc cref="BeginSealInternal" path="/param"/>
        internal static SealedFragment SealInternal(
            byte[] plaintext,
            string epoch,
            string pageId,
            byte[] masterPublicKey,
            string signX,
            string signY,
            SealOptions options,
            string debugToken)
        {
            var operation = BeginSealInternal(
                plaintext, epoch, pageId, masterPublicKey, signX, signY, options, debugToken);
            while (operation.MoveNext())
            {
                // every step runs back to back; callers that care about latency
                // drive the operation themselves and yield between steps
            }
            return operation.Result;
        }

        /// <summary>
        /// The real implementation behind <see cref="BeginSeal"/>, with one extra
        /// argument for demos.
        /// </summary>
        /// <param name="plaintext">The hidden fragment, as UTF-8 HTML.</param>
        /// <param name="epoch">Epoch id, mixed into the key derivation and the AEAD tag.</param>
        /// <param name="pageId">Assigned page id; the identity a key must match.</param>
        /// <param name="masterPublicKey">The epoch's public half, 96 compressed bytes.</param>
        /// <param name="signX">Signature verification key X, base64url, from the key table.</param>
        /// <param name="signY">Signature verification key Y, base64url, from the key table.</param>
        /// <param name="options">Page behaviour; defaults to attribution shown, expiry not enforced.</param>
        /// <param name="debugToken">
        /// A signed token, as <c>php issue.php</c> emits it, to pre-fill the key entry
        /// box with. Null for every normal page, which is what the public entry points
        /// pass. Nothing is bypassed: the page still verifies the signature and the
        /// page binding exactly as it would for a key typed by hand, so a wrong token
        /// here simply fails to open the page.
        ///
        /// A page built this way carries a working key, so anyone holding the file can
        /// read the sealed content. That is the point for a demo and unacceptable
        /// anywhere else, which is why this entry point is internal.
        /// </param>
        internal static SealOperation BeginSealInternal(
            byte[] plaintext,
            string epoch,
            string pageId,
            byte[] masterPublicKey,
            string signX,
            string signY,
            SealOptions options,
            string debugToken)
        {
            if (plaintext == null) throw new ArgumentNullException(nameof(plaintext));
            if (masterPublicKey == null) throw new ArgumentNullException(nameof(masterPublicKey));
            if (string.IsNullOrEmpty(epoch)) throw new ArgumentException("epoch is required", nameof(epoch));
            if (string.IsNullOrEmpty(pageId)) throw new ArgumentException("page id is required", nameof(pageId));
            if (string.IsNullOrEmpty(signX) || string.IsNullOrEmpty(signY))
            {
                throw new ArgumentException("signature verification key is required");
            }
            if (masterPublicKey.Length != 96)
            {
                throw new ArgumentException("master public key must be 96 compressed bytes", nameof(masterPublicKey));
            }
            if (debugToken != null && !IsWellFormedToken(debugToken))
            {
                // caught here rather than producing a page whose entry box is
                // pre-filled with something the browser will only reject
                throw new ArgumentException(
                    "debug token must look like NO1.<base64url>.<base64url>", nameof(debugToken));
            }

            return new SealOperation(
                plaintext, epoch, pageId, masterPublicKey, signX, signY,
                options ?? new SealOptions(), debugToken);
        }

        /// <summary>Shape check only; the browser is what actually verifies a token.</summary>
        private static bool IsWellFormedToken(string token)
        {
            var parts = token.Split('.');
            if (parts.Length != 3 || parts[0] != "NO1") { return false; }
            for (var i = 1; i < 3; i++)
            {
                if (parts[i].Length == 0) { return false; }
                foreach (var c in parts[i])
                {
                    var ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                          || (c >= '0' && c <= '9') || c == '-' || c == '_';
                    if (!ok) { return false; }
                }
            }
            return true;
        }

        internal static Scalar IdentityOf(string pageId)
        {
            return Identity(pageId);
        }

        internal static Gt SharedValue(Scalar ephemeral)
        {
            return PairingConstant * ephemeral;
        }

        /// <summary>
        /// Exposes the embedded constant so ReportSeal.SelfTest can confirm it still
        /// equals a freshly computed pairing. Not part of the sealing contract.
        /// </summary>
        public static Gt SharedValueForTest(Scalar ephemeral)
        {
            return SharedValue(ephemeral);
        }

        internal static byte[] SealBody(
            byte[] plaintext, string epoch, string pageId, Gt shared, bool compress, out byte[] iv)
        {
            // Compression sits inside the AEAD, so the ciphertext is what gets
            // authenticated either way and the key derivation is untouched.
            var body = compress ? Gzip(plaintext) : plaintext;

            var info = Encoding.UTF8.GetBytes("reportseal/v2|" + epoch + "|" + pageId);
            var aad = Encoding.UTF8.GetBytes(epoch + "|" + pageId);
            var key = DeriveKey(Canonicalise(shared), info);

            iv = new byte[12];
            RandomNumberGenerator.Fill(iv);

            var output = new byte[body.Length + 16];
            using (var gcm = new AesGcm(key))
            {
                gcm.Encrypt(
                    iv,
                    body,
                    new Span<byte>(output, 0, body.Length),
                    new Span<byte>(output, body.Length, 16),
                    aad);
            }
            CryptographicOperations.ZeroMemory(key);
            return output;
        }

        /// <summary>
        /// Gzip rather than raw deflate: netstandard2.1 has no ZLibStream, and the
        /// browser's DecompressionStream takes "gzip" everywhere it exists. The
        /// 18-byte header is noise beside a payload of tens of kilobytes.
        /// </summary>
        private static byte[] Gzip(byte[] data)
        {
            using (var buffer = new MemoryStream())
            {
                using (var gzip = new GZipStream(buffer, CompressionLevel.Optimal, true))
                {
                    gzip.Write(data, 0, data.Length);
                }
                return buffer.ToArray();
            }
        }

        internal static string Markup(
            string elementId, string epoch, string pageId, byte[] iv, byte[] ciphertext,
            byte[] c1, string signX, string signY, SealOptions options, string debugToken)
        {
            return BuildMarkup(
                elementId, epoch, pageId, iv, ciphertext, c1, signX, signY, options, debugToken);
        }

        internal static string NewElementId()
        {
            return RandomElementId();
        }

        internal static Scalar NewEphemeral()
        {
            return RandomScalar();
        }

        /// <summary>
        /// The page identity: SHA-256 over the tagged page id, reduced modulo the
        /// group order. PHP derives the same value, so the two must stay in step.
        /// </summary>
        private static Scalar Identity(string pageId)
        {
            byte[] digest;
            using (var sha = SHA256.Create())
            {
                digest = sha.ComputeHash(Encoding.UTF8.GetBytes(IdentityTag + pageId));
            }
            return WideScalar(digest);
        }

        private static Scalar RandomScalar()
        {
            var raw = new byte[64];
            RandomNumberGenerator.Fill(raw);
            return Scalar.FromBytesWide(raw);
        }

        /// <summary>
        /// Interprets big-endian bytes as an integer and reduces it. Neo takes
        /// little-endian input, so the digest is reversed on the way in.
        /// </summary>
        private static Scalar WideScalar(byte[] bigEndian)
        {
            var wide = new byte[64];
            for (var i = 0; i < bigEndian.Length; i++)
            {
                wide[i] = bigEndian[bigEndian.Length - 1 - i];
            }
            return Scalar.FromBytesWide(wide);
        }

        /// <summary>
        /// Neo serialises the twelve field coefficients in the opposite order to
        /// @noble/curves. Each 48-byte block is identical, so reversing the blocks
        /// puts both sides on the same bytes. Verified against captured vectors.
        /// </summary>
        private static byte[] Canonicalise(Gt value)
        {
            var raw = value.ToArray();
            if (raw.Length != 576)
            {
                throw new InvalidOperationException("unexpected Gt encoding length " + raw.Length);
            }
            var flipped = new byte[576];
            for (var block = 0; block < 12; block++)
            {
                Buffer.BlockCopy(raw, block * 48, flipped, (11 - block) * 48, 48);
            }
            return flipped;
        }

        /// <summary>
        /// HKDF-SHA256 with an empty salt, one 32-byte block. Written out rather
        /// than using the HKDF class, which does not exist in netstandard2.1.
        /// </summary>
        private static byte[] DeriveKey(byte[] ikm, byte[] info)
        {
            byte[] prk;
            using (var extract = new HMACSHA256(new byte[32]))
            {
                prk = extract.ComputeHash(ikm);
            }
            var block = new byte[info.Length + 1];
            Buffer.BlockCopy(info, 0, block, 0, info.Length);
            block[info.Length] = 0x01;
            using (var expand = new HMACSHA256(prk))
            {
                var key = expand.ComputeHash(block);
                CryptographicOperations.ZeroMemory(prk);
                return key;
            }
        }

        /// <summary>
        /// The hidden div: ciphertext as its text, every other public value as a data
        /// attribute. The script finds it by id and needs no JSON parsing.
        /// </summary>
        private static string BuildMarkup(
            string elementId,
            string epoch,
            string pageId,
            byte[] iv,
            byte[] ciphertext,
            byte[] c1,
            string signX,
            string signY,
            SealOptions options,
            string debugToken)
        {
            var sb = new StringBuilder();
            sb.Append("<div id=\"").Append(elementId).Append('"')
              .Append(" hidden")
              .Append(" data-epoch=\"").Append(TextEscape.Html(epoch)).Append('"')
              .Append(" data-page=\"").Append(TextEscape.Html(pageId)).Append('"')
              .Append(" data-c1=\"").Append(Base64Url.Encode(c1)).Append('"')
              .Append(" data-iv=\"").Append(Base64Url.Encode(iv)).Append('"')
              .Append(" data-sign-x=\"").Append(TextEscape.Html(signX)).Append('"')
              .Append(" data-sign-y=\"").Append(TextEscape.Html(signY)).Append('"');
            // Only the non-default choices are written, so a page carries no noise.
            if (!options.ShowAttribution) { sb.Append(" data-no-attribution"); }
            if (options.EnforceExpiry) { sb.Append(" data-enforce-expiry"); }
            if (options.Compress) { sb.Append(" data-encoding=\"gzip\""); }
            if (debugToken != null)
            {
                sb.Append(" data-debug-key=\"").Append(TextEscape.Html(debugToken)).Append('"');
            }
            sb.Append('>')
              .Append(Base64Url.Encode(ciphertext))
              .Append("</div>");
            return sb.ToString();
        }

        private static string RandomElementId()
        {
            var raw = new byte[6];
            RandomNumberGenerator.Fill(raw);
            var sb = new StringBuilder(13).Append('p');
            foreach (var b in raw)
            {
                sb.Append(b.ToString("x2"));
            }
            return sb.ToString();
        }
    }
}
