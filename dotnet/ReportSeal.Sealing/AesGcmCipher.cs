using System;
using System.Security.Cryptography;

namespace ReportSeal.Sealing
{
    /// <summary>
    /// The AES-256-GCM encryption the sealer needs, behind a seam so a host can supply
    /// its own. The default, <see cref="PlatformAesGcm"/>, uses the runtime's
    /// <see cref="System.Security.Cryptography.AesGcm"/>; a host where that is missing —
    /// Unity WebGL, for instance — can route the call to the browser instead.
    ///
    /// An implementation may finish at once or later. The sealer only ever polls the
    /// returned job, so an asynchronous implementation works with
    /// <see cref="Sealer.BeginSeal"/> driven a step at a time. The synchronous
    /// <see cref="Sealer.Seal"/> cannot wait for one, and says so rather than hanging.
    /// </summary>
    public interface IAesGcm
    {
        /// <summary>
        /// Begins encrypting. The result must be the ciphertext followed by the 16-byte
        /// tag — the layout WebCrypto produces and the page expects.
        /// </summary>
        /// <param name="key">32-byte content key. Treat as secret; do not log it.</param>
        /// <param name="nonce">12-byte nonce.</param>
        /// <param name="plaintext">The fragment, already compressed if the page asked for it.</param>
        /// <param name="associatedData">
        /// Authenticated but not encrypted. Must be passed through: the page decrypts with
        /// the same value, and ciphertext produced without it can never be opened.
        /// </param>
        AesGcmJob Encrypt(byte[] key, byte[] nonce, byte[] plaintext, byte[] associatedData);
    }

    /// <summary>
    /// An encryption that is finished now or will be later. An asynchronous
    /// implementation creates one, returns it, and calls <see cref="Complete"/> or
    /// <see cref="Fail"/> when its result arrives.
    /// </summary>
    public sealed class AesGcmJob
    {
        private byte[] result;
        private Exception error;
        private volatile bool done;

        /// <summary>True once the job has either a result or an error.</summary>
        public bool IsComplete => done;

        /// <summary>Ciphertext followed by the tag, once complete and successful.</summary>
        public byte[] CiphertextAndTag => done ? result : null;

        /// <summary>Why the job failed, if it did.</summary>
        public Exception Error => done ? error : null;

        public void Complete(byte[] ciphertextAndTag)
        {
            if (ciphertextAndTag == null) throw new ArgumentNullException(nameof(ciphertextAndTag));
            if (done) throw new InvalidOperationException("this job has already finished");
            result = ciphertextAndTag;
            done = true;
        }

        public void Fail(Exception reason)
        {
            if (reason == null) throw new ArgumentNullException(nameof(reason));
            if (done) throw new InvalidOperationException("this job has already finished");
            error = reason;
            done = true;
        }

        /// <summary>A job that is already finished, for implementations that complete at once.</summary>
        public static AesGcmJob Completed(byte[] ciphertextAndTag)
        {
            var job = new AesGcmJob();
            job.Complete(ciphertextAndTag);
            return job;
        }
    }

    /// <summary>
    /// The runtime's own AES-GCM. Finishes synchronously. This is the default, and it
    /// requires a runtime that supports <see cref="System.Security.Cryptography.AesGcm"/>:
    /// .NET Core 3.0+ or .NET 5+ do; Mono 6.12 does not.
    /// </summary>
    public sealed class PlatformAesGcm : IAesGcm
    {
        public static readonly PlatformAesGcm Instance = new PlatformAesGcm();

        private PlatformAesGcm() { }

        public AesGcmJob Encrypt(byte[] key, byte[] nonce, byte[] plaintext, byte[] associatedData)
        {
            var output = new byte[plaintext.Length + 16];
            using (var gcm = new AesGcm(key))
            {
                gcm.Encrypt(
                    nonce,
                    plaintext,
                    new Span<byte>(output, 0, plaintext.Length),
                    new Span<byte>(output, plaintext.Length, 16),
                    associatedData);
            }
            return AesGcmJob.Completed(output);
        }
    }
}
