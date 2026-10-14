using System;

namespace ReportSeal.Sealing
{
    /// <summary>
    /// One epoch: its name, and the public half of its master keypair.
    ///
    /// The two travel together because every epoch has its own master scalar — that
    /// is what makes rotation mean anything — so a name without its key, or a key
    /// without its name, is not usable. The name is not merely a label either: it is
    /// folded into the key derivation and the AEAD associated data, so renaming an
    /// epoch invalidates tokens already issued under the old name even though the
    /// scalar behind it is unchanged.
    /// </summary>
    public sealed class EpochKey
    {
        /// <param name="id">Epoch name, as published in the key table.</param>
        /// <param name="masterPublicKey">That epoch's X = s*G2, 96 compressed bytes.</param>
        public EpochKey(string id, byte[] masterPublicKey)
        {
            if (string.IsNullOrEmpty(id))
            {
                throw new ArgumentException("epoch id is required", nameof(id));
            }
            if (!IsValidId(id))
            {
                throw new ArgumentException(
                    "epoch id may use A-Za-z0-9_.- only, and may not contain '+', which separates ids",
                    nameof(id));
            }
            if (masterPublicKey == null)
            {
                throw new ArgumentNullException(nameof(masterPublicKey));
            }
            if (masterPublicKey.Length != 96)
            {
                throw new ArgumentException(
                    "master public key must be 96 compressed bytes", nameof(masterPublicKey));
            }

            Id = id;
            MasterPublicKey = masterPublicKey;
        }

        public string Id { get; }

        public byte[] MasterPublicKey { get; }

        private static bool IsValidId(string id)
        {
            foreach (var c in id)
            {
                var ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                      || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-';
                if (!ok) { return false; }
            }
            return true;
        }
    }
}
