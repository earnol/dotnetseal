using System;
using System.Collections;
using Neo.Cryptography.BLS12_381;

namespace ReportSeal.Sealing
{
    /// <summary>
    /// A sealing operation split into steps, so a host without threads can spread
    /// the work across frames instead of blocking for all of it.
    ///
    /// It implements <see cref="IEnumerator"/> with a null <see cref="Current"/>,
    /// which is exactly what a Unity coroutine consumes:
    ///
    /// <code>
    /// var op = Sealer.BeginSeal(bytes, epoch, pageId, mpk, x, y);
    /// while (op.MoveNext()) { yield return null; }
    /// var fragment = op.Result;
    /// </code>
    ///
    /// Driving it to completion in a tight loop is what <see cref="Sealer.Seal"/>
    /// does, so both paths run identical code and are covered by the same tests.
    ///
    /// The steps are the three group operations plus a cheap prologue and epilogue.
    /// The heaviest is the Gt exponentiation, measured at 17-27 ms, which sets the
    /// floor for how short a stall this can achieve without driving the ladders by
    /// hand. ReportSeal.SelfTest prints the per-step cost.
    /// </summary>
    public sealed class SealOperation : IEnumerator
    {
        private readonly byte[] plaintext;
        private readonly EpochKey[] epochs;
        private readonly string epochNames;
        private readonly string pageId;
        private readonly string signX;
        private readonly string signY;
        private readonly SealOptions options;
        private readonly string debugToken;

        private int step;
        private Scalar identity;
        private Scalar ephemeral;
        private G2Projective offsetGenerator;
        private readonly string[] c1List;
        private Gt shared;

        internal SealOperation(
            byte[] plaintext,
            EpochKey[] epochs,
            string pageId,
            string signX,
            string signY,
            SealOptions options,
            string debugToken)
        {
            this.plaintext = plaintext;
            this.epochs = epochs;
            this.epochNames = Sealer.JoinIds(epochs);
            this.c1List = new string[epochs.Length];
            this.pageId = pageId;
            this.signX = signX;
            this.signY = signY;
            this.options = options;
            this.debugToken = debugToken;
        }

        /// <summary>The finished parts, once <see cref="MoveNext"/> has returned false.</summary>
        public SealedFragment Result { get; private set; }

        /// <summary>True once the work is complete.</summary>
        public bool IsDone => Result != null;

        /// <summary>
        /// How many steps this operation takes: a prologue, one for id*G2, one per
        /// epoch for its C1, the Gt exponentiation, and the epilogue. Each epoch gets
        /// its own step so the longest stall does not grow with the list.
        /// </summary>
        public int StepCount => 4 + epochs.Length;

        /// <summary>Steps completed so far, for a progress bar if a host wants one.</summary>
        public int StepsCompleted => step;

        /// <summary>Always null: a Unity coroutine reads this as "resume next frame".</summary>
        public object Current => null;

        /// <summary>
        /// Performs the next step. Returns true while work remains, false when
        /// <see cref="Result"/> is ready.
        /// </summary>
        public bool MoveNext()
        {
            switch (step)
            {
                case 0:
                    // cheap: hash the page id, draw the ephemeral scalar
                    identity = Sealer.IdentityOf(pageId);
                    ephemeral = Sealer.NewEphemeral();
                    step = 1;
                    return true;

                case 1:
                    // 10-17 ms: id * G2
                    offsetGenerator = G2Affine.Generator * identity;
                    step = 2;
                    return true;

                default:
                    // 14-22 ms each: C1_i = k * (X_i + id * G2), one epoch per step
                    if (step - 2 < epochs.Length)
                    {
                        var index = step - 2;
                        var x = G2Affine.FromCompressed(epochs[index].MasterPublicKey);
                        c1List[index] = Base64Url.Encode(
                            new G2Affine((x + offsetGenerator) * ephemeral).ToCompressed());
                        step++;
                        return true;
                    }
                    if (step - 2 == epochs.Length)
                    {
                        // 17-27 ms: the shared value, e(G1, G2)^k, the same for every
                        // epoch listed, which is why one ciphertext serves them all
                        shared = Sealer.SharedValue(ephemeral);
                        step++;
                        return true;
                    }
                    if (Result != null) { return false; }
                    // cheap: derive the key, encrypt, assemble the markup
                    byte[] iv;
                    var ciphertext = Sealer.SealBody(
                        plaintext, epochNames, pageId, shared, options.Compress, out iv);
                    var elementId = Sealer.NewElementId();
                    Result = new SealedFragment(
                        elementId,
                        Sealer.Markup(elementId, epochNames, pageId, iv, ciphertext,
                            string.Join("+", c1List), signX, signY, options, debugToken),
                        UnlockAssets.Styles,
                        UnlockAssets.Script(elementId));
                    step++;
                    return false;
            }
        }

        /// <summary>Not supported: sealing draws fresh randomness and cannot be replayed.</summary>
        public void Reset()
        {
            throw new NotSupportedException("a sealing operation cannot be restarted");
        }
    }
}
