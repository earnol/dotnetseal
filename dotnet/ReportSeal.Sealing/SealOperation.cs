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
        private readonly string epoch;
        private readonly string pageId;
        private readonly byte[] masterPublicKey;
        private readonly string signX;
        private readonly string signY;
        private readonly SealOptions options;
        private readonly string debugToken;

        private int step;
        private Scalar identity;
        private Scalar ephemeral;
        private G2Projective offsetGenerator;
        private G2Affine c1;
        private Gt shared;

        internal SealOperation(
            byte[] plaintext,
            string epoch,
            string pageId,
            byte[] masterPublicKey,
            string signX,
            string signY,
            SealOptions options,
            string debugToken)
        {
            this.plaintext = plaintext;
            this.epoch = epoch;
            this.pageId = pageId;
            this.masterPublicKey = masterPublicKey;
            this.signX = signX;
            this.signY = signY;
            this.options = options;
            this.debugToken = debugToken;
        }

        /// <summary>The finished parts, once <see cref="MoveNext"/> has returned false.</summary>
        public SealedFragment Result { get; private set; }

        /// <summary>True once the work is complete.</summary>
        public bool IsDone => Result != null;

        /// <summary>How many steps this operation takes in total.</summary>
        public int StepCount => 5;

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

                case 2:
                    // 14-22 ms: C1 = k * (X + id * G2)
                    var x = G2Affine.FromCompressed(masterPublicKey);
                    c1 = new G2Affine((x + offsetGenerator) * ephemeral);
                    step = 3;
                    return true;

                case 3:
                    // 17-27 ms: the shared value, e(G1, G2)^k
                    shared = Sealer.SharedValue(ephemeral);
                    step = 4;
                    return true;

                case 4:
                    // cheap: derive the key, encrypt, assemble the markup
                    byte[] iv;
                    var ciphertext = Sealer.SealBody(
                        plaintext, epoch, pageId, shared, options.Compress, out iv);
                    var elementId = Sealer.NewElementId();
                    Result = new SealedFragment(
                        elementId,
                        Sealer.Markup(elementId, epoch, pageId, iv, ciphertext,
                            c1.ToCompressed(), signX, signY, options, debugToken),
                        UnlockAssets.Styles,
                        UnlockAssets.Script(elementId));
                    step = 5;
                    return false;

                default:
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
