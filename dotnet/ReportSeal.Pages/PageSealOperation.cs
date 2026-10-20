using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using ReportSeal.Sealing;

namespace ReportSeal.Pages
{
    /// <summary>
    /// Seals a page one step per <see cref="MoveNext"/>: fetch the key table, check its
    /// signature, then each fragment's own sealing steps. A step that waits on a seam —
    /// the table source, the verifier or the cipher — returns true without advancing,
    /// so a host polls it from its frame loop:
    ///
    /// <code>
    /// var op = PageSealer.BeginSeal(html, options);
    /// while (op.MoveNext()) { yield return null; }
    /// var page = op.Result;
    /// </code>
    ///
    /// It implements <see cref="IEnumerator"/> with a null <see cref="Current"/>, so it
    /// can also go straight to Unity's <c>StartCoroutine</c>. A failure is thrown from
    /// the <see cref="MoveNext"/> call that discovers it.
    /// </summary>
    public sealed class PageSealOperation : IEnumerator
    {
        private enum Phase { Fetch, AwaitTable, AwaitSignature, Fragments, Done }

        private readonly string pageHtml;
        private readonly List<PageSealer.Region> regions;
        private readonly Uri location;
        private readonly IAesGcm cipher;
        private readonly ITableSource source;
        private readonly IEcdsaVerifier verifier;

        private Phase phase = Phase.Fetch;
        private Pending<string> fetch;
        private Pending<bool> check;
        private KeyTable.Unverified unverified;
        private EpochKey[][] epochs;
        private int index;
        private SealOperation current;
        private readonly List<SealedFragment> sealedFragments = new List<SealedFragment>();

        internal PageSealOperation(string pageHtml, List<PageSealer.Region> regions, PageSealOptions options)
        {
            this.pageHtml = pageHtml;
            this.regions = regions;
            location = PageSealer.TableOf(regions);
            cipher = options.Cipher;
            source = options.TableSource ?? DefaultTableSource.Instance;
            verifier = options.Verifier ?? PlatformEcdsaVerifier.Instance;
        }

        /// <summary>Where the page's markers say the key table is.</summary>
        public Uri TableLocation => location;

        /// <summary>The checked key table, once its signature has verified.</summary>
        public KeyTable Table { get; private set; }

        /// <summary>The sealed page, once <see cref="MoveNext"/> has returned false.</summary>
        public SealedPage Result { get; private set; }

        public bool IsDone => Result != null;

        /// <summary>True while a seam has been asked for something and has not answered.</summary>
        public bool IsWaiting =>
            (phase == Phase.AwaitTable && !fetch.IsComplete)
            || (phase == Phase.AwaitSignature && !check.IsComplete)
            || (current != null && current.IsWaitingOnCipher);

        public object Current => null;

        public bool MoveNext()
        {
            switch (phase)
            {
                case Phase.Fetch:
                    fetch = source.Fetch(location)
                        ?? throw new InvalidOperationException("the table source returned no result");
                    phase = Phase.AwaitTable;
                    return true;

                case Phase.AwaitTable:
                    if (!fetch.IsComplete) { return true; }
                    if (fetch.Error != null)
                    {
                        throw new KeyTableException(
                            "could not read the key table at " + KeyTable.Describe(location) + ": " +
                            fetch.Error.Message, fetch.Error);
                    }
                    unverified = KeyTable.Read(fetch.Result ?? "", location);
                    check = verifier.Verify(unverified.PublicKey, unverified.Signature, unverified.SignedBytes)
                        ?? throw new InvalidOperationException("the signature verifier returned no result");
                    phase = Phase.AwaitSignature;
                    return true;

                case Phase.AwaitSignature:
                    if (!check.IsComplete) { return true; }
                    if (check.Error != null)
                    {
                        throw new KeyTableException(
                            "could not check the signature of the key table at " +
                            KeyTable.Describe(location) + ": " + check.Error.Message, check.Error);
                    }
                    if (!check.Result)
                    {
                        throw KeyTable.Problem(location,
                            "has a signature that does not verify: it has been altered since it was published");
                    }
                    Table = unverified.Table;
                    unverified = null;

                    var byId = new Dictionary<string, EpochKey>(StringComparer.Ordinal);
                    foreach (var key in Table.Epochs) { byId[key.Id] = key; }
                    epochs = new EpochKey[regions.Count][];
                    for (var i = 0; i < regions.Count; i++)
                    {
                        epochs[i] = PageSealer.ResolveEpochs(regions[i].Options, byId, regions[i].Open);
                    }
                    phase = Phase.Fragments;
                    return true;

                case Phase.Fragments:
                    if (current == null)
                    {
                        var region = regions[index];
                        current = Sealer.BeginSeal(
                            Encoding.UTF8.GetBytes(region.Fragment),
                            epochs[index],
                            region.Options["PageID"],
                            Table.SignX,
                            Table.SignY,
                            PageSealer.FragmentOptions(region, cipher));
                    }
                    if (current.MoveNext()) { return true; }

                    sealedFragments.Add(current.Result);
                    current = null;
                    index++;
                    if (index < regions.Count) { return true; }

                    Result = Assemble();
                    phase = Phase.Done;
                    return false;

                default:
                    return false;
            }
        }

        /// <summary>
        /// For the synchronous <see cref="PageSealer.Seal"/>: blocks on a task-backed
        /// result, and refuses one that only a callback could deliver.
        /// </summary>
        internal void WaitOrRefuse()
        {
            if (current != null && current.IsWaitingOnCipher)
            {
                throw new InvalidOperationException(
                    "the configured AES-GCM implementation completes asynchronously, which a " +
                    "synchronous Seal cannot wait for; drive PageSealer.BeginSeal from a coroutine instead");
            }
            if (phase == Phase.AwaitTable && !fetch.IsComplete) { Wait(fetch.CanBlock, fetch.Block, "table source"); }
            if (phase == Phase.AwaitSignature && !check.IsComplete) { Wait(check.CanBlock, check.Block, "signature verifier"); }
        }

        private static void Wait(bool canBlock, Action block, string what)
        {
            if (!canBlock)
            {
                throw new InvalidOperationException(
                    "the configured " + what + " answers through a callback, which a synchronous " +
                    "Seal cannot wait for; drive PageSealer.BeginSeal from a coroutine instead");
            }
            block();
        }

        private SealedPage Assemble()
        {
            var output = new StringBuilder(pageHtml.Length * 2);
            var infos = new SealedFragmentInfo[regions.Count];
            var cursor = 0;
            for (var i = 0; i < regions.Count; i++)
            {
                var region = regions[i];
                output.Append(pageHtml, cursor, region.Open - cursor);
                output.Append(sealedFragments[i].Markup);
                cursor = region.CloseEnd;

                var ids = new string[epochs[i].Length];
                for (var e = 0; e < ids.Length; e++) { ids[e] = epochs[i][e].Id; }
                infos[i] = new SealedFragmentInfo(
                    region.Options["PageID"], ids, sealedFragments[i].ElementId,
                    Encoding.UTF8.GetByteCount(region.Fragment));
            }
            output.Append(pageHtml, cursor, pageHtml.Length - cursor);

            // The styles and the unlock code go in once, however many fragments there
            // are: the script finds them all by itself.
            var html = PageSealer.Inject(
                output.ToString(), sealedFragments[0].Styles, sealedFragments[0].Script, out var styledByPage);
            return new SealedPage(html, infos, styledByPage, Table);
        }

        /// <summary>Not supported: sealing draws fresh randomness and cannot be replayed.</summary>
        public void Reset()
        {
            throw new NotSupportedException("a sealing operation cannot be restarted");
        }
    }
}
