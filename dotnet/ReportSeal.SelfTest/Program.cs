using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using Neo.Cryptography.BLS12_381;
using ReportSeal.Pages;
using ReportSeal.Sealing;

namespace ReportSeal.SelfTest;

/// <summary>
/// Checks the properties the browser tests cannot reach: that the embedded pairing
/// constant is still correct, that stepwise and one-shot sealing agree, and that the
/// library really is safe to call from several threads at once.
/// </summary>
internal static class Program
{
    private static int passed;
    private static int failed;

    private static int Main()
    {
        var mpk = new G2Affine(G2Affine.Generator * Scalar.FromBytesWide(Fill(64, 3))).ToCompressed();
        var mpk2 = new G2Affine(G2Affine.Generator * Scalar.FromBytesWide(Fill(64, 5))).ToCompressed();
        var e1 = new[] { new EpochKey("E1", mpk) };
        var e1e2 = new[] { new EpochKey("E1", mpk), new EpochKey("E2", mpk2) };
        const string SignX = "Ph7DAvv2pWX745kh-lez5LFj0SyVB4PzNaUjK715794";
        const string SignY = "EvGyF2FJHZmJGCFpqI5Twed-Wne73G1PCJUHx9-nxgY";
        var body = Encoding.UTF8.GetBytes("<p>self test</p>");

        Console.WriteLine("== the embedded pairing constant still matches the library");
        // Sealing derives its key from e(G1,G2)^k. If the constant were wrong every
        // page would be undecryptable, so this is the check that must never fail.
        var computed = Bls12.Pairing(G1Affine.Generator, G2Affine.Generator);
        var one = Scalar.FromBytesWide(Fill(64, 0, 1));
        Check("constant == Bls12.Pairing(G1, G2)", Sealer.SharedValueForTest(one) == computed * one);

        Console.WriteLine("== stepwise sealing produces the same shape as one shot");
        var direct = Sealer.Seal(body, e1, "DOC-1", SignX, SignY);
        var op = Sealer.BeginSeal(body, e1, "DOC-1", SignX, SignY);
        var steps = 0;
        while (op.MoveNext()) { steps++; }
        Check("takes more than one step", steps > 1);
        Check("step count is reported", op.StepCount == steps + 1);
        Check("IsDone once finished", op.IsDone);
        Check("result is produced", op.Result != null);
        Check("same markup length as one shot", op.Result.Markup.Length == direct.Markup.Length);
        Check("element ids differ per page", op.Result.ElementId != direct.ElementId);
        Check("scripts are identical", op.Result.Script.Length == direct.Script.Length);

        Console.WriteLine("== a finished operation stays finished");
        Check("further MoveNext is false", !op.MoveNext());
        try
        {
            op.Reset();
            Check("Reset throws", false);
        }
        catch (NotSupportedException)
        {
            Check("Reset throws", true);
        }

        Console.WriteLine("== page id rules match the issuer's");
        // The issuer refuses these, so sealing must too: a page nobody can be given
        // a key for is worse than a rejected argument.
        foreach (var bad in new[] { "DOC%1", "DOC&1", "DOC*1", "DOC'1", "DOC\"1", "DOC+1",
                                    "DOC|1", "DOC<1", "DOC>1", "DOC 1", "DOC\t1", "DOC/1",
                                    "DOC\\1", "DOC?1", "DOC#1", "DOC=1", "DOC;1", "DOC\n1",
                                    "DOC\u00001", "" })
        {
            try
            {
                Sealer.Seal(body, e1, bad, SignX, SignY);
                Check("rejects page id " + Describe(bad), false);
            }
            catch (ArgumentException)
            {
                Check("rejects page id " + Describe(bad), true);
            }
        }
        foreach (var good in new[] { "DOC-1234", "DOC-\u00c5rsrapport-\u00dcbersicht",
                                     "a.b:c_d-e", new string('\u00c5', 64) })
        {
            try
            {
                Sealer.Seal(body, e1, good, SignX, SignY);
                Check("accepts page id " + Describe(good), true);
            }
            catch (ArgumentException)
            {
                Check("accepts page id " + Describe(good), false);
            }
        }
        try { Sealer.Seal(body, e1, new string('\u00c5', 65), SignX, SignY);
              Check("rejects 65 characters", false); }
        catch (ArgumentException) { Check("rejects 65 characters", true); }

        Console.WriteLine("== several epochs on one page");
        var multi = Sealer.Seal(body, e1e2, "DOC-1", SignX, SignY);
        Check("epoch names are joined with +", multi.Markup.Contains("data-epochs=\"E1+E2\""));
        Check("one C1 per epoch",
            multi.Markup.Contains("data-c1=\"") &&
            System.Text.RegularExpressions.Regex.Match(multi.Markup, "data-c1=\"([^\"]*)\"")
                .Groups[1].Value.Split('+').Length == 2);
        var single = Sealer.Seal(body, e1, "DOC-1", SignX, SignY);
        Check("one epoch still names just itself", single.Markup.Contains("data-epochs=\"E1\""));
        // order must not change the derivation, so the set is sorted
        var reversed = Sealer.Seal(body, new[] { new EpochKey("E2", mpk2), new EpochKey("E1", mpk) },
            "DOC-1", SignX, SignY);
        Check("caller order does not matter", reversed.Markup.Contains("data-epochs=\"E1+E2\""));
        var stepped = Sealer.BeginSeal(body, e1e2, "DOC-1", SignX, SignY);
        Check("one extra step per epoch", stepped.StepCount == single_steps(body, e1, SignX, SignY) + 1);

        Console.WriteLine("== epoch list validation");
        foreach (var bad in new (string, EpochKey[])[] {
            ("empty", new EpochKey[0]),
            ("duplicate ids", new[] { new EpochKey("E1", mpk), new EpochKey("E1", mpk2) }),
            ("null entry", new EpochKey[] { null }) })
        {
            try
            {
                Sealer.Seal(body, bad.Item2, "DOC-1", SignX, SignY);
                Check("rejects " + bad.Item1, false);
            }
            catch (ArgumentException)
            {
                Check("rejects " + bad.Item1, true);
            }
        }
        try { new EpochKey("E1", new byte[10]); Check("rejects a short master key", false); }
        catch (ArgumentException) { Check("rejects a short master key", true); }
        try { new EpochKey("E1+E2", mpk); Check("rejects '+' in an epoch id", false); }
        catch (ArgumentException) { Check("rejects '+' in an epoch id", true); }

        Console.WriteLine("== compression");
        Check("on by default", new SealOptions().Compress);
        var compressible = Encoding.UTF8.GetBytes(
            string.Concat(Enumerable.Repeat("<p>Revenue held steady across the quarter.</p>\n", 200)));
        var gz = Sealer.Seal(compressible, e1, "DOC-1", SignX, SignY);
        var raw = Sealer.Seal(compressible, e1, "DOC-1", SignX, SignY,
            new SealOptions { Compress = false });
        Check("compressed page declares the encoding", gz.Markup.Contains("data-encoding=\"gzip\""));
        Check("uncompressed page does not", !raw.Markup.Contains("data-encoding"));
        Check("compressed markup is much smaller", gz.Markup.Length * 4 < raw.Markup.Length);
        Console.WriteLine($"     {compressible.Length} B fragment -> markup "
            + $"{raw.Markup.Length} B raw, {gz.Markup.Length} B gzipped");

        Console.WriteLine("== the debug seam pre-fills a key without changing anything else");
        // A real token would come from the issuer; shape is all the library checks.
        const string DemoToken = "NO1.eyJ2IjoyfQ.c2lnbmF0dXJl";
        var plain = Sealer.Seal(body, e1, "DOC-1", SignX, SignY);
        Check("normal pages carry no debug key", !plain.Markup.Contains("data-debug-key"));
        var demo = Sealer.SealInternal(body, e1, "DOC-1", SignX, SignY, null, DemoToken);
        Check("debug page carries the token", demo.Markup.Contains("data-debug-key=\"" + DemoToken + "\""));
        Check("debug page is otherwise identical in shape",
            demo.Markup.Length == plain.Markup.Length + " data-debug-key=\"\"".Length + DemoToken.Length);
        var stepwise = Sealer.BeginSealInternal(body, e1, "DOC-1", SignX, SignY, null, DemoToken);
        while (stepwise.MoveNext()) { }
        Check("stepwise debug seal agrees", stepwise.Result.Markup.Contains("data-debug-key"));
        foreach (var bad in new[] { "nonsense", "NO1.only-two", "XX1.aaa.bbb", "NO1..bbb", "NO1.a+b.ccc" })
        {
            try
            {
                Sealer.BeginSealInternal(body, e1, "DOC-1", SignX, SignY, null, bad);
                Check("rejects malformed token '" + bad + "'", false);
            }
            catch (ArgumentException)
            {
                Check("rejects malformed token '" + bad + "'", true);
            }
        }

        Console.WriteLine("== the AES-GCM seam");
        // An asynchronous cipher: answers only after a few polls, as a browser call would.
        var slow = new DelayedCipher(3);
        var waiting = Sealer.BeginSeal(body, e1, "DOC-1", SignX, SignY, new SealOptions { Cipher = slow });
        var calls = 0;
        var sawWaiting = false;
        while (waiting.MoveNext())
        {
            calls++;
            if (waiting.IsWaitingOnCipher) { sawWaiting = true; slow.Poll(); }
        }
        Check("yields while the cipher works", sawWaiting);
        Check("takes extra calls, not extra steps", calls > waiting.StepCount - 1);
        Check("finishes with a result", waiting.Result != null);
        Check("same output shape as the platform cipher",
            waiting.Result.Markup.Length == Sealer.Seal(body, e1, "DOC-1", SignX, SignY).Markup.Length);
        Check("the cipher received the associated data", slow.LastAad == "E1|DOC-1");
        Check("and a 32-byte key", slow.LastKeyLength == 32);
        Check("and a 12-byte nonce", slow.LastNonceLength == 12);
        Check("the key is cleared once collected", slow.KeyWasClearedAfter);

        try
        {
            Sealer.Seal(body, e1, "DOC-1", SignX, SignY, new SealOptions { Cipher = new DelayedCipher(3) });
            Check("synchronous Seal refuses an asynchronous cipher", false);
        }
        catch (InvalidOperationException ex)
        {
            Check("synchronous Seal refuses an asynchronous cipher", ex.Message.Contains("BeginSeal"));
        }

        foreach (var (label, bad) in new (string, IAesGcm)[] {
            ("a failing cipher", new FailingCipher()),
            ("a cipher that drops the tag", new TruncatingCipher()) })
        {
            try
            {
                Sealer.Seal(body, e1, "DOC-1", SignX, SignY, new SealOptions { Cipher = bad });
                Check(label + " is reported", false);
            }
            catch (System.Security.Cryptography.CryptographicException)
            {
                Check(label + " is reported", true);
            }
        }

        Console.WriteLine("== concurrent sealing from many threads");
        // A GUI host may seal on a worker while another is in flight. Nothing here
        // has thread affinity, and this is what proves it.
        var results = new SealedFragment[32];
        Exception failure = null;
        Parallel.For(0, results.Length, i =>
        {
            try
            {
                results[i] = Sealer.Seal(body, e1, "DOC-" + i, SignX, SignY);
            }
            catch (Exception ex)
            {
                failure = ex;
            }
        });
        Check("no exceptions", failure == null);
        Check("all 32 produced output", results.All(r => r != null && r.Markup.Length > 0));
        Check("element ids are unique", results.Select(r => r.ElementId).Distinct().Count() == results.Length);

        Console.WriteLine("== canonical JSON, as the table signature needs it");
        Check("keys sorted, no whitespace",
            CanonicalJson.Write(CanonicalJson.Parse("{ \"b\" : 1, \"a\" : [true, null, \"x\"] }")) == "{\"a\":[true,null,\"x\"],\"b\":1}");
        Check("sorted by UTF-16 code unit",
            CanonicalJson.Write(CanonicalJson.Parse("{\"\\u00e9\":1,\"z\":2,\"Z\":3}")) == "{\"Z\":3,\"z\":2,\"\u00e9\":1}");
        Check("minimal escapes, non-ASCII kept",
            CanonicalJson.Write(CanonicalJson.Parse("\"\\u00c5\\/\\u0001\\n\\\"\"")) == "\"\u00c5/\\u0001\\n\\\"\"");
        foreach (var bad in new[] { "{\"a\":1,\"a\":2}", "1.5", "1e3", "9007199254740992", "\"\\ud800\"", "{\"a\":1} x", "[1,]" })
        {
            try { CanonicalJson.Parse(bad); Check("rejects " + bad, false); }
            catch (FormatException) { Check("rejects " + bad, true); }
        }

        Console.WriteLine("== page sealing through callback seams, as on Unity WebGL");
        using (var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256))
        {
            var q = signer.ExportParameters(false).Q;
            var tableJson = SignedTable(signer, mpk, mpk2);
            const string Page = "<html><head></head><body><!-- ReportSeal PageID: DOC-1, Epoch: E1+E2, Compress: true, "
                + "EnforceExpiry: false, ShowAttribution: true, Table: https://issuer.example/epochs.json -->"
                + "<p>SELFTEST-PLAINTEXT</p><!-- EndOfReportSeal --></body></html>";

            var source = new LaterSource(tableJson);
            var verifier = new LaterVerifier();
            var pageOp = PageSealer.BeginSeal(Page, new PageSealOptions { TableSource = source, Verifier = verifier });
            Check("the marker's location is reported", pageOp.TableLocation.AbsoluteUri == "https://issuer.example/epochs.json");
            var waitedForTable = false;
            var waitedForSignature = false;
            var guard = 0;
            while (pageOp.MoveNext() && guard++ < 10000)
            {
                if (pageOp.IsWaiting && source.Asked != null && !source.Answered) { waitedForTable = true; source.Answer(); }
                else if (pageOp.IsWaiting && verifier.Asked != null && !verifier.Asked.IsComplete) { waitedForSignature = true; verifier.Answer(); }
            }
            Check("yields while the table is fetched", waitedForTable);
            Check("yields while the signature is checked", waitedForSignature);
            Check("the page is sealed", pageOp.IsDone && pageOp.Result.Html.Contains("data-reportseal") && !pageOp.Result.Html.Contains("SELFTEST-PLAINTEXT"));
            Check("the table's verify key is used", pageOp.Result.Html.Contains(Base64Url.Encode(q.X)));
            Check("both epochs are offered", pageOp.Result.Table.Epochs.Count == 2);

            try { PageSealer.Seal(Page, new PageSealOptions { TableSource = new LaterSource(tableJson) }); Check("Seal refuses a callback source", false); }
            catch (InvalidOperationException ex) { Check("Seal refuses a callback source", ex.Message.Contains("BeginSeal")); }

            var viaTask = PageSealer.Seal(Page, new PageSealOptions
            {
                TableSource = new TaskSource(tableJson),
            });
            Check("Seal waits for a task-backed source", viaTask.Fragments.Length == 1);

            var tampered = tableJson.Replace("\"version\":2", "\"version\":2,\"note\":\"x\"");
            try { PageSealer.Seal(Page, new PageSealOptions { TableSource = new TaskSource(tampered) }); Check("an added member breaks the signature", false); }
            catch (KeyTableException ex) { Check("an added member breaks the signature", ex.Message.Contains("does not verify")); }

            try { PageSealer.BeginSeal(Page.Replace("https://issuer.example/epochs.json", "gopher://x/t.json")); Check("refuses gopher:", false); }
            catch (PageMarkupException ex) { Check("refuses gopher:", ex.Message.Contains("only https://")); }

            Check("relative file:// is taken from the executable",
                TableLocation.Resolve("file://keys/t.json").LocalPath == Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "keys/t.json")));
            Check("file:/// is absolute", TableLocation.Resolve("file:///srv/keys/t.json").LocalPath == "/srv/keys/t.json");
            Check("percent-escapes are decoded", TableLocation.Resolve("file:///srv/my%20keys/t.json").LocalPath == "/srv/my keys/t.json");
            foreach (var bad in new[] { "keys/t.json", "/srv/keys/t.json", "file:/srv/t.json", "file://" })
            {
                try { TableLocation.Resolve(bad); Check("refuses Table: " + bad, false); }
                catch (KeyTableException) { Check("refuses Table: " + bad, true); }
            }

            try { PageSealer.BeginSeal(Page.Replace(", Table: https://issuer.example/epochs.json", "")); Check("Table is required", false); }
            catch (PageMarkupException ex) { Check("Table is required", ex.Message.Contains("'Table'")); }
        }

        Console.WriteLine("== cost of a step, for scheduling decisions");
        var timings = new List<double>();
        var timed = Sealer.BeginSeal(body, e1, "DOC-timing", SignX, SignY);
        var sw = new Stopwatch();
        while (true)
        {
            sw.Restart();
            var more = timed.MoveNext();
            sw.Stop();
            timings.Add(sw.Elapsed.TotalMilliseconds);
            if (!more) { break; }
        }
        for (var i = 0; i < timings.Count; i++)
        {
            Console.WriteLine($"     step {i}: {timings[i]:F1} ms");
        }
        Console.WriteLine($"     worst step: {timings.Max():F1} ms, total {timings.Sum():F1} ms");

        Console.WriteLine();
        Console.WriteLine($"{passed} passed, {failed} failed");
        return failed == 0 ? 0 : 1;
    }

    private static int single_steps(byte[] body, EpochKey[] epochs, string x, string y)
    {
        return Sealer.BeginSeal(body, epochs, "DOC-1", x, y).StepCount;
    }

    private static string Describe(string value)
    {
        if (value.Length == 0) { return "(empty)"; }
        if (value.Length > 20) { return value.Substring(0, 8) + "... (" + value.Length + ")"; }
        return "'" + value.Replace("\t", "\\t").Replace("\n", "\\n").Replace("\0", "\\0") + "'";
    }

    /// <summary>Wraps the platform cipher but answers only after a given number of polls.</summary>
    private sealed class DelayedCipher : IAesGcm
    {
        private readonly int delay;
        private AesGcmJob job;
        private AesGcmJob inner;
        private byte[] key;
        private int polls;

        public DelayedCipher(int delay) { this.delay = delay; }

        public string LastAad { get; private set; }
        public int LastKeyLength { get; private set; }
        public int LastNonceLength { get; private set; }

        public bool KeyWasClearedAfter => key != null && Array.TrueForAll(key, b => b == 0);

        public AesGcmJob Encrypt(byte[] key, byte[] nonce, byte[] plaintext, byte[] associatedData)
        {
            LastAad = Encoding.UTF8.GetString(associatedData);
            LastKeyLength = key.Length;
            LastNonceLength = nonce.Length;
            this.key = key;        // the sealer's own array, so clearing it is observable
            inner = PlatformAesGcm.Instance.Encrypt(key, nonce, plaintext, associatedData);
            job = new AesGcmJob();
            return job;
        }

        public void Poll()
        {
            if (job != null && !job.IsComplete && ++polls >= delay)
            {
                job.Complete(inner.CiphertextAndTag);
            }
        }
    }

    private sealed class FailingCipher : IAesGcm
    {
        public AesGcmJob Encrypt(byte[] key, byte[] nonce, byte[] plaintext, byte[] associatedData)
        {
            var job = new AesGcmJob();
            job.Fail(new InvalidOperationException("simulated failure"));
            return job;
        }
    }

    private sealed class TruncatingCipher : IAesGcm
    {
        public AesGcmJob Encrypt(byte[] key, byte[] nonce, byte[] plaintext, byte[] associatedData)
        {
            var full = PlatformAesGcm.Instance.Encrypt(key, nonce, plaintext, associatedData).CiphertextAndTag;
            var cut = new byte[full.Length - 16];
            Array.Copy(full, cut, cut.Length);
            return AesGcmJob.Completed(cut);
        }
    }

    private static string SignedTable(ECDsa signer, byte[] mpk, byte[] mpk2)
    {
        var q = signer.ExportParameters(false).Q;
        var body = "{\"epochs\":{\"E1\":\"" + Base64Url.Encode(mpk) + "\",\"E2\":\"" + Base64Url.Encode(mpk2)
            + "\"},\"signpublic\":{\"x\":\"" + Base64Url.Encode(q.X) + "\",\"y\":\"" + Base64Url.Encode(q.Y) + "\"},\"version\":2}";
        var sig = signer.SignData(Encoding.UTF8.GetBytes(body), HashAlgorithmName.SHA256);
        return body.Substring(0, body.Length - 1) + ",\"signature\":\"" + Base64Url.Encode(sig) + "\"}";
    }

    /// <summary>Answers only when told to, like a browser callback.</summary>
    private sealed class LaterSource : ITableSource
    {
        private readonly string json;
        public Pending<string> Asked;
        public bool Answered;
        public LaterSource(string json) { this.json = json; }
        public Pending<string> Fetch(Uri location) { Asked = new Pending<string>(); return Asked; }
        public void Answer() { Answered = true; Asked.Complete(json); }
    }

    private sealed class LaterVerifier : IEcdsaVerifier
    {
        private byte[] key, sig, data;
        public Pending<bool> Asked;
        public Pending<bool> Verify(byte[] publicKey, byte[] signature, byte[] signed)
        {
            key = publicKey; sig = signature; data = signed;
            Asked = new Pending<bool>();
            return Asked;
        }
        public void Answer() => Asked.Complete(PlatformEcdsaVerifier.Instance.Verify(key, sig, data).Result);
    }

    private sealed class TaskSource : ITableSource
    {
        private readonly string json;
        public TaskSource(string json) { this.json = json; }
        public Pending<string> Fetch(Uri location) =>
            Pending<string>.FromTask(Task.Run(async () => { await Task.Delay(20); return json; }));
    }

    private static void Check(string name, bool ok)
    {
        if (ok)
        {
            passed++;
            Console.WriteLine($"  ok   {name}");
        }
        else
        {
            failed++;
            Console.WriteLine($"  FAIL {name}");
        }
    }

    private static byte[] Fill(int length, params byte[] prefix)
    {
        var buffer = new byte[length];
        prefix.CopyTo(buffer, 0);
        return buffer;
    }
}
