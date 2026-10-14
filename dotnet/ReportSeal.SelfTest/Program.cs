using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Neo.Cryptography.BLS12_381;
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
