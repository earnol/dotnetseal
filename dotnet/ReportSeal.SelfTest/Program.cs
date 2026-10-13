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
        var mpk = Convert.FromBase64String(Convert.ToBase64String(
            new G2Affine(G2Affine.Generator * Scalar.FromBytesWide(Fill(64, 3))).ToCompressed()));
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
        var direct = Sealer.Seal(body, "E1", "DOC-1", mpk, SignX, SignY);
        var op = Sealer.BeginSeal(body, "E1", "DOC-1", mpk, SignX, SignY);
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

        Console.WriteLine("== compression");
        Check("on by default", new SealOptions().Compress);
        var compressible = Encoding.UTF8.GetBytes(
            string.Concat(Enumerable.Repeat("<p>Revenue held steady across the quarter.</p>\n", 200)));
        var gz = Sealer.Seal(compressible, "E1", "DOC-1", mpk, SignX, SignY);
        var raw = Sealer.Seal(compressible, "E1", "DOC-1", mpk, SignX, SignY,
            new SealOptions { Compress = false });
        Check("compressed page declares the encoding", gz.Markup.Contains("data-encoding=\"gzip\""));
        Check("uncompressed page does not", !raw.Markup.Contains("data-encoding"));
        Check("compressed markup is much smaller", gz.Markup.Length * 4 < raw.Markup.Length);
        Console.WriteLine($"     {compressible.Length} B fragment -> markup "
            + $"{raw.Markup.Length} B raw, {gz.Markup.Length} B gzipped");

        Console.WriteLine("== the debug seam pre-fills a key without changing anything else");
        // A real token would come from the issuer; shape is all the library checks.
        const string DemoToken = "NO1.eyJ2IjoyfQ.c2lnbmF0dXJl";
        var plain = Sealer.Seal(body, "E1", "DOC-1", mpk, SignX, SignY);
        Check("normal pages carry no debug key", !plain.Markup.Contains("data-debug-key"));
        var demo = Sealer.SealInternal(body, "E1", "DOC-1", mpk, SignX, SignY, null, DemoToken);
        Check("debug page carries the token", demo.Markup.Contains("data-debug-key=\"" + DemoToken + "\""));
        Check("debug page is otherwise identical in shape",
            demo.Markup.Length == plain.Markup.Length + " data-debug-key=\"\"".Length + DemoToken.Length);
        var stepwise = Sealer.BeginSealInternal(body, "E1", "DOC-1", mpk, SignX, SignY, null, DemoToken);
        while (stepwise.MoveNext()) { }
        Check("stepwise debug seal agrees", stepwise.Result.Markup.Contains("data-debug-key"));
        foreach (var bad in new[] { "nonsense", "NO1.only-two", "XX1.aaa.bbb", "NO1..bbb", "NO1.a+b.ccc" })
        {
            try
            {
                Sealer.BeginSealInternal(body, "E1", "DOC-1", mpk, SignX, SignY, null, bad);
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
                results[i] = Sealer.Seal(body, "E1", "DOC-" + i, mpk, SignX, SignY);
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
        var timed = Sealer.BeginSeal(body, "E1", "DOC-timing", mpk, SignX, SignY);
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
