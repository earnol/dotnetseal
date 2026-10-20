using System.Text;
using ReportSeal.Pages;

namespace ReportSeal.Generator;

/// <summary>
/// Command line host. The page says what to seal, through ReportSeal comments, so
/// this program only reads and writes files. The markers name the key table, and
/// ReportSeal.Pages fetches it and checks its signature.
/// </summary>
internal static class Program
{
    private static int Main(string[] args)
    {
        try
        {
            return Run(args);
        }
        catch (PageMarkupException ex)
        {
            Console.Error.WriteLine("error in the page: " + ex.Message);
            return 1;
        }
        catch (KeyTableException ex)
        {
            Console.Error.WriteLine("error: " + ex.Message);
            return 1;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("error: " + ex.Message);
            return 1;
        }
    }

    private static int Run(string[] args)
    {
        var opt = Options.Parse(args);
        if (opt is null)
        {
            Console.Error.WriteLine(
                """
                usage: reportseal-gen --in <page.html> --out <file>

                  --in <page.html>  a complete page whose regions to seal are marked with
                                    <!-- ReportSeal PageID: …, Epoch: …, Compress: …,
                                         EnforceExpiry: …, ShowAttribution: …, Table: … -->
                                      …content…
                                    <!-- EndOfReportSeal -->
                                    Table is an https://, http:// or file:// location; a
                                    relative file:// path is taken from this executable's directory
                  --out <file>      page to write
                """);
            return 2;
        }

        var sealedPage = PageSealer.Seal(File.ReadAllText(opt.In));

        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(opt.Out))!);
        File.WriteAllText(opt.Out, sealedPage.Html, new UTF8Encoding(false));

        var table = sealedPage.Table;
        Console.WriteLine($"table   : {(table.Location.IsFile ? table.Location.LocalPath : table.Location.AbsoluteUri)} "
            + $"(signature verified; epochs {string.Join(", ", table.Epochs.Select(e => e.Id))})");
        Console.WriteLine($"sealed  : {sealedPage.Fragments.Length} fragment(s)");
        Console.WriteLine($"styles  : {(sealedPage.StyledByPage ? "the page's own" : "defaults injected")}");
        foreach (var fragment in sealedPage.Fragments)
        {
            Console.WriteLine(
                $"  {fragment.ElementId}  page {fragment.PageId}  "
                + $"epoch {string.Join("+", fragment.Epochs)}  "
                + $"{fragment.PlaintextLength} bytes  (identity {Fingerprint(fragment.PageId)})");
        }
        Console.WriteLine($"written : {Path.GetFullPath(opt.Out)} ({new FileInfo(opt.Out).Length} bytes)");
        return 0;
    }

    /// <summary>
    /// Short fingerprint of the exact bytes a page id hashes to, matching what
    /// php/issue.php prints. Two ids that look alike but differ in Unicode
    /// composition produce different identities, and without this the only symptom
    /// is a key that will not open its page.
    /// </summary>
    private static string Fingerprint(string pageId)
    {
        using var sha = System.Security.Cryptography.SHA256.Create();
        var digest = sha.ComputeHash(Encoding.UTF8.GetBytes("reportseal/v2|" + pageId));
        return Convert.ToHexString(digest).ToLowerInvariant().Substring(0, 12);
    }

    private sealed record Options(string In, string Out)
    {
        public static Options? Parse(string[] args)
        {
            string? input = null, output = null;

            for (var i = 0; i < args.Length; i++)
            {
                var next = i + 1 < args.Length ? args[i + 1] : null;
                switch (args[i])
                {
                    case "--in": input = next; i++; break;
                    case "--out": output = next; i++; break;
                    default: return null;
                }
            }
            if (input is null || output is null) return null;
            return new Options(input, output);
        }
    }
}
