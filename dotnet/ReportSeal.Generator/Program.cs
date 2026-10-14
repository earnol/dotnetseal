using System.Text;
using System.Text.Json.Nodes;
using ReportSeal.Sealing;

namespace ReportSeal.Generator;

/// <summary>
/// Command line host. ReportSeal.Sealing does the encryption and hands back three page
/// parts; everything here is file I/O, key-table parsing, and merging those parts
/// into a page whose header and layout belong to this project, not the library.
/// </summary>
internal static class Program
{
    private static int Main(string[] args)
    {
        try
        {
            return Run(args);
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
                usage: reportseal-gen --page <id> --hidden <file> --out <file> [options]

                  --page <id>       assigned page id; keys are issued against it (required)
                  --hidden <file>   HTML fragment to encrypt (required)
                  --out <file>      page to write (required)
                  --table <file>    published key table (default ../../keys/epochs.json)
                  --epoch <ids>     epoch, or several joined with '+' as in E1+E3;
                                    a key from any of them opens the page
                                    (default: the last epoch listed in the table)
                  --max-epochs <n>  guard against a runaway list (default 3)
                  --title <text>    page title and heading
                  --header <file>   HTML fragment for the visible header
                  --no-compress     store the fragment uncompressed (wider browser support)
                  --no-attribution  do not print who the key was issued to
                  --enforce-expiry  refuse to reveal content once the key's date passes
                """);
            return 2;
        }

        var table = JsonNode.Parse(File.ReadAllText(opt.Table))!.AsObject();
        var published = table["epochs"]!.AsObject();
        var wanted = (opt.Epoch ?? published.Select(e => e.Key).LastOrDefault()
            ?? throw new InvalidOperationException($"{opt.Table} lists no epochs — run php/setup.php"))
            .Split('+', StringSplitOptions.RemoveEmptyEntries);

        if (wanted.Length > opt.MaxEpochs)
        {
            throw new InvalidOperationException(
                $"{wanted.Length} epochs requested but --max-epochs is {opt.MaxEpochs}; "
                + "a page readable under that many epochs is usually a mistake");
        }

        var epochs = wanted.Select(id =>
        {
            if (!published.TryGetPropertyValue(id, out var mpk) || mpk is null)
            {
                throw new InvalidOperationException(
                    $"epoch '{id}' is not in {opt.Table} "
                    + $"(have: {string.Join(", ", published.Select(e => e.Key))})");
            }
            return new EpochKey(id, Base64Url.Decode((string)mpk!));
        }).ToArray();

        var plaintext = File.ReadAllBytes(opt.Hidden);

        var fragment = Sealer.Seal(
            plaintext,
            epochs,
            opt.Page,
            (string)table["signpublic"]!["x"]!,
            (string)table["signpublic"]!["y"]!,
            new SealOptions
            {
                Compress = !opt.NoCompress,
                ShowAttribution = !opt.NoAttribution,
                EnforceExpiry = opt.EnforceExpiry,
            });

        var page = MergePage(
            opt.Title,
            opt.Header is null ? "" : File.ReadAllText(opt.Header),
            fragment);

        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(opt.Out))!);
        File.WriteAllText(opt.Out, page, new UTF8Encoding(false));

        Console.WriteLine($"epochs  : {string.Join(", ", epochs.Select(e => e.Id))}");
        Console.WriteLine($"page id : {opt.Page}  (identity {PageFingerprint(opt.Page)})");
        Console.WriteLine($"element : {fragment.ElementId}");
        Console.WriteLine($"hidden  : {plaintext.Length} bytes sealed"
            + (opt.NoCompress ? " uncompressed" : " gzipped"));
        Console.WriteLine($"written : {Path.GetFullPath(opt.Out)} ({new FileInfo(opt.Out).Length} bytes)");
        return 0;
    }

    /// <summary>
    /// Short fingerprint of the exact bytes the page id hashes to, matching what
    /// php/issue.php prints. Two ids that look alike but differ in Unicode
    /// composition produce different identities, and without this the only symptom
    /// is a key that will not open its page.
    /// </summary>
    private static string PageFingerprint(string pageId)
    {
        using var sha = System.Security.Cryptography.SHA256.Create();
        var digest = sha.ComputeHash(Encoding.UTF8.GetBytes("reportseal/v2|" + pageId));
        return Convert.ToHexString(digest).ToLowerInvariant().Substring(0, 12);
    }

    /// <summary>
    /// Page shell plus the three parts from the library: styles in the head, hidden
    /// ciphertext element in the body, unlock script after it.
    /// </summary>
    private static string MergePage(string title, string headerHtml, SealedFragment fragment)
    {
        var sb = new StringBuilder();
        sb.Append("""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>
""".TrimEnd('\n'));
        sb.Append(Escape(title));
        sb.Append("""
</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 16px/1.5 system-ui, sans-serif; margin: 0 auto; max-width: 46rem; padding: 2rem 1rem; }
  header { border-bottom: 1px solid #8884; padding-bottom: 1rem; margin-bottom: 1.5rem; }
  h1 { font-size: 1.5rem; margin: 0 0 .25rem; }
  .muted { color: #8a8a8a; font-size: .875rem; }
  table { border-collapse: collapse; }
  th, td { text-align: left; padding: .25rem .75rem .25rem 0; }
""");
        sb.Append(fragment.Styles).Append('\n');
        sb.Append("""
</style>
</head>
<body>

<header>
  <h1>
""".TrimEnd('\n'));
        sb.Append(Escape(title)).Append("</h1>\n  ").Append(headerHtml.TrimEnd('\n'))
          .Append("\n  <p class=\"muted\" data-reportseal-attribution hidden></p>\n</header>\n\n");

        sb.Append(fragment.Markup).Append('\n');
        sb.Append("\n<script>\n").Append(fragment.Script).Append("\n</script>\n\n</body>\n</html>\n");

        return sb.ToString();
    }

    private static string Escape(string s) => s
        .Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;");

    private sealed record Options(
        string Page, string Hidden, string Out, string Table, string? Epoch, string Title, string? Header,
        bool NoAttribution, bool EnforceExpiry, bool NoCompress, int MaxEpochs)
    {
        public static Options? Parse(string[] args)
        {
            string? hidden = null, output = null, header = null, page = null, epoch = null;
            var table = Path.Combine(AppContext.BaseDirectory, "../../../../../keys/epochs.json");
            var title = "Protected document";
            var noAttribution = false;
            var enforceExpiry = false;
            var noCompress = false;
            var maxEpochs = 3;

            for (var i = 0; i < args.Length; i++)
            {
                var next = i + 1 < args.Length ? args[i + 1] : null;
                switch (args[i])
                {
                    case "--hidden": hidden = next; i++; break;
                    case "--out": output = next; i++; break;
                    case "--table": table = next!; i++; break;
                    case "--page": page = next; i++; break;
                    case "--epoch": epoch = next; i++; break;
                    case "--title": title = next!; i++; break;
                    case "--header": header = next; i++; break;
                    case "--max-epochs": maxEpochs = int.Parse(next!); i++; break;
                    case "--no-compress": noCompress = true; break;
                    case "--no-attribution": noAttribution = true; break;
                    case "--enforce-expiry": enforceExpiry = true; break;
                    default: return null;
                }
            }
            if (hidden is null || output is null || page is null) return null;
            return new Options(page, hidden, output, Path.GetFullPath(table), epoch, title, header,
                noAttribution, enforceExpiry, noCompress, maxEpochs);
        }
    }
}
