using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using ReportSeal.Sealing;

namespace ReportSeal.Pages
{
    /// <summary>What was sealed in one fragment, for the caller to report.</summary>
    public sealed class SealedFragmentInfo
    {
        internal SealedFragmentInfo(string pageId, string[] epochs, string elementId, int plaintextLength)
        {
            PageId = pageId;
            Epochs = epochs;
            ElementId = elementId;
            PlaintextLength = plaintextLength;
        }

        public string PageId { get; }

        public string[] Epochs { get; }

        public string ElementId { get; }

        public int PlaintextLength { get; }
    }

    /// <summary>The sealed page and an account of what went into it.</summary>
    public sealed class SealedPage
    {
        internal SealedPage(string html, SealedFragmentInfo[] fragments, bool styledByPage)
        {
            Html = html;
            Fragments = fragments;
            StyledByPage = styledByPage;
        }

        public string Html { get; }

        public SealedFragmentInfo[] Fragments { get; }

        /// <summary>
        /// True when the page carried its own `.reportseal-` rules, so the default
        /// styles were left out.
        /// </summary>
        public bool StyledByPage { get; }
    }

    /// <summary>
    /// Raised when a page's markers are malformed. Carries a message meant to be
    /// shown to whoever wrote the page.
    /// </summary>
    public sealed class PageMarkupException : Exception
    {
        public PageMarkupException(string message) : base(message) { }
    }

    /// <summary>
    /// Seals the marked regions of a complete HTML page, leaving the rest alone.
    ///
    /// This is the page-level interface, built on <see cref="Sealer"/>. A caller that
    /// wants to decide the layout itself can keep using <see cref="Sealer"/> directly;
    /// this one takes a whole page and hands back a whole page.
    ///
    /// Regions are delimited by comments, and every key is required so that a page
    /// says exactly what it wants rather than inheriting anything:
    ///
    /// <code>
    /// &lt;!-- ReportSeal PageID: DOC-5643, Epoch: E1+E3, Compress: true,
    ///      EnforceExpiry: false, ShowAttribution: true --&gt;
    ///   …content to seal…
    /// &lt;!-- EndOfReportSeal --&gt;
    /// </code>
    ///
    /// Several regions may appear on one page. Those sharing a page id and epoch set
    /// are opened together by one key, which the browser arranges by grouping them;
    /// nothing extra is needed here.
    /// </summary>
    public static class PageSealer
    {
        private const string OpenMarker = "ReportSeal";
        private const string CloseMarker = "EndOfReportSeal";

        /// <summary>Guard against a runaway epoch list, as the CLI used to carry.</summary>
        public const int MaxEpochsPerFragment = 3;

        private static readonly string[] RequiredKeys =
            { "PageID", "Epoch", "Compress", "EnforceExpiry", "ShowAttribution" };

        /// <param name="pageHtml">The complete page, markers and all.</param>
        /// <param name="available">Every epoch the key table publishes.</param>
        /// <param name="signX">Signature verification key X, base64url.</param>
        /// <param name="signY">Signature verification key Y, base64url.</param>
        /// <param name="cipher">
        /// AES-GCM to encrypt with; null for the runtime's own. Page-level sealing is
        /// synchronous, so an asynchronous cipher is refused here — seal fragments with
        /// <see cref="Sealer.BeginSeal"/> instead.
        /// </param>
        public static SealedPage Seal(
            string pageHtml, EpochKey[] available, string signX, string signY, IAesGcm cipher = null)
        {
            if (pageHtml == null) throw new ArgumentNullException(nameof(pageHtml));
            if (available == null) throw new ArgumentNullException(nameof(available));

            var byId = new Dictionary<string, EpochKey>(StringComparer.Ordinal);
            foreach (var key in available)
            {
                byId[key.Id] = key;
            }

            var output = new StringBuilder();
            var fragments = new List<SealedFragmentInfo>();
            var styles = (string)null;
            var script = (string)null;
            var cursor = 0;

            while (true)
            {
                var open = FindComment(pageHtml, cursor, OpenMarker, out var openEnd, out var body);
                if (open < 0) { break; }

                var strayClose = FindComment(pageHtml, cursor, CloseMarker, out _, out _);
                if (strayClose >= 0 && strayClose < open)
                {
                    throw new PageMarkupException(
                        "found " + CloseMarker + " before any " + OpenMarker +
                        " at offset " + strayClose);
                }

                var close = FindComment(pageHtml, openEnd, CloseMarker, out var closeEnd, out _);
                if (close < 0)
                {
                    throw new PageMarkupException(
                        OpenMarker + " at offset " + open + " is never closed by " + CloseMarker);
                }

                var nested = FindComment(pageHtml, openEnd, OpenMarker, out _, out _);
                if (nested >= 0 && nested < close)
                {
                    throw new PageMarkupException(
                        "nested " + OpenMarker + " at offset " + nested +
                        "; close the one at offset " + open + " first");
                }

                var options = ParseMarker(body, open);
                var epochs = ResolveEpochs(options, byId, open);
                var fragment = pageHtml.Substring(openEnd, close - openEnd);

                var sealedFragment = Sealer.Seal(
                    Encoding.UTF8.GetBytes(fragment),
                    epochs,
                    options["PageID"],
                    signX,
                    signY,
                    new SealOptions
                    {
                        Compress = Flag(options, "Compress", open),
                        EnforceExpiry = Flag(options, "EnforceExpiry", open),
                        ShowAttribution = Flag(options, "ShowAttribution", open),
                        Cipher = cipher,
                    });

                output.Append(pageHtml, cursor, open - cursor);
                output.Append(sealedFragment.Markup);

                styles = styles ?? sealedFragment.Styles;
                script = script ?? sealedFragment.Script;

                var ids = new string[epochs.Length];
                for (var i = 0; i < epochs.Length; i++) { ids[i] = epochs[i].Id; }
                fragments.Add(new SealedFragmentInfo(
                    options["PageID"], ids, sealedFragment.ElementId,
                    Encoding.UTF8.GetByteCount(fragment)));

                cursor = closeEnd;
            }

            var trailingClose = FindComment(pageHtml, cursor, CloseMarker, out _, out _);
            if (trailingClose >= 0)
            {
                throw new PageMarkupException(
                    "found " + CloseMarker + " at offset " + trailingClose +
                    " with no matching " + OpenMarker);
            }

            if (fragments.Count == 0)
            {
                throw new PageMarkupException(
                    "the page contains no " + OpenMarker + " marker, so there is nothing to seal");
            }

            output.Append(pageHtml, cursor, pageHtml.Length - cursor);

            // The styles and the unlock code go in once, however many fragments there
            // are: the script finds them all by itself.
            var html = Inject(output.ToString(), styles, script, out var styledByPage);
            return new SealedPage(html, fragments.ToArray(), styledByPage);
        }

        /// <summary>
        /// Finds the next <c>&lt;!-- name …  --&gt;</c>, returning its start, the offset
        /// just past it, and whatever followed the name inside the comment.
        /// </summary>
        private static int FindComment(string html, int from, string name, out int end, out string body)
        {
            end = -1;
            body = null;
            var at = from;
            while (true)
            {
                at = html.IndexOf("<!--", at, StringComparison.Ordinal);
                if (at < 0) { return -1; }
                var stop = html.IndexOf("-->", at, StringComparison.Ordinal);
                if (stop < 0)
                {
                    throw new PageMarkupException("unterminated HTML comment at offset " + at);
                }

                var inner = html.Substring(at + 4, stop - at - 4).Trim();
                if (inner.StartsWith(name, StringComparison.OrdinalIgnoreCase)
                    && (inner.Length == name.Length || char.IsWhiteSpace(inner[name.Length])))
                {
                    end = stop + 3;
                    body = inner.Substring(name.Length).Trim();
                    return at;
                }
                at = stop + 3;
            }
        }

        private static Dictionary<string, string> ParseMarker(string body, int offset)
        {
            var options = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var part in body.Split(','))
            {
                var text = part.Trim();
                if (text.Length == 0) { continue; }

                var colon = text.IndexOf(':');
                if (colon <= 0)
                {
                    throw new PageMarkupException(
                        "marker at offset " + offset + " has '" + text +
                        "' where a 'Key: value' pair was expected");
                }
                var key = text.Substring(0, colon).Trim();
                var value = text.Substring(colon + 1).Trim();
                if (value.Length == 0)
                {
                    throw new PageMarkupException(
                        "marker at offset " + offset + " gives no value for '" + key + "'");
                }

                var known = false;
                foreach (var candidate in RequiredKeys)
                {
                    if (string.Equals(candidate, key, StringComparison.OrdinalIgnoreCase))
                    {
                        known = true;
                        key = candidate;
                        break;
                    }
                }
                if (!known)
                {
                    throw new PageMarkupException(
                        "marker at offset " + offset + " has unknown key '" + key +
                        "'; expected " + string.Join(", ", RequiredKeys));
                }
                if (options.ContainsKey(key))
                {
                    throw new PageMarkupException(
                        "marker at offset " + offset + " repeats '" + key + "'");
                }
                options[key] = value;
            }

            foreach (var required in RequiredKeys)
            {
                if (!options.ContainsKey(required))
                {
                    throw new PageMarkupException(
                        "marker at offset " + offset + " is missing '" + required +
                        "'; every key is required");
                }
            }
            return options;
        }

        private static EpochKey[] ResolveEpochs(
            Dictionary<string, string> options, Dictionary<string, EpochKey> byId, int offset)
        {
            var names = options["Epoch"].Split(new[] { '+' }, StringSplitOptions.RemoveEmptyEntries);
            if (names.Length == 0)
            {
                throw new PageMarkupException("marker at offset " + offset + " names no epoch");
            }
            if (names.Length > MaxEpochsPerFragment)
            {
                throw new PageMarkupException(
                    "marker at offset " + offset + " names " + names.Length + " epochs; at most " +
                    MaxEpochsPerFragment + " is allowed, because a page readable under more than " +
                    "that is usually a mistake");
            }

            var keys = new EpochKey[names.Length];
            for (var i = 0; i < names.Length; i++)
            {
                var name = names[i].Trim();
                if (!byId.TryGetValue(name, out var key))
                {
                    var known = new List<string>(byId.Keys);
                    known.Sort(StringComparer.Ordinal);
                    throw new PageMarkupException(
                        "marker at offset " + offset + " names epoch '" + name +
                        "', which the key table does not publish (it has: " +
                        string.Join(", ", known) + ")");
                }
                keys[i] = key;
            }
            return keys;
        }

        private static bool Flag(Dictionary<string, string> options, string key, int offset)
        {
            var value = options[key];
            if (string.Equals(value, "true", StringComparison.OrdinalIgnoreCase)) { return true; }
            if (string.Equals(value, "false", StringComparison.OrdinalIgnoreCase)) { return false; }
            throw new PageMarkupException(
                "marker at offset " + offset + " gives '" + key + ": " + value +
                "', which is neither true nor false");
        }

        /// <summary>
        /// True when the page already carries rules for the unlock classes, in which
        /// case it owns the styling and the defaults are left out entirely. All or
        /// nothing on purpose: half the defaults mixed with half the page's own rules
        /// would be harder to reason about than either alone.
        /// </summary>
        public static bool StylesTheUi(string pageHtml)
        {
            return pageHtml.IndexOf(".reportseal-", StringComparison.Ordinal) >= 0;
        }

        private static string Inject(string html, string styles, string script, out bool styledByPage)
        {
            styledByPage = StylesTheUi(html);
            var withStyles = styledByPage
                ? html
                : InsertBefore(
                    html, "</head>", "<style>\n" + styles + "\n</style>\n",
                    "the page has no </head> for the unlock styles");
            return InsertBefore(
                withStyles, "</body>", "<script>\n" + script + "\n</script>\n",
                "the page has no </body> for the unlock script");
        }

        private static string InsertBefore(string html, string tag, string content, string complaint)
        {
            var at = html.LastIndexOf(tag, StringComparison.OrdinalIgnoreCase);
            if (at < 0) { throw new PageMarkupException(complaint); }
            return html.Substring(0, at) + content + html.Substring(at);
        }
    }
}
