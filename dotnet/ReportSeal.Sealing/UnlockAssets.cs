using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;

namespace ReportSeal.Sealing
{
    /// <summary>
    /// The CSS and JavaScript that unlock a sealed fragment, loaded from embedded
    /// resources rather than held as string constants. They are ordinary .css and
    /// .js files under assets/, so they can be linted, diffed and — the point of
    /// the exercise — replaced with a newer crypto library without touching C#.
    ///
    /// Scripts are concatenated in the order listed, so a vendored library can be
    /// dropped in ahead of the unlock code by adding it to <see cref="ScriptFiles"/>.
    /// </summary>
    internal static class UnlockAssets
    {
        /// <summary>Vendor libraries first, unlock code last.</summary>
        private static readonly string[] ScriptFiles = { "bls12-381.js", "unlock.js" };

        private const string StyleFile = "unlock.css";

        private static readonly Dictionary<string, string> Cache = new Dictionary<string, string>();
        private static readonly object CacheLock = new object();

        public static string Styles => Read(StyleFile);

        /// <summary>
        /// The unlock code, identical for every page: it discovers each sealed
        /// element itself, so one copy serves any number of fragments.
        /// </summary>
        public static string Script()
        {
            var sb = new StringBuilder();
            foreach (var file in ScriptFiles)
            {
                if (sb.Length > 0) { sb.Append('\n'); }
                sb.Append(Read(file));
            }
            return sb.ToString();
        }

        private static string Read(string file)
        {
            lock (CacheLock)
            {
                if (Cache.TryGetValue(file, out var cached))
                {
                    return cached;
                }

                var assembly = typeof(UnlockAssets).GetTypeInfo().Assembly;
                var name = "ReportSeal.Sealing.assets." + file;
                using (var stream = assembly.GetManifestResourceStream(name))
                {
                    if (stream == null)
                    {
                        throw new InvalidOperationException(
                            "embedded asset '" + name + "' is missing; available: " +
                            string.Join(", ", assembly.GetManifestResourceNames()));
                    }
                    using (var reader = new StreamReader(stream, new UTF8Encoding(false)))
                    {
                        var text = reader.ReadToEnd().TrimEnd('\n');
                        Cache[file] = text;
                        return text;
                    }
                }
            }
        }
    }
}
