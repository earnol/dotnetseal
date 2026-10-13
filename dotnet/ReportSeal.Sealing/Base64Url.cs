using System;
using System.Text;

namespace ReportSeal.Sealing
{
    /// <summary>base64url without padding, the form both WebCrypto JWKs and the tokens use.</summary>
    public static class Base64Url
    {
        public static string Encode(byte[] raw)
        {
            return Convert.ToBase64String(raw).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        public static byte[] Decode(string value)
        {
            var s = value.Replace('-', '+').Replace('_', '/');
            switch (s.Length % 4)
            {
                case 2: s += "=="; break;
                case 3: s += "="; break;
            }
            return Convert.FromBase64String(s);
        }
    }

    internal static class TextEscape
    {
        public static string Html(string s)
        {
            return s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;");
        }

        /// <summary>
        /// JSON string escaping. The values written here are base64url, hex or seed
        /// ids, but this stays strict so a caller cannot break out of the block.
        /// </summary>
        public static string Json(string s)
        {
            var sb = new StringBuilder(s.Length + 2);
            foreach (var c in s)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\f': sb.Append("\\f"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < ' ' || c == '<' || c == '>' || c == '&')
                        {
                            sb.Append("\\u").Append(((int)c).ToString("x4"));
                        }
                        else
                        {
                            sb.Append(c);
                        }
                        break;
                }
            }
            return sb.ToString();
        }
    }
}
