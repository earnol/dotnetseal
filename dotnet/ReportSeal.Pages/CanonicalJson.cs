using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace ReportSeal.Pages
{
    /// <summary>
    /// A strict JSON reader and an RFC 8785 writer, enough for the key table: objects,
    /// arrays, strings, integers, booleans and null. Written out because
    /// System.Text.Json is not part of netstandard2.1 or of Unity.
    ///
    /// Strict where ambiguity could be used against the signature: a repeated member
    /// name, a lone surrogate, a fraction or an integer beyond 2^53 is refused rather
    /// than read one way here and another way elsewhere.
    ///
    /// Objects are <see cref="Dictionary{TKey,TValue}"/> of string to object, arrays
    /// <see cref="List{T}"/> of object, integers <see cref="long"/>.
    /// </summary>
    internal static class CanonicalJson
    {
        private const int MaxDepth = 32;
        private const long MaxSafeInteger = 9007199254740991; // 2^53 - 1

        public static object Parse(string text)
        {
            var reader = new Reader(text);
            if (reader.Peek() == '\uFEFF') reader.Advance();
            var value = reader.Value(0);
            reader.SkipWhitespace();
            if (!reader.AtEnd) throw reader.Error("unexpected content after the JSON value");
            return value;
        }

        public static string Write(object value)
        {
            var sb = new StringBuilder();
            Write(sb, value);
            return sb.ToString();
        }

        private static void Write(StringBuilder sb, object value)
        {
            switch (value)
            {
                case null:
                    sb.Append("null");
                    break;
                case bool b:
                    sb.Append(b ? "true" : "false");
                    break;
                case long l:
                    sb.Append(l.ToString(CultureInfo.InvariantCulture));
                    break;
                case string s:
                    WriteString(sb, s);
                    break;
                case Dictionary<string, object> obj:
                    // RFC 8785 sorts by UTF-16 code units, which is what ordinal does
                    var keys = new List<string>(obj.Keys);
                    keys.Sort(string.CompareOrdinal);
                    sb.Append('{');
                    for (var i = 0; i < keys.Count; i++)
                    {
                        if (i > 0) sb.Append(',');
                        WriteString(sb, keys[i]);
                        sb.Append(':');
                        Write(sb, obj[keys[i]]);
                    }
                    sb.Append('}');
                    break;
                case List<object> list:
                    sb.Append('[');
                    for (var i = 0; i < list.Count; i++)
                    {
                        if (i > 0) sb.Append(',');
                        Write(sb, list[i]);
                    }
                    sb.Append(']');
                    break;
                default:
                    throw new ArgumentException("not a JSON value: " + value.GetType().Name);
            }
        }

        private static void WriteString(StringBuilder sb, string s)
        {
            sb.Append('"');
            foreach (var c in s)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\t': sb.Append("\\t"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\f': sb.Append("\\f"); break;
                    case '\r': sb.Append("\\r"); break;
                    default:
                        if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                        else sb.Append(c);
                        break;
                }
            }
            sb.Append('"');
        }

        private sealed class Reader
        {
            private readonly string text;
            private int at;

            public Reader(string text)
            {
                this.text = text ?? throw new ArgumentNullException(nameof(text));
            }

            public bool AtEnd => at >= text.Length;

            public char Peek() => at < text.Length ? text[at] : '\0';

            public void Advance() => at++;

            public FormatException Error(string message) =>
                new FormatException(message + " at character " + at);

            public void SkipWhitespace()
            {
                while (at < text.Length && (text[at] == ' ' || text[at] == '\t' || text[at] == '\n' || text[at] == '\r'))
                {
                    at++;
                }
            }

            public object Value(int depth)
            {
                if (depth > MaxDepth) throw Error("nested too deeply");
                SkipWhitespace();
                if (AtEnd) throw Error("unexpected end of the JSON text");
                var c = text[at];
                switch (c)
                {
                    case '{': return Object(depth);
                    case '[': return Array(depth);
                    case '"': return String();
                    case 't': Literal("true"); return true;
                    case 'f': Literal("false"); return false;
                    case 'n': Literal("null"); return null;
                    default:
                        if (c == '-' || (c >= '0' && c <= '9')) return Integer();
                        throw Error("unexpected '" + c + "'");
                }
            }

            private Dictionary<string, object> Object(int depth)
            {
                var obj = new Dictionary<string, object>(StringComparer.Ordinal);
                at++;
                SkipWhitespace();
                if (Peek() == '}') { at++; return obj; }
                while (true)
                {
                    SkipWhitespace();
                    if (Peek() != '"') throw Error("expected a member name");
                    var name = String();
                    if (obj.ContainsKey(name)) throw Error("member '" + name + "' appears twice");
                    SkipWhitespace();
                    if (Peek() != ':') throw Error("expected ':'");
                    at++;
                    obj[name] = Value(depth + 1);
                    SkipWhitespace();
                    var next = Peek();
                    at++;
                    if (next == '}') return obj;
                    if (next != ',') { at--; throw Error("expected ',' or '}'"); }
                }
            }

            private List<object> Array(int depth)
            {
                var list = new List<object>();
                at++;
                SkipWhitespace();
                if (Peek() == ']') { at++; return list; }
                while (true)
                {
                    list.Add(Value(depth + 1));
                    SkipWhitespace();
                    var next = Peek();
                    at++;
                    if (next == ']') return list;
                    if (next != ',') { at--; throw Error("expected ',' or ']'"); }
                }
            }

            private string String()
            {
                at++; // opening quote
                var sb = new StringBuilder();
                while (true)
                {
                    if (AtEnd) throw Error("unterminated string");
                    var c = text[at++];
                    if (c == '"') break;
                    if (c < 0x20) { at--; throw Error("control character in a string"); }
                    if (c != '\\') { sb.Append(c); continue; }

                    if (AtEnd) throw Error("unterminated escape");
                    var e = text[at++];
                    switch (e)
                    {
                        case '"': sb.Append('"'); break;
                        case '\\': sb.Append('\\'); break;
                        case '/': sb.Append('/'); break;
                        case 'b': sb.Append('\b'); break;
                        case 'f': sb.Append('\f'); break;
                        case 'n': sb.Append('\n'); break;
                        case 'r': sb.Append('\r'); break;
                        case 't': sb.Append('\t'); break;
                        case 'u':
                            if (at + 4 > text.Length
                                || !int.TryParse(text.Substring(at, 4), NumberStyles.AllowHexSpecifier,
                                    CultureInfo.InvariantCulture, out var code))
                            {
                                throw Error("malformed \\u escape");
                            }
                            at += 4;
                            sb.Append((char)code);
                            break;
                        default:
                            throw Error("unknown escape '\\" + e + "'");
                    }
                }

                var s = sb.ToString();
                for (var i = 0; i < s.Length; i++)
                {
                    if (char.IsHighSurrogate(s[i]) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) { i++; continue; }
                    if (char.IsSurrogate(s[i])) throw Error("lone surrogate in a string");
                }
                return s;
            }

            private void Literal(string word)
            {
                if (string.CompareOrdinal(text, at, word, 0, word.Length) != 0) throw Error("unexpected token");
                at += word.Length;
            }

            private long Integer()
            {
                var start = at;
                if (Peek() == '-') at++;
                if (Peek() == '0') at++;
                else if (Peek() >= '1' && Peek() <= '9') { while (Peek() >= '0' && Peek() <= '9') at++; }
                else throw Error("malformed number");
                if (Peek() == '.' || Peek() == 'e' || Peek() == 'E')
                {
                    throw Error("only integers are accepted");
                }
                if (!long.TryParse(text.Substring(start, at - start), NumberStyles.AllowLeadingSign,
                        CultureInfo.InvariantCulture, out var n) || n > MaxSafeInteger || n < -MaxSafeInteger)
                {
                    throw Error("integer out of range");
                }
                return n;
            }
        }
    }
}
