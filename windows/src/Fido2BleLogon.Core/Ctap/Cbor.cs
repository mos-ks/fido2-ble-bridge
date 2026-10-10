using System.Formats.Cbor;
using System.Text;

namespace Fido2BleLogon.Ctap;

/// <summary>A decoded CBOR map. CTAP keys are integers (boxed as <see cref="long"/>) or text.</summary>
public sealed class CborMap
{
    private readonly Dictionary<object, object?> _items = [];

    public object? this[long key] => _items.GetValueOrDefault(key);
    public object? this[string key] => _items.GetValueOrDefault(key);

    public IEnumerable<KeyValuePair<object, object?>> Entries => _items;

    internal void Set(object key, object? value) => _items[key] = value;
}

/// <summary>Just enough CBOR for CTAP2: decode to plain objects, and display them.</summary>
public static class Cbor
{
    // CTAP messages nest a few levels at most; a limit keeps a malicious response from overflowing the stack.
    private const int MaxDepth = 16;

    /// <summary>Decodes a single CBOR value: maps become <see cref="CborMap"/>, arrays <see cref="List{T}"/>,
    /// integers <see cref="long"/>, byte strings <c>byte[]</c>. Malformed input throws <see cref="CtapProtocolException"/>.</summary>
    public static object? Decode(ReadOnlyMemory<byte> data)
    {
        try
        {
            return Read(new CborReader(data, CborConformanceMode.Lax));
        }
        catch (Exception ex) when (IsMalformed(ex))
        {
            throw new CtapProtocolException($"The security key sent malformed CBOR ({ex.Message})");
        }
    }

    /// <summary>Reads the next value; callers convert failures with <see cref="IsMalformed"/>.</summary>
    public static object? Read(CborReader reader) => Read(reader, 0);

    /// <summary>True for the exceptions <see cref="CborReader"/> throws on bad input.</summary>
    public static bool IsMalformed(Exception ex) =>
        ex is CborContentException or OverflowException or InvalidOperationException or FormatException;

    private static object? Read(CborReader reader, int depth)
    {
        if (depth > MaxDepth)
            throw new CtapProtocolException("The security key sent CBOR nested too deeply.");
        switch (reader.PeekState())
        {
            case CborReaderState.UnsignedInteger:
            case CborReaderState.NegativeInteger:
                return reader.ReadInt64();
            case CborReaderState.ByteString:
                return reader.ReadByteString();
            case CborReaderState.TextString:
                return reader.ReadTextString();
            case CborReaderState.StartArray:
            {
                reader.ReadStartArray();
                var list = new List<object?>();
                while (reader.PeekState() != CborReaderState.EndArray)
                    list.Add(Read(reader, depth + 1));
                reader.ReadEndArray();
                return list;
            }
            case CborReaderState.StartMap:
            {
                reader.ReadStartMap();
                var map = new CborMap();
                while (reader.PeekState() != CborReaderState.EndMap)
                {
                    var key = Read(reader, depth + 1) ?? throw new CtapProtocolException("CBOR map has a null key.");
                    map.Set(key, Read(reader, depth + 1));
                }
                reader.ReadEndMap();
                return map;
            }
            case CborReaderState.Boolean:
                return reader.ReadBoolean();
            case CborReaderState.Null:
                reader.ReadNull();
                return null;
            case CborReaderState.Tag:
                reader.ReadTag();
                return Read(reader, depth + 1);
            case CborReaderState.HalfPrecisionFloat:
            case CborReaderState.SinglePrecisionFloat:
            case CborReaderState.DoublePrecisionFloat:
                return reader.ReadDouble();
            default:
                reader.SkipValue();
                return null;
        }
    }

    /// <summary>Writes a P-256 public key as a COSE_Key for ECDH-ES+HKDF-256 (CTAP2 keyAgreement).</summary>
    public static void WriteCoseEcdhKey(CborWriter writer, byte[] x, byte[] y)
    {
        writer.WriteStartMap(5);
        writer.WriteInt32(1); writer.WriteInt32(2);     // kty: EC2
        writer.WriteInt32(3); writer.WriteInt32(-25);   // alg: ECDH-ES+HKDF-256
        writer.WriteInt32(-1); writer.WriteInt32(1);    // crv: P-256
        writer.WriteInt32(-2); writer.WriteByteString(x);
        writer.WriteInt32(-3); writer.WriteByteString(y);
        writer.WriteEndMap();
    }

    public static string ToDisplayString(object? value, int indent = 0)
    {
        var pad = new string(' ', indent);
        switch (value)
        {
            case null:
                return "null";
            case bool b:
                return b ? "true" : "false";
            case string s:
                return $"\"{s}\"";
            case byte[] bytes:
                return $"h'{Convert.ToHexString(bytes)}'";
            case List<object?> list:
                return list.All(v => v is not CborMap)
                    ? "[" + string.Join(", ", list.Select(v => ToDisplayString(v))) + "]"
                    : "[\n" + string.Join(",\n", list.Select(v => pad + "  " + ToDisplayString(v, indent + 2))) + "\n" + pad + "]";
            case CborMap map:
            {
                var sb = new StringBuilder("{\n");
                foreach (var (k, v) in map.Entries)
                    sb.Append(pad).Append("  ").Append(ToDisplayString(k)).Append(": ").Append(ToDisplayString(v, indent + 2)).Append('\n');
                return sb.Append(pad).Append('}').ToString();
            }
            default:
                return Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture) ?? "?";
        }
    }
}
