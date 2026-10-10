using Fido2BleLogon.Ctap;

namespace Fido2BleLogon.Core.Tests;

public class CborTests
{
    [Fact]
    public void Maps_decode_with_integer_and_text_keys()
    {
        // {1: "a", "b": h'01', -1: [true, null]}
        var map = (CborMap)Cbor.Decode(new byte[] { 0xA3, 0x01, 0x61, 0x61, 0x61, 0x62, 0x41, 0x01, 0x20, 0x82, 0xF5, 0xF6 })!;
        Assert.Equal("a", map[1]);
        Assert.Equal(new byte[] { 0x01 }, map["b"]);
        Assert.Equal(new List<object?> { true, null }, map[-1]);
    }

    [Fact]
    public void Truncated_input_is_a_protocol_error()
    {
        Assert.Throws<CtapProtocolException>(() => Cbor.Decode(new byte[] { 0xA5, 0x01 }));
    }

    [Fact]
    public void Deep_nesting_is_refused_instead_of_overflowing_the_stack()
    {
        var input = Enumerable.Repeat((byte)0x81, 10_000).Append((byte)0x00).ToArray();
        Assert.Throws<CtapProtocolException>(() => Cbor.Decode(input));
    }

    [Fact]
    public void The_canonical_reader_used_by_the_simulated_key_rejects_unsorted_keys()
    {
        // {2: 0, 1: 0}: keys out of CTAP2 canonical order. If this didn't throw, the simulated key's checks would be moot.
        var reader = new System.Formats.Cbor.CborReader(new byte[] { 0xA2, 0x02, 0x00, 0x01, 0x00 },
            System.Formats.Cbor.CborConformanceMode.Ctap2Canonical);
        Assert.ThrowsAny<Exception>(() => Cbor.Read(reader));
    }

    [Fact]
    public void Integers_beyond_64_bits_signed_are_a_protocol_error()
    {
        Assert.Throws<CtapProtocolException>(() => Cbor.Decode(new byte[] { 0x1B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }));
    }
}
