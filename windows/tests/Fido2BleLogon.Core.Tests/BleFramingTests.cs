using Fido2BleLogon.Ble;

namespace Fido2BleLogon.Core.Tests;

public class BleFramingTests
{
    [Fact]
    public void A_short_message_fits_in_the_initialization_fragment()
    {
        var frames = BleFraming.Fragment(BleFraming.CmdMsg, [0x04], 20);
        Assert.Equal([[0x83, 0x00, 0x01, 0x04]], frames);
    }

    [Fact]
    public void Long_messages_continue_with_sequence_numbers_that_wrap_after_0x7F()
    {
        var data = Enumerable.Range(0, 17 + 19 * 130).Select(i => (byte)i).ToArray();
        var frames = BleFraming.Fragment(BleFraming.CmdMsg, data, 20);

        Assert.Equal(131, frames.Count);
        Assert.All(frames, f => Assert.True(f.Length <= 20));
        Assert.Equal([0x83, (byte)(data.Length >> 8), (byte)data.Length], frames[0][..3]);
        Assert.Equal(0x00, frames[1][0]);
        Assert.Equal(0x7F, frames[128][0]);
        Assert.Equal(0x00, frames[129][0]);
        Assert.Equal(0x01, frames[130][0]);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(152)]
    [InlineData(153)]
    [InlineData(5000)]
    public void Fragments_reassemble_to_the_original(int length)
    {
        var data = Enumerable.Range(0, length).Select(i => (byte)(i * 7)).ToArray();
        var assembler = new BleResponseAssembler(BleFraming.CmdMsg);
        byte[]? result = null;
        foreach (var frame in BleFraming.Fragment(BleFraming.CmdMsg, data, 155))
        {
            Assert.Null(result);
            result = assembler.Add(frame, out _);
        }
        Assert.Equal(data, result);
    }

    [Fact]
    public void Keepalives_report_their_status_and_are_skipped()
    {
        var assembler = new BleResponseAssembler(BleFraming.CmdMsg);
        Assert.Null(assembler.Add([0x82, 0x00, 0x01, 0x02], out var keepalive));
        Assert.Equal(BleFraming.KeepaliveUpNeeded, keepalive);
        Assert.Equal([0x00], assembler.Add([0x83, 0x00, 0x01, 0x00], out _));
    }

    [Fact]
    public void Error_frames_throw()
    {
        var assembler = new BleResponseAssembler(BleFraming.CmdMsg);
        var error = Assert.Throws<BleFidoException>(() => assembler.Add([0xBF, 0x00, 0x01, 0x05], out _));
        Assert.Contains("0x05", error.Message);
    }

    [Fact]
    public void Stray_continuations_before_a_response_are_ignored()
    {
        var assembler = new BleResponseAssembler(BleFraming.CmdMsg);
        Assert.Null(assembler.Add([0x03, 0xAA, 0xBB], out _));
        Assert.Equal([0x00], assembler.Add([0x83, 0x00, 0x01, 0x00], out _));
    }

    [Fact]
    public void Out_of_order_continuations_throw()
    {
        var assembler = new BleResponseAssembler(BleFraming.CmdMsg);
        Assert.Null(assembler.Add([0x83, 0x00, 0x05, 0x01], out _));
        Assert.Throws<BleFidoException>(() => assembler.Add([0x01, 0x02], out _));
    }
}
