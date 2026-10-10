namespace Fido2BleLogon.Ble;

/// <summary>CTAP 2.1 §11.4 framing. A message travels as an initialization fragment (CMD | HLEN | LLEN | DATA)
/// followed by continuation fragments (SEQ | DATA), each at most the key's fidoControlPointLength.</summary>
internal static class BleFraming
{
    public const byte CmdPing = 0x81;
    public const byte CmdKeepalive = 0x82;
    public const byte CmdMsg = 0x83;
    public const byte CmdCancel = 0xBE;
    public const byte CmdError = 0xBF;
    public const byte KeepaliveUpNeeded = 0x02;

    public static List<byte[]> Fragment(byte command, ReadOnlySpan<byte> data, int maxFragmentLength)
    {
        if (data.Length > ushort.MaxValue)
            throw new BleFidoException("Request too large for Bluetooth framing.");
        ArgumentOutOfRangeException.ThrowIfLessThan(maxFragmentLength, 20);

        int first = Math.Min(data.Length, maxFragmentLength - 3);
        byte[] initialization = [command, (byte)(data.Length >> 8), (byte)data.Length, .. data[..first]];
        var frames = new List<byte[]> { initialization };
        int offset = first;
        byte sequence = 0;
        while (offset < data.Length)
        {
            int count = Math.Min(data.Length - offset, maxFragmentLength - 1);
            frames.Add([sequence, .. data.Slice(offset, count)]);
            offset += count;
            sequence = (byte)((sequence + 1) & 0x7F);
        }
        return frames;
    }
}

/// <summary>Reassembles one response from fidoStatus notifications.</summary>
internal sealed class BleResponseAssembler(byte expectedCommand)
{
    private byte[]? _payload;
    private int _received;
    private byte _sequence;

    /// <summary>Adds a frame. Returns the payload once complete, otherwise null; a keepalive frame reports its status
    /// through <paramref name="keepalive"/>. Throws <see cref="BleFidoException"/> on error frames and bad sequences.</summary>
    public byte[]? Add(byte[] frame, out byte? keepalive)
    {
        keepalive = null;
        if (_payload is null)
        {
            if (frame.Length < 3)
                throw new BleFidoException("Truncated frame from the security key.");
            byte command = frame[0];
            if (command == BleFraming.CmdKeepalive)
            {
                keepalive = frame.Length > 3 ? frame[3] : (byte)0;
                return null;
            }
            if (command == BleFraming.CmdError)
                throw new BleFidoException($"The key reported a Bluetooth framing error 0x{(frame.Length > 3 ? frame[3] : 0):X2}.");
            if (command != expectedCommand)
                return null; // stray continuation from an aborted exchange

            _payload = new byte[(frame[1] << 8) | frame[2]];
            _received = Math.Min(_payload.Length, frame.Length - 3);
            frame.AsSpan(3, _received).CopyTo(_payload);
        }
        else
        {
            if (frame.Length < 1 || frame[0] != _sequence)
                throw new BleFidoException($"Out-of-order fragment from the key (expected {_sequence}, got {(frame.Length > 0 ? frame[0] : -1)}).");
            int count = Math.Min(_payload.Length - _received, frame.Length - 1);
            frame.AsSpan(1, count).CopyTo(_payload.AsSpan(_received));
            _received += count;
            _sequence = (byte)((_sequence + 1) & 0x7F);
        }
        return _received >= _payload.Length ? _payload : null;
    }
}
