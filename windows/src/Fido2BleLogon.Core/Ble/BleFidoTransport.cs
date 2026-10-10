using System.Buffers.Binary;
using System.Threading.Channels;
using Fido2BleLogon.Ctap;
using Windows.Devices.Bluetooth;
using Windows.Devices.Bluetooth.GenericAttributeProfile;
using Windows.Devices.Enumeration;
using Windows.Security.Cryptography;

namespace Fido2BleLogon.Ble;

/// <summary>A paired Bluetooth LE device that exposes the FIDO service.</summary>
public sealed record PairedKey(string Name, ulong Address)
{
    public override string ToString() => $"{Name} ({BleFidoTransport.FormatAddress(Address)})";
}

public sealed class BleFidoException(string message) : Exception(message);

/// <summary>CTAP2 over Bluetooth LE (CTAP 2.1 §11.4): framed messages are written to fidoControlPoint and
/// answered through fidoStatus notifications. Windows only lets elevated processes (or SYSTEM) open this service.</summary>
public sealed class BleFidoTransport : ICtapTransport
{
    public static readonly Guid FidoServiceUuid = new("0000fffd-0000-1000-8000-00805f9b34fb");
    private static readonly Guid ControlPointUuid = new("f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb");
    private static readonly Guid StatusUuid = new("f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb");
    private static readonly Guid ControlPointLengthUuid = new("f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb");
    private static readonly Guid ServiceRevisionBitfieldUuid = new("f1d0fff4-deaa-ecee-b42f-c9ba7ed623bb");

    private const byte CmdMsg = BleFraming.CmdMsg;
    private const byte CmdCancel = BleFraming.CmdCancel;
    private const byte RevisionFido2 = 0x20;

    /// <summary>Longest a single request may take, fingerprint wait included.</summary>
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(90);

    // Bounded so a key flooding notifications can't grow memory; the largest response (64 KiB) is ~430 frames.
    private const int MaxQueuedFrames = 1024;

    private const string AccessDeniedMessage = "Windows denied access to the key's FIDO Bluetooth service. Run this as administrator.";
    private const string DisconnectedMessage = "The security key disconnected (it may have gone to sleep).";

    private readonly BluetoothLEDevice _device;
    private readonly GattSession _session;
    private readonly GattDeviceService _service;
    private readonly GattCharacteristic _controlPoint;
    private readonly GattCharacteristic _status;
    private readonly Channel<byte[]> _frames = Channel.CreateBounded<byte[]>(
        new BoundedChannelOptions(MaxQueuedFrames) { FullMode = BoundedChannelFullMode.DropWrite, SingleReader = true });
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly TaskCompletionSource _disconnected = new(TaskCreationOptions.RunContinuationsAsynchronously);

    private BleFidoTransport(BluetoothLEDevice device, GattSession session, GattDeviceService service,
        GattCharacteristic controlPoint, GattCharacteristic status, int maxFragmentLength, byte offeredRevisions)
    {
        _device = device;
        _session = session;
        _service = service;
        _controlPoint = controlPoint;
        _status = status;
        MaxFragmentLength = maxFragmentLength;
        OfferedRevisions = offeredRevisions;
    }

    public event Action? WaitingForUser;

    /// <summary>Largest fragment the key accepts (fidoControlPointLength).</summary>
    public int MaxFragmentLength { get; }

    /// <summary>Protocol revisions the key offered (fidoServiceRevisionBitfield; 0x20 = FIDO2).</summary>
    public byte OfferedRevisions { get; }

    /// <summary>Lists paired LE devices whose cached GATT database includes the FIDO service.</summary>
    public static async Task<IReadOnlyList<PairedKey>> FindPairedKeysAsync()
    {
        var infos = await DeviceInformation.FindAllAsync(BluetoothLEDevice.GetDeviceSelectorFromPairingState(true));
        var keys = new List<PairedKey>();
        foreach (var info in infos)
        {
            using var device = await BluetoothLEDevice.FromIdAsync(info.Id);
            if (device is null)
                continue;
            var result = await device.GetGattServicesForUuidAsync(FidoServiceUuid, BluetoothCacheMode.Cached);
            bool isKey = result.Status == GattCommunicationStatus.Success && result.Services.Count > 0;
            foreach (var service in result.Services)
                service.Dispose();
            if (isKey)
                keys.Add(new PairedKey(SafeName(device.Name), device.BluetoothAddress));
        }
        return keys;
    }

    /// <summary>Connects to the key, waiting up to <paramref name="wakeTimeout"/> for it to wake up.</summary>
    /// <param name="waitingForKey">Called once if the key is asleep, so the caller can ask for a button press.</param>
    public static async Task<BleFidoTransport> ConnectAsync(ulong address, TimeSpan wakeTimeout, Action? waitingForKey, CancellationToken ct)
    {
        var device = await BluetoothLEDevice.FromBluetoothAddressAsync(address).AsTask(ct)
            ?? throw new BleFidoException($"No paired Bluetooth device with address {FormatAddress(address)}.");
        GattSession? session = null;
        GattDeviceService? service = null;
        try
        {
            session = await GattSession.FromDeviceIdAsync(device.BluetoothDeviceId).AsTask(ct);
            session.MaintainConnection = true;

            // MaintainConnection makes Windows reconnect by itself as soon as the key wakes up and advertises.
            // So while the key sleeps, only watch the connection state (no radio traffic, kind to the battery when
            // a lock screen waits for hours); query the key when it connects, plus now and then as a fallback.
            var deadline = DateTime.UtcNow + wakeTimeout;
            var nextQuery = DateTime.MinValue;
            bool announced = false;
            while (service is null)
            {
                if (device.ConnectionStatus == BluetoothConnectionStatus.Connected || DateTime.UtcNow >= nextQuery)
                {
                    var result = await device.GetGattServicesForUuidAsync(FidoServiceUuid, BluetoothCacheMode.Uncached).AsTask(ct);
                    if (result.Status == GattCommunicationStatus.Success && result.Services.Count > 0)
                    {
                        service = result.Services[0];
                        foreach (var extra in result.Services.Skip(1))
                            extra.Dispose();
                        break;
                    }
                    if (result.Status == GattCommunicationStatus.AccessDenied)
                        throw new UnauthorizedAccessException(AccessDeniedMessage);
                    nextQuery = DateTime.UtcNow + TimeSpan.FromSeconds(5);
                }
                if (!announced)
                {
                    waitingForKey?.Invoke();
                    announced = true;
                }
                if (DateTime.UtcNow > deadline)
                    throw new TimeoutException("The security key did not respond. Press its button to wake it and try again.");
                await Task.Delay(250, ct);
            }

            var open = await service.OpenAsync(GattSharingMode.SharedReadAndWrite).AsTask(ct);
            if (open == GattOpenStatus.AccessDenied)
                throw new UnauthorizedAccessException(AccessDeniedMessage);
            if (open is not (GattOpenStatus.Success or GattOpenStatus.AlreadyOpened))
                throw new BleFidoException($"Could not open the key's FIDO service: {open}.");

            var characteristics = await service.GetCharacteristicsAsync(BluetoothCacheMode.Uncached).AsTask(ct);
            if (characteristics.Status == GattCommunicationStatus.AccessDenied)
                throw new UnauthorizedAccessException(AccessDeniedMessage);
            if (characteristics.Status != GattCommunicationStatus.Success)
                throw new BleFidoException($"Could not read the key's FIDO characteristics: {characteristics.Status}.");
            GattCharacteristic? Find(Guid uuid) => characteristics.Characteristics.FirstOrDefault(c => c.Uuid == uuid);
            var controlPoint = Find(ControlPointUuid) ?? throw new BleFidoException("The key has no fidoControlPoint.");
            var status = Find(StatusUuid) ?? throw new BleFidoException("The key has no fidoStatus.");
            var lengthChar = Find(ControlPointLengthUuid) ?? throw new BleFidoException("The key has no fidoControlPointLength.");
            var revisionChar = Find(ServiceRevisionBitfieldUuid) ?? throw new BleFidoException("The key does not support FIDO2 over Bluetooth.");

            var length = await ReadAsync(lengthChar, ct);
            int maxFragment = length.Length >= 2 ? BinaryPrimitives.ReadUInt16BigEndian(length) : 20;
            if (maxFragment < 20)
                throw new BleFidoException($"The key reported an invalid fragment size ({maxFragment}).");

            var revisions = await ReadAsync(revisionChar, ct);
            byte offered = revisions.Length > 0 ? revisions[0] : (byte)0;
            if ((offered & RevisionFido2) == 0)
                throw new BleFidoException($"The key does not offer FIDO2 over Bluetooth (revisions 0x{offered:X2}).");
            await WriteAsync(revisionChar, [RevisionFido2], ct);

            var transport = new BleFidoTransport(device, session, service, controlPoint, status, maxFragment, offered);
            await transport.SubscribeAsync(ct);
            return transport;
        }
        catch
        {
            service?.Dispose();
            session?.Dispose();
            device.Dispose();
            throw;
        }
    }

    public async Task<byte[]> TransceiveAsync(byte[] request, CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            // A key may power down after a command that needed the user (CTAP 2.1 §11.4.14). Fail fast so the
            // caller can reconnect, instead of waiting for Windows to time out a write to a sleeping key.
            if (_device.ConnectionStatus == BluetoothConnectionStatus.Disconnected)
                throw new BleFidoException(DisconnectedMessage);
            while (_frames.Reader.TryRead(out _)) { } // drop anything left over from an earlier request
            await SendAsync(CmdMsg, request);
            // A real key ends a fingerprint wait by itself after about 30 s; a broken or hostile one could keep
            // sending keepalives forever, so every request also has a hard limit.
            using var limit = CancellationTokenSource.CreateLinkedTokenSource(ct);
            limit.CancelAfter(RequestTimeout);
            try
            {
                return await ReceiveAsync(CmdMsg, limit.Token);
            }
            catch (OperationCanceledException)
            {
                // Stop the key waiting for a finger that isn't coming. Bounded: the link may already be gone.
                try { await WriteAsync(_controlPoint, [CmdCancel, 0, 0]).WaitAsync(TimeSpan.FromSeconds(2)); } catch { }
                if (!ct.IsCancellationRequested)
                    throw new BleFidoException("The security key stopped responding.");
                throw;
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public ValueTask DisposeAsync()
    {
        _status.ValueChanged -= OnStatusChanged;
        _device.ConnectionStatusChanged -= OnConnectionStatusChanged;
        _service.Dispose();
        _session.Dispose();
        _device.Dispose();
        _gate.Dispose();
        return ValueTask.CompletedTask;
    }

    /// <summary>A device name as the device chose it can carry control characters (terminal escapes) and any length;
    /// keep it printable and short before showing it.</summary>
    public static string SafeName(string? name) =>
        new string((name ?? "").Where(c => !char.IsControl(c) && !char.IsSurrogate(c)).Take(40).ToArray()).Trim();

    public static string FormatAddress(ulong address) =>
        string.Join(':', Enumerable.Range(0, 6).Select(i => ((address >> (8 * (5 - i))) & 0xFF).ToString("X2")));

    public static ulong ParseAddress(string text) => Convert.ToUInt64(text.Replace(":", "").Replace("-", ""), 16);

    private async Task SubscribeAsync(CancellationToken ct)
    {
        _status.ValueChanged += OnStatusChanged;
        _device.ConnectionStatusChanged += OnConnectionStatusChanged;
        var result = await _status.WriteClientCharacteristicConfigurationDescriptorWithResultAsync(
            GattClientCharacteristicConfigurationDescriptorValue.Notify).AsTask(ct);
        if (result.Status != GattCommunicationStatus.Success)
            throw new BleFidoException($"Could not subscribe to the key's responses: {result.Status}.");
    }

    private void OnStatusChanged(GattCharacteristic sender, GattValueChangedEventArgs args)
    {
        CryptographicBuffer.CopyToByteArray(args.CharacteristicValue, out byte[] frame);
        if (frame is { Length: > 0 })
            _frames.Writer.TryWrite(frame);
    }

    // An empty frame tells a pending receive that the link is gone.
    private void OnConnectionStatusChanged(BluetoothLEDevice sender, object args)
    {
        if (sender.ConnectionStatus == BluetoothConnectionStatus.Disconnected)
        {
            _frames.Writer.TryWrite([]);
            _disconnected.TrySetResult();
        }
    }

    public Task WaitForDisconnectAsync(CancellationToken ct)
    {
        if (_device.ConnectionStatus == BluetoothConnectionStatus.Disconnected)
            _disconnected.TrySetResult();
        return _disconnected.Task.WaitAsync(ct);
    }

    private async Task SendAsync(byte command, byte[] data)
    {
        foreach (var frame in BleFraming.Fragment(command, data, MaxFragmentLength))
            await WriteAsync(_controlPoint, frame);
    }

    private async Task<byte[]> ReceiveAsync(byte expectedCommand, CancellationToken ct)
    {
        var assembler = new BleResponseAssembler(expectedCommand);
        bool announcedUser = false;
        while (true)
        {
            var payload = assembler.Add(await NextFrameAsync(ct), out var keepalive);
            if (keepalive == BleFraming.KeepaliveUpNeeded && !announcedUser)
            {
                announcedUser = true;
                WaitingForUser?.Invoke();
            }
            if (payload is not null)
                return payload;
        }
    }

    private async Task<byte[]> NextFrameAsync(CancellationToken ct)
    {
        var frame = await _frames.Reader.ReadAsync(ct);
        if (frame.Length == 0)
            throw new BleFidoException(DisconnectedMessage);
        return frame;
    }

    private static async Task<byte[]> ReadAsync(GattCharacteristic characteristic, CancellationToken ct)
    {
        var result = await characteristic.ReadValueAsync(BluetoothCacheMode.Uncached).AsTask(ct);
        if (result.Status != GattCommunicationStatus.Success)
            throw new BleFidoException($"Bluetooth read failed: {result.Status}.");
        CryptographicBuffer.CopyToByteArray(result.Value, out byte[] value);
        return value ?? [];
    }

    private static async Task WriteAsync(GattCharacteristic characteristic, byte[] data, CancellationToken ct = default)
    {
        var result = await characteristic.WriteValueWithResultAsync(
            CryptographicBuffer.CreateFromByteArray(data), GattWriteOption.WriteWithResponse).AsTask(ct);
        if (result.Status != GattCommunicationStatus.Success)
            throw new BleFidoException($"Bluetooth write failed: {result.Status}"
                + (result.ProtocolError is byte error ? $" (ATT error 0x{error:X2})." : "."));
    }
}
