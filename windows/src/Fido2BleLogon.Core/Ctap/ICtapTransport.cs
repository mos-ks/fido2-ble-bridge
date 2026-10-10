namespace Fido2BleLogon.Ctap;

/// <summary>A channel that carries CTAP2 messages to an authenticator.</summary>
public interface ICtapTransport : IAsyncDisposable
{
    /// <summary>Raised once per request when the authenticator starts waiting for the user (finger on the sensor).</summary>
    event Action? WaitingForUser;

    /// <summary>Sends a CTAP2 request (command byte + CBOR) and returns the response (status byte + CBOR).</summary>
    Task<byte[]> TransceiveAsync(byte[] request, CancellationToken cancellationToken);

    /// <summary>Completes when the link to the authenticator drops (for a BLE key: it went to sleep).</summary>
    Task WaitForDisconnectAsync(CancellationToken cancellationToken);
}
