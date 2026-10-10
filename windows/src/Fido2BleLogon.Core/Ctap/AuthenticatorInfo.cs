namespace Fido2BleLogon.Ctap;

/// <summary>The authenticatorGetInfo response (CTAP 2.1 §6.4).</summary>
public sealed class AuthenticatorInfo(CborMap raw)
{
    public CborMap Raw { get; } = raw;

    public IReadOnlyList<string> Versions => Strings(Raw[1]);
    public IReadOnlyList<string> Extensions => Strings(Raw[2]);
    public byte[]? Aaguid => Raw[3] as byte[];
    public CborMap? Options => Raw[4] as CborMap;
    public long? MaxMsgSize => Raw[5] as long?;
    public IReadOnlyList<long> PinUvAuthProtocols => (Raw[6] as List<object?>)?.OfType<long>().ToList() ?? [];
    public string? FirmwareVersion => Raw[0x0E] is long v ? $"{v} (0x{v:X})" : null;

    public bool SupportsHmacSecret => Extensions.Contains("hmac-secret");

    /// <summary>The value of an option, or null if the authenticator doesn't list it.</summary>
    public bool? Option(string name) => Options?[name] as bool?;

    /// <summary>True when built-in UV (the fingerprint) is supported and at least one finger is enrolled.</summary>
    public bool FingerprintReady => Option("uv") == true;

    /// <summary>CTAP 2.1 authenticators hand out UV tokens; CTAP 2.0 ones take the "uv" option directly.</summary>
    public bool UsesUvTokens => Option("pinUvAuthToken") == true;

    /// <summary>The strongest PIN/UV protocol both sides support (CTAP 2.0 keys that omit the list use protocol one).</summary>
    public PinUvAuthProtocol PreferredProtocol =>
        PinUvAuthProtocol.Create(PinUvAuthProtocols.Contains(2) ? 2 : 1);

    private static List<string> Strings(object? value) => (value as List<object?>)?.OfType<string>().ToList() ?? [];
}
