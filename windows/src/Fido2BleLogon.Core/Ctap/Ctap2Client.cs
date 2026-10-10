using System.Formats.Cbor;
using System.Security.Cryptography;

namespace Fido2BleLogon.Ctap;

/// <summary>Proof of user verification for one operation (CTAP 2.1 pinUvAuthToken). When an operation is
/// given no token, it sends the CTAP 2.0 "uv" option and the key checks the fingerprint itself.</summary>
public sealed record UvToken(PinUvAuthProtocol Protocol, byte[] Token);

/// <summary>Input for the hmac-secret extension: a 32-byte salt, protected by an ECDH shared secret.</summary>
public sealed record HmacSecretInput(PinUvAuthProtocol Protocol, KeyAgreement KeyAgreement, byte[] Salt);

public sealed record Assertion(AuthenticatorData AuthData, byte[] Signature, byte[]? HmacSecret);

/// <summary>The CTAP2 commands this tool needs (CTAP 2.1 §6).</summary>
public sealed class Ctap2Client(ICtapTransport transport)
{
    private const byte CmdMakeCredential = 0x01;
    private const byte CmdGetAssertion = 0x02;
    private const byte CmdGetInfo = 0x04;
    private const byte CmdClientPin = 0x06;

    private const int SubGetKeyAgreement = 0x02;
    private const int SubGetPinUvAuthTokenUsingUvWithPermissions = 0x06;
    private const int SubGetUvRetries = 0x07;

    public const byte PermissionMakeCredential = 0x01;
    public const byte PermissionGetAssertion = 0x02;

    public async Task<AuthenticatorInfo> GetInfoAsync(CancellationToken ct) =>
        new(await SendAsync(CmdGetInfo, null, ct) ?? throw new CtapProtocolException("getInfo returned nothing."));

    /// <summary>Fetches the key's ECDH public key and derives a fresh shared secret with it.</summary>
    public async Task<KeyAgreement> GetKeyAgreementAsync(PinUvAuthProtocol protocol, CancellationToken ct)
    {
        var w = NewWriter();
        w.WriteStartMap(2);
        w.WriteInt32(1); w.WriteInt32(protocol.Version);
        w.WriteInt32(2); w.WriteInt32(SubGetKeyAgreement);
        w.WriteEndMap();
        var response = await SendAsync(CmdClientPin, w.Encode(), ct);
        var key = response?[1] as CborMap ?? throw new CtapProtocolException("The key returned no key agreement key.");
        try
        {
            return protocol.Encapsulate(key);
        }
        catch (CryptographicException ex)
        {
            throw new CtapProtocolException($"The key's key agreement key is invalid ({ex.Message})");
        }
    }

    /// <summary>Built-in fingerprint attempts left before the key blocks them (CTAP 2.1 getUVRetries), or null
    /// when the key can't tell. Every request that ends without a match may use one up.</summary>
    public async Task<int?> GetUvRetriesAsync(PinUvAuthProtocol protocol, CancellationToken ct)
    {
        var w = NewWriter();
        w.WriteStartMap(2);
        w.WriteInt32(1); w.WriteInt32(protocol.Version);
        w.WriteInt32(2); w.WriteInt32(SubGetUvRetries);
        w.WriteEndMap();
        try
        {
            var response = await SendAsync(CmdClientPin, w.Encode(), ct);
            return response?[5] is long retries and >= 0 and <= 255 ? (int)retries : null;
        }
        catch (CtapException)
        {
            return null; // CTAP 2.0 keys don't know this subcommand
        }
    }

    /// <summary>CTAP 2.1: the key verifies the fingerprint and returns a single-use token for <paramref name="permissions"/>.</summary>
    public async Task<UvToken> GetUvTokenAsync(PinUvAuthProtocol protocol, KeyAgreement keyAgreement, byte permissions, string rpId, CancellationToken ct)
    {
        var w = NewWriter();
        w.WriteStartMap(5);
        w.WriteInt32(1); w.WriteInt32(protocol.Version);
        w.WriteInt32(2); w.WriteInt32(SubGetPinUvAuthTokenUsingUvWithPermissions);
        w.WriteInt32(3); Cbor.WriteCoseEcdhKey(w, keyAgreement.X, keyAgreement.Y);
        w.WriteInt32(9); w.WriteInt32(permissions);
        w.WriteInt32(10); w.WriteTextString(rpId);
        w.WriteEndMap();
        var response = await SendAsync(CmdClientPin, w.Encode(), ct);
        var encrypted = response?[2] as byte[] ?? throw new CtapProtocolException("The key returned no UV token.");
        return new UvToken(protocol, Decrypt(protocol, keyAgreement, encrypted, "UV token"));
    }

    /// <summary>Creates a non-discoverable ES256 credential with hmac-secret enabled. Requires the fingerprint.</summary>
    /// <param name="credProtect">credProtect policy; 3 makes the credential unusable without user verification.</param>
    public async Task<AuthenticatorData> MakeCredentialAsync(string rpId, byte[] userId, string userName, byte[] clientDataHash,
        UvToken? uv, int? credProtect, CancellationToken ct)
    {
        // "rk" is left out: false is the default, and CTAP 2.1 rejects the option on keys that don't list it.
        var w = NewWriter();
        w.WriteStartMap(uv is null ? 6 : 7);
        w.WriteInt32(1); w.WriteByteString(clientDataHash);
        w.WriteInt32(2);
        w.WriteStartMap(2);
        w.WriteTextString("id"); w.WriteTextString(rpId);
        w.WriteTextString("name"); w.WriteTextString(rpId);
        w.WriteEndMap();
        w.WriteInt32(3);
        w.WriteStartMap(3);
        w.WriteTextString("id"); w.WriteByteString(userId);
        w.WriteTextString("name"); w.WriteTextString(userName);
        w.WriteTextString("displayName"); w.WriteTextString(userName);
        w.WriteEndMap();
        w.WriteInt32(4);
        w.WriteStartArray(1);
        w.WriteStartMap(2);
        w.WriteTextString("alg"); w.WriteInt32(-7); // ES256
        w.WriteTextString("type"); w.WriteTextString("public-key");
        w.WriteEndMap();
        w.WriteEndArray();
        w.WriteInt32(6);
        w.WriteStartMap(credProtect is null ? 1 : 2);
        if (credProtect is int level) { w.WriteTextString("credProtect"); w.WriteInt32(level); }
        w.WriteTextString("hmac-secret"); w.WriteBoolean(true);
        w.WriteEndMap();
        if (uv is null)
        {
            w.WriteInt32(7);
            w.WriteStartMap(1);
            w.WriteTextString("uv"); w.WriteBoolean(true);
            w.WriteEndMap();
        }
        else
        {
            w.WriteInt32(8); w.WriteByteString(uv.Protocol.Authenticate(uv.Token, clientDataHash));
            w.WriteInt32(9); w.WriteInt32(uv.Protocol.Version);
        }
        w.WriteEndMap();

        var response = await SendAsync(CmdMakeCredential, w.Encode(), ct)
            ?? throw new CtapProtocolException("makeCredential returned nothing.");
        var authData = AuthenticatorData.Parse(response[2] as byte[]
            ?? throw new CtapProtocolException("makeCredential returned no authenticator data."));
        if (authData.CredentialId is null || authData.CredentialPublicKey is null)
            throw new CtapProtocolException("makeCredential returned no credential.");
        return authData;
    }

    /// <summary>Signs with an existing credential, optionally evaluating hmac-secret. Requires the fingerprint.</summary>
    public async Task<Assertion> GetAssertionAsync(string rpId, byte[] clientDataHash, byte[] credentialId, UvToken? uv, HmacSecretInput? hmacSecret, CancellationToken ct)
    {
        var w = NewWriter();
        w.WriteStartMap(3 + (hmacSecret is null ? 0 : 1) + (uv is null ? 1 : 2));
        w.WriteInt32(1); w.WriteTextString(rpId);
        w.WriteInt32(2); w.WriteByteString(clientDataHash);
        w.WriteInt32(3);
        w.WriteStartArray(1);
        w.WriteStartMap(2);
        w.WriteTextString("id"); w.WriteByteString(credentialId);
        w.WriteTextString("type"); w.WriteTextString("public-key");
        w.WriteEndMap();
        w.WriteEndArray();
        if (hmacSecret is not null)
        {
            var (protocol, keyAgreement, salt) = hmacSecret;
            var saltEnc = protocol.Encrypt(keyAgreement.SharedSecret, salt);
            w.WriteInt32(4);
            w.WriteStartMap(1);
            w.WriteTextString("hmac-secret");
            w.WriteStartMap(protocol.Version == 1 ? 3 : 4);
            w.WriteInt32(1); Cbor.WriteCoseEcdhKey(w, keyAgreement.X, keyAgreement.Y);
            w.WriteInt32(2); w.WriteByteString(saltEnc);
            w.WriteInt32(3); w.WriteByteString(protocol.Authenticate(keyAgreement.SharedSecret, saltEnc));
            if (protocol.Version != 1) { w.WriteInt32(4); w.WriteInt32(protocol.Version); }
            w.WriteEndMap();
            w.WriteEndMap();
        }
        if (uv is null)
        {
            w.WriteInt32(5);
            w.WriteStartMap(1);
            w.WriteTextString("uv"); w.WriteBoolean(true);
            w.WriteEndMap();
        }
        else
        {
            w.WriteInt32(6); w.WriteByteString(uv.Protocol.Authenticate(uv.Token, clientDataHash));
            w.WriteInt32(7); w.WriteInt32(uv.Protocol.Version);
        }
        w.WriteEndMap();

        var response = await SendAsync(CmdGetAssertion, w.Encode(), ct)
            ?? throw new CtapProtocolException("getAssertion returned nothing.");
        var authData = AuthenticatorData.Parse(response[2] as byte[]
            ?? throw new CtapProtocolException("getAssertion returned no authenticator data."));
        var signature = response[3] as byte[] ?? throw new CtapProtocolException("getAssertion returned no signature.");

        byte[]? secret = null;
        if (hmacSecret is not null)
        {
            var encrypted = authData.Extensions?["hmac-secret"] as byte[]
                ?? throw new CtapProtocolException("The key did not return an hmac-secret output.");
            secret = Decrypt(hmacSecret.Protocol, hmacSecret.KeyAgreement, encrypted, "hmac-secret output");
            if (secret.Length != 32)
                throw new CtapProtocolException($"Unexpected hmac-secret output length {secret.Length}.");
        }
        return new Assertion(authData, signature, secret);
    }

    /// <summary>Extracts the P-256 coordinates from a COSE ES256 public key.</summary>
    public static (byte[] X, byte[] Y) ReadEs256PublicKey(CborMap coseKey)
    {
        if (coseKey[1] is not 2L || coseKey[3] is not -7L || coseKey[-1] is not 1L
            || coseKey[-2] is not byte[] { Length: 32 } x || coseKey[-3] is not byte[] { Length: 32 } y)
            throw new CtapProtocolException("The credential public key is not an ES256 P-256 key.");
        return (x, y);
    }

    /// <summary>Checks an ES256 assertion signature (over authData || clientDataHash) against a P-256 public key.</summary>
    public static bool VerifySignature(byte[] x, byte[] y, byte[] authData, byte[] clientDataHash, byte[] signature)
    {
        using var ecdsa = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = x, Y = y },
        });
        byte[] signedData = [.. authData, .. clientDataHash];
        return ecdsa.VerifyData(signedData, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
    }

    private static CborWriter NewWriter() => new(CborConformanceMode.Ctap2Canonical);

    private static byte[] Decrypt(PinUvAuthProtocol protocol, KeyAgreement keyAgreement, byte[] ciphertext, string what)
    {
        try
        {
            return protocol.Decrypt(keyAgreement.SharedSecret, ciphertext);
        }
        catch (CryptographicException ex)
        {
            throw new CtapProtocolException($"The key sent an invalid {what} ({ex.Message})");
        }
    }

    private async Task<CborMap?> SendAsync(byte command, byte[]? payload, CancellationToken ct)
    {
        byte[] request = payload is null ? [command] : [command, .. payload];
        var response = await transport.TransceiveAsync(request, ct);
        if (response.Length == 0)
            throw new CtapProtocolException("Empty response from the security key.");
        if (response[0] != 0)
            throw new CtapException(response[0]);
        return response.Length == 1
            ? null
            : Cbor.Decode(response.AsMemory(1)) as CborMap
                ?? throw new CtapProtocolException("The security key sent a response that isn't a CBOR map.");
    }
}
