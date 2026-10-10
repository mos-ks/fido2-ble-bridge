using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;
using Fido2BleLogon.Ble;
using Fido2BleLogon.Ctap;

namespace Fido2BleLogon.Core.Tests;

/// <summary>A software CTAP2 authenticator modelled on the real key: CTAP 2.0-style built-in fingerprint check
/// through the "uv" option, PIN/UV auth protocol one, hmac-secret and credProtect. It decodes every request in
/// CTAP2 canonical mode, so the tests also check that requests are encoded canonically.</summary>
internal sealed class FakeAuthenticator
{
    private const int MaxUvRetries = 8;
    private const int TriesPerRequest = 3;

    private readonly ECDiffieHellman _keyAgreement = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
    private readonly Dictionary<string, Credential> _credentials = [];

    public bool SupportsCredProtect { get; set; } = true;
    public bool FingerprintEnrolled { get; set; } = true;

    /// <summary>Fingerprint attempts left; null models a CTAP 2.0 key without getUVRetries.</summary>
    public int? UvRetries { get; set; } = MaxUvRetries;

    /// <summary>Outcome of the next fingerprint checks; an empty queue means the finger matches.</summary>
    public Queue<bool> Fingerprints { get; } = new();

    /// <summary>Status for a failed match: 0x27 on CTAP 2.0 keys, 0x36 on CTAP 2.1 keys with a PIN set.</summary>
    public byte RejectStatus { get; set; } = CtapException.OperationDenied;

    /// <summary>Drop the link after the next command that needed the user, as CTAP 2.1 §11.4.14 allows.</summary>
    public bool DisconnectAfterUserCommand { get; set; }

    /// <summary>Answer the next command with malformed CBOR.</summary>
    public bool SendMalformedResponse { get; set; }

    public int FingerprintRequests { get; private set; }
    public int Connections { get; private set; }

    private Link? _current;

    public ICtapTransport Connect()
    {
        Connections++;
        _current = new Link(this);
        return _current;
    }

    /// <summary>The key goes to sleep: the current link drops.</summary>
    public void Sleep() => _current?.Drop();

    private sealed record Credential(ECDsa Key, byte[] CredRandom, long CredProtect, byte[] RpIdHash);

    private sealed class Status(byte code) : Exception
    {
        public byte Code { get; } = code;
    }

    private sealed class Link(FakeAuthenticator authenticator) : ICtapTransport
    {
        public bool Disconnected { get; set; }

        public event Action? WaitingForUser;

        public void AnnounceWaitingForUser() => WaitingForUser?.Invoke();

        public Task<byte[]> TransceiveAsync(byte[] request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (Disconnected)
                throw new BleFidoException("The security key disconnected (it may have gone to sleep).");
            return Task.FromResult(authenticator.Handle(this, request));
        }

        private readonly TaskCompletionSource _dropped = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public void Drop()
        {
            Disconnected = true;
            _dropped.TrySetResult();
        }

        public Task WaitForDisconnectAsync(CancellationToken cancellationToken) => _dropped.Task.WaitAsync(cancellationToken);

        public ValueTask DisposeAsync()
        {
            Disconnected = true;
            return ValueTask.CompletedTask;
        }
    }

    private byte[] Handle(Link link, byte[] request)
    {
        if (SendMalformedResponse)
        {
            SendMalformedResponse = false;
            return [0x00, 0xA5, 0x01]; // claims a 5-entry map, then ends
        }
        try
        {
            var parameters = request.Length > 1 ? DecodeCanonical(request.AsMemory(1)) : null;
            return request[0] switch
            {
                0x04 => Ok(GetInfo()),
                0x06 => Ok(ClientPin(parameters!)),
                0x01 => Ok(MakeCredential(link, parameters!)),
                0x02 => Ok(GetAssertion(link, parameters!)),
                _ => [0x01], // CTAP1_ERR_INVALID_COMMAND
            };
        }
        catch (Status status)
        {
            return [status.Code];
        }
    }

    private static CborMap DecodeCanonical(ReadOnlyMemory<byte> cbor)
    {
        try
        {
            return (CborMap)Cbor.Read(new CborReader(cbor, CborConformanceMode.Ctap2Canonical))!;
        }
        catch (Exception ex) when (Cbor.IsMalformed(ex))
        {
            throw new InvalidOperationException($"Request is not CTAP2 canonical CBOR: {ex.Message}", ex);
        }
    }

    private static byte[] Ok(byte[] cbor) => [0x00, .. cbor];

    private byte[] GetInfo()
    {
        var w = new CborWriter(CborConformanceMode.Lax);
        w.WriteStartMap(6);
        w.WriteInt32(1); WriteStrings(w, "FIDO_2_0", "FIDO_2_1_PRE");
        w.WriteInt32(2); WriteStrings(w, SupportsCredProtect ? ["credProtect", "hmac-secret"] : ["hmac-secret"]);
        w.WriteInt32(3); w.WriteByteString(new byte[16]);
        w.WriteInt32(4);
        w.WriteStartMap(3);
        w.WriteTextString("rk"); w.WriteBoolean(true);
        w.WriteTextString("uv"); w.WriteBoolean(FingerprintEnrolled);
        w.WriteTextString("clientPin"); w.WriteBoolean(true);
        w.WriteEndMap();
        w.WriteInt32(5); w.WriteInt32(2048);
        w.WriteInt32(6); w.WriteStartArray(1); w.WriteInt32(1); w.WriteEndArray();
        w.WriteEndMap();
        return w.Encode();
    }

    private byte[] ClientPin(CborMap parameters)
    {
        var w = new CborWriter(CborConformanceMode.Lax);
        switch (parameters[2])
        {
            case 2L: // getKeyAgreement
                var q = _keyAgreement.ExportParameters(false).Q;
                w.WriteStartMap(1);
                w.WriteInt32(1); Cbor.WriteCoseEcdhKey(w, q.X!, q.Y!);
                w.WriteEndMap();
                return w.Encode();
            case 7L when UvRetries is int retries: // getUVRetries
                w.WriteStartMap(1);
                w.WriteInt32(5); w.WriteInt32(retries);
                w.WriteEndMap();
                return w.Encode();
            default:
                throw new Status(0x3E); // CTAP2_ERR_INVALID_SUBCOMMAND
        }
    }

    private void CheckFingerprint(Link link)
    {
        if (UvRetries == 0)
            throw new Status(CtapException.UvBlocked);
        FingerprintRequests++;
        link.AnnounceWaitingForUser();
        if (Fingerprints.Count > 0 && !Fingerprints.Dequeue())
        {
            if (UvRetries is int left)
                UvRetries = Math.Max(0, left - TriesPerRequest);
            throw new Status(RejectStatus);
        }
        if (UvRetries is not null)
            UvRetries = MaxUvRetries;
    }

    private void AfterUserCommand(Link link)
    {
        if (DisconnectAfterUserCommand)
        {
            DisconnectAfterUserCommand = false;
            link.Disconnected = true;
        }
    }

    private byte[] MakeCredential(Link link, CborMap parameters)
    {
        var rpId = (string)((CborMap)parameters[2]!)["id"]!;
        if ((parameters[7] as CborMap)?["uv"] is not true)
            throw new Status(CtapException.PinRequired); // a PIN is set, so CTAP 2.0 wants pinAuth or built-in UV
        var extensions = parameters[6] as CborMap;
        long? credProtect = SupportsCredProtect && extensions?["credProtect"] is long level ? level : null;
        bool hmacSecret = extensions?["hmac-secret"] is true;

        CheckFingerprint(link);
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var id = RandomNumberGenerator.GetBytes(48);
        var rpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes(rpId));
        _credentials[Convert.ToHexString(id)] = new Credential(key, RandomNumberGenerator.GetBytes(32), credProtect ?? 1, rpIdHash);

        var q = key.ExportParameters(false).Q;
        var cose = new CborWriter(CborConformanceMode.Lax);
        cose.WriteStartMap(5);
        cose.WriteInt32(1); cose.WriteInt32(2);
        cose.WriteInt32(3); cose.WriteInt32(-7);
        cose.WriteInt32(-1); cose.WriteInt32(1);
        cose.WriteInt32(-2); cose.WriteByteString(q.X!);
        cose.WriteInt32(-3); cose.WriteByteString(q.Y!);
        cose.WriteEndMap();

        var ext = new CborWriter(CborConformanceMode.Lax);
        ext.WriteStartMap(credProtect is null ? 1 : 2);
        if (credProtect is long cp) { ext.WriteTextString("credProtect"); ext.WriteInt64(cp); }
        ext.WriteTextString("hmac-secret"); ext.WriteBoolean(hmacSecret);
        ext.WriteEndMap();

        byte[] authData = [.. rpIdHash, 0x01 | 0x04 | 0x40 | 0x80, 0, 0, 0, 1, .. new byte[16],
            (byte)(id.Length >> 8), (byte)id.Length, .. id, .. cose.Encode(), .. ext.Encode()];

        var w = new CborWriter(CborConformanceMode.Lax);
        w.WriteStartMap(3);
        w.WriteInt32(1); w.WriteTextString("none");
        w.WriteInt32(2); w.WriteByteString(authData);
        w.WriteInt32(3); w.WriteStartMap(0); w.WriteEndMap();
        w.WriteEndMap();
        AfterUserCommand(link);
        return w.Encode();
    }

    private byte[] GetAssertion(Link link, CborMap parameters)
    {
        var rpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes((string)parameters[1]!));
        var clientDataHash = (byte[])parameters[2]!;
        var id = (byte[])((CborMap)((List<object?>)parameters[3]!)[0]!)["id"]!;
        bool uv = (parameters[5] as CborMap)?["uv"] is true;
        if (!_credentials.TryGetValue(Convert.ToHexString(id), out var credential)
            || !credential.RpIdHash.AsSpan().SequenceEqual(rpIdHash)
            || (credential.CredProtect == 3 && !uv))
            throw new Status(CtapException.NoCredentials);
        if (uv)
            CheckFingerprint(link);

        byte[]? hmacOutput = null;
        if ((parameters[4] as CborMap)?["hmac-secret"] is CborMap input)
        {
            var platformKey = (CborMap)input[1]!;
            using var peer = ECDiffieHellman.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = (byte[])platformKey[-2]!, Y = (byte[])platformKey[-3]! },
            });
            var shared = SHA256.HashData(_keyAgreement.DeriveRawSecretAgreement(peer.PublicKey));
            var protocol = PinUvAuthProtocol.Create(1);
            var saltEnc = (byte[])input[2]!;
            if (!protocol.Authenticate(shared, saltEnc).AsSpan().SequenceEqual((byte[])input[3]!))
                throw new Status(0x02); // CTAP1_ERR_INVALID_PARAMETER
            hmacOutput = protocol.Encrypt(shared, HMACSHA256.HashData(credential.CredRandom, protocol.Decrypt(shared, saltEnc)));
        }

        byte flags = (byte)(0x01 | (uv ? 0x04 : 0) | (hmacOutput is null ? 0 : 0x80));
        byte[] authData = [.. rpIdHash, flags, 0, 0, 0, 2];
        if (hmacOutput is not null)
        {
            var ext = new CborWriter(CborConformanceMode.Lax);
            ext.WriteStartMap(1);
            ext.WriteTextString("hmac-secret"); ext.WriteByteString(hmacOutput);
            ext.WriteEndMap();
            authData = [.. authData, .. ext.Encode()];
        }
        byte[] signedData = [.. authData, .. clientDataHash];
        var signature = credential.Key.SignData(signedData, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        var w = new CborWriter(CborConformanceMode.Lax);
        w.WriteStartMap(3);
        w.WriteInt32(1);
        w.WriteStartMap(2);
        w.WriteTextString("id"); w.WriteByteString(id);
        w.WriteTextString("type"); w.WriteTextString("public-key");
        w.WriteEndMap();
        w.WriteInt32(2); w.WriteByteString(authData);
        w.WriteInt32(3); w.WriteByteString(signature);
        w.WriteEndMap();
        AfterUserCommand(link);
        return w.Encode();
    }

    private static void WriteStrings(CborWriter w, params string[] values)
    {
        w.WriteStartArray(values.Length);
        foreach (var value in values)
            w.WriteTextString(value);
        w.WriteEndArray();
    }
}
