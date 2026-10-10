using System.Buffers.Binary;
using System.Formats.Cbor;

namespace Fido2BleLogon.Ctap;

/// <summary>Parsed authenticator data (WebAuthn §6.1).</summary>
public sealed class AuthenticatorData
{
    private const byte FlagUserPresent = 0x01;
    private const byte FlagUserVerified = 0x04;
    private const byte FlagAttestedCredentialData = 0x40;
    private const byte FlagExtensionData = 0x80;

    public required byte[] Raw { get; init; }
    public required byte[] RpIdHash { get; init; }
    public required byte Flags { get; init; }
    public required uint SignCount { get; init; }
    public byte[]? CredentialId { get; init; }
    public CborMap? CredentialPublicKey { get; init; }
    public CborMap? Extensions { get; init; }

    public bool UserPresent => (Flags & FlagUserPresent) != 0;
    public bool UserVerified => (Flags & FlagUserVerified) != 0;

    public static AuthenticatorData Parse(byte[] raw)
    {
        if (raw.Length < 37)
            throw new CtapProtocolException("Authenticator data is too short.");

        byte flags = raw[32];
        int offset = 37;
        byte[]? credentialId = null;
        if ((flags & FlagAttestedCredentialData) != 0)
        {
            // aaguid (16) | credentialIdLength (2) | credentialId | credentialPublicKey (CBOR)
            if (raw.Length < offset + 18)
                throw new CtapProtocolException("Attested credential data is truncated.");
            int idLength = BinaryPrimitives.ReadUInt16BigEndian(raw.AsSpan(offset + 16, 2));
            if (raw.Length < offset + 18 + idLength)
                throw new CtapProtocolException("Credential ID is truncated.");
            credentialId = raw.AsSpan(offset + 18, idLength).ToArray();
            offset += 18 + idLength;
        }

        CborMap? publicKey, extensions;
        try
        {
            var reader = new CborReader(raw.AsMemory(offset), CborConformanceMode.Lax, allowMultipleRootLevelValues: true);
            publicKey = credentialId is null ? null : Cbor.Read(reader) as CborMap;
            extensions = (flags & FlagExtensionData) != 0 ? Cbor.Read(reader) as CborMap : null;
        }
        catch (Exception ex) when (Cbor.IsMalformed(ex))
        {
            throw new CtapProtocolException($"Authenticator data contains malformed CBOR ({ex.Message})");
        }

        return new AuthenticatorData
        {
            Raw = raw,
            RpIdHash = raw[..32],
            Flags = flags,
            SignCount = BinaryPrimitives.ReadUInt32BigEndian(raw.AsSpan(33, 4)),
            CredentialId = credentialId,
            CredentialPublicKey = publicKey,
            Extensions = extensions,
        };
    }
}
