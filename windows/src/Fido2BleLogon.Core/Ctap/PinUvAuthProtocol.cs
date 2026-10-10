using System.Security.Cryptography;

namespace Fido2BleLogon.Ctap;

/// <summary>The platform half of an ECDH exchange with the authenticator.</summary>
public sealed record KeyAgreement(byte[] X, byte[] Y, byte[] SharedSecret);

/// <summary>CTAP2 PIN/UV auth protocols one and two (CTAP 2.1 §6.5.6–6.5.7). They protect
/// tokens and hmac-secret salts/outputs on the wire, which matters because the Bluetooth link is radio.</summary>
public abstract class PinUvAuthProtocol
{
    public abstract int Version { get; }

    public static PinUvAuthProtocol Create(long version) => version switch
    {
        1 => new One(),
        2 => new Two(),
        _ => throw new NotSupportedException($"PIN/UV auth protocol {version} is not supported."),
    };

    /// <summary>Generates an ephemeral P-256 key and derives the shared secret with the authenticator's key.</summary>
    public KeyAgreement Encapsulate(CborMap authenticatorKey)
    {
        if (authenticatorKey[-2] is not byte[] { Length: 32 } x || authenticatorKey[-3] is not byte[] { Length: 32 } y)
            throw new CtapProtocolException("The key agreement key from the security key is malformed.");

        using var peer = ECDiffieHellman.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = x, Y = y },
        });
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var z = ecdh.DeriveRawSecretAgreement(peer.PublicKey);
        var q = ecdh.ExportParameters(false).Q;
        return new KeyAgreement(q.X!, q.Y!, Kdf(z));
    }

    protected abstract byte[] Kdf(byte[] z);
    public abstract byte[] Encrypt(byte[] key, byte[] plaintext);
    public abstract byte[] Decrypt(byte[] key, byte[] ciphertext);
    public abstract byte[] Authenticate(byte[] key, byte[] message);

    private sealed class One : PinUvAuthProtocol
    {
        public override int Version => 1;

        protected override byte[] Kdf(byte[] z) => SHA256.HashData(z);

        public override byte[] Encrypt(byte[] key, byte[] plaintext)
        {
            using var aes = Aes.Create();
            aes.Key = key;
            return aes.EncryptCbc(plaintext, new byte[16], PaddingMode.None);
        }

        public override byte[] Decrypt(byte[] key, byte[] ciphertext)
        {
            using var aes = Aes.Create();
            aes.Key = key;
            return aes.DecryptCbc(ciphertext, new byte[16], PaddingMode.None);
        }

        public override byte[] Authenticate(byte[] key, byte[] message) => HMACSHA256.HashData(key, message)[..16];
    }

    private sealed class Two : PinUvAuthProtocol
    {
        public override int Version => 2;

        // Shared secret = HMAC key (32 bytes) || AES key (32 bytes).
        protected override byte[] Kdf(byte[] z)
        {
            var salt = new byte[32];
            var hmacKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, z, 32, salt, "CTAP2 HMAC key"u8.ToArray());
            var aesKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, z, 32, salt, "CTAP2 AES key"u8.ToArray());
            return [.. hmacKey, .. aesKey];
        }

        public override byte[] Encrypt(byte[] key, byte[] plaintext)
        {
            var iv = RandomNumberGenerator.GetBytes(16);
            using var aes = Aes.Create();
            aes.Key = key[32..];
            return [.. iv, .. aes.EncryptCbc(plaintext, iv, PaddingMode.None)];
        }

        public override byte[] Decrypt(byte[] key, byte[] ciphertext)
        {
            if (ciphertext.Length < 16)
                throw new CtapProtocolException("Encrypted data from the security key is too short.");
            using var aes = Aes.Create();
            aes.Key = key[32..];
            return aes.DecryptCbc(ciphertext.AsSpan(16), ciphertext.AsSpan(0, 16), PaddingMode.None);
        }

        // A 64-byte shared secret authenticates with its HMAC half; a 32-byte token is used whole.
        public override byte[] Authenticate(byte[] key, byte[] message) =>
            HMACSHA256.HashData(key.Length > 32 ? key[..32] : key, message);
    }
}
