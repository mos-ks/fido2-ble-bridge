using System.Formats.Cbor;
using System.Security.Cryptography;
using Fido2BleLogon.Ctap;
using Fido2BleLogon.Logon;

namespace Fido2BleLogon.Core.Tests;

public class CryptoTests
{
    private static CborMap CoseKey(ECDiffieHellman key)
    {
        var q = key.ExportParameters(false).Q;
        var w = new CborWriter();
        Cbor.WriteCoseEcdhKey(w, q.X!, q.Y!);
        return (CborMap)Cbor.Decode(w.Encode())!;
    }

    private static byte[] AuthenticatorSideZ(ECDiffieHellman authenticator, KeyAgreement platform)
    {
        using var peer = ECDiffieHellman.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = platform.X, Y = platform.Y },
        });
        return authenticator.DeriveRawSecretAgreement(peer.PublicKey);
    }

    [Fact]
    public void Protocol_one_shared_secret_is_sha256_of_the_ecdh_x_coordinate()
    {
        using var authenticator = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var platform = PinUvAuthProtocol.Create(1).Encapsulate(CoseKey(authenticator));
        Assert.Equal(SHA256.HashData(AuthenticatorSideZ(authenticator, platform)), platform.SharedSecret);
    }

    [Fact]
    public void Protocol_two_shared_secret_is_the_hkdf_hmac_key_then_aes_key()
    {
        using var authenticator = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var platform = PinUvAuthProtocol.Create(2).Encapsulate(CoseKey(authenticator));
        var z = AuthenticatorSideZ(authenticator, platform);
        var salt = new byte[32];
        byte[] expected =
        [
            .. HKDF.DeriveKey(HashAlgorithmName.SHA256, z, 32, salt, "CTAP2 HMAC key"u8.ToArray()),
            .. HKDF.DeriveKey(HashAlgorithmName.SHA256, z, 32, salt, "CTAP2 AES key"u8.ToArray()),
        ];
        Assert.Equal(expected, platform.SharedSecret);
    }

    [Theory]
    [InlineData(1, 32, 16)]
    [InlineData(2, 64, 32)]
    public void Protocols_round_trip_and_authenticate_with_the_specified_lengths(int version, int keyLength, int macLength)
    {
        var protocol = PinUvAuthProtocol.Create(version);
        var key = RandomNumberGenerator.GetBytes(keyLength);
        var plaintext = RandomNumberGenerator.GetBytes(64);
        Assert.Equal(plaintext, protocol.Decrypt(key, protocol.Encrypt(key, plaintext)));
        Assert.Equal(macLength, protocol.Authenticate(key, plaintext).Length);
    }

    [Fact]
    public void Protocol_one_uses_a_zero_iv()
    {
        var protocol = PinUvAuthProtocol.Create(1);
        var key = RandomNumberGenerator.GetBytes(32);
        var plaintext = RandomNumberGenerator.GetBytes(32);
        Assert.Equal(protocol.Encrypt(key, plaintext), protocol.Encrypt(key, plaintext));
    }

    [Fact]
    public void Protocol_two_uses_a_random_iv()
    {
        var protocol = PinUvAuthProtocol.Create(2);
        var key = RandomNumberGenerator.GetBytes(64);
        var plaintext = RandomNumberGenerator.GetBytes(32);
        Assert.NotEqual(protocol.Encrypt(key, plaintext), protocol.Encrypt(key, plaintext));
    }

    private static Enrollment Sealed(string password, byte[] secret, string sid = "S-1-5-21-1-2-3-1001")
    {
        var credentialId = new byte[48];
        var (nonce, ciphertext, tag) = PasswordVault.Seal(secret, password,
            PasswordVault.AssociatedData("rp", sid, "PC", "user", credentialId));
        return new Enrollment
        {
            KeyName = "key", KeyAddress = 1, RpId = "rp", Domain = "PC", UserName = "user", UserSid = sid,
            CredentialId = credentialId, PublicKeyX = new byte[32], PublicKeyY = new byte[32], Salt = new byte[32],
            Nonce = nonce, Ciphertext = ciphertext, Tag = tag, EnrolledAt = DateTimeOffset.UnixEpoch,
        };
    }

    [Theory]
    [InlineData("a")]
    [InlineData("pässwörd with spaces ✓")]
    public void The_vault_round_trips(string password)
    {
        var secret = RandomNumberGenerator.GetBytes(32);
        Assert.Equal(password, PasswordVault.Open(secret, Sealed(password, secret)));
    }

    [Fact]
    public void The_vault_rejects_the_wrong_secret()
    {
        var enrollment = Sealed("pw", RandomNumberGenerator.GetBytes(32));
        Assert.ThrowsAny<CryptographicException>(() => PasswordVault.Open(RandomNumberGenerator.GetBytes(32), enrollment));
    }

    [Fact]
    public void The_vault_is_bound_to_the_account()
    {
        var secret = RandomNumberGenerator.GetBytes(32);
        var enrollment = Sealed("pw", secret) with { UserSid = "S-1-5-21-9-9-9-1001" };
        Assert.ThrowsAny<CryptographicException>(() => PasswordVault.Open(secret, enrollment));
    }

    [Theory]
    [InlineData(1, 64)]
    [InlineData(63, 64)]
    [InlineData(64, 128)]
    public void The_vault_pads_to_hide_the_password_length(int length, int expected)
    {
        var enrollment = Sealed(new string('x', length), RandomNumberGenerator.GetBytes(32));
        Assert.Equal(expected, enrollment.Ciphertext.Length);
    }

    [Fact]
    public void Enrollment_validation_rejects_wrong_field_sizes()
    {
        var good = Sealed("pw", RandomNumberGenerator.GetBytes(32));
        good.Validate();
        Assert.Throws<InvalidDataException>(() => (good with { Nonce = new byte[11] }).Validate());
        Assert.Throws<InvalidDataException>(() => (good with { Tag = new byte[15] }).Validate());
        Assert.Throws<InvalidDataException>(() => (good with { Salt = new byte[31] }).Validate());
        Assert.Throws<InvalidDataException>(() => (good with { Ciphertext = new byte[65] }).Validate());
        Assert.Throws<InvalidDataException>(() => (good with { UserSid = "not a sid" }).Validate());
    }
}
