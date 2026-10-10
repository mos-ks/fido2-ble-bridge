using System.Security.Cryptography;
using System.Text;

namespace Fido2BleLogon.Logon;

/// <summary>AES-256-GCM sealing of the account password under a key derived from the hmac-secret output.</summary>
public static class PasswordVault
{
    private static readonly byte[] KeyInfo = "Fido2BleLogon v1 password key"u8.ToArray();
    private const int PaddingBlock = 64; // hides the password length

    public static (byte[] Nonce, byte[] Ciphertext, byte[] Tag) Seal(byte[] hmacSecret, string password, byte[] associatedData)
    {
        if (password.Contains('\0'))
            throw new ArgumentException("Passwords cannot contain NUL characters.", nameof(password));

        var utf8 = Encoding.UTF8.GetBytes(password);
        var plaintext = new byte[(utf8.Length / PaddingBlock + 1) * PaddingBlock];
        utf8.CopyTo(plaintext, 0);
        var key = DeriveKey(hmacSecret);
        try
        {
            var nonce = RandomNumberGenerator.GetBytes(12);
            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[16];
            using var aes = new AesGcm(key, tag.Length);
            aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
            return (nonce, ciphertext, tag);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(utf8);
        }
    }

    /// <summary>Decrypts the password. Throws <see cref="AuthenticationTagMismatchException"/> if the secret is wrong.</summary>
    public static string Open(byte[] hmacSecret, Enrollment enrollment)
    {
        var chars = OpenChars(hmacSecret, enrollment);
        try
        {
            return new string(chars);
        }
        finally
        {
            Array.Clear(chars);
        }
    }

    /// <summary>Like <see cref="Open"/>, but returns the password in a buffer the caller clears when done.
    /// A string can't be wiped and may stay in memory (and crash dumps) until the GC reuses it.</summary>
    public static char[] OpenChars(byte[] hmacSecret, Enrollment enrollment)
    {
        var key = DeriveKey(hmacSecret);
        var plaintext = new byte[enrollment.Ciphertext.Length];
        try
        {
            using var aes = new AesGcm(key, enrollment.Tag.Length);
            aes.Decrypt(enrollment.Nonce, enrollment.Ciphertext, enrollment.Tag, plaintext, AssociatedData(enrollment));
            int length = Array.IndexOf(plaintext, (byte)0);
            return Encoding.UTF8.GetChars(plaintext, 0, length < 0 ? plaintext.Length : length);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    /// <summary>Binds the ciphertext to the account, credential and relying party it was enrolled for.</summary>
    public static byte[] AssociatedData(string rpId, string userSid, string domain, string userName, byte[] credentialId) =>
        Encoding.UTF8.GetBytes($"Fido2BleLogon v1\n{rpId}\n{userSid}\n{domain}\\{userName}\n{Convert.ToBase64String(credentialId)}");

    private static byte[] AssociatedData(Enrollment e) =>
        AssociatedData(e.RpId, e.UserSid, e.Domain, e.UserName, e.CredentialId);

    private static byte[] DeriveKey(byte[] hmacSecret) =>
        HKDF.DeriveKey(HashAlgorithmName.SHA256, hmacSecret, 32, info: KeyInfo);
}
