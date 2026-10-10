using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using static Fido2BleLogon.CpHarness.NativeHost;

namespace Fido2BleLogon.CpHarness;

/// <summary>A decoded logon serialization. <see cref="Password"/> is never printed.</summary>
internal sealed record DecodedLogon(int MessageType, string Domain, string UserName, string Password, bool WasProtected);

/// <summary>
/// Reads the serialization the provider returns, written independently of the provider's packer (it follows
/// KerbInteractiveUnlockLogonUnpackInPlace from the Microsoft sample, including its bounds checks).
/// </summary>
internal static class LogonBuffer
{
    public const int KerbInteractiveLogon = 2;
    public const int KerbWorkstationUnlockLogon = 7;
    private const int FixedSize = 64;

    public static string MessageTypeName(int type) => type switch
    {
        KerbInteractiveLogon => "KerbInteractiveLogon",
        KerbWorkstationUnlockLogon => "KerbWorkstationUnlockLogon",
        _ => $"0x{type:X}",
    };

    /// <summary>Copies, decodes and unprotects a packed KERB_INTERACTIVE_UNLOCK_LOGON (offsets, not pointers).</summary>
    public static DecodedLogon DecodeKerb(IntPtr buffer, uint size)
    {
        if (buffer == IntPtr.Zero || size < FixedSize)
            throw new InvalidDataException($"Serialization too small ({size} bytes; the fixed part alone is {FixedSize}).");
        var bytes = new byte[size];
        try
        {
            Marshal.Copy(buffer, bytes, 0, bytes.Length);
            int messageType = BinaryPrimitives.ReadInt32LittleEndian(bytes);
            string domain = ReadUnicodeString(bytes, 8, "LogonDomainName");
            string user = ReadUnicodeString(bytes, 24, "UserName");
            string passwordField = ReadUnicodeString(bytes, 40, "Password");
            if (BinaryPrimitives.ReadInt64LittleEndian(bytes.AsSpan(56)) != 0)
                throw new InvalidDataException("LogonId is not zero.");
            bool isProtected = IsProtected(passwordField);
            string password = isProtected ? Unprotect(passwordField) : passwordField;
            return new DecodedLogon(messageType, domain, user, password, isProtected);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static string ReadUnicodeString(byte[] buffer, int at, string name)
    {
        ushort length = BinaryPrimitives.ReadUInt16LittleEndian(buffer.AsSpan(at));
        ushort maximum = BinaryPrimitives.ReadUInt16LittleEndian(buffer.AsSpan(at + 2));
        long offset = BinaryPrimitives.ReadInt64LittleEndian(buffer.AsSpan(at + 8));
        if (length > maximum || length % 2 != 0)
            throw new InvalidDataException($"{name}: bad length {length}/{maximum}.");
        if (length == 0)
            return string.Empty;
        if (offset < FixedSize || offset + maximum > buffer.Length)
            throw new InvalidDataException($"{name}: offset {offset} + {maximum} is outside the {buffer.Length}-byte buffer.");
        return Encoding.Unicode.GetString(buffer, (int)offset, length);
    }

    public static bool IsProtected(string value) =>
        value.Length > 0 && CredIsProtectedW(value, out int type) && type != CredUnprotected;

    private static string Unprotect(string protectedValue)
    {
        uint cch = 0;
        if (CredUnprotectW(false, protectedValue, (uint)(protectedValue.Length + 1), IntPtr.Zero, ref cch)
            || Marshal.GetLastPInvokeError() != ERROR_INSUFFICIENT_BUFFER || cch == 0)
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError(), "CredUnprotectW sizing failed.");
        }
        IntPtr buffer = Marshal.AllocCoTaskMem(checked((int)cch * sizeof(char)));
        try
        {
            if (!CredUnprotectW(false, protectedValue, (uint)(protectedValue.Length + 1), buffer, ref cch))
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "CredUnprotectW failed.");
            return (Marshal.PtrToStringUni(buffer, (int)cch) ?? "").TrimEnd('\0');
        }
        finally
        {
            Marshal.Copy(new byte[(int)cch * sizeof(char)], 0, buffer, (int)cch * sizeof(char));
            Marshal.FreeCoTaskMem(buffer);
        }
    }

    /// <summary>Overwrites and frees a CoTaskMem serialization buffer (it holds a password).</summary>
    public static void Free(IntPtr buffer, uint size)
    {
        if (buffer == IntPtr.Zero)
            return;
        if (size > 0)
            Marshal.Copy(new byte[size], 0, buffer, (int)size);
        CoTaskMemFree(buffer);
    }
}
