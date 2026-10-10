using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Fido2BleLogon.CredentialProvider.Interop;

namespace Fido2BleLogon.CredentialProvider;

/// <summary>
/// Builds the logon serialization LogonUI submits: a relocatable KERB_INTERACTIVE_UNLOCK_LOGON for the
/// "Negotiate" package, packed exactly like the Microsoft SampleV2CredentialProvider (helpers.cpp:
/// KerbInteractiveUnlockLogonInit / KerbInteractiveUnlockLogonPack / ProtectIfNecessaryAndCopyPassword /
/// RetrieveNegotiateAuthPackage).
/// <para>
/// The password only ever exists in buffers this class (or its caller) clears: it is never turned into a
/// <see cref="string"/>, and every intermediate copy (the NUL-terminated CredProtect input and the CredProtect
/// output) lives in native memory that is zeroed before it is freed, so the GC never moves or leaves copies of it.
/// </para>
/// </summary>
internal static unsafe class KerbSerializer
{
    // KERB_LOGON_SUBMIT_TYPE (ntsecapi.h)
    public const int KerbInteractiveLogon = 2;
    public const int KerbWorkstationUnlockLogon = 7;

    // x64 KERB_INTERACTIVE_UNLOCK_LOGON: MessageType (4 + 4 padding), three 16-byte UNICODE_STRINGs
    // (USHORT Length, USHORT MaximumLength, 4 padding, PWSTR Buffer), then the 8-byte LUID LogonId.
    public const int FixedSize = 64;
    public const int DomainStringOffset = 8;
    public const int UserStringOffset = 24;
    public const int PasswordStringOffset = 40;

    private const string NegotiatePackage = "Negotiate"; // NEGOSSP_NAME_A

    /// <summary>
    /// Packs the logon for <paramref name="cpus"/> (logon or unlock; the provider offers no other scenario):
    /// MessageType KerbWorkstationUnlockLogon for the lock screen, KerbInteractiveLogon for logon. The password is
    /// always protected with CredProtect, per the sample's rules for these scenarios. Reads
    /// <paramref name="password"/> without keeping or copying it anywhere that outlives this call (the caller still
    /// owns and clears it). Returns a CoTaskMemAlloc'ed buffer that LogonUI frees.
    /// </summary>
    public static IntPtr Serialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, string domain, string userName, ReadOnlySpan<char> password, out uint size)
    {
        int messageType = cpus == CREDENTIAL_PROVIDER_USAGE_SCENARIO.CPUS_UNLOCK_WORKSTATION
            ? KerbWorkstationUnlockLogon
            : KerbInteractiveLogon;
        using var secret = ProtectIfNecessary(password);
        return Pack(messageType, domain, userName, secret.Span, out size);
    }

    /// <summary>LsaConnectUntrusted + LsaLookupAuthenticationPackage("Negotiate"). Throws on failure.</summary>
    public static uint GetNegotiateAuthPackage()
    {
        int status = NativeMethods.LsaConnectUntrusted(out var lsa);
        if (status < 0)
            throw new Win32Exception($"LsaConnectUntrusted failed (NTSTATUS 0x{status:X8}).");
        IntPtr name = IntPtr.Zero;
        try
        {
            name = Marshal.StringToHGlobalAnsi(NegotiatePackage);
            var lsaString = new NativeMethods.LSA_STRING
            {
                Length = (ushort)NegotiatePackage.Length,
                MaximumLength = (ushort)(NegotiatePackage.Length + 1),
                Buffer = name,
            };
            status = NativeMethods.LsaLookupAuthenticationPackage(lsa, ref lsaString, out uint package);
            if (status < 0)
                throw new Win32Exception($"LsaLookupAuthenticationPackage failed (NTSTATUS 0x{status:X8}).");
            return package;
        }
        finally
        {
            if (name != IntPtr.Zero)
                Marshal.FreeHGlobal(name);
            NativeMethods.LsaDeregisterLogonProcess(lsa);
        }
    }

    /// <summary>ProtectIfNecessaryAndCopyPassword for logon/unlock: empty stays empty, an already protected
    /// password stays as is, anything else goes through CredProtect (not "as self"). The result (without the
    /// terminating NUL) is in a buffer the caller disposes, which zeroes it.</summary>
    public static SecretBuffer ProtectIfNecessary(ReadOnlySpan<char> password)
    {
        if (password.IsEmpty)
            return SecretBuffer.Allocate(0);

        // CredIsProtected / CredProtect want a NUL-terminated string; the character count passed in includes it.
        using var input = SecretBuffer.Allocate(password.Length + 1);
        password.CopyTo(input.Span);
        input.Span[password.Length] = '\0';
        uint cchInput = (uint)input.Length;

        if (NativeMethods.CredIsProtectedW(input.Pointer, out int protectionType) && protectionType != NativeMethods.CredUnprotected)
        {
            var copy = SecretBuffer.Allocate(password.Length);
            password.CopyTo(copy.Span);
            return copy;
        }

        // First call with a null buffer is expected to fail with ERROR_INSUFFICIENT_BUFFER and report the size.
        uint cch = 0;
        if (NativeMethods.CredProtectW(false, input.Pointer, cchInput, null, ref cch, out _))
            throw new InvalidOperationException("CredProtectW unexpectedly succeeded with a null buffer.");
        int error = Marshal.GetLastPInvokeError();
        if (error != NativeMethods.ERROR_INSUFFICIENT_BUFFER || cch == 0)
            throw new Win32Exception(error, $"CredProtectW sizing failed (error {error}).");

        var output = SecretBuffer.Allocate(checked((int)cch));
        try
        {
            if (!NativeMethods.CredProtectW(false, input.Pointer, cchInput, output.Pointer, ref cch, out _))
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "CredProtectW failed.");
            // The protected text ends at its NUL (as the sample's copy of it does).
            int length = output.Span.IndexOf('\0');
            output.Truncate(length < 0 ? output.Length : length);
            return output;
        }
        catch
        {
            output.Dispose();
            throw;
        }
    }

    /// <summary>
    /// KerbInteractiveUnlockLogonPack: the fixed struct, then domain, user name and password (UTF-16, no
    /// terminators) in that order. Each UNICODE_STRING.Buffer holds the byte offset of its text from the start
    /// of the buffer; Length = MaximumLength = byte count. LogonId stays zero. Written straight into the
    /// CoTaskMem buffer LogonUI receives, so no other copy of the password is made.
    /// </summary>
    public static IntPtr Pack(int messageType, string domain, string userName, ReadOnlySpan<char> password, out uint size)
    {
        int domainBytes = domain.Length * sizeof(char);
        int userBytes = userName.Length * sizeof(char);
        int passwordBytes = password.Length * sizeof(char);
        if (domainBytes > ushort.MaxValue || userBytes > ushort.MaxValue || passwordBytes > ushort.MaxValue)
            throw new InvalidOperationException("A logon field is too long to serialize.");

        int total = FixedSize + domainBytes + userBytes + passwordBytes;
        IntPtr buffer = Marshal.AllocCoTaskMem(total);
        var target = new Span<byte>((void*)buffer, total);
        target.Clear(); // padding and LogonId must be zero
        BinaryPrimitives.WriteInt32LittleEndian(target, messageType);

        int domainAt = FixedSize;
        int userAt = domainAt + domainBytes;
        int passwordAt = userAt + userBytes;
        WriteUnicodeString(target, DomainStringOffset, (ushort)domainBytes, domainAt);
        WriteUnicodeString(target, UserStringOffset, (ushort)userBytes, userAt);
        WriteUnicodeString(target, PasswordStringOffset, (ushort)passwordBytes, passwordAt);
        MemoryMarshal.AsBytes(domain.AsSpan()).CopyTo(target[domainAt..]);
        MemoryMarshal.AsBytes(userName.AsSpan()).CopyTo(target[userAt..]);
        MemoryMarshal.AsBytes(password).CopyTo(target[passwordAt..]);
        size = (uint)total;
        return buffer;
    }

    /// <summary>Zeroes and frees a buffer from <see cref="Serialize"/> that never reached LogonUI. Null is ignored.</summary>
    public static void ZeroAndFree(IntPtr buffer, uint size)
    {
        if (buffer == IntPtr.Zero)
            return;
        new Span<byte>((void*)buffer, checked((int)size)).Clear();
        Marshal.FreeCoTaskMem(buffer);
    }

    private static void WriteUnicodeString(Span<byte> target, int offset, ushort byteLength, int bufferOffset)
    {
        BinaryPrimitives.WriteUInt16LittleEndian(target[offset..], byteLength);      // Length
        BinaryPrimitives.WriteUInt16LittleEndian(target[(offset + 2)..], byteLength);  // MaximumLength
        BinaryPrimitives.WriteInt64LittleEndian(target[(offset + 8)..], bufferOffset); // Buffer = offset
    }
}

/// <summary>
/// A UTF-16 buffer in native memory for secret text: it never moves (unlike a managed array, which the GC may
/// copy), and <see cref="Dispose"/> zeroes all of it before freeing it.
/// </summary>
internal sealed unsafe class SecretBuffer : IDisposable
{
    private char* _pointer;
    private readonly int _capacity;

    private SecretBuffer(int capacity)
    {
        _capacity = capacity;
        Length = capacity;
        // At least one char, so Pointer is never null (CredIsProtected / CredProtect need a real buffer).
        _pointer = (char*)NativeMemory.AllocZeroed((nuint)Math.Max(capacity, 1), sizeof(char));
    }

    public static SecretBuffer Allocate(int length) => new(length);

    public char* Pointer => _pointer != null ? _pointer : throw new ObjectDisposedException(nameof(SecretBuffer));

    /// <summary>The number of characters in use (at most the allocated size).</summary>
    public int Length { get; private set; }

    public Span<char> Span => new(Pointer, Length);

    /// <summary>Uses only the first <paramref name="length"/> characters; the rest stays allocated (and is zeroed on dispose).</summary>
    public void Truncate(int length) => Length = Math.Clamp(length, 0, _capacity);

    public void Dispose()
    {
        char* pointer = _pointer;
        if (pointer == null)
            return;
        _pointer = null;
        NativeMemory.Clear(pointer, (nuint)Math.Max(_capacity, 1) * sizeof(char));
        NativeMemory.Free(pointer);
    }
}
