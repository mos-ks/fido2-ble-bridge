using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Fido2BleLogon.Logon;

/// <summary>Everything needed to turn a fingerprint on the key back into the account password. The password is
/// stored only encrypted, under a key that the security key derives (hmac-secret) after a fingerprint match.</summary>
public sealed record Enrollment
{
    public int Version { get; init; } = 1;
    public required string KeyName { get; init; }
    public required ulong KeyAddress { get; init; }
    public required string RpId { get; init; }
    public required string Domain { get; init; }
    public required string UserName { get; init; }
    public required string UserSid { get; init; }
    public required byte[] CredentialId { get; init; }
    public required byte[] PublicKeyX { get; init; }
    public required byte[] PublicKeyY { get; init; }
    public required byte[] Salt { get; init; }
    public required byte[] Nonce { get; init; }
    public required byte[] Ciphertext { get; init; }
    public required byte[] Tag { get; init; }
    public required DateTimeOffset EnrolledAt { get; init; }

    [JsonIgnore]
    public string QualifiedUserName => $"{Domain}\\{UserName}";

    /// <summary>Throws <see cref="InvalidDataException"/> unless every field has the shape enrollment produces.</summary>
    public void Validate()
    {
        static void Require(bool ok, string what)
        {
            if (!ok)
                throw new InvalidDataException($"The enrollment has an invalid {what}.");
        }

        Require(Version == 1, "version");
        Require(!string.IsNullOrWhiteSpace(KeyName) && KeyAddress != 0, "key");
        Require(!string.IsNullOrWhiteSpace(RpId), "relying party");
        Require(!string.IsNullOrWhiteSpace(Domain) && !string.IsNullOrWhiteSpace(UserName), "account name");
        Require(UserSid.StartsWith("S-1-", StringComparison.Ordinal), "account SID");
        Require(CredentialId is { Length: > 0 and <= 1024 }, "credential ID");
        Require(PublicKeyX is { Length: 32 } && PublicKeyY is { Length: 32 }, "public key");
        Require(Salt is { Length: 32 }, "salt");
        Require(Nonce is { Length: 12 }, "nonce");
        Require(Tag is { Length: 16 }, "tag");
        Require(Ciphertext is { Length: > 0 } && Ciphertext.Length % 64 == 0, "ciphertext");
    }
}

/// <summary>Keeps the enrollment in %ProgramData%\Fido2BleLogon. The directory and file are owned by Administrators
/// and readable only by SYSTEM and Administrators; the SYSTEM-level logon tile refuses anything else.</summary>
public static class EnrollmentStore
{
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true, RespectNullableAnnotations = true };

    private static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier LocalSystem = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier TrustedInstaller = new("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");

    public static string DirectoryPath { get; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Fido2BleLogon");

    public static string FilePath { get; } = Path.Combine(DirectoryPath, "enrollment.json");

    /// <summary>The enrollment, or null when nothing is enrolled. Throws <see cref="InvalidDataException"/> when the file
    /// is corrupt or not trustworthy, and <see cref="UnauthorizedAccessException"/> when the caller isn't elevated.</summary>
    public static Enrollment? Load()
    {
        var directory = new DirectoryInfo(DirectoryPath);
        if (!directory.Exists)
            return null;
        RequireTrusted(directory, directory.GetAccessControl());

        var file = new FileInfo(FilePath);
        byte[] bytes;
        try
        {
            bytes = File.ReadAllBytes(FilePath);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return null;
        }
        catch (IOException ex)
        {
            throw new InvalidDataException($"{FilePath} could not be read: {ex.Message}", ex);
        }
        RequireTrusted(file, file.GetAccessControl());

        Enrollment? enrollment;
        try
        {
            enrollment = JsonSerializer.Deserialize<Enrollment>(bytes, Options);
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException($"{FilePath} is not a valid enrollment file.", ex);
        }
        if (enrollment is null)
            throw new InvalidDataException($"{FilePath} is not a valid enrollment file.");
        enrollment.Validate();
        return enrollment;
    }

    /// <summary>Writes the enrollment durably (flushed to disk, then renamed into place).</summary>
    public static void Save(Enrollment enrollment)
    {
        enrollment.Validate();
        EnsureDirectory();
        var temp = FilePath + ".tmp";
        File.Delete(temp);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(enrollment, Options);
        using (var stream = new FileInfo(temp).Create(FileMode.CreateNew, FileSystemRights.Write | FileSystemRights.Read,
                   FileShare.None, 4096, FileOptions.None, ProtectedSecurity(new FileSecurity(), InheritanceFlags.None)))
        {
            stream.Write(bytes);
            stream.Flush(flushToDisk: true);
        }
        File.Move(temp, FilePath, overwrite: true);
    }

    public static bool Delete()
    {
        if (!File.Exists(FilePath))
            return false;
        File.Delete(FilePath);
        return true;
    }

    /// <summary>Creates the directory owned by Administrators, usable only by SYSTEM and Administrators, and
    /// (re)applies that ACL. Refuses links and folders that someone else owns, including one created by another
    /// process between the existence check and the create.</summary>
    public static void EnsureDirectory()
    {
        var security = ProtectedSecurity(new DirectorySecurity(), InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit);
        var directory = new DirectoryInfo(DirectoryPath);
        if (!directory.Exists)
        {
            directory.Create(security);
            directory.Refresh();
        }

        if (directory.Attributes.HasFlag(FileAttributes.ReparsePoint))
            throw new InvalidOperationException($"{DirectoryPath} is a link. Delete it and try again.");
        var owner = directory.GetAccessControl().GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (owner is null || !IsTrustedOwner(owner))
            throw new InvalidOperationException($"{DirectoryPath} is owned by another account ({owner}). Delete it and try again.");
        directory.SetAccessControl(security);
    }

    private static T ProtectedSecurity<T>(T security, InheritanceFlags inheritance) where T : FileSystemSecurity
    {
        security.SetOwner(Administrators);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var sid in new[] { LocalSystem, Administrators })
            security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, inheritance, PropagationFlags.None, AccessControlType.Allow));
        return security;
    }

    private static void RequireTrusted(FileSystemInfo item, FileSystemSecurity security)
    {
        if (item.Attributes.HasFlag(FileAttributes.ReparsePoint))
            throw new InvalidDataException($"{item.FullName} is a link; refusing to use it.");
        if (security.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner || !IsTrustedOwner(owner))
            throw new InvalidDataException($"{item.FullName} is not owned by SYSTEM or Administrators. Run 'fido2-ble-logon enroll' again.");
    }

    private static bool IsTrustedOwner(SecurityIdentifier sid) =>
        sid == Administrators || sid == LocalSystem || sid == TrustedInstaller;
}
