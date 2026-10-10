using System.Globalization;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Fido2BleLogon.Logon;

namespace Fido2BleLogon.CredentialProvider;

/// <summary>
/// Best-effort append-only log at %ProgramData%\Fido2BleLogon\logs\provider.log. The provider runs inside
/// LogonUI.exe as SYSTEM, where there is no console, so this file is the only way to see what happened.
/// <para>
/// Nothing here may throw into a COM method: every entry point swallows its own failures. Passwords,
/// secrets and the serialization buffer (or its size, which follows the password's length) are never written
/// here; callers pass only states and messages.
/// </para>
/// <para>
/// SYSTEM writing into a folder a user could redirect would be an arbitrary file write, so the log is only used
/// when %ProgramData%\Fido2BleLogon already exists as a real directory (not a junction/symlink) owned by
/// SYSTEM, Administrators or TrustedInstaller, and so is its logs folder. This class never creates or re-secures
/// %ProgramData%\Fido2BleLogon itself: that is the enrollment's folder, set up by 'fido2-ble-logon enroll' (a folder a
/// standard user made first has that user as owner and is refused), and the provider must not change it on its
/// inert paths. Without a trusted folder there is simply no log. Before each write both folders are checked
/// again for links, and before a rotation (delete + rename as SYSTEM) for their owners too.
/// </para>
/// </summary>
internal static class ProviderLog
{
    private const long MaxBytes = 1024 * 1024; // rotate at about 1 MB
    private const long RetryInitMs = 60_000;

    private static readonly object Sync = new();
    private static string? _path;
    private static long _retryInitAt;

    private static string RootPath => EnrollmentStore.DirectoryPath;

    private static string LogsPath => Path.Combine(RootPath, "logs");

    /// <summary>Appends one line with timestamp, process id, thread id and scenario.</summary>
    public static void Write(string scenario, string message)
    {
        try
        {
            string line = Format(scenario, message);
            lock (Sync)
            {
                if (TestHooks.LogPath is { } overridePath)
                {
                    Append(overridePath, line, verifyFoldersBeforeRotate: false);
                    return;
                }

                string? path = ResolvePath();
                if (path is null)
                    return;
                // Checked when the path was resolved; make sure neither folder has become a link since.
                if (!IsRealDirectory(RootPath) || !IsRealDirectory(LogsPath))
                {
                    Forget();
                    return;
                }
                Append(path, line, verifyFoldersBeforeRotate: true);
            }
        }
        catch
        {
            // Logging must never throw; drop the entry.
        }
    }

    /// <summary>Logs an exception's type and message (and the stack for unexpected ones), never any secret.</summary>
    public static void WriteException(string scenario, string context, Exception ex, bool includeStack)
    {
        try
        {
            var sb = new StringBuilder();
            sb.Append(context).Append(": ").Append(ex.GetType().Name).Append(": ").Append(ex.Message);
            if (ex.InnerException is { } inner)
                sb.Append(" [inner ").Append(inner.GetType().Name).Append(": ").Append(inner.Message).Append(']');
            if (includeStack)
                sb.Append('\n').Append(ex);
            Write(scenario, sb.ToString());
        }
        catch
        {
            // Logging must never throw.
        }
    }

    private static string Format(string scenario, string message)
    {
        // Continuation lines (stack traces) are indented so each entry still starts with a timestamp.
        string body = message.Replace("\r\n", "\n").Replace('\r', '\n').Replace("\n", "\n    ");
        return string.Create(CultureInfo.InvariantCulture,
            $"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss.fff zzz} pid={Environment.ProcessId} tid={NativeMethods.GetCurrentThreadId()} [{scenario}] {body}\n");
    }

    private static string? ResolvePath()
    {
        if (_path is not null)
            return _path;

        long now = Environment.TickCount64;
        if (now < _retryInitAt)
            return null;
        try
        {
            _path = Initialize();
        }
        catch
        {
            _path = null;
        }
        if (_path is null)
            _retryInitAt = now + RetryInitMs;
        return _path;
    }

    /// <summary>Drops the cached path; the next write after the retry delay checks the folders from scratch.</summary>
    private static void Forget()
    {
        _path = null;
        _retryInitAt = Environment.TickCount64 + RetryInitMs;
    }

    private static string? Initialize()
    {
        // Never creates or re-secures the data folder (see the class remarks): no trusted folder, no log.
        if (!IsTrustedDirectory(RootPath))
            return null;

        var logs = new DirectoryInfo(LogsPath);
        if (!logs.Exists)
            logs.Create(ProtectedDirectorySecurity()); // does nothing if someone made it meanwhile; checked next
        if (!IsTrustedDirectory(LogsPath))
            return null; // refuse to log through a junction or symlink, or into a folder someone else made

        try
        {
            logs.SetAccessControl(ProtectedDirectorySecurity()); // DACL only; the owner stays as it is
        }
        catch
        {
            // Best effort: the parent folder's protected ACL already limits who can write here.
        }
        return Path.Combine(LogsPath, "provider.log");
    }

    private static void Append(string path, string line, bool verifyFoldersBeforeRotate)
    {
        var file = new FileInfo(path);
        if (file.Exists)
        {
            if (file.Attributes.HasFlag(FileAttributes.ReparsePoint))
                return; // never write through a link
            if (file.Length > MaxBytes)
            {
                // The rotation deletes and renames files as SYSTEM: check both folders fully first.
                if (verifyFoldersBeforeRotate && !(IsTrustedDirectory(RootPath) && IsTrustedDirectory(LogsPath)))
                {
                    Forget();
                    return;
                }
                Rotate(path);
            }
        }

        using var stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
        stream.Write(Encoding.UTF8.GetBytes(line));
    }

    private static void Rotate(string path)
    {
        try
        {
            string old = path + ".1";
            File.Delete(old); // deletes a link itself, never its target
            File.Move(path, old);
        }
        catch
        {
            // A failed rotation is not worth losing the entry over; keep appending.
        }
    }

    /// <summary>An existing real directory (not a junction or symlink) owned by SYSTEM, Administrators or TrustedInstaller.</summary>
    private static bool IsTrustedDirectory(string path)
    {
        var directory = new DirectoryInfo(path);
        if (!directory.Exists || directory.Attributes.HasFlag(FileAttributes.ReparsePoint))
            return false;
        return directory.GetAccessControl(AccessControlSections.Owner).GetOwner(typeof(SecurityIdentifier)) is SecurityIdentifier owner
               && IsTrustedOwner(owner);
    }

    /// <summary>Cheap per-write check: still a directory, and not a junction or symlink.</summary>
    private static bool IsRealDirectory(string path)
    {
        try
        {
            var attributes = File.GetAttributes(path);
            return attributes.HasFlag(FileAttributes.Directory) && !attributes.HasFlag(FileAttributes.ReparsePoint);
        }
        catch
        {
            return false;
        }
    }

    private static DirectorySecurity ProtectedDirectorySecurity()
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var sid in new[] { new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null) })
        {
            security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        }
        return security;
    }

    private static bool IsTrustedOwner(SecurityIdentifier sid) =>
        sid.IsWellKnown(WellKnownSidType.LocalSystemSid)
        || sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid)
        || sid.Value == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"; // TrustedInstaller
}
