using Microsoft.Win32;

namespace Fido2BleLogon.Logon;

/// <summary>The sign-in option LogonUI preselects for a user: one value per user SID under
/// HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\UserTile holding a credential
/// provider CLSID. Writing it needs administrator or SYSTEM rights.</summary>
public static class DefaultSignInOption
{
    /// <summary>The security key tile (the credential provider's CLSID).</summary>
    public const string TileClassId = "{35E15797-DD2E-44F3-B82C-839EEB10AEBD}";

    private const string KeyPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\UserTile";

    /// <summary>The CLSID LogonUI preselects for the user, or null if Windows decides.</summary>
    public static string? Get(string userSid)
    {
        using var key = Registry.LocalMachine.OpenSubKey(KeyPath);
        return key?.GetValue(userSid) as string;
    }

    public static bool IsTile(string userSid) =>
        string.Equals(Get(userSid), TileClassId, StringComparison.OrdinalIgnoreCase);

    /// <summary>Makes the security key tile the preselected sign-in option for the user.</summary>
    public static void SetTile(string userSid)
    {
        using var key = Registry.LocalMachine.CreateSubKey(KeyPath, writable: true);
        key.SetValue(userSid, TileClassId, RegistryValueKind.String);
    }

    /// <summary>Hands the choice back to Windows (it preselects what was used last), if the tile is preselected.</summary>
    public static void ClearTile(string userSid)
    {
        if (!IsTile(userSid))
            return;
        using var key = Registry.LocalMachine.OpenSubKey(KeyPath, writable: true);
        key?.DeleteValue(userSid, throwOnMissingValue: false);
    }
}
