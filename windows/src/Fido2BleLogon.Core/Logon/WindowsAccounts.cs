using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Fido2BleLogon.Logon;

public static class WindowsAccounts
{
    private const int Logon32LogonInteractive = 2;
    private const int Logon32ProviderDefault = 0;

    /// <summary>The account running this process, as (domain, user name, SID).</summary>
    public static (string Domain, string UserName, string Sid) Current()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var parts = identity.Name.Split('\\', 2);
        return parts.Length == 2
            ? (parts[0], parts[1], identity.User!.Value)
            : (Environment.MachineName, identity.Name, identity.User!.Value);
    }

    /// <summary>Asks Windows whether the password is right, without keeping the logon session.</summary>
    public static bool CheckPassword(string domain, string userName, string password, out string? failure)
    {
        if (LogonUserW(userName, domain, password, Logon32LogonInteractive, Logon32ProviderDefault, out var token))
        {
            CloseHandle(token);
            failure = null;
            return true;
        }
        int error = Marshal.GetLastPInvokeError();
        failure = error switch
        {
            1326 => "wrong user name or password",
            1327 => "this account has a blank password or is restricted; set a password first",
            1385 => "this account may not log on interactively",
            _ => new System.ComponentModel.Win32Exception(error).Message,
        };
        return false;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LogonUserW(string userName, string domain, string password, int logonType, int logonProvider, out nint token);

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(nint handle);
}
