using Microsoft.Win32;
using Fido2BleLogon.CredentialProvider;

namespace Fido2BleLogon.CpHarness;

/// <summary>
/// Says which copy of the provider's managed code actually ran in this process. The provider's runtimeconfig
/// loads it into the default AssemblyLoadContext, and in this harness that context already knows the harness's
/// own build of Fido2BleLogon.CredentialProvider, Fido2BleLogon.Core and the CsWinRT assemblies (they are on its list of
/// trusted assemblies), so it binds to those and never looks at the installed folder. CoCreateInstance (--com)
/// therefore goes through the registered CLSID, the installed comhost and its runtimeconfig, but runs the
/// harness's copy of the managed code. install.ps1 checks the installed managed code
/// by activating the provider from Windows PowerShell (.NET Framework), which has none of these assemblies.
/// </summary>
internal static class InstalledProviderCheck
{
    private static readonly string[] AssemblyNames =
        ["Fido2BleLogon.CredentialProvider", "Fido2BleLogon.Core", "WinRT.Runtime", "Microsoft.Windows.SDK.NET"];

    /// <summary>
    /// Prints the registered comhost and where each provider assembly loaded in this process came from, with a
    /// loud warning when any of them is not the installed copy. Returns true only if at least one was loaded and
    /// every loaded one came from the registered comhost's folder.
    /// </summary>
    public static bool Report()
    {
        string? comHost = RegisteredComHost();
        string? installedFolder = comHost is null ? null : Path.GetDirectoryName(Path.GetFullPath(comHost));
        Console.WriteLine($"Registered comhost: {comHost ?? "(none: the CLSID has no InprocServer32 path)"}");

        bool anyLoaded = false;
        bool allInstalled = true;
        var loaded = AppDomain.CurrentDomain.GetAssemblies();
        foreach (string name in AssemblyNames)
        {
            var assembly = loaded.FirstOrDefault(a => string.Equals(a.GetName().Name, name, StringComparison.OrdinalIgnoreCase));
            if (assembly is null)
            {
                Console.WriteLine($"  {name}: not loaded in this process");
                continue;
            }
            anyLoaded = true;
            string location = assembly.Location;
            bool installed = installedFolder is not null && location.Length > 0
                             && string.Equals(Path.GetDirectoryName(Path.GetFullPath(location)), installedFolder, StringComparison.OrdinalIgnoreCase);
            allInstalled &= installed;
            Console.WriteLine($"  {name}: {(location.Length > 0 ? location : "(no file)")}{(installed ? "" : "   <-- NOT the installed copy")}");
        }

        if (anyLoaded && !allInstalled)
        {
            Console.WriteLine();
            Console.WriteLine("**********************************************************************************************");
            Console.WriteLine("WARNING: the provider code running here is this harness's own build, not the installed one.");
            Console.WriteLine("  The provider loads into .NET's default context, which binds to the harness's copies first.");
            Console.WriteLine("  This run checks the CLSID registration, the installed comhost and its runtimeconfig only.");
            Console.WriteLine("  scripts\\install.ps1 checks the installed managed code and its dependencies (it activates");
            Console.WriteLine("  the provider from Windows PowerShell); a passing run here does not prove that LogonUI can");
            Console.WriteLine("  load what is installed.");
            Console.WriteLine("**********************************************************************************************");
        }
        return anyLoaded && allInstalled;
    }

    /// <summary>HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32 (default value), or null.</summary>
    private static string? RegisteredComHost()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Classes\CLSID\{{{SecurityKeyProvider.ClassIdString}}}\InprocServer32");
            string? path = key?.GetValue(null) as string;
            return string.IsNullOrEmpty(path) ? null : path;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            return null;
        }
    }
}
