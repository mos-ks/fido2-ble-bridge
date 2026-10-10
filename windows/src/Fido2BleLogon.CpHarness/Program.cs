using System.Security.Principal;
using System.Text;
using Fido2BleLogon.CredentialProvider;
using Fido2BleLogon.CredentialProvider.Interop;
using Fido2BleLogon.Logon;
using static Fido2BleLogon.CredentialProvider.Interop.HResults;
using static Fido2BleLogon.CpHarness.NativeHost;
using Tile = Fido2BleLogon.CredentialProvider.SecurityKeyCredential;

namespace Fido2BleLogon.CpHarness;

/// <summary>
/// Stands in for LogonUI so the security key credential provider can be tried with the real key without putting it
/// on the logon screen. It never prints the password.
/// </summary>
internal static class Program
{
    private const int WaitSeconds = 120;

    [STAThread]
    private static int Main(string[] args)
    {
        var rest = args.ToList();
        string? logPath = TakeOption(rest, "--log");
        string? scenario = TakeOption(rest, "--scenario");
        bool hold = rest.Remove("--hold");
        bool com = rest.Remove("--com");
        bool autoClick = rest.Remove("--auto-click"); // obsolete: the tile no longer waits for a click
        bool noUserArray = rest.Remove("--no-user-array");
        string mode = rest.FirstOrDefault() ?? "simulate";

        using var tee = logPath is null ? null : ConsoleTee.Start(logPath);
        if (autoClick)
            Console.WriteLine("Note: --auto-click is no longer needed and is ignored: the tile asks for the finger without a click.");
        int exitCode;
        try
        {
            exitCode = mode switch
            {
                "simulate" => RunSimulation(scenario ?? "logon", com, !noUserArray),
                "credui" => CheckCredUiRefused(com),
                "selftest" => SelfTest.Run(),
                _ => Usage(),
            };
        }
        catch (Exception ex)
        {
            Console.WriteLine();
            Console.WriteLine("HARNESS ERROR: " + ex);
            exitCode = 1;
        }

        if (hold)
            HoldWindow();
        return exitCode;
    }

    private static int Usage()
    {
        Console.WriteLine("""
            fido2-ble-logon-cphost - LogonUI simulation harness for the security key credential provider

            Modes:
              simulate   (default) Play LogonUI in this process against the real key: select the tile (it asks
                         for the finger as soon as the key is connected), wait for the fingerprint, then check
                         the serialization with Windows. Enter clicks "Try again" while the tile waits for the
                         key to be woken after no finger was detected; Esc stops. Run elevated.
              credui     Negative check: the provider must refuse Credential UI (CredUIPromptForWindowsCredentials),
                         which any program running as you can open and read the result of. Checks that
                         SetUsageScenario(CPUS_CREDUI) returns E_NOTIMPL for every flag combination and that no
                         credential is offered, so no fingerprint request ever starts there. No key, no elevation.
              selftest   Offline test of the tile logic with a fake key: no Bluetooth, no fingerprint,
                         no elevation, no registry.

            Options:
              --scenario logon|unlock          Usage scenario for simulate (default logon). The provider offers
                                               no other scenario.
              --com                            Create the provider with CoCreateInstance (needs install.ps1
                                               -RegisterOnly). Checks the CLSID registration, the installed
                                               comhost and its runtimeconfig ONLY: the managed code that runs
                                               is this harness's own build of the provider and Core, not the
                                               installed files. install.ps1 checks those.
              --no-user-array                 Don't call SetUserArray (the tile is then offered without
                                               checking LogonUI's list of users)
              --log <file>                     Also write output to a file (never contains the password or
                                               its length)
              --hold                           Keep the window open at the end

            Exit code 0 means the fingerprint-unlocked password was accepted by Windows (or the self-test passed).
            """);
        return 2;
    }

    // ===== simulate =================================================================================

    private enum Outcome { Success, Failure, Stopped, TimedOut }

    private static int RunSimulation(string scenarioName, bool com, bool setUserArray)
    {
        CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus;
        switch (scenarioName)
        {
            case "logon":
                cpus = CREDENTIAL_PROVIDER_USAGE_SCENARIO.CPUS_LOGON;
                break;
            case "unlock":
                cpus = CREDENTIAL_PROVIDER_USAGE_SCENARIO.CPUS_UNLOCK_WORKSTATION;
                break;
            case "credui":
                Console.WriteLine("The provider never offers the tile in Credential UI. 'fido2-ble-logon-cphost credui' checks that it refuses it.");
                return 2;
            default:
                Console.WriteLine($"Unknown scenario '{scenarioName}'. Use logon or unlock.");
                return 2;
        }

        var (domain, user, sid) = WindowsAccounts.Current();
        Console.WriteLine($"LogonUI simulation: {cpus}, account {domain}\\{user} ({sid})");
        Console.WriteLine($"Provider CLSID {{{SecurityKeyProvider.ClassIdString}}}, created {(com ? "with CoCreateInstance (registered comhost)" : "directly in this process")}");
        if (!IsElevated())
            Console.WriteLine("WARNING: not elevated. The provider can't read the enrollment or open the key's Bluetooth service, so it will stay inactive.");
        Console.WriteLine();

        // A successful ReportResult makes the tile the preselected sign-in option (HKLM). This harness must not change
        // the real logon screen's settings, so it only reports the call.
        TestHooks.SetDefaultTile = tileSid => Console.WriteLine(
            $"  [harness] the tile asks to stay the preselected sign-in option for {tileSid} (DefaultSignInOption.SetTile); not written by the harness");

        Fakes.UserSid = sid;
        Fakes.QualifiedUserName = $"{domain}\\{user}";
        Fakes.UserName = user;
        Fakes.Verbose = true;
        Fakes.OwnerThreadId = Environment.CurrentManagedThreadId;
        Fakes.ResetObservations();

        Session? session;
        bool ranInstalledCode = true;
        if (com)
        {
            session = Session.CreateViaCom(out int hrCreate);
            if (session is null)
            {
                Console.WriteLine($"CoCreateInstance failed: {Session.Hr(hrCreate)}. Register the provider first (scripts\\install.ps1 -RegisterOnly), or drop --com.");
                return 2;
            }
            Console.WriteLine("Which provider code CoCreateInstance runs:");
            ranInstalledCode = InstalledProviderCheck.Report();
            Console.WriteLine();
        }
        else
        {
            session = Session.CreateDirect();
        }

        using (session)
        {
            int hr = session.Start(cpus, 0, setUserArray, print: true);
            if (hr != S_OK)
            {
                Console.WriteLine(hr == E_NOTIMPL
                    ? "The provider is inactive (Safe Mode, kill-switch file, nothing enrolled, enrollment unreadable, or not elevated). See C:\\ProgramData\\Fido2BleLogon\\logs\\provider.log."
                    : "Unexpected SetUsageScenario result.");
                return 2;
            }
            session.ReadDescriptors(print: true);
            uint count = session.Enumerate(print: true, out _, out _);
            if (count == 0 || session.Credential is null)
            {
                Console.WriteLine("The provider enumerated no credential (enrolled user not in the user array, or no UI dispatcher). See provider.log.");
                return 2;
            }
            if (!string.Equals(session.UserSid, sid, StringComparison.OrdinalIgnoreCase))
                Console.WriteLine($"NOTE: the tile belongs to {session.UserSid}, not to the account running this harness.");

            var credential = session.Credential;
            credential.SetSelected(out int autoLogon);
            Console.WriteLine($"SetSelected -> autoLogon={autoLogon} (expected 0)");
            Console.WriteLine();
            Console.WriteLine("Follow the tile: press the key's button if it asks, then touch the sensor when it says so.");
            Console.WriteLine("If no finger is detected in time, the tile asks again after you press the key's button (or Enter: \"Try again\").");
            Console.WriteLine($"Waiting up to {WaitSeconds} s. Esc stops (and cancels the request on the key).");
            Console.WriteLine();

            var outcome = Watch(credential);
            Console.WriteLine();

            int result;
            switch (outcome)
            {
                case Outcome.Success:
                    result = ValidateSuccess(session, credential, cpus);
                    break;
                case Outcome.Failure:
                    Console.WriteLine($"The tile reported a failure: \"{Fakes.Status}\" (link: \"{Fakes.LinkText}\").");
                    Console.WriteLine("The tile does not retry this kind of failure by itself. Run the harness again to try again.");
                    result = 1;
                    break;
                case Outcome.Stopped:
                    Console.WriteLine("Stopped.");
                    result = 1;
                    break;
                default:
                    Console.WriteLine($"No result after {WaitSeconds} s.");
                    result = 1;
                    break;
            }

            // Leave like LogonUI does: deselect (cancels anything still running; the key gets CTAP CANCEL),
            // then give the cancellation a moment to reach the key before tearing down.
            credential.SetDeselected();
            PumpUntil(() => false, outcome is Outcome.Stopped or Outcome.TimedOut ? 3000 : 300);
            Console.WriteLine($"Calls into LogonUI's objects from the wrong thread: {Fakes.WrongThreadCalls}");
            if (!ranInstalledCode)
                Console.WriteLine("NOTE: --com ran this harness's build of the provider code, not the installed files (see the warning above).");
            return result;
        }
    }

    /// <summary>Pumps messages like LogonUI until the tile succeeds, fails, the user stops, or time runs out.
    /// The tile retries by itself while it waits for the key to be woken ("No finger detected..." with "Try again");
    /// Enter clicks that "Try again". Any other link means a failure the tile leaves to the user: the run ends.</summary>
    private static Outcome Watch(CredentialClient credential)
    {
        Outcome? outcome = null;
        bool prompted = false;
        bool keyboard = true;
        PumpUntil(() => outcome is not null, WaitSeconds * 1000, () =>
        {
            if (Fakes.CredentialsChangedCount > 0)
            {
                outcome = Outcome.Success;
                return;
            }
            bool waitingForWake = Fakes.LinkVisible && Fakes.LinkText == Tile.TryAgainText && Fakes.Status == Tile.StatusNoFinger;
            if (Fakes.LinkVisible && !waitingForWake && Fakes.LinkText is Tile.TryAgainText or Tile.ContinueAnywayText)
            {
                outcome = Outcome.Failure;
                return;
            }

            if (waitingForWake && !prompted)
            {
                Console.WriteLine("  [harness] No finger detected. Press the key's button and the tile asks again, or press Enter to click \"Try again\".");
                prompted = true;
            }
            else if (!waitingForWake)
            {
                prompted = false;
            }

            if (!keyboard)
                return;
            try
            {
                while (Console.KeyAvailable)
                {
                    var key = Console.ReadKey(intercept: true).Key;
                    if (key == ConsoleKey.Escape)
                    {
                        outcome = Outcome.Stopped;
                        return;
                    }
                    if (key == ConsoleKey.Enter && waitingForWake)
                    {
                        Console.WriteLine("  [harness] clicking \"Try again\": the tile asks for the finger right away");
                        credential.CommandLinkClicked(SecurityKeyProvider.FieldLink);
                    }
                }
            }
            catch (InvalidOperationException)
            {
                keyboard = false;
                Console.WriteLine("  [harness] No interactive console: Enter/Esc are unavailable (wake the key with its button to retry).");
            }
        });
        return outcome ?? Outcome.TimedOut;
    }

    /// <summary>What LogonUI does after CredentialsChanged: re-enumerate, take the serialization, submit it
    /// (here: decode and check it with LogonUserW), then ReportResult.</summary>
    private static int ValidateSuccess(Session session, CredentialClient credential, CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus)
    {
        bool structureOk = true;
        session.Provider.GetCredentialCount(out uint count, out uint def, out int auto);
        Console.WriteLine($"GetCredentialCount after CredentialsChanged -> count={count}, default={Session.FormatDefault(def)}, autoLogon={auto}");
        if (count != 1 || def != 0 || auto != 1)
        {
            Console.WriteLine("  WARNING: expected count 1, default 0, autoLogon 1.");
            structureOk = false;
        }

        credential.GetSerialization(out var response, out var serialization, out string? statusText, out _);
        // No byte count: the size follows the password's length.
        Console.WriteLine($"GetSerialization -> {response}, package {serialization.ulAuthenticationPackage}, " +
                          $"clsid {{{serialization.clsidCredentialProvider}}}");
        if (statusText is not null)
            Console.WriteLine($"  status text: \"{statusText}\"");
        if (response != CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE.CPGSR_RETURN_CREDENTIAL_FINISHED || serialization.rgbSerialization == IntPtr.Zero)
        {
            Console.WriteLine("FAIL: no finished serialization was returned.");
            return 1;
        }
        if (serialization.clsidCredentialProvider != SecurityKeyProvider.ClassId)
        {
            Console.WriteLine("  WARNING: clsidCredentialProvider is not our CLSID.");
            structureOk = false;
        }

        DecodedLogon logon;
        try
        {
            logon = LogonBuffer.DecodeKerb(serialization.rgbSerialization, serialization.cbSerialization);
        }
        finally
        {
            LogonBuffer.Free(serialization.rgbSerialization, serialization.cbSerialization); // LogonUI frees it after use
        }

        int expectedType = cpus == CREDENTIAL_PROVIDER_USAGE_SCENARIO.CPUS_UNLOCK_WORKSTATION
            ? LogonBuffer.KerbWorkstationUnlockLogon
            : LogonBuffer.KerbInteractiveLogon;
        Console.WriteLine($"Decoded KERB_INTERACTIVE_UNLOCK_LOGON: {LogonBuffer.MessageTypeName(logon.MessageType)} for {logon.Domain}\\{logon.UserName}, " +
                          $"password {(logon.WasProtected ? "CredProtect'ed" : "not protected")}, {(logon.Password.Length == 0 ? "empty" : "not empty")}");
        if (logon.MessageType != expectedType || !logon.WasProtected)
        {
            Console.WriteLine($"  WARNING: expected {LogonBuffer.MessageTypeName(expectedType)} and a CredProtect'ed password.");
            structureOk = false;
        }

        bool ok = WindowsAccounts.CheckPassword(logon.Domain, logon.UserName, logon.Password, out string? failure);
        Console.WriteLine(ok
            ? "PASS: Windows accepts the fingerprint-unlocked password for this account."
            : $"FAIL: Windows rejected the unlocked password ({failure}).");

        int hr = credential.ReportResult(ok ? NtStatus.STATUS_SUCCESS : NtStatus.STATUS_LOGON_FAILURE,
            ok ? 0 : NtStatus.STATUS_WRONG_PASSWORD, out string? reportText, out var icon);
        Console.WriteLine($"ReportResult({(ok ? "STATUS_SUCCESS" : "STATUS_LOGON_FAILURE")}) -> {Session.Hr(hr)}" +
                          (reportText is null ? "" : $", \"{reportText}\" ({icon})"));

        credential.GetSerialization(out var again, out var leftover, out _, out _);
        LogonBuffer.Free(leftover.rgbSerialization, leftover.cbSerialization);
        Console.WriteLine($"GetSerialization again -> {again} (expected CPGSR_NO_CREDENTIAL_NOT_FINISHED: the password was dropped)");
        if (again != CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE.CPGSR_NO_CREDENTIAL_NOT_FINISHED)
            structureOk = false;

        return ok && structureOk ? 0 : 1;
    }

    // ===== credui (negative check) ==================================================================

    /// <summary>CREDUIWIN_* flag combinations a Credential UI caller may pass (0 is what a plain caller uses).</summary>
    private static readonly (uint Flags, string Name)[] CredUiFlags =
    [
        (0, "no flags"),
        (0x1, "CREDUIWIN_GENERIC"),
        (0x2, "CREDUIWIN_CHECKBOX"),
        (0x10, "CREDUIWIN_AUTHPACKAGE_ONLY"),
        (0x20, "CREDUIWIN_IN_CRED_ONLY"),
        (0x100, "CREDUIWIN_ENUMERATE_ADMINS"),
        (0x200, "CREDUIWIN_ENUMERATE_CURRENT_USER"),
        (0x1000, "CREDUIWIN_SECURE_PROMPT"),
        (0x10000000, "CREDUIWIN_PACK_32_WOW"),
        (0x200 | 0x1000, "CREDUIWIN_ENUMERATE_CURRENT_USER | CREDUIWIN_SECURE_PROMPT"),
    ];

    /// <summary>
    /// The tile must never be offered in Credential UI: any program running as the user can open that dialog and
    /// unpack the credential it returns. Checks SetUsageScenario(CPUS_CREDUI) -> E_NOTIMPL and no credential for
    /// every flag combination above. Nothing is selected, so no fingerprint request can start.
    /// </summary>
    private static int CheckCredUiRefused(bool com)
    {
        Console.WriteLine("Credential UI check: the provider must refuse CPUS_CREDUI, so the security key tile never appears in");
        Console.WriteLine("the Windows credential dialog (CredUIPromptForWindowsCredentials) and no fingerprint request starts there.");
        Console.WriteLine($"Provider created {(com ? "with CoCreateInstance (registered comhost)" : "directly in this process")}.");
        Console.WriteLine();

        bool ok = true;
        foreach (var (flags, name) in CredUiFlags)
        {
            int hrCreate = S_OK;
            Session? session = com ? Session.CreateViaCom(out hrCreate) : Session.CreateDirect();
            if (session is null)
            {
                Console.WriteLine($"CoCreateInstance failed: {Session.Hr(hrCreate)}. Register the provider first (scripts\\install.ps1 -RegisterOnly), or drop --com.");
                return 2;
            }
            using (session)
            {
                int hr = session.Start(CREDENTIAL_PROVIDER_USAGE_SCENARIO.CPUS_CREDUI, flags, setUserArray: false, print: false);
                uint count = session.Enumerate(print: false, out _, out _);
                bool refused = hr == E_NOTIMPL && count == 0 && session.Credential is null;
                ok &= refused;
                Console.WriteLine($"  {(refused ? "PASS" : "FAIL")}  SetUsageScenario(CPUS_CREDUI, 0x{flags:X8} {name}) -> {Session.Hr(hr)}, credentials: {count}");
            }
        }

        if (com)
        {
            Console.WriteLine();
            Console.WriteLine("Which provider code CoCreateInstance ran:");
            InstalledProviderCheck.Report();
        }
        Console.WriteLine();
        Console.WriteLine(ok
            ? "PASS: the provider refuses Credential UI for every flag combination; the tile is never offered there."
            : "FAIL: the provider accepted Credential UI. It must not: the dialog's caller could read the Windows password.");
        return ok ? 0 : 1;
    }

    // ===== helpers ==================================================================================

    private static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static string? TakeOption(List<string> args, string name)
    {
        int index = args.IndexOf(name);
        if (index < 0 || index + 1 >= args.Count)
            return null;
        var value = args[index + 1];
        args.RemoveRange(index, 2);
        return value;
    }

    private static void HoldWindow()
    {
        Console.WriteLine();
        Console.Write("Press any key to close this window (it closes by itself in 60 s)...");
        try
        {
            var until = DateTime.UtcNow.AddSeconds(60);
            while (DateTime.UtcNow < until && !Console.KeyAvailable)
                Thread.Sleep(100);
        }
        catch (InvalidOperationException)
        {
            // No interactive console (input redirected).
        }
    }
}

/// <summary>Copies console output to a log file, so a run in a separate elevated window can be read afterwards.</summary>
internal sealed class ConsoleTee : IDisposable
{
    private readonly TextWriter _originalOut;
    private readonly StreamWriter _file;

    private ConsoleTee(string path)
    {
        _originalOut = Console.Out;
        _file = new StreamWriter(path, append: false, Encoding.UTF8) { AutoFlush = true };
        Console.SetOut(TextWriter.Synchronized(new TeeWriter(_originalOut, _file)));
    }

    public static ConsoleTee Start(string path) => new(path);

    public void Dispose()
    {
        Console.SetOut(_originalOut);
        _file.Dispose();
    }

    private sealed class TeeWriter(TextWriter console, TextWriter file) : TextWriter
    {
        public override Encoding Encoding => console.Encoding;
        public override void Write(char value) { console.Write(value); file.Write(value); }
        public override void Write(string? value) { console.Write(value); file.Write(value); }
        public override void WriteLine(string? value) { console.WriteLine(value); file.WriteLine(value); }
        public override void Flush() { console.Flush(); file.Flush(); }
    }
}
