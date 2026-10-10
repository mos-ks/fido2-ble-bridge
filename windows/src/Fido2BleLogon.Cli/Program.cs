using System.Security.Principal;
using System.Text;
using Fido2BleLogon.Ble;
using Fido2BleLogon.Ctap;
using Fido2BleLogon.Logon;
using Windows.Devices.Bluetooth;
using Windows.Devices.Bluetooth.Advertisement;
using Windows.Devices.Enumeration;

namespace Fido2BleLogon.Cli;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        var rest = args.ToList();
        string? logPath = TakeOption(rest, "--log");
        string? address = TakeOption(rest, "--address");
        bool hold = rest.Remove("--hold");

        using var tee = logPath is null ? null : ConsoleTee.Start(logPath);
        int exitCode;
        try
        {
            exitCode = rest.FirstOrDefault() switch
            {
                "probe" => await ProbeAsync(address),
                "enroll" => await EnrollAsync(address),
                "test" => await TestAsync(),
                "status" => Status(),
                "unenroll" => Unenroll(),
                "default" => DefaultCommand(rest.ElementAtOrDefault(1)),
                "keys" => await KeysAsync(),
                "pair" => await PairAsync(),
                _ => Usage(),
            };
        }
        catch (Exception ex)
        {
            Console.WriteLine();
            Highlight($"ERROR: {ex.Message}", ConsoleColor.Red);
            if (ex is LogonException { Failure: LogonFailure.Other or LogonFailure.Protocol, InnerException: { } inner })
                Console.WriteLine(inner);
            else if (ex is not (LogonException or BleFidoException or UnauthorizedAccessException or InvalidDataException or InvalidOperationException))
                Console.WriteLine(ex);
            exitCode = 1;
        }
        if (hold)
            HoldWindow();
        return exitCode;
    }

    private static int Usage()
    {
        Console.WriteLine("""
            fido2-ble-logon - fingerprint logon with a Bluetooth FIDO2 key

            Commands (run as administrator):
              probe      Connect to the key over Bluetooth and show what it supports
              enroll     Link your Windows password to the key (two fingerprint touches)
              test       Unlock the stored password with one fingerprint touch and check it
              status     Show the current enrollment
              unenroll   Delete the enrollment (and stop preselecting the tile)
              default on|off   Preselect the fingerprint tile at sign-in, or let Windows choose again
              keys       List paired Bluetooth security keys (no administrator rights needed)
              pair       Pair a key that is in pairing mode (skipped if one is already paired)

            Options:
              --address XX:XX:XX:XX:XX:XX   Use this key instead of the first paired one
              --log <file>                  Also write output to a file (never contains the password)
              --hold                        Keep the window open at the end
            """);
        return 2;
    }

    private static async Task<int> ProbeAsync(string? address)
    {
        RequireElevation();
        var key = await SelectKeyAsync(address);
        Console.WriteLine($"Using {key}.");
        Console.WriteLine("Connecting over Bluetooth...");
        await using var transport = await BleFidoTransport.ConnectAsync(key.Address, TimeSpan.FromSeconds(90),
            () => Highlight(">>> Press the button on your security key now to wake it.", ConsoleColor.Yellow),
            CancellationToken.None);
        Console.WriteLine($"Connected. Max fragment {transport.MaxFragmentLength} bytes, revisions offered 0x{transport.OfferedRevisions:X2}.");

        var ctap = new Ctap2Client(transport);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var info = await ctap.GetInfoAsync(timeout.Token);

        Console.WriteLine();
        Console.WriteLine("authenticatorGetInfo:");
        Console.WriteLine(Cbor.ToDisplayString(info.Raw));
        Console.WriteLine();
        Console.WriteLine($"  CTAP versions     : {string.Join(", ", info.Versions)}");
        Console.WriteLine($"  Firmware          : {info.FirmwareVersion ?? "(not reported)"}");
        Console.WriteLine($"  hmac-secret       : {(info.SupportsHmacSecret ? "yes" : "NO")}");
        Console.WriteLine($"  Fingerprint (uv)  : {Tristate(info.Option("uv"), "enrolled", "supported, but no finger enrolled", "not supported")}");
        Console.WriteLine($"  PIN (clientPin)   : {Tristate(info.Option("clientPin"), "set", "supported, not set", "not supported")}");
        Console.WriteLine($"  UV method         : {(info.UsesUvTokens ? "UV token (CTAP 2.1)" : "uv option (CTAP 2.0)")}");
        Console.WriteLine($"  PIN/UV protocols  : {(info.PinUvAuthProtocols.Count > 0 ? string.Join(", ", info.PinUvAuthProtocols) : "(none listed, so 1)")}");
        var uvRetries = await ctap.GetUvRetriesAsync(info.PreferredProtocol, timeout.Token);
        Console.WriteLine($"  Fingerprint tries : {(uvRetries is int left ? $"{left} left before the key blocks fingerprints" : "not reported by this key")}");
        Console.WriteLine();

        bool ready = info.SupportsHmacSecret && info.FingerprintReady;
        Highlight(ready
            ? "This key has everything fingerprint logon needs."
            : "This key is missing something fingerprint logon needs (see above).",
            ready ? ConsoleColor.Green : ConsoleColor.Red);
        return ready ? 0 : 3;
    }

    private static async Task<int> EnrollAsync(string? address)
    {
        RequireElevation();
        var (domain, userName, sid) = WindowsAccounts.Current();
        if (sid == new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).Value)
            throw new LogonException("Run enroll from your own account (elevated), not as SYSTEM.");

        Console.WriteLine($"Enrolling {domain}\\{userName}.");
        try
        {
            if (EnrollmentStore.Load() is { } existing)
                Console.WriteLine($"This replaces the existing enrollment for {existing.QualifiedUserName} (key {existing.KeyName}).");
        }
        catch (InvalidDataException ex)
        {
            Console.WriteLine($"The existing enrollment can't be used and will be replaced ({ex.Message}).");
        }
        Console.WriteLine();

        var password = ReadValidatedPassword(domain, userName);
        var key = await SelectKeyAsync(address);
        Console.WriteLine($"Using {key}.");
        Console.WriteLine("You will touch the fingerprint sensor twice: once to create the credential, once to seal your password.");

        var enrollment = await ConfirmingFewAttemptsAsync(async logon =>
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(3));
            return await logon.EnrollAsync(key, domain, userName, sid, password, timeout.Token);
        });
        EnrollmentStore.Save(enrollment);
        DefaultSignInOption.SetTile(sid);

        Console.WriteLine();
        Console.WriteLine($"Saved {EnrollmentStore.FilePath} (only SYSTEM and Administrators can read it).");
        Console.WriteLine("The fingerprint tile is now the preselected sign-in option for this account.");
        Highlight("Enrolled. Next, run 'fido2-ble-logon test' to try a fingerprint unlock.", ConsoleColor.Green);
        return 0;
    }

    private static async Task<int> TestAsync()
    {
        RequireElevation();
        var enrollment = EnrollmentStore.Load()
            ?? throw new LogonException("Nothing is enrolled yet. Run 'fido2-ble-logon enroll' first.");
        Console.WriteLine($"Unlocking {enrollment.QualifiedUserName} with {enrollment.KeyName} ({BleFidoTransport.FormatAddress(enrollment.KeyAddress)}).");

        var started = DateTime.UtcNow;
        var password = await ConfirmingFewAttemptsAsync(async logon =>
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(2));
            return await logon.UnlockAsync(enrollment, timeout.Token);
        });
        var elapsed = DateTime.UtcNow - started;

        if (!WindowsAccounts.CheckPassword(enrollment.Domain, enrollment.UserName, password, out var failure))
            throw new LogonException($"The key unlocked a password, but Windows rejected it ({failure}). If you changed your password, run 'fido2-ble-logon enroll' again.");

        Console.WriteLine();
        Highlight($"Success: your fingerprint unlocked a valid Windows password ({elapsed.TotalSeconds:F1} s including the wake-up).", ConsoleColor.Green);
        return 0;
    }

    private static int Status()
    {
        RequireElevation(); // the enrollment folder is unreadable without it, which would look like "not enrolled"
        var enrollment = EnrollmentStore.Load();
        if (enrollment is null)
        {
            Console.WriteLine("Not enrolled.");
            return 1;
        }
        Console.WriteLine($"Account     : {enrollment.QualifiedUserName} ({enrollment.UserSid})");
        Console.WriteLine($"Key         : {enrollment.KeyName} ({BleFidoTransport.FormatAddress(enrollment.KeyAddress)})");
        Console.WriteLine($"Credential  : {Convert.ToHexString(enrollment.CredentialId)[..16]}... (rpId {enrollment.RpId})");
        Console.WriteLine($"Enrolled at : {enrollment.EnrolledAt:yyyy-MM-dd HH:mm}");
        Console.WriteLine($"File        : {EnrollmentStore.FilePath}");
        Console.WriteLine($"Preselected : {(DefaultSignInOption.IsTile(enrollment.UserSid) ? "yes, the fingerprint tile" : "no, Windows chooses")}");
        return 0;
    }

    private static int DefaultCommand(string? setting)
    {
        RequireElevation();
        var enrollment = EnrollmentStore.Load()
            ?? throw new LogonException("Nothing is enrolled yet. Run 'fido2-ble-logon enroll' first.");
        switch (setting)
        {
            case "on":
                DefaultSignInOption.SetTile(enrollment.UserSid);
                Console.WriteLine($"The fingerprint tile is now preselected when {enrollment.QualifiedUserName} signs in.");
                return 0;
            case "off":
                DefaultSignInOption.ClearTile(enrollment.UserSid);
                Console.WriteLine("Windows chooses the preselected sign-in option again (usually the one used last).");
                return 0;
            default:
                Console.WriteLine($"Preselected: {(DefaultSignInOption.IsTile(enrollment.UserSid) ? "the fingerprint tile" : "chosen by Windows")}. Use 'default on' or 'default off'.");
                return 2;
        }
    }

    /// <summary>Pairs a key that is in pairing mode: finds it by the FIDO service in its advertisement and pairs
    /// with link encryption, answering whatever confirmation or code the key asks for on the console.</summary>
    private static async Task<int> PairAsync()
    {
        var paired = await BleFidoTransport.FindPairedKeysAsync();
        if (paired.Count > 0)
        {
            Console.WriteLine($"Already paired: {string.Join(", ", paired)}.");
            return 0;
        }

        Highlight(">>> Put your key in pairing mode now: hold its button about 5 seconds until the LED blinks fast.", ConsoleColor.Yellow);
        Console.WriteLine("    Do this somewhere private: pairing decides which device this PC will trust as your key.");

        // Collect every FIDO device that advertises, never just the first: a device someone else controls must
        // not be able to win a race and become "the key". The user confirms or picks.
        var candidates = new System.Collections.Concurrent.ConcurrentDictionary<ulong, (string Name, short Rssi)>();
        var first = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var watcher = new BluetoothLEAdvertisementWatcher { ScanningMode = BluetoothLEScanningMode.Active };
        watcher.AdvertisementFilter.Advertisement.ServiceUuids.Add(BleFidoTransport.FidoServiceUuid);
        watcher.Received += (_, e) =>
        {
            var name = BleFidoTransport.SafeName(e.Advertisement.LocalName);
            candidates.AddOrUpdate(e.BluetoothAddress, (name, e.RawSignalStrengthInDBm),
                (_, old) => (name.Length > 0 ? name : old.Name, e.RawSignalStrengthInDBm));
            first.TrySetResult();
        };
        watcher.Start();
        try
        {
            await first.Task.WaitAsync(TimeSpan.FromMinutes(2));
            await Task.Delay(TimeSpan.FromSeconds(5)); // let every advertising device show up
        }
        catch (TimeoutException)
        {
            throw new BleFidoException("No key in pairing mode showed up within 2 minutes. If it is connected to another device, turn that device's Bluetooth off and try again.");
        }
        finally
        {
            watcher.Stop();
        }

        var list = candidates.OrderByDescending(c => c.Value.Rssi).ToList();
        string Describe(KeyValuePair<ulong, (string Name, short Rssi)> c) =>
            $"{(c.Value.Name.Length > 0 ? c.Value.Name : "(no name)")}  {BleFidoTransport.FormatAddress(c.Key)}  signal {c.Value.Rssi} dBm";
        ulong address;
        if (list.Count == 1)
        {
            Console.WriteLine($"Found one security key in pairing mode: {Describe(list[0])}");
            Console.Write("Is this your key (its LED is blinking fast right now)? [y/N] ");
            if (!string.Equals(Console.ReadLine()?.Trim(), "y", StringComparison.OrdinalIgnoreCase))
                throw new BleFidoException("Not paired. Run 'fido2-ble-logon pair' again when only your key is in pairing mode.");
            address = list[0].Key;
        }
        else
        {
            Highlight($"{list.Count} devices in pairing mode advertise as security keys. If you have only one key, another device nearby is advertising: pair somewhere else.", ConsoleColor.Yellow);
            for (int i = 0; i < list.Count; i++)
                Console.WriteLine($"  {i + 1}. {Describe(list[i])}");
            Console.Write($"Which one is your key? [1-{list.Count}, Enter to cancel] ");
            if (!int.TryParse(Console.ReadLine()?.Trim(), out int choice) || choice < 1 || choice > list.Count)
                throw new BleFidoException("Not paired.");
            address = list[choice - 1].Key;
        }

        using var device = await BluetoothLEDevice.FromBluetoothAddressAsync(address)
            ?? throw new BleFidoException("The key disappeared before it could be paired. Try again.");
        string deviceName = BleFidoTransport.SafeName(device.Name);
        Console.WriteLine($"Pairing {deviceName} ({BleFidoTransport.FormatAddress(address)})...");
        var pairing = device.DeviceInformation.Pairing.Custom;
        pairing.PairingRequested += (_, request) =>
        {
            switch (request.PairingKind)
            {
                case DevicePairingKinds.ProvidePin:
                    request.Accept(ReadHidden("The key asks for a pairing code (see its manual; often printed on the key): ").Trim());
                    break;
                case DevicePairingKinds.ConfirmPinMatch:
                    Console.Write($"Does the key show the code {request.Pin}? [y/N] ");
                    if (string.Equals(Console.ReadLine()?.Trim(), "y", StringComparison.OrdinalIgnoreCase))
                        request.Accept();
                    break;
                case DevicePairingKinds.DisplayPin:
                    Highlight($">>> Enter {request.Pin} on the key.", ConsoleColor.Yellow);
                    request.Accept();
                    break;
                default:
                    request.Accept();
                    break;
            }
        };
        var result = await pairing.PairAsync(
            DevicePairingKinds.ConfirmOnly | DevicePairingKinds.ProvidePin | DevicePairingKinds.ConfirmPinMatch | DevicePairingKinds.DisplayPin,
            DevicePairingProtectionLevel.Encryption);
        if (result.Status is not (DevicePairingResultStatus.Paired or DevicePairingResultStatus.AlreadyPaired))
            throw new BleFidoException($"Pairing failed ({result.Status}). Put the key in pairing mode again and retry.");
        Highlight($"Paired {deviceName} ({BleFidoTransport.FormatAddress(address)}).", ConsoleColor.Green);
        return 0;
    }

    /// <summary>Lists paired keys from Windows' Bluetooth cache; works without elevation. Exit 3 if none.</summary>
    private static async Task<int> KeysAsync()
    {
        var keys = await BleFidoTransport.FindPairedKeysAsync();
        foreach (var key in keys)
            Console.WriteLine(key);
        if (keys.Count == 0)
            Console.WriteLine("No paired Bluetooth security key found.");
        return keys.Count > 0 ? 0 : 3;
    }

    private static int Unenroll()
    {
        RequireElevation();
        try
        {
            if (EnrollmentStore.Load() is { } enrollment)
                DefaultSignInOption.ClearTile(enrollment.UserSid);
        }
        catch (InvalidDataException)
        {
            // Unreadable enrollment: delete it anyway.
        }
        Console.WriteLine(EnrollmentStore.Delete() ? "Enrollment deleted." : "Nothing was enrolled.");
        return 0;
    }

    /// <summary>Runs a fingerprint operation. If the key has only a few attempts left, nothing was asked yet:
    /// tell the user and run it again only if they confirm.</summary>
    private static async Task<T> ConfirmingFewAttemptsAsync<T>(Func<FingerprintLogon, Task<T>> operation)
    {
        try
        {
            return await operation(NewLogon(allowFewAttemptsLeft: false));
        }
        catch (LogonException ex) when (ex.Failure == LogonFailure.FewAttemptsLeft)
        {
            Highlight(ex.Message, ConsoleColor.Yellow);
            Console.Write("Continue? [y/N] ");
            if (!string.Equals(Console.ReadLine()?.Trim(), "y", StringComparison.OrdinalIgnoreCase))
                throw new LogonException(LogonFailure.FewAttemptsLeft, "Stopped; no fingerprint attempt was used.");
            return await operation(NewLogon(allowFewAttemptsLeft: true));
        }
    }

    private static FingerprintLogon NewLogon(bool allowFewAttemptsLeft)
    {
        var logon = new FingerprintLogon { AllowFewAttemptsLeft = allowFewAttemptsLeft };
        logon.StageChanged += stage =>
        {
            switch (stage)
            {
                case LogonStage.Connecting:
                    Console.WriteLine("Connecting over Bluetooth...");
                    break;
                case LogonStage.WaitingForKey:
                    Highlight(">>> Press the button on your security key now to wake it.", ConsoleColor.Yellow);
                    break;
                case LogonStage.Connected:
                    Console.WriteLine("Connected.");
                    break;
                case LogonStage.WaitingForFinger:
                    Highlight(">>> Touch the fingerprint sensor now (green LED blinks).", ConsoleColor.Yellow);
                    break;
                case LogonStage.FingerAccepted:
                    Console.WriteLine("Fingerprint accepted.");
                    break;
            }
        };
        return logon;
    }

    private static string ReadValidatedPassword(string domain, string userName)
    {
        for (int attempt = 1; ; attempt++)
        {
            var password = ReadHidden($"Windows password for {domain}\\{userName} (typing is hidden): ");
            if (WindowsAccounts.CheckPassword(domain, userName, password, out var failure))
            {
                Console.WriteLine("Password verified with Windows.");
                return password;
            }
            Highlight($"Windows rejected that password: {failure}.", ConsoleColor.Red);
            if (attempt == 3)
                throw new LogonException("Giving up after three attempts.");
        }
    }

    private static string ReadHidden(string prompt)
    {
        Console.Write(prompt);
        var input = new StringBuilder();
        while (true)
        {
            var keyInfo = Console.ReadKey(intercept: true);
            if (keyInfo.Key == ConsoleKey.Enter)
                break;
            if (keyInfo.Key == ConsoleKey.Backspace)
            {
                if (input.Length > 0)
                    input.Length--;
                continue;
            }
            if (!char.IsControl(keyInfo.KeyChar))
                input.Append(keyInfo.KeyChar);
        }
        Console.WriteLine();
        return input.ToString();
    }

    private static async Task<PairedKey> SelectKeyAsync(string? address)
    {
        if (address is not null)
            return new PairedKey("(from --address)", BleFidoTransport.ParseAddress(address));
        var keys = await BleFidoTransport.FindPairedKeysAsync();
        if (keys.Count == 0)
            throw new BleFidoException("No paired Bluetooth security key found. Run 'fido2-ble-logon pair' first.");
        if (keys.Count == 1)
            return keys[0];
        Console.WriteLine("More than one security key is paired:");
        for (int i = 0; i < keys.Count; i++)
            Console.WriteLine($"  {i + 1}. {keys[i]}");
        Console.Write($"Which one? [1-{keys.Count}] ");
        if (!int.TryParse(Console.ReadLine()?.Trim(), out int choice) || choice < 1 || choice > keys.Count)
            throw new BleFidoException("No key chosen.");
        return keys[choice - 1];
    }

    private static void RequireElevation()
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (!identity.IsSystem && !new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
            throw new UnauthorizedAccessException("Windows only lets administrators talk to FIDO keys directly. Run this from an elevated terminal.");
    }

    private static string Tristate(bool? value, string yes, string no, string absent) =>
        value switch { true => yes, false => no, null => absent };

    private static void Highlight(string message, ConsoleColor color)
    {
        var previous = Console.ForegroundColor;
        Console.ForegroundColor = color;
        Console.WriteLine(message);
        Console.ForegroundColor = previous;
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
