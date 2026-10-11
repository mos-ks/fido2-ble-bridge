using System.Collections.Concurrent;
using System.Security.Principal;
using Fido2BleLogon.CredentialProvider;
using Fido2BleLogon.CredentialProvider.Interop;
using Fido2BleLogon.Logon;
using static Fido2BleLogon.CredentialProvider.Interop.HResults;
using static Fido2BleLogon.CpHarness.NativeHost;
using Cpus = Fido2BleLogon.CredentialProvider.Interop.CREDENTIAL_PROVIDER_USAGE_SCENARIO;
using Tile = Fido2BleLogon.CredentialProvider.SecurityKeyCredential;

namespace Fido2BleLogon.CpHarness;

/// <summary>
/// Offline self-test: drives the real provider and credential (through their COM vtables, on an STA thread with
/// a message pump, like LogonUI) with a fake enrollment and a scripted <see cref="FakeKey"/> in place of
/// FingerprintLogon. No Bluetooth, no fingerprint, no elevation, no registry (the default sign-in option write goes
/// through a seam). It checks the tile's state machine: selecting the tile asks for a finger without a click, stage
/// texts, auto-logon, the serialization, failure texts and links, the only automatic attempts (after the key wasn't
/// woken, and after no finger / a dropped link, which wait for the key to be woken again), and that nothing else ever
/// retries by itself. It also checks that Credential UI is always refused, and (through the fake key, which keeps a
/// reference to every password buffer it hands out) that the tile clears the password buffer on every path.
/// </summary>
internal static class SelfTest
{
    private const string Domain = "SELFTEST-PC";
    private const string User = "selftest";
    private const string Sid = "S-1-5-21-1000000001-1000000002-1000000003-1001";
    private const string FakePassword = "Selftest-Pa55word-not-a-secret";

    /// <summary>Base delay before an automatic attempt in this test (production: 1.5 s).</summary>
    private static readonly TimeSpan RestartDelay = TimeSpan.FromMilliseconds(100);

    private static readonly FakeKey Key = new() { Password = FakePassword };
    private static readonly ConcurrentQueue<string> DefaultTileCalls = new();
    private static int _checks;
    private static int _failures;

    private static readonly Enrollment FakeEnrollment = new()
    {
        KeyName = "Fake key",
        KeyAddress = 0x0000_1122_3344_5566,
        RpId = FingerprintLogon.RpId,
        Domain = Domain,
        UserName = User,
        UserSid = Sid,
        CredentialId = new byte[16],
        PublicKeyX = new byte[32],
        PublicKeyY = new byte[32],
        Salt = new byte[32],
        Nonce = new byte[12],
        Ciphertext = new byte[64],
        Tag = new byte[16],
        EnrolledAt = DateTimeOffset.Now,
    };

    public static int Run()
    {
        string log = Path.Combine(Path.GetTempPath(), "fido2-ble-logon-cphost-selftest.log");
        Console.WriteLine("Offline self-test of the security key credential provider.");
        Console.WriteLine("Real provider + tile, fake enrollment, scripted fake key: no Bluetooth, no fingerprint, no registry.");
        Console.WriteLine($"Provider log for this run: {log}");

        TestHooks.LogPath = log;
        TestHooks.LoadEnrollment = () => FakeEnrollment;
        TestHooks.Unlock = Key.UnlockAsync;
        TestHooks.SetDefaultTile = RecordDefaultTile;
        TestHooks.AutoRestartDelay = RestartDelay;
        Fakes.Verbose = false;
        Fakes.OwnerThreadId = Environment.CurrentManagedThreadId;
        try
        {
            Case("fields, tile image, initial state and CLSID", Fields);
            Case("selecting the tile asks for a finger without a click, then success (logon)", SelectAsksRightAway);
            Case("sleeping key woken with its button (unlock)", WokenKey);
            Case("Credential UI is never offered, whatever its flags", CredUiRefused);
            Case("the password buffer is cleared: deselect after the auto-logon window, provider UnAdvise, late result", PasswordBufferCleared);
            Case("key not woken in time: a new attempt starts by itself, no link", KeyNotFoundRestarts);
            Case("no finger in time: the next attempt waits for the key to be woken", NoFingerWaitsForWake);
            Case("no finger in time, then Try again: asks right away", NoFingerThenTryAgain);
            Case("link dropped while waiting for the finger: same as no finger", LinkDroppedWaitsForWake);
            Case("deselect cancels the attempt waiting for the key to be woken; nothing restarts", DeselectWhileWaitingForWake);
            Case("deselect before an automatic attempt starts: it never starts", DeselectDuringRestartDelay);
            Case("automatic attempts that fail at once back off", InstantFailuresBackOff);
            Case("rejected fingerprints never retry by themselves", RejectionsNeverRetry);
            Case("rejections on a key that reports attempts left: no extra warning", RejectionsWithRetriesReported);
            Case("few attempts left: Continue anyway", FewAttemptsLeft);
            Case("deselect while waiting for the key: silent reset", DeselectWhileWaitingForKey);
            Case("deselect while the key waits for a finger: cancelled", DeselectWhileWaitingForFinger);
            Case("provider UnAdvise cancels a running attempt", ProviderUnAdviseCancels);
            Case("Busy", Busy);
            Case("unexpected exception", Unexpected);
            Case("Windows rejects the stored password (ReportResult): re-enroll, no retry", WindowsRejects);
            Case("Windows refuses because of the account's state (ReportResult): its own message, no retry", WindowsRefusesAccount);
            Case("Windows refuses for another reason (ReportResult): its own message, Try again", WindowsRefusesOther);
            Case("auto-logon that LogonUI never picks up expires", AutoLogonExpires);
            Case("enrolled user not in LogonUI's user array: no tile", SidNotInArray);
            Case("inactive cases", Inactive);
        }
        finally
        {
            TestHooks.LogPath = null;
            TestHooks.LoadEnrollment = null;
            TestHooks.Unlock = null;
            TestHooks.SetDefaultTile = null;
            TestHooks.AutoLogonWindow = null;
            TestHooks.AutoRestartDelay = null;
            Fakes.Verbose = true;
        }

        Console.WriteLine();
        Console.WriteLine(_failures == 0
            ? $"SELF-TEST PASSED: {_checks} checks."
            : $"SELF-TEST FAILED: {_failures} of {_checks} checks failed.");
        return _failures == 0 ? 0 : 1;
    }

    // ===== Cases ====================================================================================

    private static void Fields()
    {
        using (var s = Session.CreateDirect())
        {
            Check(s.Start(Cpus.CPUS_LOGON, 0, setUserArray: true, print: false) == S_OK, "SetUsageScenario(CPUS_LOGON) -> S_OK");
            var d = s.ReadDescriptors(print: false);
            Check(d.Count == 5, "5 field descriptors");
            Check(d.Count == 5 && d[0].Type == CREDENTIAL_PROVIDER_FIELD_TYPE.CPFT_TILE_IMAGE && d[0].GuidFieldType == CredentialProviderConstants.CPFG_CREDENTIAL_PROVIDER_LOGO,
                "field 0: tile image, CPFG_CREDENTIAL_PROVIDER_LOGO");
            Check(d.Count == 5 && d[1].Type == CREDENTIAL_PROVIDER_FIELD_TYPE.CPFT_LARGE_TEXT && d[1].Label == Tile.LabelText, "field 1: large text \"Security key fingerprint\"");
            Check(d.Count == 5 && d[2].Type == CREDENTIAL_PROVIDER_FIELD_TYPE.CPFT_SMALL_TEXT, "field 2: small text (status)");
            Check(d.Count == 5 && d[3].Type == CREDENTIAL_PROVIDER_FIELD_TYPE.CPFT_COMMAND_LINK, "field 3: command link");
            Check(d.Count == 5 && d[4].Type == CREDENTIAL_PROVIDER_FIELD_TYPE.CPFT_SMALL_TEXT && d[4].GuidFieldType == CredentialProviderConstants.CPFG_CREDENTIAL_PROVIDER_LABEL,
                "field 4: small text, CPFG_CREDENTIAL_PROVIDER_LABEL");

            uint count = s.Enumerate(print: false, out uint def, out int auto);
            Check(count == 1 && s.Credential is not null, "one credential");
            Check(def == 0 && auto == 0, "tile preselected (default 0) but no auto-logon before a fingerprint");
            Check(s.LastBitmap == (TileImage.Size, TileImage.Size, 32), $"tile image is a {TileImage.Size}x{TileImage.Size} 32-bpp bitmap");
            Check(s.UserSid == Sid, "GetUserSid returns the enrolled SID");
            Check(!Fakes.LinkVisible && Fakes.Status == "", "initially: no status, link hidden");
            Check(Key.Calls == 0, "nothing asks the key before the tile is selected");

            var c = s.Credential!;
            c.GetFieldState(SecurityKeyProvider.FieldImage, out var f0, out _);
            c.GetFieldState(SecurityKeyProvider.FieldTitle, out var f1, out _);
            c.GetFieldState(SecurityKeyProvider.FieldStatus, out var f2, out _);
            c.GetFieldState(SecurityKeyProvider.FieldProviderLabel, out var f4, out _);
            Check(f0 == CREDENTIAL_PROVIDER_FIELD_STATE.CPFS_DISPLAY_IN_BOTH && f1 == CREDENTIAL_PROVIDER_FIELD_STATE.CPFS_DISPLAY_IN_BOTH
                  && f2 == CREDENTIAL_PROVIDER_FIELD_STATE.CPFS_DISPLAY_IN_SELECTED_TILE && f4 == CREDENTIAL_PROVIDER_FIELD_STATE.CPFS_HIDDEN,
                "field states: image/title in both, status in the selected tile, provider label hidden");

            c.GetSerialization(out var response, out var ser, out _, out _);
            LogonBuffer.Free(ser.rgbSerialization, ser.cbSerialization);
            Check(response == CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE.CPGSR_NO_CREDENTIAL_NOT_FINISHED,
                "GetSerialization without a fingerprint -> CPGSR_NO_CREDENTIAL_NOT_FINISHED");

            providerEvents = s.ProviderEventsObject;
            credentialEvents = s.CredentialEventsObject;
        }
        Check(Fakes.RefCount(providerEvents) == 1 && Fakes.RefCount(credentialEvents) == 1,
            "after UnAdvise every reference the provider took on LogonUI's objects is released");

        // The CLSID registered for the provider must be the one written as the preselected sign-in option.
        var tileClassId = Guid.Parse(DefaultSignInOption.TileClassId);
        Check(Guid.Parse(SecurityKeyProvider.ClassIdString) == tileClassId && SecurityKeyProvider.ClassId == tileClassId
              && typeof(SecurityKeyProvider).GUID == tileClassId,
            $"SecurityKeyProvider's CLSID equals DefaultSignInOption.TileClassId {DefaultSignInOption.TileClassId}");
    }

    private static IntPtr providerEvents;
    private static IntPtr credentialEvents;

    private static void SelectAsksRightAway()
    {
        Key.Asleep = false;
        using var s = Open(Cpus.CPUS_LOGON);
        var c = s.Credential!;
        c.SetSelected(out int auto);
        Check(auto == 0, "SetSelected never requests auto-logon");
        Check(PumpUntil(() => Fakes.CredentialsChangedCount == 1), "without any click the key is asked for a finger; after a match: CredentialsChanged");
        Check(Fakes.LinkShown.Count == 0, "no link was shown at any point");
        Check(Fakes.StatusHistory.Contains(Tile.StatusConnecting) && Fakes.StatusHistory.Contains(Tile.StatusWaitingForFinger) && Fakes.Status == Tile.StatusSigningIn,
            $"status: \"{Tile.StatusConnecting}\", \"{Tile.StatusWaitingForFinger}\", then \"{Tile.StatusSigningIn}\"");
        Check(Key.RequireWakeHistory.SequenceEqual([false]), "the attempt asks as soon as the key is connected (RequireWake = false)");
        Check(Fakes.LastPcpc == c.Pointer, "pcpc in the events calls is the pointer GetCredentialAt returned");

        s.Provider.GetCredentialCount(out uint count, out uint def, out int autoLogon);
        Check(count == 1 && def == 0 && autoLogon == 1, "GetCredentialCount: default 0 with auto-logon");
        Check(Key.Buffers.Length == 1 && !FakeKey.IsCleared(Key.Buffers[0]), "the tile holds the key's password buffer while it waits for LogonUI");
        ExpectSerialization(c, LogonBuffer.KerbInteractiveLogon);

        c.GetSerialization(out var again, out var ser, out _, out _);
        LogonBuffer.Free(ser.rgbSerialization, ser.cbSerialization);
        Check(again == CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE.CPGSR_NO_CREDENTIAL_NOT_FINISHED, "the password is gone after one serialization");
        s.Provider.GetCredentialCount(out _, out def, out autoLogon);
        Check(def == 0 && autoLogon == 0, "auto-logon flag cleared (tile stays preselected)");

        Check(DefaultTileCalls.IsEmpty, "the preselected sign-in option is untouched until Windows accepts the logon");
        c.ReportResult(NtStatus.STATUS_SUCCESS, 0, out string? text, out var icon);
        Check(text is null && icon == CREDENTIAL_PROVIDER_STATUS_ICON.CPSI_NONE, "ReportResult(success): no message");
        Check(DefaultTileCalls.SequenceEqual([Sid]), "ReportResult(success) keeps this tile as the enrolled user's preselected sign-in option (SetTile seam)");
        Check(Key.Calls == 1 && Key.FingerRequests == 1, "exactly one attempt, one finger request");
    }

    private static void WokenKey()
    {
        Key.Asleep = true;
        using var s = Open(Cpus.CPUS_UNLOCK_WORKSTATION);
        var c = s.Credential!;
        c.SetSelected(out _);
        Check(PumpUntil(() => Fakes.CredentialsChangedCount == 1), "after the key is woken it is asked for a finger without a click; CredentialsChanged after the match");
        Check(Fakes.StatusHistory.Contains(Tile.StatusWaitingForKey), $"status asked: \"{Tile.StatusWaitingForKey}\"");
        Check(Fakes.LinkShown.Count == 0, "no link was shown");
        ExpectSerialization(c, LogonBuffer.KerbWorkstationUnlockLogon);
        c.ReportResult(NtStatus.STATUS_SUCCESS, 0, out _, out _);
        Check(DefaultTileCalls.SequenceEqual([Sid]), "unlock: ReportResult(success) keeps this tile preselected too");
    }

    /// <summary>Any program running as the user can open the credential dialog and unpack what it returns, so the
    /// tile must never be offered there: E_NOTIMPL and no credential for every flag combination, even when the
    /// enrolled user is the caller.</summary>
    private static void CredUiRefused()
    {
        (uint Flags, string Name)[] flags =
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
        string currentSid = CurrentUserSid();
        var saved = TestHooks.LoadEnrollment;
        try
        {
            foreach (var (f, name) in flags)
            {
                bool refused = true;
                // Enrolled user = someone else, and = the user running the caller (the old CREDUIWIN_ENUMERATE_CURRENT_USER case).
                foreach (string enrolledSid in new[] { Sid, currentSid })
                {
                    TestHooks.LoadEnrollment = () => FakeEnrollment with { UserSid = enrolledSid };
                    using var s = Session.CreateDirect();
                    int hr = s.Start(Cpus.CPUS_CREDUI, f, setUserArray: false, print: false);
                    uint count = s.Enumerate(print: false, out _, out int auto);
                    refused &= hr == E_NOTIMPL && count == 0 && auto == 0 && s.Credential is null;
                }
                Check(refused, $"SetUsageScenario(CPUS_CREDUI, {name}) -> E_NOTIMPL, no credential (enrolled user = caller or not)");
            }
        }
        finally
        {
            TestHooks.LoadEnrollment = saved;
        }

        // The same provider object still works for the lock screen afterwards (LogonUI may reuse it).
        using (var s = Session.CreateDirect())
        {
            Check(s.Start(Cpus.CPUS_CREDUI, 0, false, false) == E_NOTIMPL && s.Start(Cpus.CPUS_UNLOCK_WORKSTATION, 0, true, false) == S_OK
                  && s.Enumerate(print: false, out _, out _) == 1,
                "after refusing Credential UI, the same provider still offers the tile for CPUS_UNLOCK_WORKSTATION");
        }
        Check(Key.Calls == 0 && Key.Buffers.Length == 0, "no unlock was started, no password produced");
        Check(DefaultTileCalls.IsEmpty, "the preselected sign-in option was not touched");
    }

    /// <summary>The password buffer from the key is cleared on the paths that drop it without a serialization.</summary>
    private static void PasswordBufferCleared()
    {
        // 1. Deselect once the auto-logon window is over (but before the expiry timer runs): dropped and cleared.
        TestHooks.AutoLogonWindow = TimeSpan.FromMilliseconds(600);
        Key.Asleep = false;
        using (var s = Open(Cpus.CPUS_LOGON))
        {
            var c = s.Credential!;
            c.SetSelected(out _);
            Check(PumpUntil(() => Fakes.CredentialsChangedCount == 1), "CredentialsChanged");
            Check(Key.Buffers.Length == 1 && !FakeKey.IsCleared(Key.Buffers[0]), "the tile holds the password buffer");
            Pump(800); // past the 600 ms window, before the expiry timer (window + 500 ms)
            s.Provider.GetCredentialCount(out _, out uint def, out int auto);
            Check(def == 0 && auto == 0, "after the window: no auto-logon offered");
            c.SetDeselected();
            Check(FakeKey.IsCleared(Key.Buffers[0]), "deselect after the auto-logon window: the password buffer is cleared at once");
            c.GetSerialization(out var response, out var ser, out _, out _);
            LogonBuffer.Free(ser.rgbSerialization, ser.cbSerialization);
            Check(response == CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE.CPGSR_NO_CREDENTIAL_NOT_FINISHED, "and nothing can be serialized any more");
        }
        TestHooks.AutoLogonWindow = null;

        // 2. Provider UnAdvise (LogonUI tears the tile down) while the password waits: cleared.
        Key.Reset();
        Fakes.ResetObservations();
        using (var s = Open(Cpus.CPUS_UNLOCK_WORKSTATION))
        {
            s.Credential!.SetSelected(out _);
            Check(PumpUntil(() => Fakes.CredentialsChangedCount == 1), "CredentialsChanged");
            Check(Key.Buffers.Length == 1 && !FakeKey.IsCleared(Key.Buffers[0]), "the tile holds the password buffer");
            s.UnAdviseProvider();
            Check(FakeKey.IsCleared(Key.Buffers[0]), "provider UnAdvise: the password buffer is cleared");
        }

        // 3. A result that arrives after the tile moved on (stale generation): never kept, cleared at once.
        Key.Reset();
        Fakes.ResetObservations();
        Key.Enqueue(FakeKey.Outcome.LateSuccess);
        using (var s = Open(Cpus.CPUS_LOGON))
        {
            var c = s.Credential!;
            c.SetSelected(out _);
            Check(PumpUntil(() => Key.FingerRequests == 1 && Fakes.Status == Tile.StatusWaitingForFinger), "the key asks for the finger");
            c.SetDeselected();
            Check(PumpUntil(() => Key.Buffers.Length == 1, 2000), "the match arrives after the deselect");
            Pump(200);
            Check(FakeKey.IsCleared(Key.Buffers[0]), "late result: the password buffer is cleared, not kept");
            Check(Fakes.CredentialsChangedCount == 0 && Fakes.Status == "", "no auto-logon, the tile stays reset");
        }
    }

    private static void KeyNotFoundRestarts()
    {
        Key.Asleep = true;
        Key.Enqueue(FakeKey.Outcome.KeyNotFound, FakeKey.Outcome.KeyNotFound);
        using var s = Open(Cpus.CPUS_LOGON);
        var c = s.Credential!;
        c.SetSelected(out _);
        Check(PumpUntil(() => Fakes.CredentialsChangedCount == 1, 5000),
            "after two attempts nobody woke the key for, the third starts by itself, asks for the finger and signs in");
        Check(Key.Calls == 3 && Key.FingerRequests == 1, "3 attempts, 1 finger request");
        Check(Key.RequireWakeHistory.SequenceEqual([false, false, false]), "the automatic attempts ask as soon as the key is connected (RequireWake = false)");
        Check(Fakes.LinkShown.Count == 0, "no link at any point");
        Check(!Fakes.StatusHistory.Contains(FakeKey.KeyNotFoundMessage), "the KeyNotFound message is never shown");
        Check(Fakes.StatusHistory.Count(t => t == Tile.StatusWaitingForKey) == 1 && Fakes.StatusHistory.Count(t => t == Tile.StatusConnecting) == 1,
            $"the status stays \"{Tile.StatusWaitingForKey}\" across the automatic attempts (no \"{Tile.StatusConnecting}\" in between)");

        // The registry write after a successful logon is best effort.
        c.GetSerialization(out var response, out var ser, out _, out _);
        LogonBuffer.Free(ser.rgbSerialization, ser.cbSerialization);
        Check(response == CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE.CPGSR_RETURN_CREDENTIAL_FINISHED, "serialization returned");
        TestHooks.SetDefaultTile = _ => throw new UnauthorizedAccessException("self-test: HKLM is not writable");
        int hr = c.ReportResult(NtStatus.STATUS_SUCCESS, 0, out string? text, out var icon);
        Check(hr == S_OK && text is null && icon == CREDENTIAL_PROVIDER_STATUS_ICON.CPSI_NONE,
            "a failing preselected-sign-in-option write is swallowed: ReportResult(success) -> S_OK, no message");
    }

    private static void NoFingerWaitsForWake()
    {
        Key.Asleep = false;
        Key.Enqueue(FakeKey.Outcome.NoFinger);
        using var s = Open(Cpus.CPUS_LOGON);
        var c = s.Credential!;
        c.SetSelected(out _);
        Check(PumpUntil(() => LinkIs(Tile.TryAgainText) && Fakes.Status == Tile.StatusNoFinger),
            $"no finger in time: \"{Tile.StatusNoFinger}\" with \"{Tile.TryAgainText}\"");
        Check(PumpUntil(() => Key.Calls == 2 && Key.WaitingForWake), "a new attempt starts by itself and waits for the key to be woken");
        Check(Key.RequireWakeHistory.SequenceEqual([false, true]), "the automatic attempt runs with RequireWake = true");
        Pump(300);
        Check(Fakes.Status == Tile.StatusNoFinger && LinkIs(Tile.TryAgainText), "its Connecting / Connected stages leave the status and the link alone");
        Check(Key.FingerRequests == 1 && FailureCounter.Current == 0, "one finger request so far; a timeout is not counted as a rejection");

        Key.Wake();
        Check(PumpUntil(() => Fakes.CredentialsChangedCount == 1), "once the key is woken it asks for the finger; a match signs in");
        Check(StatusesAfter(Tile.StatusNoFinger).FirstOrDefault() == Tile.StatusWaitingForFinger,
            $"after \"{Tile.StatusNoFinger}\" the next status is \"{Tile.StatusWaitingForFinger}\" (the wake's stages showed nothing)");
        Check(!Fakes.LinkVisible, "link hidden once the key asks for the finger");
        Check(Key.Calls == 2 && Key.FingerRequests == 2, "2 attempts, 2 finger requests");
        ExpectSerialization(c, LogonBuffer.KerbInteractiveLogon);
    }

    private static void NoFingerThenTryAgain()
    {
        Key.Asleep = false;
        Key.Enqueue(FakeKey.Outcome.NoFinger);
        using var s = Open(Cpus.CPUS_LOGON);
        var c = s.Credential!;
        c.SetSelected(out _);
        Check(PumpUntil(() => Key.Calls == 2 && Key.WaitingForWake && LinkIs(Tile.TryAgainText)), "the automatic attempt waits for the key to be woken, \"Try again\" shown");
        c.CommandLinkClicked(SecurityKeyProvider.FieldLink);
        Check(PumpUntil(() => Fakes.CredentialsChangedCount == 1), "\"Try again\" stops waiting and asks right away; a match signs in");
        Check(Key.CancelCount == 1, "the attempt waiting for the wake was cancelled");
        Check(Key.RequireWakeHistory.SequenceEqual([false, true, false]), "the clicked attempt runs with RequireWake = false");
        Check(Key.Calls == 3 && Key.FingerRequests == 2, "3 attempts, 2 finger requests");
        Check(!Fakes.LinkVisible, "link hidden");
    }

    private static void LinkDroppedWaitsForWake()
    {
        Key.Asleep = true;
        Key.Enqueue(FakeKey.Outcome.LinkDropped);
        using var s = Open(Cpus.CPUS_UNLOCK_WORKSTATION);
        var c = s.Credential!;
        c.SetSelected(out _);
        Check(PumpUntil(() => LinkIs(Tile.TryAgainText) && Fakes.Status == Tile.StatusNoFinger),
            $"link dropped: \"{Tile.StatusNoFinger}\" with \"{Tile.TryAgainText}\"");
        Check(PumpUntil(() => Key.Calls == 2 && Key.WaitingForWake) && Key.RequireWakeHistory.SequenceEqual([false, true]),
            "a new attempt starts by itself with RequireWake = true");
        Check(!Fakes.StatusHistory.Contains(FakeKey.LinkDroppedMessage), "the Bluetooth error itself is not shown");
        Key.Wake();
        Check(PumpUntil(() => Fakes.CredentialsChangedCount == 1), "after the key is woken: finger, match, CredentialsChanged");
        ExpectSerialization(c, LogonBuffer.KerbWorkstationUnlockLogon);
    }

    private static void DeselectWhileWaitingForWake()
    {
        Key.Asleep = false;
        Key.Enqueue(FakeKey.Outcome.NoFinger);
        using var s = Open(Cpus.CPUS_LOGON);
        var c = s.Credential!;
        c.SetSelected(out _);
        Check(PumpUntil(() => Key.Calls == 2 && Key.WaitingForWake && LinkIs(Tile.TryAgainText)), "the automatic attempt waits for the key to be woken");
        c.SetDeselected();
        Check(PumpUntil(() => Key.CancelCount == 1), "deselect cancels it");
        Pump(800);
        Check(Key.Calls == 2, "nothing starts by itself while the tile isn't selected");
        Check(!Fakes.LinkVisible && Fakes.Status == "", "silent reset: no message, link hidden");

        c.SetSelected(out _);
        Check(PumpUntil(() => Fakes.CredentialsChangedCount == 1), "selecting the tile again starts an attempt that asks right away; a match signs in");
        Check(Key.RequireWakeHistory.SequenceEqual([false, true, false]), "that attempt runs with RequireWake = false");
    }

    private static void DeselectDuringRestartDelay()
    {
        TestHooks.AutoRestartDelay = TimeSpan.FromSeconds(1);
        Key.Asleep = false;
        Key.Enqueue(FakeKey.Outcome.NoFinger);
        using var s = Open(Cpus.CPUS_LOGON);
        var c = s.Credential!;
        c.SetSelected(out _);
        Check(PumpUntil(() => LinkIs(Tile.TryAgainText) && Fakes.Status == Tile.StatusNoFinger), $"\"{Tile.StatusNoFinger}\" while the next attempt waits to start");
        Check(Key.Calls == 1, "the automatic attempt hasn't reached the key yet");
        c.SetDeselected();
        Pump(1600);
        Check(Key.Calls == 1, "deselected during the delay: the automatic attempt never starts");
        Check(!Fakes.LinkVisible && Fakes.Status == "", "silent reset");
    }

    private static void InstantFailuresBackOff()
    {
        Key.Asleep = false;
        Key.Enqueue(Enumerable.Repeat(FakeKey.Outcome.BluetoothAtConnect, 40).ToArray());
        using var s = Open(Cpus.CPUS_LOGON);
        var c = s.Credential!;
        c.SetSelected(out _);
        Pump(2000);
        int calls = Key.Calls;
        // Delays 100, 200, 400, 800 ms...: about 5 attempts in 2 s; a fixed 100 ms delay would make about 16.
        Check(calls is >= 3 and <= 6, $"{calls} attempts in 2 s: each automatic attempt that fails at once waits longer than the last");
        Check(Fakes.Status == Tile.StatusNoFinger && LinkIs(Tile.TryAgainText) && Key.RequireWakeHistory.Skip(1).All(r => r),
            "meanwhile the tile shows \"No finger detected...\" and every automatic attempt waits for a wake");
        Check(Key.FingerRequests == 0, "no finger was asked for");

        c.SetDeselected();
        calls = Key.Calls;
        Pump(1000);
        Check(Key.Calls == calls, "deselect stops the automatic attempts");

        c.SetSelected(out _);
        Check(PumpUntil(() => Key.Calls >= calls + 2, 1500), "selecting again starts over with the short delay");
        c.SetDeselected();
    }

    private static void RejectionsNeverRetry()
    {
        Key.Asleep = false;
        Key.Enqueue(FakeKey.Outcome.Reject, FakeKey.Outcome.Reject);
        using var s = Open(Cpus.CPUS_LOGON);
        var c = s.Credential!;
        c.SetSelected(out _);
        Check(PumpUntil(() => LinkIs(Tile.TryAgainText)), "after a rejection: \"Try again\"");
        Check(Fakes.Status == FakeKey.RejectedMessage, $"status is the short message: \"{Fakes.Status}\"");

        Pump(1500);
        Check(Key.Calls == 1 && Key.FingerRequests == 1, "no automatic retry (1 attempt after 1.5 s)");
        c.SetDeselected();
        c.SetSelected(out _);
        Pump(600);
        Check(Key.Calls == 1, "deselect + reselect of a failed tile does not retry either");
        Check(LinkIs(Tile.TryAgainText) && Fakes.Status == FakeKey.RejectedMessage, "the failure stays visible until the user acts");

        c.CommandLinkClicked(SecurityKeyProvider.FieldLink);
        Check(PumpUntil(() => Key.Calls == 2 && LinkIs(Tile.TryAgainText) && Fakes.Status.EndsWith(Tile.CarefulSuffix, StringComparison.Ordinal)),
            $"second rejection: \"{Tile.CarefulSuffix}\" appended (key doesn't report attempts left)");
        Check(Key.FingerRequests == 2 && Key.RequireWakeHistory.SequenceEqual([false, false]), "\"Try again\" asks right away");
        Check(FailureCounter.Current == 2, "process-wide consecutive rejection counter is 2");
        Pump(1000);
        Check(Key.Calls == 2, "still no automatic retry");
    }

    private static void RejectionsWithRetriesReported()
    {
        Key.Asleep = true;
        Key.ReportRetries = true;
        Key.Enqueue(FakeKey.Outcome.Reject, FakeKey.Outcome.Reject);
        using var s = Open(Cpus.CPUS_LOGON);
        var c = s.Credential!;
        c.SetSelected(out _);
        Check(PumpUntil(() => LinkIs(Tile.TryAgainText)), "first rejection shown");
        c.CommandLinkClicked(SecurityKeyProvider.FieldLink);
        Check(PumpUntil(() => Key.Calls == 2 && LinkIs(Tile.TryAgainText) && Fakes.StatusHistory.Count(t => t.StartsWith("Fingerprint not recognized", StringComparison.Ordinal)) >= 2),
            "second rejection shown");
        Check(!Fakes.Status.Contains(Tile.CarefulSuffix, StringComparison.Ordinal) && Fakes.Status.Contains("attempts left", StringComparison.Ordinal),
            "the key's own \"attempts left\" message is shown instead of the generic warning");
    }

    private static void FewAttemptsLeft()
    {
        Key.Asleep = false;
        Key.FewLeftUnlessAllowed = true;
        using var s = Open(Cpus.CPUS_LOGON);
        var c = s.Credential!;
        c.SetSelected(out _);
        Check(PumpUntil(() => LinkIs(Tile.ContinueAnywayText)), "few attempts left: \"Continue anyway\"");
        Check(Fakes.Status == FakeKey.FewLeftMessage, "status shows the key's message");
        Check(Key.FingerRequests == 0, "no finger was asked for");
        Pump(800);
        Check(Key.Calls == 1, "no automatic retry");

        c.CommandLinkClicked(SecurityKeyProvider.FieldLink);
        Check(PumpUntil(() => Fakes.CredentialsChangedCount == 1), "after Continue anyway and a match: CredentialsChanged");
        Check(Key.LastAllowFewAttemptsLeft, "the new attempt runs with AllowFewAttemptsLeft = true");
        Check(Key.Calls == 2 && Key.FingerRequests == 1, "\"Continue anyway\" asks right away: no other click");
        ExpectSerialization(c, LogonBuffer.KerbInteractiveLogon);
    }

    private static void DeselectWhileWaitingForKey()
    {
        Key.Asleep = true;
        Key.Enqueue(FakeKey.Outcome.HangForKey, FakeKey.Outcome.HangForKey);
        using var s = Open(Cpus.CPUS_LOGON);
        var c = s.Credential!;
        c.SetSelected(out _);
        Check(PumpUntil(() => Fakes.Status == Tile.StatusWaitingForKey), $"waiting for the key: \"{Tile.StatusWaitingForKey}\"");
        c.SetDeselected();
        Check(PumpUntil(() => Key.CancelCount == 1), "deselect cancels the waiting attempt");
        Pump(300);
        Check(!Fakes.LinkVisible && Fakes.Status == "", "silent reset: no message, link hidden");
        Check(Key.FingerRequests == 0, "no finger was asked for");

        c.SetSelected(out _);
        Check(PumpUntil(() => Key.Calls == 2 && Fakes.Status == Tile.StatusWaitingForKey), "selecting again starts a fresh attempt");
        c.SetDeselected();
        Check(PumpUntil(() => Key.CancelCount == 2), "cancelled again on deselect");
        Pump(500);
        Check(Key.Calls == 2, "and nothing starts by itself");
    }

    private static void DeselectWhileWaitingForFinger()
    {
        Key.Asleep = true;
        Key.Enqueue(FakeKey.Outcome.HangForFinger);
        using var s = Open(Cpus.CPUS_LOGON);
        var c = s.Credential!;
        c.SetSelected(out _);
        Check(PumpUntil(() => Key.FingerRequests == 1 && Fakes.Status == Tile.StatusWaitingForFinger), $"status: \"{Tile.StatusWaitingForFinger}\"");
        c.SetDeselected();
        Check(PumpUntil(() => Key.CancelCount == 1), "deselect cancels the finger request (Core then sends CTAP CANCEL)");
        Pump(300);
        Check(!Fakes.LinkVisible && Fakes.Status == "" && FailureCounter.Current == 0, "silent reset, nothing counted as a rejection");
        Check(Key.Calls == 1, "no automatic attempt after the cancel");
    }

    private static void ProviderUnAdviseCancels()
    {
        Key.Asleep = true;
        Key.Enqueue(FakeKey.Outcome.HangForKey);
        using var s = Open(Cpus.CPUS_LOGON);
        var c = s.Credential!;
        c.SetSelected(out _);
        Check(PumpUntil(() => Fakes.Status == Tile.StatusWaitingForKey), "waiting for the key");
        s.UnAdviseProvider();
        Check(PumpUntil(() => Key.CancelCount == 1), "provider UnAdvise cancels the attempt");
        Pump(500);
        Check(Key.FingerRequests == 0 && Key.Calls == 1, "no finger was asked for, and nothing started again");
    }

    private static void Busy()
    {
        Key.Asleep = true;
        Key.Enqueue(FakeKey.Outcome.Busy);
        using var s = Open(Cpus.CPUS_LOGON);
        s.Credential!.SetSelected(out _);
        Check(PumpUntil(() => LinkIs(Tile.TryAgainText)), "Busy: \"Try again\"");
        Check(Fakes.Status == Tile.StatusBusy, $"status: \"{Tile.StatusBusy}\"");
        Pump(500);
        Check(Key.Calls == 1, "no automatic retry");
    }

    private static void Unexpected()
    {
        Key.Asleep = true;
        Key.Enqueue(FakeKey.Outcome.Unexpected);
        using var s = Open(Cpus.CPUS_LOGON);
        s.Credential!.SetSelected(out _);
        Check(PumpUntil(() => LinkIs(Tile.TryAgainText)), "unexpected exception: \"Try again\"");
        Check(Fakes.Status == Tile.StatusGeneric, $"status: \"{Tile.StatusGeneric}\"");
        Pump(500);
        Check(Key.Calls == 1, "no automatic retry");
    }

    private static void WindowsRejects()
    {
        Key.Asleep = true;
        using var s = OpenAndSubmit(Cpus.CPUS_LOGON);
        var c = s.Credential!;
        c.ReportResult(NtStatus.STATUS_LOGON_FAILURE, NtStatus.STATUS_WRONG_PASSWORD, out string? text, out var icon);
        Check(text == Tile.ReportResultText && icon == CREDENTIAL_PROVIDER_STATUS_ICON.CPSI_ERROR, $"ReportResult(wrong password): \"{text}\" with CPSI_ERROR");
        Check(PumpUntil(() => Fakes.Status == Tile.ReportResultText) && !Fakes.LinkVisible,
            "tile shows the re-enroll message and no \"Try again\" (it would submit the same stored password)");
        Check(DefaultTileCalls.IsEmpty, "a refused logon leaves the preselected sign-in option alone");

        c.CommandLinkClicked(SecurityKeyProvider.FieldLink);
        c.SetDeselected();
        c.SetSelected(out _);
        Pump(500);
        Check(Key.Calls == 1 && Key.FingerRequests == 1, "neither a click nor reselecting starts another attempt with the stored password");
        Check(Fakes.Status == Tile.ReportResultText && !Fakes.LinkVisible, "the message stays");
    }

    private static void WindowsRefusesAccount()
    {
        foreach (var (status, substatus, name) in new[]
                 {
                     (NtStatus.STATUS_ACCOUNT_LOCKED_OUT, 0, "STATUS_ACCOUNT_LOCKED_OUT"),
                     (NtStatus.STATUS_PASSWORD_MUST_CHANGE, 0, "STATUS_PASSWORD_MUST_CHANGE"),
                     (NtStatus.STATUS_ACCOUNT_RESTRICTION, NtStatus.STATUS_ACCOUNT_DISABLED, "STATUS_ACCOUNT_RESTRICTION/ACCOUNT_DISABLED"),
                 })
        {
            Key.Reset();
            Fakes.ResetObservations();
            using var s = OpenAndSubmit(Cpus.CPUS_LOGON);
            var c = s.Credential!;
            c.ReportResult(status, substatus, out string? text, out var icon);
            Check(text is null && icon == CREDENTIAL_PROVIDER_STATUS_ICON.CPSI_NONE, $"{name}: no text of its own, so LogonUI shows Windows' message");
            Check(PumpUntil(() => Fakes.Status == Tile.StatusUseOtherOption) && !Fakes.LinkVisible, $"{name}: \"{Tile.StatusUseOtherOption}\", no \"Try again\"");
            Pump(300);
            Check(Key.Calls == 1, $"{name}: no other attempt");
        }
    }

    private static void WindowsRefusesOther()
    {
        const int statusNoLogonServers = unchecked((int)0xC000005E); // STATUS_NO_LOGON_SERVERS: may pass
        using var s = OpenAndSubmit(Cpus.CPUS_LOGON);
        var c = s.Credential!;
        c.ReportResult(statusNoLogonServers, 0, out string? text, out var icon);
        Check(text is null && icon == CREDENTIAL_PROVIDER_STATUS_ICON.CPSI_NONE, "no text of its own, so LogonUI shows Windows' message");
        Check(PumpUntil(() => LinkIs(Tile.TryAgainText)) && Fakes.Status == Tile.StatusWindowsRefused, $"\"{Tile.StatusWindowsRefused}\" with \"Try again\"");
        Pump(500);
        Check(Key.Calls == 1, "no automatic retry");
        c.CommandLinkClicked(SecurityKeyProvider.FieldLink);
        Check(PumpUntil(() => Fakes.CredentialsChangedCount == 2), "\"Try again\" starts one new attempt");
        Check(Key.Calls == 2 && Key.FingerRequests == 2, "exactly one more attempt");
    }

    private static void AutoLogonExpires()
    {
        TestHooks.AutoLogonWindow = TimeSpan.FromMilliseconds(500);
        Key.Asleep = true;
        using var s = Open(Cpus.CPUS_LOGON);
        var c = s.Credential!;
        c.SetSelected(out _);
        Check(PumpUntil(() => Fakes.CredentialsChangedCount == 1), "CredentialsChanged");
        c.SetDeselected();
        s.Provider.GetCredentialCount(out _, out uint def, out int auto);
        Check(def == 0 && auto == 1, "a deselect during LogonUI's re-enumeration keeps the pending auto-logon");
        Check(Key.Buffers.Length == 1 && !FakeKey.IsCleared(Key.Buffers[0]), "... and the password buffer, for that short window");
        Check(PumpUntil(() => LinkIs(Tile.TryAgainText) && Fakes.Status == Tile.StatusSignInNotStarted), $"after the window: \"{Tile.StatusSignInNotStarted}\"");
        Check(FakeKey.IsCleared(Key.Buffers[0]), "the expired password buffer is cleared");
        s.Provider.GetCredentialCount(out _, out def, out auto);
        Check(def == 0 && auto == 0, "auto-logon withdrawn");
        c.GetSerialization(out var response, out var ser, out _, out _);
        LogonBuffer.Free(ser.rgbSerialization, ser.cbSerialization);
        Check(response == CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE.CPGSR_NO_CREDENTIAL_NOT_FINISHED, "the password was dropped");
        Check(Key.Calls == 1, "no automatic attempt");
    }

    private static void SidNotInArray()
    {
        string saved = Fakes.UserSid;
        Fakes.UserSid = "S-1-5-21-9-9-9-1002";
        try
        {
            using var s = Session.CreateDirect();
            Check(s.Start(Cpus.CPUS_LOGON, 0, setUserArray: true, print: false) == S_OK, "SetUsageScenario -> S_OK");
            Check(s.Enumerate(print: false, out _, out _) == 0, "GetCredentialCount -> 0");
        }
        finally
        {
            Fakes.UserSid = saved;
        }
    }

    private static void Inactive()
    {
        foreach (var cpus in new[] { Cpus.CPUS_INVALID, Cpus.CPUS_CHANGE_PASSWORD, Cpus.CPUS_PLAP, (Cpus)99 })
        {
            using var s = Session.CreateDirect();
            Check(s.Start(cpus, 0, true, false) == E_NOTIMPL, $"{cpus} -> E_NOTIMPL");
        }

        var saved = TestHooks.LoadEnrollment;
        try
        {
            TestHooks.LoadEnrollment = () => null;
            using (var s = Session.CreateDirect())
                Check(s.Start(Cpus.CPUS_LOGON, 0, true, false) == E_NOTIMPL, "nothing enrolled -> E_NOTIMPL");
            TestHooks.LoadEnrollment = () => throw new InvalidDataException("corrupt enrollment (self-test)");
            using (var s = Session.CreateDirect())
                Check(s.Start(Cpus.CPUS_LOGON, 0, true, false) == E_NOTIMPL, "unreadable enrollment -> E_NOTIMPL");
            TestHooks.LoadEnrollment = () => throw new UnauthorizedAccessException("not elevated (self-test)");
            using (var s = Session.CreateDirect())
                Check(s.Start(Cpus.CPUS_LOGON, 0, true, false) == E_NOTIMPL, "enrollment access denied -> E_NOTIMPL");
        }
        finally
        {
            TestHooks.LoadEnrollment = saved;
        }
        Check(Key.Calls == 0, "no unlock was started by any of these");
    }

    // ===== Helpers ==================================================================================

    private static void Case(string name, Action test)
    {
        Console.WriteLine();
        Console.WriteLine($"== {name}");
        Key.Reset();
        FailureCounter.Reset();
        Fakes.ResetObservations();
        Fakes.UserSid = Sid;
        Fakes.QualifiedUserName = $"{Domain}\\{User}";
        Fakes.UserName = User;
        TestHooks.AutoLogonWindow = null;
        TestHooks.AutoRestartDelay = RestartDelay;
        TestHooks.SetDefaultTile = RecordDefaultTile;
        DefaultTileCalls.Clear();
        try
        {
            test();
        }
        catch (Exception ex)
        {
            Check(false, $"threw {ex}");
        }
        Pump(200); // let cancelled attempts wind down before the next case
        Check(Fakes.WrongThreadCalls == 0, "every call into LogonUI's objects came on the LogonUI thread");
        var buffers = Key.Buffers;
        Check(Array.TrueForAll(buffers, FakeKey.IsCleared), $"every password buffer the tile received ({buffers.Length}) is cleared after teardown");
    }

    private static void RecordDefaultTile(string sid) => DefaultTileCalls.Enqueue(sid);

    private static Session Open(Cpus cpus, bool setUserArray = true)
    {
        var s = Session.CreateDirect();
        Check(s.Start(cpus, 0, setUserArray, print: false) == S_OK, $"SetUsageScenario({cpus}) -> S_OK");
        uint count = s.Enumerate(print: false, out uint def, out int auto);
        Check(count == 1 && s.Credential is not null, "one credential");
        Check(def == 0 && auto == 0, "preselected, no auto-logon yet");
        if (s.Credential is null)
            throw new InvalidOperationException("no credential to test");
        return s;
    }

    /// <summary>Opens a session, signs in with the fake key (select + match) and takes the serialization, so the
    /// tile waits for ReportResult.</summary>
    private static Session OpenAndSubmit(Cpus cpus)
    {
        var s = Open(cpus);
        var c = s.Credential!;
        c.SetSelected(out _);
        Check(PumpUntil(() => Fakes.CredentialsChangedCount == 1), "CredentialsChanged");
        c.GetSerialization(out var response, out var ser, out _, out _);
        LogonBuffer.Free(ser.rgbSerialization, ser.cbSerialization);
        Check(response == CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE.CPGSR_RETURN_CREDENTIAL_FINISHED, "serialization returned");
        return s;
    }

    private static string CurrentUserSid()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return identity.User?.Value ?? throw new InvalidOperationException("no user SID for this process");
    }

    /// <summary>GetSerialization must return the logon (always CredProtect'ed: logon and unlock are the only
    /// scenarios) and clear the password buffer it packed.</summary>
    private static void ExpectSerialization(CredentialClient c, int messageType)
    {
        int buffers = Key.Buffers.Length;
        c.GetSerialization(out var response, out var ser, out _, out _);
        try
        {
            Check(response == CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE.CPGSR_RETURN_CREDENTIAL_FINISHED && ser.rgbSerialization != IntPtr.Zero,
                "GetSerialization -> CPGSR_RETURN_CREDENTIAL_FINISHED");
            Check(buffers > 0 && FakeKey.IsCleared(Key.Buffers[buffers - 1]), "the password buffer the tile packed is cleared right after GetSerialization");
            Check(ser.clsidCredentialProvider == SecurityKeyProvider.ClassId, "clsidCredentialProvider is our CLSID");
            if (ser.rgbSerialization == IntPtr.Zero)
                return;
            var logon = LogonBuffer.DecodeKerb(ser.rgbSerialization, ser.cbSerialization);
            Check(logon.MessageType == messageType, $"MessageType {LogonBuffer.MessageTypeName(messageType)}");
            Check(logon.Domain == Domain && logon.UserName == User, $"account {Domain}\\{User}");
            Check(logon.WasProtected, "password protected with CredProtect");
            Check(logon.Password == FakePassword, "password round-trips (value not printed)");
        }
        finally
        {
            LogonBuffer.Free(ser.rgbSerialization, ser.cbSerialization);
        }
    }

    private static bool LinkIs(string text) => Fakes.LinkVisible && Fakes.LinkText == text;

    /// <summary>The statuses shown after the first time <paramref name="status"/> was shown.</summary>
    private static IEnumerable<string> StatusesAfter(string status) => Fakes.StatusHistory.SkipWhile(t => t != status).Skip(1);

    private static bool PumpUntil(Func<bool> done, int timeoutMs = 3000) => NativeHost.PumpUntil(done, timeoutMs);

    private static void Pump(int ms) => NativeHost.PumpUntil(() => false, ms);

    private static void Check(bool ok, string what)
    {
        _checks++;
        if (!ok)
            _failures++;
        Console.WriteLine($"  {(ok ? "PASS" : "FAIL")}  {what}");
    }
}

/// <summary>A scripted stand-in for FingerprintLogon.UnlockToBufferAsync. Mimics its stages, its RequireWake wait and
/// its LogonException failures. Never touches Bluetooth. Keeps a reference to every password buffer it hands to the
/// tile (<see cref="Buffers"/>), which owns them, so the self-test can check that the tile cleared them.</summary>
internal sealed class FakeKey
{
    public enum Outcome
    {
        Success,
        /// <summary>The key asks for the finger, and the match arrives late: the result comes back (with a password)
        /// even if the attempt was cancelled meanwhile, as a request that already left for the key can.</summary>
        LateSuccess,
        Reject,
        Busy,
        Unexpected,
        /// <summary>The key asks for the finger and waits until cancelled.</summary>
        HangForFinger,
        /// <summary>The key never wakes; the attempt waits until cancelled.</summary>
        HangForKey,
        /// <summary>Nobody woke the key before the wake timeout (no finger asked for).</summary>
        KeyNotFound,
        /// <summary>The key asked for the finger and gave up: nobody touched the sensor.</summary>
        NoFinger,
        /// <summary>The link dropped while the key waited for the finger.</summary>
        LinkDropped,
        /// <summary>Bluetooth fails at once, before anything reaches the key.</summary>
        BluetoothAtConnect,
    }

    public const string RejectedMessage = "Fingerprint not recognized.";
    public const string FewLeftMessage = "Only 2 fingerprint attempts are left before the key blocks fingerprints. Make sure you use an enrolled finger, then confirm to continue.";
    public const string KeyNotFoundMessage = "Couldn't reach your security key. Press its button to wake it, then try again.";
    public const string NoFingerMessage = "No finger was detected in time.";
    public const string LinkDroppedMessage = "The security key disconnected (self-test).";

    private readonly ConcurrentQueue<Outcome> _outcomes = new();
    private readonly ConcurrentQueue<bool> _requireWake = new();
    private readonly ConcurrentQueue<char[]> _buffers = new();
    private SemaphoreSlim _wakes = new(0);
    private int _calls;
    private int _fingerRequests;
    private int _cancelCount;
    private int _retriesLeft = 5;
    private volatile bool _waitingForWake;

    public string Password { get; init; } = "";
    public bool Asleep { get; set; }
    public bool FewLeftUnlessAllowed { get; set; }
    public bool ReportRetries { get; set; }
    public bool LastAllowFewAttemptsLeft { get; private set; }
    public int Calls => Volatile.Read(ref _calls);
    public int FingerRequests => Volatile.Read(ref _fingerRequests);
    public int CancelCount => Volatile.Read(ref _cancelCount);

    /// <summary>An attempt with RequireWake is waiting for the key to be woken (<see cref="Wake"/>).</summary>
    public bool WaitingForWake => _waitingForWake;

    /// <summary>RequireWake of every attempt so far, in order.</summary>
    public bool[] RequireWakeHistory => [.. _requireWake];

    /// <summary>Every password buffer handed to the tile so far, in order (the tile owns and must clear them).</summary>
    public char[][] Buffers => [.. _buffers];

    /// <summary>Whether a buffer holds nothing but zeros (the tile cleared it).</summary>
    public static bool IsCleared(char[] buffer) => Array.TrueForAll(buffer, c => c == '\0');

    /// <summary>The user presses the key's button.</summary>
    public void Wake() => _wakes.Release();

    public void Enqueue(params Outcome[] outcomes)
    {
        foreach (var o in outcomes)
            _outcomes.Enqueue(o);
    }

    public void Reset()
    {
        _outcomes.Clear();
        _requireWake.Clear();
        _buffers.Clear();
        _wakes = new SemaphoreSlim(0);
        _waitingForWake = false;
        _calls = _fingerRequests = _cancelCount = 0;
        _retriesLeft = 5;
        Asleep = FewLeftUnlessAllowed = ReportRetries = LastAllowFewAttemptsLeft = false;
    }

    public async Task<char[]> UnlockAsync(Enrollment enrollment, UnlockRequest request, CancellationToken ct)
    {
        Interlocked.Increment(ref _calls);
        LastAllowFewAttemptsLeft = request.AllowFewAttemptsLeft;
        _requireWake.Enqueue(request.RequireWake);
        var wakes = _wakes;
        try
        {
            var outcome = _outcomes.TryDequeue(out var next) ? next : Outcome.Success;
            request.StageChanged(LogonStage.Connecting);
            await Task.Delay(20, ct);
            if (outcome == Outcome.BluetoothAtConnect)
                throw new LogonException(LogonFailure.Bluetooth, LinkDroppedMessage);

            if (request.RequireWake)
            {
                // Like Core: a key still awake from the last request is left alone until it sleeps; either way the
                // attempt waits for the user to wake the key before it asks for a finger.
                request.StageChanged(Asleep ? LogonStage.WaitingForKey : LogonStage.Connected);
                await Task.Delay(20, ct);
                _waitingForWake = true;
                try
                {
                    await wakes.WaitAsync(ct);
                }
                finally
                {
                    _waitingForWake = false;
                }
                request.StageChanged(LogonStage.Connecting);
                request.StageChanged(LogonStage.WaitingForKey);
                await Task.Delay(20, ct);
            }
            else if (Asleep || outcome is Outcome.KeyNotFound or Outcome.HangForKey)
            {
                request.StageChanged(LogonStage.WaitingForKey);
                await Task.Delay(20, ct);
            }
            if (outcome == Outcome.KeyNotFound)
                throw new LogonException(LogonFailure.KeyNotFound, KeyNotFoundMessage);
            if (outcome == Outcome.HangForKey)
            {
                await Task.Delay(Timeout.Infinite, ct);
                throw new InvalidOperationException("unreachable");
            }

            request.StageChanged(LogonStage.Connected);
            await Task.Delay(20, ct);
            if (outcome == Outcome.Busy)
                throw new LogonException(LogonFailure.Busy, "Another fingerprint request is already in progress.");
            if (FewLeftUnlessAllowed && !request.AllowFewAttemptsLeft)
                throw new LogonException(LogonFailure.FewAttemptsLeft, FewLeftMessage) { UvRetries = 2 };

            Interlocked.Increment(ref _fingerRequests);
            request.StageChanged(LogonStage.WaitingForFinger);
            if (outcome == Outcome.LateSuccess)
            {
                await Task.Delay(400, CancellationToken.None); // the answer is on its way: cancelling can't stop it
                request.StageChanged(LogonStage.FingerAccepted);
                return HandOut();
            }
            await Task.Delay(20, ct);

            switch (outcome)
            {
                case Outcome.Reject:
                    int? left = ReportRetries ? --_retriesLeft : null;
                    string text = left is int l ? $"{RejectedMessage} {l} attempts left before the key blocks fingerprints." : RejectedMessage;
                    throw new LogonException(LogonFailure.FingerprintRejected, text) { UvRetries = left };
                case Outcome.Unexpected:
                    throw new InvalidOperationException("self-test: simulated bug");
                case Outcome.HangForFinger:
                    await Task.Delay(Timeout.Infinite, ct);
                    throw new InvalidOperationException("unreachable");
                case Outcome.NoFinger:
                    throw new LogonException(LogonFailure.FingerprintTimeout, NoFingerMessage);
                case Outcome.LinkDropped:
                    throw new LogonException(LogonFailure.Bluetooth, LinkDroppedMessage);
                default:
                    request.StageChanged(LogonStage.FingerAccepted);
                    await Task.Delay(20, ct);
                    return HandOut();
            }
        }
        catch (OperationCanceledException)
        {
            Interlocked.Increment(ref _cancelCount);
            throw;
        }
    }

    /// <summary>A fresh buffer with the password, as FingerprintLogon.UnlockToBufferAsync returns; remembered so the
    /// self-test can check the tile cleared it.</summary>
    private char[] HandOut()
    {
        var buffer = Password.ToCharArray();
        _buffers.Enqueue(buffer);
        return buffer;
    }
}
