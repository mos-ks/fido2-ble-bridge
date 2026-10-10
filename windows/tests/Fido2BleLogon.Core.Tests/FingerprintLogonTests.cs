using System.Collections.Concurrent;
using Fido2BleLogon.Ble;
using Fido2BleLogon.Ctap;
using Fido2BleLogon.Logon;

// FingerprintLogon allows one operation per process, so these tests must not run in parallel.
[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace Fido2BleLogon.Core.Tests;

public class FingerprintLogonTests
{
    private const string Password = "correct horse battery staple ✓";
    private static readonly PairedKey Key = new("Simulated key", 0xAABBCCDDEEFF);

    private static FingerprintLogon Logon(FakeAuthenticator key, bool keyAsleep = false,
        Func<bool, CancellationToken, Task>? gate = null, bool allowFewAttemptsLeft = false) => new()
    {
        Connector = (_, _, waitingForKey, _) =>
        {
            if (keyAsleep)
                waitingForKey();
            return Task.FromResult(key.Connect());
        },
        BeforeFingerprint = gate,
        AllowFewAttemptsLeft = allowFewAttemptsLeft,
    };

    private static Task<Enrollment> EnrollAsync(FakeAuthenticator key) =>
        Logon(key).EnrollAsync(Key, "PC", "user", "S-1-5-21-1-2-3-1001", Password, CancellationToken.None);

    [Fact]
    public async Task Enrolling_then_unlocking_returns_the_password()
    {
        var key = new FakeAuthenticator();
        var enrollment = await EnrollAsync(key);
        Assert.Equal(2, key.FingerprintRequests); // one to create the credential, one to seal the password

        Assert.Equal(Password, await Logon(key).UnlockAsync(enrollment, CancellationToken.None));
        Assert.Equal(3, key.FingerprintRequests);
        enrollment.Validate();
        Assert.Equal(FingerprintLogon.RpId, enrollment.RpId);
    }

    [Theory]
    [InlineData(CtapException.OperationDenied)]
    [InlineData(CtapException.PinRequired)]
    [InlineData(CtapException.UvInvalid)]
    public async Task A_rejected_finger_is_reported_with_attempts_left_and_never_retried(byte status)
    {
        var key = new FakeAuthenticator { RejectStatus = status };
        var enrollment = await EnrollAsync(key);
        key.Fingerprints.Enqueue(false);
        int before = key.FingerprintRequests;

        var error = await Assert.ThrowsAsync<LogonException>(() => Logon(key).UnlockAsync(enrollment, CancellationToken.None));

        Assert.Equal(LogonFailure.FingerprintRejected, error.Failure);
        Assert.Equal(5, error.UvRetries);
        Assert.Contains("5 attempts left", error.Message);
        Assert.Equal(before + 1, key.FingerprintRequests);
    }

    [Fact]
    public async Task A_key_without_getUVRetries_still_reports_a_rejected_finger()
    {
        var key = new FakeAuthenticator { UvRetries = null };
        var enrollment = await EnrollAsync(key);
        key.Fingerprints.Enqueue(false);

        var error = await Assert.ThrowsAsync<LogonException>(() => Logon(key).UnlockAsync(enrollment, CancellationToken.None));

        Assert.Equal(LogonFailure.FingerprintRejected, error.Failure);
        Assert.Null(error.UvRetries);
    }

    [Fact]
    public async Task With_few_attempts_left_nothing_is_asked_until_the_user_confirms()
    {
        var key = new FakeAuthenticator();
        var enrollment = await EnrollAsync(key);
        key.UvRetries = 2;
        int before = key.FingerprintRequests;

        var error = await Assert.ThrowsAsync<LogonException>(() => Logon(key).UnlockAsync(enrollment, CancellationToken.None));
        Assert.Equal(LogonFailure.FewAttemptsLeft, error.Failure);
        Assert.Equal(2, error.UvRetries);
        Assert.Equal(before, key.FingerprintRequests);

        Assert.Equal(Password, await Logon(key, allowFewAttemptsLeft: true).UnlockAsync(enrollment, CancellationToken.None));
        Assert.Equal(before + 1, key.FingerprintRequests);
    }

    [Fact]
    public async Task A_blocked_key_is_reported_without_asking()
    {
        var key = new FakeAuthenticator();
        var enrollment = await EnrollAsync(key);
        key.UvRetries = 0;
        int before = key.FingerprintRequests;

        var error = await Assert.ThrowsAsync<LogonException>(() =>
            Logon(key, allowFewAttemptsLeft: true).UnlockAsync(enrollment, CancellationToken.None));

        Assert.Equal(LogonFailure.FingerprintBlocked, error.Failure);
        Assert.Equal(before, key.FingerprintRequests);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task The_gate_learns_whether_the_user_woke_the_key(bool keyAsleep)
    {
        var key = new FakeAuthenticator();
        var enrollment = await EnrollAsync(key);
        bool? seen = null;

        var password = await Logon(key, keyAsleep, (woke, _) =>
        {
            seen = woke;
            return Task.CompletedTask;
        }).UnlockAsync(enrollment, CancellationToken.None);

        Assert.Equal(Password, password);
        Assert.Equal(keyAsleep, seen);
    }

    [Fact]
    public async Task RequireWake_waits_for_an_awake_key_to_sleep_and_be_woken_before_asking()
    {
        var key = new FakeAuthenticator();
        var enrollment = await EnrollAsync(key);
        int before = key.FingerprintRequests;
        int connects = 0;
        var logon = new FingerprintLogon
        {
            RequireWake = true,
            Connector = (_, _, waitingForKey, _) =>
            {
                if (++connects > 1)
                    waitingForKey(); // after sleeping, the key has to be woken
                return Task.FromResult(key.Connect());
            },
        };

        var unlock = logon.UnlockAsync(enrollment, CancellationToken.None);
        await Task.Delay(200);
        Assert.False(unlock.IsCompleted);
        Assert.Equal(before, key.FingerprintRequests); // nothing asked while the key was still awake

        key.Sleep();
        Assert.Equal(Password, await unlock.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Equal(2, connects);
        Assert.Equal(before + 1, key.FingerprintRequests);
    }

    [Fact]
    public async Task RequireWake_asks_at_once_when_the_user_had_to_wake_the_key()
    {
        var key = new FakeAuthenticator();
        var enrollment = await EnrollAsync(key);
        var logon = new FingerprintLogon
        {
            RequireWake = true,
            Connector = (_, _, waitingForKey, _) =>
            {
                waitingForKey();
                return Task.FromResult(key.Connect());
            },
        };

        Assert.Equal(Password, await logon.UnlockAsync(enrollment, CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Equal(1, key.Connections - 1); // enrollment's connection plus exactly one
    }

    [Fact]
    public async Task Cancelling_at_the_gate_uses_no_fingerprint_attempt()
    {
        var key = new FakeAuthenticator();
        var enrollment = await EnrollAsync(key);
        int before = key.FingerprintRequests;

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            Logon(key, gate: (_, _) => throw new OperationCanceledException()).UnlockAsync(enrollment, CancellationToken.None));

        Assert.Equal(before, key.FingerprintRequests);
    }

    [Fact]
    public async Task A_second_operation_while_one_runs_is_refused()
    {
        var key = new FakeAuthenticator();
        var enrollment = await EnrollAsync(key);
        var atGate = new TaskCompletionSource();
        var release = new TaskCompletionSource();
        var first = Logon(key, gate: async (_, ct) =>
        {
            atGate.SetResult();
            await release.Task.WaitAsync(ct);
        }).UnlockAsync(enrollment, CancellationToken.None);
        await atGate.Task;

        var error = await Assert.ThrowsAsync<LogonException>(() => Logon(key).UnlockAsync(enrollment, CancellationToken.None));
        Assert.Equal(LogonFailure.Busy, error.Failure);

        release.SetResult();
        Assert.Equal(Password, await first);
    }

    [Fact]
    public async Task Enrollment_reconnects_when_the_key_powers_down_after_the_first_touch()
    {
        var key = new FakeAuthenticator { DisconnectAfterUserCommand = true };
        var enrollment = await EnrollAsync(key);

        Assert.Equal(2, key.Connections);
        Assert.Equal(2, key.FingerprintRequests);
        Assert.Equal(Password, await Logon(key).UnlockAsync(enrollment, CancellationToken.None));
    }

    [Fact]
    public async Task Enrollment_requires_credProtect()
    {
        var key = new FakeAuthenticator { SupportsCredProtect = false };
        var error = await Assert.ThrowsAsync<LogonException>(() => EnrollAsync(key));
        Assert.Equal(LogonFailure.Unsupported, error.Failure);
        Assert.Equal(0, key.FingerprintRequests);
    }

    [Fact]
    public async Task Enrollment_requires_an_enrolled_fingerprint()
    {
        var key = new FakeAuthenticator { FingerprintEnrolled = false };
        var error = await Assert.ThrowsAsync<LogonException>(() => EnrollAsync(key));
        Assert.Equal(LogonFailure.Unsupported, error.Failure);
        Assert.Equal(0, key.FingerprintRequests);
    }

    [Fact]
    public async Task A_different_key_is_reported_as_not_enrolled()
    {
        var enrollment = await EnrollAsync(new FakeAuthenticator());
        var error = await Assert.ThrowsAsync<LogonException>(() =>
            Logon(new FakeAuthenticator()).UnlockAsync(enrollment, CancellationToken.None));
        Assert.Equal(LogonFailure.NotEnrolled, error.Failure);
    }

    [Fact]
    public async Task A_tampered_enrollment_does_not_decrypt()
    {
        var key = new FakeAuthenticator();
        var enrollment = await EnrollAsync(key);
        var tampered = enrollment with { Salt = new byte[32] };

        var error = await Assert.ThrowsAsync<LogonException>(() => Logon(key).UnlockAsync(tampered, CancellationToken.None));
        Assert.Equal(LogonFailure.NotEnrolled, error.Failure);
    }

    [Fact]
    public async Task Malformed_responses_become_protocol_errors()
    {
        var key = new FakeAuthenticator();
        var enrollment = await EnrollAsync(key);
        key.SendMalformedResponse = true;
        int before = key.FingerprintRequests;

        var error = await Assert.ThrowsAsync<LogonException>(() => Logon(key).UnlockAsync(enrollment, CancellationToken.None));
        Assert.Equal(LogonFailure.Protocol, error.Failure);
        Assert.Equal(before, key.FingerprintRequests);
    }

    [Fact]
    public async Task Stages_arrive_in_order()
    {
        var key = new FakeAuthenticator();
        var enrollment = await EnrollAsync(key);
        var stages = new ConcurrentQueue<LogonStage>();
        var logon = Logon(key, keyAsleep: true);
        logon.StageChanged += stages.Enqueue;

        await logon.UnlockAsync(enrollment, CancellationToken.None);

        Assert.Equal(
            [LogonStage.Connecting, LogonStage.WaitingForKey, LogonStage.Connected, LogonStage.WaitingForFinger, LogonStage.FingerAccepted],
            stages.ToArray());
    }

    [Fact]
    public async Task A_throwing_stage_handler_does_not_break_the_operation()
    {
        var key = new FakeAuthenticator();
        var enrollment = await EnrollAsync(key);
        var logon = Logon(key);
        logon.StageChanged += _ => throw new InvalidOperationException("broken UI");

        Assert.Equal(Password, await logon.UnlockAsync(enrollment, CancellationToken.None));
    }
}
