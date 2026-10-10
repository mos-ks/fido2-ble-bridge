using Fido2BleLogon.Logon;

namespace Fido2BleLogon.CredentialProvider;

/// <summary>What the tile needs from one unlock attempt.</summary>
/// <param name="AllowFewAttemptsLeft">Ask for a finger even when the key reports only a few attempts left
/// (only after the user clicked "Continue anyway").</param>
/// <param name="RequireWake">Ask for a finger only after the key was woken during this attempt; see
/// <see cref="FingerprintLogon.RequireWake"/>. Used for the attempt the tile starts by itself after a request that
/// ended with no finger.</param>
/// <param name="StageChanged">Progress callback; runs on a thread-pool thread.</param>
internal sealed record UnlockRequest(
    bool AllowFewAttemptsLeft,
    bool RequireWake,
    Action<LogonStage> StageChanged);

/// <summary>Runs <see cref="FingerprintLogon.UnlockToBufferAsync"/> for the tile (or the self-test's fake key).</summary>
internal static class Unlocker
{
    /// <summary>How long one attempt waits for a sleeping key to be woken. When it runs out the tile quietly starts
    /// the next attempt, so this only bounds how long one Bluetooth connection attempt lives.</summary>
    public static readonly TimeSpan WakeTimeout = TimeSpan.FromMinutes(5);

    /// <summary>Returns the password in a buffer the caller owns and must clear on every path that drops it (never
    /// a string, which can't be wiped).</summary>
    public static Task<char[]> UnlockAsync(Enrollment enrollment, UnlockRequest request, CancellationToken ct)
    {
        if (TestHooks.Unlock is { } fake)
            return fake(enrollment, request, ct);

        var logon = new FingerprintLogon
        {
            WakeTimeout = WakeTimeout,
            AllowFewAttemptsLeft = request.AllowFewAttemptsLeft,
            RequireWake = request.RequireWake,
        };
        logon.StageChanged += request.StageChanged;
        return logon.UnlockToBufferAsync(enrollment, ct);
    }
}

/// <summary>
/// Seams for the offline self-test (<c>fido2-ble-logon-cphost selftest</c>), which drives the real provider and
/// credential with a fake enrollment and a scripted fake key, so no Bluetooth or fingerprint is involved.
/// All of them are null in production; nothing in the provider sets them.
/// </summary>
internal static class TestHooks
{
    /// <summary>Replaces <see cref="EnrollmentStore.Load"/>.</summary>
    public static Func<Enrollment?>? LoadEnrollment;

    /// <summary>Replaces <see cref="FingerprintLogon.UnlockToBufferAsync"/>. The tile takes ownership of the returned
    /// buffer and clears it when it drops it, so the fake can keep a reference and check that it was cleared.</summary>
    public static Func<Enrollment, UnlockRequest, CancellationToken, Task<char[]>>? Unlock;

    /// <summary>Replaces <see cref="DefaultSignInOption.SetTile"/> (which writes HKLM).</summary>
    public static Action<string>? SetDefaultTile;

    /// <summary>Writes the provider log here instead of %ProgramData%\Fido2BleLogon\logs.</summary>
    public static string? LogPath;

    /// <summary>Replaces how long a ready password waits for LogonUI to ask for it.</summary>
    public static TimeSpan? AutoLogonWindow;

    /// <summary>Replaces the base delay before an attempt the tile starts by itself.</summary>
    public static TimeSpan? AutoRestartDelay;
}
