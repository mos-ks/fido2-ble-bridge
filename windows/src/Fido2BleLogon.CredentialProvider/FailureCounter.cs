namespace Fido2BleLogon.CredentialProvider;

/// <summary>
/// Process-wide count of consecutive "fingerprint not recognized" results. The key locks for good after
/// 15 failed matches in a row, and not every key reports how many attempts are left, so from the second
/// failure on the tile adds a warning. It is reset when a fingerprint is accepted or Windows accepts the logon.
/// Static on purpose: Credential UI creates a new provider per prompt, and LogonUI may recreate tiles.
/// </summary>
internal static class FailureCounter
{
    private static int _count;

    public static int Increment() => Interlocked.Increment(ref _count);

    public static int Current => Volatile.Read(ref _count);

    public static void Reset() => Interlocked.Exchange(ref _count, 0);
}
