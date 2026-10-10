using System.Security.Cryptography;
using System.Text;
using Fido2BleLogon.Ble;
using Fido2BleLogon.Ctap;

namespace Fido2BleLogon.Logon;

public enum LogonStage
{
    Connecting,
    WaitingForKey,
    Connected,
    WaitingForFinger,
    FingerAccepted,
}

/// <summary>Why an operation failed, so callers can react without parsing messages.</summary>
public enum LogonFailure
{
    /// <summary>The key reported a failed fingerprint match. Each one counts toward the key's lockout.</summary>
    FingerprintRejected,
    /// <summary>The key refuses fingerprint checks until it is unblocked.</summary>
    FingerprintBlocked,
    /// <summary>So few attempts are left that one more failed request would block the key; nothing was asked.
    /// Retry with <see cref="FingerprintLogon.AllowFewAttemptsLeft"/> after the user confirms.</summary>
    FewAttemptsLeft,
    /// <summary>No finger was presented before the key gave up.</summary>
    FingerprintTimeout,
    /// <summary>The key never answered (asleep, out of range, or connected elsewhere).</summary>
    KeyNotFound,
    /// <summary>The key doesn't hold the enrolled credential (reset, or a different key).</summary>
    NotEnrolled,
    /// <summary>The process may not talk to the key (not elevated).</summary>
    AccessDenied,
    /// <summary>Another fingerprint operation is running in this process.</summary>
    Busy,
    /// <summary>The key lacks a capability fingerprint logon needs.</summary>
    Unsupported,
    Bluetooth,
    Protocol,
    Other,
}

public sealed class LogonException(LogonFailure failure, string message, Exception? inner = null) : Exception(message, inner)
{
    public LogonException(string message) : this(LogonFailure.Other, message) { }

    public LogonFailure Failure { get; } = failure;

    /// <summary>Fingerprint attempts left before the key blocks them, when the key reports it.</summary>
    public int? UvRetries { get; init; }
}

/// <summary>Enrolls an account and unlocks it again with the key and a fingerprint. Shared by the CLI and the
/// logon tile. An instance runs one operation at a time and is not thread-safe.
/// <para>Each operation asks for the finger exactly once per fingerprint step and never retries a failed match,
/// because the key blocks fingerprints after repeated failures. Per CTAP 2.1 §6.5.3.1 a request that ends any other
/// way than a match (cancelled, timed out) may also use up an attempt, so callers should only start an operation
/// when the user means it; see <see cref="BeforeFingerprint"/>.</para>
/// <para>Every failure surfaces as <see cref="LogonException"/> or <see cref="OperationCanceledException"/>.</para></summary>
public sealed class FingerprintLogon
{
    public const string RpId = "fido2-ble-logon.local";
    private const int CredProtectUserVerificationRequired = 3;
    private const int AttemptsPerRequest = 3; // a key typically tries the finger up to 3 times per request

    private const string BlockedMessage =
        "The key has blocked fingerprint checks after too many failed attempts. Using the key's PIN once " +
        "(for example in Windows Settings > Accounts > Sign-in options > Security key > Manage) may unblock it; " +
        "otherwise the key must be reset.";

    private static readonly byte[] RpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes(RpId));

    // Two operations would share the key's BLE link and see each other's frames, so allow one per process.
    private static readonly SemaphoreSlim Busy = new(1, 1);

    private readonly Lock _eventLock = new();
    private Task _events = Task.CompletedTask;
    private LogonStage? _stage;
    private bool _wokeKey;

    /// <summary>Raised when the operation moves to a new stage (never twice in a row for the same stage).
    /// Handlers run in order on a thread-pool thread, off the Bluetooth path; exceptions they throw are ignored.</summary>
    public event Action<LogonStage>? StageChanged;

    /// <summary>How long to wait for a sleeping key to be woken by its button.</summary>
    public TimeSpan WakeTimeout { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>Ask for a finger even when the key reports only a few attempts left (after the user confirmed).</summary>
    public bool AllowFewAttemptsLeft { get; init; }

    /// <summary>Awaited right before each request that asks for a finger, with whether the key failed to answer the
    /// first connection attempt of this operation (a hint, not proof, that the user pressed its button). A caller can
    /// use it to wait for an explicit user action. Throwing or cancelling aborts the operation without using an attempt.</summary>
    public Func<bool, CancellationToken, Task>? BeforeFingerprint { get; init; }

    /// <summary>Only ask for a finger after the user woke the key during this unlock. If the key is already
    /// connected when the unlock starts, wait without sending it anything until it disconnects (goes to sleep),
    /// then until it is woken again. Meant for retries nobody explicitly asked for, such as after a request that
    /// timed out with nobody at the sensor: each such request may cost a fingerprint attempt.</summary>
    public bool RequireWake { get; init; }

    /// <summary>Fingerprint attempts left as last reported by the key (null if the key can't tell).</summary>
    public int? UvRetries { get; private set; }

    /// <summary>Opens the link to the key at an address; calls the action if the key has to be woken first.
    /// Tests substitute a simulated authenticator.</summary>
    internal Func<ulong, TimeSpan, Action, CancellationToken, Task<ICtapTransport>> Connector { get; init; } =
        async (address, wakeTimeout, waitingForKey, ct) => await BleFidoTransport.ConnectAsync(address, wakeTimeout, waitingForKey, ct);

    /// <summary>Creates a fingerprint-protected credential on the key and seals the password under it.
    /// The user touches the sensor twice: once to create the credential, once to derive the secret.</summary>
    public Task<Enrollment> EnrollAsync(PairedKey key, string domain, string userName, string userSid, string password, CancellationToken ct) =>
        RunExclusiveAsync(() => EnrollCoreAsync(key, domain, userName, userSid, password, ct));

    /// <summary>Recovers the account password: wakes the key, asks for one fingerprint, decrypts.</summary>
    public async Task<string> UnlockAsync(Enrollment enrollment, CancellationToken ct)
    {
        var password = await UnlockToBufferAsync(enrollment, ct);
        try
        {
            return new string(password);
        }
        finally
        {
            Array.Clear(password);
        }
    }

    /// <summary>Like <see cref="UnlockAsync"/>, but returns the password in a buffer the caller clears as soon as
    /// it has used it (a string can't be wiped). For code that holds the password in a long-lived process.</summary>
    public Task<char[]> UnlockToBufferAsync(Enrollment enrollment, CancellationToken ct) =>
        RunExclusiveAsync(() => UnlockCoreAsync(enrollment, ct));

    private async Task<Enrollment> EnrollCoreAsync(PairedKey key, string domain, string userName, string userSid, string password, CancellationToken ct)
    {
        var transport = await ConnectAsync(key.Address, ct);
        try
        {
            var ctap = new Ctap2Client(transport);
            var info = await ctap.GetInfoAsync(ct);
            if (!info.SupportsHmacSecret)
                throw new LogonException(LogonFailure.Unsupported, "This key does not support the hmac-secret extension.");
            if (!info.Extensions.Contains("credProtect"))
                throw new LogonException(LogonFailure.Unsupported,
                    "This key does not support credProtect, so it cannot guarantee that only a fingerprint unlocks your password.");
            if (!info.FingerprintReady)
                throw new LogonException(LogonFailure.Unsupported,
                    "This key has no fingerprint enrolled. Enroll one first (Windows Settings > Accounts > Sign-in options > Security key, or the vendor's app).");
            var protocol = info.PreferredProtocol;

            await BeforeFingerprintAsync(ctap, protocol, ct);
            UvToken? token = info.UsesUvTokens
                ? await AskFingerAsync(ctap, protocol, () => GetUvTokenAsync(ctap, protocol, Ctap2Client.PermissionMakeCredential, ct))
                : null;
            var clientDataHash = RandomNumberGenerator.GetBytes(32);
            Task<AuthenticatorData> MakeCredential() => ctap.MakeCredentialAsync(RpId, RandomNumberGenerator.GetBytes(16),
                $"{domain}\\{userName}", clientDataHash, token, CredProtectUserVerificationRequired, ct);
            var credential = token is null ? await AskFingerAsync(ctap, protocol, MakeCredential) : await MakeCredential();

            if (!credential.UserVerified)
                throw new LogonException(LogonFailure.Protocol, "The key created the credential without verifying a fingerprint.");
            if (!credential.RpIdHash.AsSpan().SequenceEqual(RpIdHash))
                throw new LogonException(LogonFailure.Protocol, "The key returned a credential for a different relying party.");
            if (credential.Extensions?["hmac-secret"] is not true)
                throw new LogonException(LogonFailure.Unsupported, "The key did not enable hmac-secret for the new credential.");
            if (credential.Extensions?["credProtect"] is not (long)CredProtectUserVerificationRequired)
                throw new LogonException(LogonFailure.Unsupported, "The key did not confirm that the credential requires a fingerprint (credProtect).");

            var credentialId = credential.CredentialId!;
            var (x, y) = Ctap2Client.ReadEs256PublicKey(credential.CredentialPublicKey!);
            var salt = RandomNumberGenerator.GetBytes(32);

            // Reconnect first if the key powered down after the touch, then check before the second touch.
            (transport, ctap, var keyAgreement) = await KeyAgreementAsync(transport, ctap, protocol, key.Address, ct);
            await BeforeFingerprintAsync(ctap, protocol, ct);
            var secret = await DeriveSecretAsync(ctap, info, keyAgreement, credentialId, x, y, salt, ct);
            try
            {
                var associatedData = PasswordVault.AssociatedData(RpId, userSid, domain, userName, credentialId);
                var (nonce, ciphertext, tag) = PasswordVault.Seal(secret, password, associatedData);
                return new Enrollment
                {
                    KeyName = key.Name,
                    KeyAddress = key.Address,
                    RpId = RpId,
                    Domain = domain,
                    UserName = userName,
                    UserSid = userSid,
                    CredentialId = credentialId,
                    PublicKeyX = x,
                    PublicKeyY = y,
                    Salt = salt,
                    Nonce = nonce,
                    Ciphertext = ciphertext,
                    Tag = tag,
                    EnrolledAt = DateTimeOffset.Now,
                };
            }
            finally
            {
                CryptographicOperations.ZeroMemory(secret);
            }
        }
        finally
        {
            await transport.DisposeAsync();
        }
    }

    private async Task<char[]> UnlockCoreAsync(Enrollment enrollment, CancellationToken ct)
    {
        var transport = await ConnectAsync(enrollment.KeyAddress, ct);
        try
        {
            while (RequireWake && !_wokeKey)
            {
                // Still awake from earlier: let it go to sleep (sending nothing keeps its idle timer running),
                // then wait for the user to wake it again.
                await transport.WaitForDisconnectAsync(ct);
                await transport.DisposeAsync();
                transport = await ConnectAsync(enrollment.KeyAddress, ct);
            }
            var ctap = new Ctap2Client(transport);
            var info = await ctap.GetInfoAsync(ct);
            var protocol = info.PreferredProtocol;
            await BeforeFingerprintAsync(ctap, protocol, ct);
            (transport, ctap, var keyAgreement) = await KeyAgreementAsync(transport, ctap, protocol, enrollment.KeyAddress, ct);
            var secret = await DeriveSecretAsync(ctap, info, keyAgreement, enrollment.CredentialId, enrollment.PublicKeyX,
                enrollment.PublicKeyY, enrollment.Salt, ct);
            try
            {
                return PasswordVault.OpenChars(secret, enrollment);
            }
            catch (AuthenticationTagMismatchException ex)
            {
                throw new LogonException(LogonFailure.NotEnrolled,
                    "The key's secret does not match the enrollment. Run 'fido2-ble-logon enroll' again.", ex);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(secret);
            }
        }
        finally
        {
            await transport.DisposeAsync();
        }
    }

    /// <summary>One fingerprint-verified assertion that evaluates hmac-secret with <paramref name="salt"/>.</summary>
    private async Task<byte[]> DeriveSecretAsync(Ctap2Client ctap, AuthenticatorInfo info, KeyAgreement keyAgreement,
        byte[] credentialId, byte[] publicKeyX, byte[] publicKeyY, byte[] salt, CancellationToken ct)
    {
        var protocol = info.PreferredProtocol;
        UvToken? token = info.UsesUvTokens
            ? await AskFingerAsync(ctap, protocol, () => GetUvTokenAsync(ctap, protocol, Ctap2Client.PermissionGetAssertion, ct))
            : null;
        var clientDataHash = RandomNumberGenerator.GetBytes(32);
        Task<Assertion> GetAssertion() => ctap.GetAssertionAsync(RpId, clientDataHash, credentialId, token,
            new HmacSecretInput(protocol, keyAgreement, salt), ct);
        var assertion = token is null ? await AskFingerAsync(ctap, protocol, GetAssertion) : await GetAssertion();

        if (!assertion.AuthData.UserVerified)
            throw new LogonException(LogonFailure.Protocol, "The key answered without verifying a fingerprint.");
        if (!assertion.AuthData.RpIdHash.AsSpan().SequenceEqual(RpIdHash))
            throw new LogonException(LogonFailure.Protocol, "The key answered for a different relying party.");
        if (!Ctap2Client.VerifySignature(publicKeyX, publicKeyY, assertion.AuthData.Raw, clientDataHash, assertion.Signature))
            throw new LogonException(LogonFailure.NotEnrolled, "The key's signature did not verify; this is not the enrolled credential.");
        return assertion.HmacSecret!;
    }

    private static async Task<UvToken> GetUvTokenAsync(Ctap2Client ctap, PinUvAuthProtocol protocol, byte permission, CancellationToken ct)
    {
        var keyAgreement = await ctap.GetKeyAgreementAsync(protocol, ct);
        return await ctap.GetUvTokenAsync(protocol, keyAgreement, permission, RpId, ct);
    }

    /// <summary>Checks the attempts left, then lets the caller hold the request until the user means it.</summary>
    private async Task BeforeFingerprintAsync(Ctap2Client ctap, PinUvAuthProtocol protocol, CancellationToken ct)
    {
        UvRetries = await ctap.GetUvRetriesAsync(protocol, ct);
        if (UvRetries == 0)
            throw new LogonException(LogonFailure.FingerprintBlocked, BlockedMessage) { UvRetries = 0 };
        if (UvRetries is int left && left <= AttemptsPerRequest && !AllowFewAttemptsLeft)
            throw new LogonException(LogonFailure.FewAttemptsLeft,
                $"Only {left} fingerprint attempts are left before the key blocks fingerprints. " +
                "Make sure you use an enrolled finger, then confirm to continue.") { UvRetries = left };
        if (BeforeFingerprint is { } gate)
            await gate(_wokeKey, ct);
    }

    /// <summary>Sends a request the key answers only after checking the finger, and explains a failed check.</summary>
    private async Task<T> AskFingerAsync<T>(Ctap2Client ctap, PinUvAuthProtocol protocol, Func<Task<T>> request)
    {
        Report(LogonStage.WaitingForFinger);
        try
        {
            var result = await request();
            Report(LogonStage.FingerAccepted);
            return result;
        }
        catch (CtapException ex) when (ex.IsFingerprintRejected || ex.IsBlocked)
        {
            int? retries = null;
            try
            {
                retries = await ctap.GetUvRetriesAsync(protocol, CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(3));
            }
            catch
            {
                // Best effort: the key may have dropped the link after the failure.
            }
            UvRetries = retries;
            if (ex.IsBlocked || retries == 0)
                throw new LogonException(LogonFailure.FingerprintBlocked, BlockedMessage, ex) { UvRetries = retries };
            var left = retries is int r ? $" {r} attempts left before the key blocks fingerprints." : "";
            throw new LogonException(LogonFailure.FingerprintRejected, "Fingerprint not recognized." + left, ex) { UvRetries = retries };
        }
    }

    /// <summary>Gets a fresh key agreement, reconnecting once if the key dropped the link since the last command
    /// (it may power down after a request that needed the user, or while waiting for <see cref="BeforeFingerprint"/>).</summary>
    private async Task<(ICtapTransport, Ctap2Client, KeyAgreement)> KeyAgreementAsync(ICtapTransport transport, Ctap2Client ctap,
        PinUvAuthProtocol protocol, ulong address, CancellationToken ct)
    {
        try
        {
            return (transport, ctap, await ctap.GetKeyAgreementAsync(protocol, ct));
        }
        catch (BleFidoException)
        {
            await transport.DisposeAsync();
            transport = await ConnectAsync(address, ct);
            ctap = new Ctap2Client(transport);
            return (transport, ctap, await ctap.GetKeyAgreementAsync(protocol, ct));
        }
    }

    private async Task<ICtapTransport> ConnectAsync(ulong address, CancellationToken ct)
    {
        lock (_eventLock)
            _stage = null;
        Report(LogonStage.Connecting);
        var transport = await Connector(address, WakeTimeout, () =>
        {
            _wokeKey = true;
            Report(LogonStage.WaitingForKey);
        }, ct);
        transport.WaitingForUser += () => Report(LogonStage.WaitingForFinger);
        Report(LogonStage.Connected);
        return transport;
    }

    private async Task<T> RunExclusiveAsync<T>(Func<Task<T>> operation)
    {
        if (!Busy.Wait(0))
            throw new LogonException(LogonFailure.Busy, "Another fingerprint request is already in progress.");
        _wokeKey = false;
        try
        {
            return await operation();
        }
        catch (Exception ex) when (ex is not (OperationCanceledException or LogonException))
        {
            throw Translate(ex);
        }
        finally
        {
            Busy.Release();
            try
            {
                await _events.WaitAsync(TimeSpan.FromSeconds(2)); // let the last stage reach the UI first
            }
            catch
            {
                // A slow handler must not hold up the result.
            }
        }
    }

    private static LogonException Translate(Exception ex) => ex switch
    {
        CtapException { Status: CtapException.NoCredentials or CtapException.InvalidCredential } => new(LogonFailure.NotEnrolled,
            "This key doesn't hold the enrolled credential (was it reset, or is it a different key?). Enroll again.", ex),
        CtapException { Status: CtapException.UserActionTimeout } => new(LogonFailure.FingerprintTimeout,
            "No finger was detected in time.", ex),
        CtapException { IsBlocked: true } => new(LogonFailure.FingerprintBlocked, BlockedMessage, ex),
        CtapException { IsFingerprintRejected: true } => new(LogonFailure.FingerprintRejected, "Fingerprint not recognized.", ex),
        CtapException c => new(LogonFailure.Protocol, $"The security key refused the request ({CtapException.Describe(c.Status)}).", ex),
        TimeoutException => new(LogonFailure.KeyNotFound, "Couldn't reach your security key. Press its button to wake it, then try again.", ex),
        UnauthorizedAccessException => new(LogonFailure.AccessDenied, ex.Message, ex),
        BleFidoException => new(LogonFailure.Bluetooth, ex.Message, ex),
        CtapProtocolException or CryptographicException => new(LogonFailure.Protocol,
            $"The security key sent an unexpected response: {ex.Message}", ex),
        _ => new(LogonFailure.Other, $"Unexpected error: {ex.Message}", ex),
    };

    private void Report(LogonStage stage)
    {
        lock (_eventLock)
        {
            if (_stage == stage)
                return;
            _stage = stage;
            if (StageChanged is not { } handler)
                return;
            _events = _events.ContinueWith(_ =>
            {
                try
                {
                    handler(stage);
                }
                catch
                {
                    // A broken handler must not break the operation.
                }
            }, CancellationToken.None, TaskContinuationOptions.None, TaskScheduler.Default);
        }
    }
}
