using System.Runtime.InteropServices;
using Fido2BleLogon.CredentialProvider.Interop;
using Fido2BleLogon.Logon;
using static Fido2BleLogon.CredentialProvider.Interop.HResults;

namespace Fido2BleLogon.CredentialProvider;

/// <summary>Where the tile is in its life.</summary>
internal enum TilePhase
{
    /// <summary>Nothing running; selecting the tile starts an unlock.</summary>
    Idle,
    /// <summary>An unlock is running: about to start, waiting for the key, or waiting for a finger.</summary>
    Running,
    /// <summary>The key returned the password; waiting for LogonUI to call GetSerialization.</summary>
    Ready,
    /// <summary>The serialization went to LogonUI; waiting for ReportResult.</summary>
    Submitted,
    /// <summary>Something failed; the message and a link stay up until the user clicks the link.</summary>
    Failed,
}

/// <summary>What the command link (field 3) does when clicked.</summary>
internal enum LinkAction
{
    None,
    /// <summary>After a failure: start a new attempt. While an attempt waits for the key to be woken after "No finger
    /// detected": stop waiting and ask for the finger right away.</summary>
    TryAgain,
    ContinueAnyway,
}

/// <summary>
/// The security key tile (ICredentialProviderCredential2). Selecting it starts <see cref="FingerprintLogon.UnlockToBufferAsync"/>
/// on a background task, which asks for a finger as soon as the key is connected; no click is needed. Waiting for the
/// key needs no click either: an attempt waits up to <see cref="Unlocker.WakeTimeout"/> for the key to be woken, and
/// if nobody woke it (KeyNotFound, so no finger was asked for) the tile quietly starts the same kind of attempt again.
/// <para>
/// SAFETY: the key locks for good after 15 failed matches in a row, and per CTAP 2.1 a fingerprint request that ends
/// without a match (timed out, cancelled) may count as a failed attempt too. LogonUI can select the tile with nobody
/// there, so after a request that ended with no finger (FingerprintTimeout) or a dropped link (Bluetooth) the tile's
/// next attempt uses <see cref="FingerprintLogon.RequireWake"/>: it asks again only after someone woke the key with
/// its button (or clicked "Try again"). Those two and KeyNotFound are the only automatic attempts. A rejected finger,
/// and every other failure, is never retried by itself: the message and a link stay until the user clicks the link.
/// Automatic attempts start after a short delay that grows while they keep failing at once, only while the tile is
/// selected, and never pile up (each one replaces the attempt that failed, under a new generation number).
/// </para>
/// <para>
/// Threading: every COM method runs on LogonUI's UI thread. Background code (the unlock, stage callbacks,
/// timers) only changes the state under <c>_sync</c> and posts <see cref="Render"/> to the UI thread through the
/// provider's dispatcher window; only <see cref="Render"/> and COM methods call LogonUI's events interface.
/// Every operation carries a generation number, so a late result from a cancelled operation is ignored.
/// </para>
/// <para>
/// The password: only ever the <c>char[]</c> the key's unlock returned, never a string. The tile owns that buffer and
/// clears it on every path that drops it (serialized, deselected, expired, failed, shut down, or a stale result).
/// Whoever removes it from <c>_password</c> under <c>_sync</c> owns it: <see cref="GetSerialization"/> takes it out
/// of the field before packing it, and every other path only clears a buffer it took out of the field itself
/// (<see cref="DropPasswordLocked"/>), so no thread can clear the buffer while the UI thread packs it.
/// </para>
/// </summary>
// Not a registered coclass: LogonUI never creates the credential itself, it receives the interface pointer
// from GetCredentialAt. ComVisible(false) keeps it out of the comhost CLSID map; the CCW still works.
[ComVisible(false)]
public sealed class SecurityKeyCredential : ICredentialProviderCredential2
{
    internal const string LabelText = "Security key fingerprint";
    internal const string TryAgainText = "Try again";
    internal const string ContinueAnywayText = "Continue anyway";

    internal const string StatusConnecting = "Connecting to your security key...";
    internal const string StatusWaitingForKey = "Press the button on your security key";
    internal const string StatusConnected = "Connected";
    internal const string StatusWaitingForFinger = "Touch the fingerprint sensor";
    internal const string StatusSigningIn = "Signing in...";
    /// <summary>A request ended with no finger (or the link dropped); the next attempt waits for the key to be woken.</summary>
    internal const string StatusNoFinger = "No finger detected. Press the button on your security key to try again.";
    internal const string StatusBusy = "Another fingerprint request is in progress.";
    internal const string StatusGeneric = "Something went wrong. Try again.";
    internal const string StatusSignInNotStarted = "Sign-in didn't start. Try again.";
    internal const string StatusPrepareFailed = "Couldn't prepare the sign-in. Try again.";
    internal const string StatusWindowsRejected = "Windows rejected the stored password.";
    /// <summary>The stored password is wrong (changed since enrollment): status line and ReportResult text.</summary>
    internal const string ReportResultText = StatusWindowsRejected + " Run 'fido2-ble-logon enroll' again.";
    /// <summary>Windows refused the logon for a reason a retry may fix; LogonUI shows Windows' own message.</summary>
    internal const string StatusWindowsRefused = "Windows did not sign you in.";
    /// <summary>Windows refused the logon because of the account's state (locked out, disabled, password expired or
    /// must change, logon hours...); a retry can't help and LogonUI shows Windows' own message.</summary>
    internal const string StatusUseOtherOption = "Windows did not sign you in. Use another sign-in option.";
    internal const string CarefulSuffix = "Careful: the key locks after repeated failures.";

    private static readonly TimeSpan DefaultAutoLogonWindow = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan PreviousOperationWait = TimeSpan.FromSeconds(20);

    // Automatic attempts start after DefaultRestartDelay, doubled for each one in a row that failed within
    // QuickFailure (something fails at once, e.g. Bluetooth is off), up to 2^MaxRestartBackoff times.
    private static readonly TimeSpan DefaultRestartDelay = TimeSpan.FromSeconds(1.5);
    private static readonly TimeSpan QuickFailure = TimeSpan.FromSeconds(5);
    private const int MaxRestartBackoff = 4;

    // Core allows one fingerprint operation per process; a new one first waits for the last to wind down
    // (a cancelled one still sends CTAP CANCEL), instead of failing at once with Busy.
    private static readonly object OperationChainLock = new();
    private static Task s_lastOperation = Task.CompletedTask;

    private readonly SecurityKeyProvider _owner;
    private readonly CREDENTIAL_PROVIDER_USAGE_SCENARIO _cpus;
    private readonly Enrollment _enrollment;
    private readonly string _scenario;

    // Guarded by _sync (touched by background threads).
    private readonly object _sync = new();
    private TilePhase _phase = TilePhase.Idle;
    private int _generation;
    private CancellationTokenSource? _cts;
    private bool _requireWake;    // the running attempt waits for the key to be woken ("Try again" asks right away)
    private bool _selected;       // between SetSelected and SetDeselected: automatic attempts only start then
    private int _restartStreak;   // automatic attempts in a row whose predecessor failed quickly
    private string _status = string.Empty;
    private LinkAction _link = LinkAction.None;
    private string _linkText = TryAgainText;
    private char[]? _password;    // owned by the tile; cleared by whoever removes it (see the class remarks)
    private bool _autoLogonPending;
    private long _autoLogonDeadline;
    private bool _shutdown;

    // UI-thread only.
    private IntPtr _events; // ICredentialProviderCredentialEvents*, AddRef'ed
    private string? _shownStatus;
    private string? _shownLinkText;
    private bool? _shownLinkVisible;

    internal SecurityKeyCredential(SecurityKeyProvider owner, CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, Enrollment enrollment)
    {
        _owner = owner;
        _cpus = cpus;
        _enrollment = enrollment;
        _scenario = SecurityKeyProvider.ScenarioName(cpus);
    }

    /// <summary>One attempt. <paramref name="Automatic"/>: the tile started it by itself after a failure (not a
    /// selection or a click); it starts after <paramref name="Delay"/>.</summary>
    private readonly record struct Ticket(int Generation, CancellationToken Token, bool AllowFewAttemptsLeft, bool RequireWake,
        bool Automatic, TimeSpan Delay);

    private static TimeSpan AutoLogonWindow => TestHooks.AutoLogonWindow ?? DefaultAutoLogonWindow;

    private static TimeSpan RestartDelay => TestHooks.AutoRestartDelay ?? DefaultRestartDelay;

    /// <summary>True while a password from the key waits for LogonUI (GetCredentialCount reports auto-logon).</summary>
    internal bool WantsAutoLogon
    {
        get
        {
            lock (_sync)
                return _phase == TilePhase.Ready && _password is not null && _autoLogonPending
                       && Environment.TickCount64 < _autoLogonDeadline;
        }
    }

    // ===== Advise / selection =======================================================================

    public int Advise(IntPtr pcpce)
    {
        try
        {
            ReleaseEvents();
            if (pcpce != IntPtr.Zero)
            {
                Marshal.AddRef(pcpce);
                _events = pcpce;
            }
            // LogonUI reads the fields again for a new sink; push everything on the next render.
            _shownStatus = null;
            _shownLinkText = null;
            _shownLinkVisible = null;
            _owner.EnsureUiPump();
            return S_OK;
        }
        catch (Exception ex)
        {
            Log("Advise", ex);
            return S_OK;
        }
    }

    public int UnAdvise()
    {
        try
        {
            ReleaseEvents();
            return S_OK;
        }
        catch (Exception ex)
        {
            Log("UnAdvise", ex);
            return S_OK;
        }
    }

    public int SetSelected(out int pbAutoLogon)
    {
        // Never auto-submit from selection: LogonUI may select this tile without any user action. Only a password
        // the key returned after a fingerprint leads to a sign-in (OnSuccess).
        pbAutoLogon = 0;
        try
        {
            _owner.EnsureUiPump();
            Ticket? ticket = null;
            TilePhase phase;
            lock (_sync)
            {
                _selected = true;
                phase = _phase;
                // Asks for the finger as soon as the key is connected: no click needed.
                if (_phase == TilePhase.Idle && !_shutdown)
                    ticket = BeginOperationLocked(allowFewAttemptsLeft: false, requireWake: false, automatic: false);
            }
            if (ticket is { } t)
            {
                ProviderLog.Write(_scenario, $"tile selected; starting unlock #{t.Generation}");
                Launch(t);
            }
            else
            {
                ProviderLog.Write(_scenario, $"tile selected ({phase}); nothing started");
            }
            Render();
            return S_OK;
        }
        catch (Exception ex)
        {
            Log("SetSelected", ex);
            pbAutoLogon = 0;
            return S_OK;
        }
    }

    public int SetDeselected()
    {
        try
        {
            CancellationTokenSource? cts = null;
            string action;
            lock (_sync)
            {
                _selected = false; // nothing starts by itself from here on
                switch (_phase)
                {
                    case TilePhase.Running:
                        // Also an attempt waiting for the key to be woken, or one waiting to start.
                        _generation++; // a late result of this operation is now ignored
                        cts = _cts;
                        action = _requireWake ? "cancelled the unlock waiting for the key to be woken" : "cancelled the running unlock";
                        ResetLocked();
                        break;
                    case TilePhase.Ready when _autoLogonPending && Environment.TickCount64 < _autoLogonDeadline:
                        // LogonUI may deselect while it re-enumerates for the auto-logon we asked for; keep the
                        // password for that short window (it expires on its own).
                        action = "kept the ready password for the pending auto-logon";
                        break;
                    case TilePhase.Ready:
                    case TilePhase.Submitted:
                        _generation++;
                        ResetLocked();
                        action = "dropped the pending password";
                        break;
                    default:
                        // Idle: nothing to do. Failed: the message and link stay until the user acts on them.
                        action = $"nothing to do ({_phase})";
                        break;
                }
            }
            Cancel(cts);
            ProviderLog.Write(_scenario, $"tile deselected; {action}");
            Render();
            return S_OK;
        }
        catch (Exception ex)
        {
            Log("SetDeselected", ex);
            return S_OK;
        }
    }

    // ===== Field getters ============================================================================

    public int GetFieldState(uint dwFieldID, out CREDENTIAL_PROVIDER_FIELD_STATE pcpfs, out CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE pcpfis)
    {
        pcpfis = CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE.CPFIS_NONE;
        try
        {
            switch (dwFieldID)
            {
                case SecurityKeyProvider.FieldImage:
                case SecurityKeyProvider.FieldTitle:
                    pcpfs = CREDENTIAL_PROVIDER_FIELD_STATE.CPFS_DISPLAY_IN_BOTH;
                    return S_OK;
                case SecurityKeyProvider.FieldStatus:
                    pcpfs = CREDENTIAL_PROVIDER_FIELD_STATE.CPFS_DISPLAY_IN_SELECTED_TILE;
                    return S_OK;
                case SecurityKeyProvider.FieldLink:
                    bool visible;
                    lock (_sync)
                        visible = _link != LinkAction.None;
                    _shownLinkVisible = visible;
                    pcpfs = visible ? CREDENTIAL_PROVIDER_FIELD_STATE.CPFS_DISPLAY_IN_SELECTED_TILE : CREDENTIAL_PROVIDER_FIELD_STATE.CPFS_HIDDEN;
                    return S_OK;
                case SecurityKeyProvider.FieldProviderLabel:
                    pcpfs = CREDENTIAL_PROVIDER_FIELD_STATE.CPFS_HIDDEN;
                    return S_OK;
                default:
                    pcpfs = CREDENTIAL_PROVIDER_FIELD_STATE.CPFS_HIDDEN;
                    return E_INVALIDARG;
            }
        }
        catch (Exception ex)
        {
            Log("GetFieldState", ex);
            pcpfs = CREDENTIAL_PROVIDER_FIELD_STATE.CPFS_HIDDEN;
            pcpfis = CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE.CPFIS_NONE;
            return E_FAIL;
        }
    }

    public int GetStringValue(uint dwFieldID, out IntPtr ppsz)
    {
        ppsz = IntPtr.Zero;
        try
        {
            string? value;
            switch (dwFieldID)
            {
                case SecurityKeyProvider.FieldTitle:
                case SecurityKeyProvider.FieldProviderLabel:
                    value = LabelText;
                    break;
                case SecurityKeyProvider.FieldStatus:
                    lock (_sync)
                        value = _status;
                    _shownStatus = value;
                    break;
                case SecurityKeyProvider.FieldLink:
                    lock (_sync)
                        value = _linkText;
                    _shownLinkText = value;
                    break;
                default:
                    return E_INVALIDARG;
            }
            ppsz = Marshal.StringToCoTaskMemUni(value);
            return S_OK;
        }
        catch (Exception ex)
        {
            Log("GetStringValue", ex);
            ppsz = IntPtr.Zero;
            return E_FAIL;
        }
    }

    public int GetBitmapValue(uint dwFieldID, out IntPtr phbmp)
    {
        phbmp = IntPtr.Zero;
        try
        {
            if (dwFieldID != SecurityKeyProvider.FieldImage)
                return E_INVALIDARG;
            if (!TileImage.TryCreate(out var hbmp))
                return E_NOTIMPL;
            phbmp = hbmp; // LogonUI owns and frees it
            return S_OK;
        }
        catch (Exception ex)
        {
            Log("GetBitmapValue", ex);
            phbmp = IntPtr.Zero;
            return E_NOTIMPL;
        }
    }

    public int GetCheckboxValue(uint dwFieldID, out int pbChecked, out IntPtr ppszLabel)
    {
        pbChecked = 0;
        ppszLabel = IntPtr.Zero;
        return E_INVALIDARG;
    }

    public int GetSubmitButtonValue(uint dwFieldID, out uint pdwAdjacentTo)
    {
        pdwAdjacentTo = 0;
        return E_INVALIDARG; // no submit button: the fingerprint is the submit action
    }

    public int GetComboBoxValueCount(uint dwFieldID, out uint pcItems, out uint pdwSelectedItem)
    {
        pcItems = 0;
        pdwSelectedItem = 0;
        return E_INVALIDARG;
    }

    public int GetComboBoxValueAt(uint dwFieldID, uint dwItem, out IntPtr ppszItem)
    {
        ppszItem = IntPtr.Zero;
        return E_INVALIDARG;
    }

    // ===== Field setters / actions ==================================================================

    public int SetStringValue(uint dwFieldID, string? psz) => E_INVALIDARG; // no editable fields

    public int SetCheckboxValue(uint dwFieldID, int bChecked) => E_INVALIDARG;

    public int SetComboBoxSelectedValue(uint dwFieldID, uint dwSelectedItem) => E_INVALIDARG;

    public int CommandLinkClicked(uint dwFieldID)
    {
        if (dwFieldID != SecurityKeyProvider.FieldLink)
            return E_INVALIDARG;
        try
        {
            CancellationTokenSource? replaced = null;
            Ticket? ticket = null;
            LinkAction clicked;
            lock (_sync)
            {
                clicked = _link;
                // A click is the user asking for a finger now: the new attempt asks as soon as the key is connected.
                switch (_link)
                {
                    case LinkAction.TryAgain when _phase == TilePhase.Failed && !_shutdown:
                        ticket = BeginOperationLocked(allowFewAttemptsLeft: false, requireWake: false, automatic: false);
                        break;
                    // "Try again" next to "No finger detected": stop waiting for the key to be woken and ask right away.
                    case LinkAction.TryAgain when _phase == TilePhase.Running && _requireWake && !_shutdown:
                        replaced = _cts;
                        ticket = BeginOperationLocked(allowFewAttemptsLeft: false, requireWake: false, automatic: false);
                        break;
                    case LinkAction.ContinueAnyway when _phase == TilePhase.Failed && !_shutdown:
                        ticket = BeginOperationLocked(allowFewAttemptsLeft: true, requireWake: false, automatic: false);
                        break;
                }
                if (ticket is not null)
                    _selected = true; // LogonUI shows the link only in the selected tile
            }

            Cancel(replaced); // its late result carries an old generation and is ignored
            if (ticket is { } t)
                Launch(t);
            ProviderLog.Write(_scenario, ticket is { } started
                ? $"{clicked} clicked; {(replaced is not null ? "stopped waiting for the key to be woken; " : "")}starting unlock #{started.Generation}"
                : $"link clicked ({clicked}); nothing to do");
            Render();
            return S_OK;
        }
        catch (Exception ex)
        {
            Log("CommandLinkClicked", ex);
            return S_OK;
        }
    }

    // ===== Serialization ============================================================================

    public int GetSerialization(out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE pcpgsr,
        out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION pcpcs, out IntPtr ppszOptionalStatusText,
        out CREDENTIAL_PROVIDER_STATUS_ICON pcpsiOptionalStatusIcon)
    {
        pcpgsr = CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE.CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        pcpcs = default;
        ppszOptionalStatusText = IntPtr.Zero;
        pcpsiOptionalStatusIcon = CREDENTIAL_PROVIDER_STATUS_ICON.CPSI_NONE;
        char[]? password = null;
        IntPtr buffer = IntPtr.Zero;
        uint size = 0;
        try
        {
            lock (_sync)
            {
                if (_phase == TilePhase.Ready && _password is not null)
                {
                    // Take ownership: from here on no other path can reach (or clear) this buffer; this call
                    // clears it once it is packed (finally below), whatever happens.
                    password = _password;
                    _password = null;
                    _autoLogonPending = false;
                    _generation++; // the auto-logon expiry timer no longer applies
                }
            }
            if (password is null)
            {
                ProviderLog.Write(_scenario, "GetSerialization: no password ready");
                return S_OK;
            }

            // Everything that can fail happens before the out parameters are set.
            uint package = KerbSerializer.GetNegotiateAuthPackage();
            buffer = KerbSerializer.Serialize(_cpus, _enrollment.Domain, _enrollment.UserName, password, out size);

            pcpcs = new CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION
            {
                ulAuthenticationPackage = package,
                clsidCredentialProvider = SecurityKeyProvider.ClassId,
                cbSerialization = size,
                rgbSerialization = buffer,
            };
            pcpgsr = CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE.CPGSR_RETURN_CREDENTIAL_FINISHED;

            lock (_sync)
            {
                _generation++;
                _autoLogonPending = false;
                _phase = TilePhase.Submitted;
                _status = StatusSigningIn;
                _link = LinkAction.None;
            }
            // Never log the size: it follows the password's length.
            ProviderLog.Write(_scenario, $"serialization handed to LogonUI (package {package})");
            return S_OK;
        }
        catch (Exception ex)
        {
            Log("GetSerialization", ex);
            pcpgsr = CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE.CPGSR_NO_CREDENTIAL_NOT_FINISHED;
            pcpcs = default;
            ppszOptionalStatusText = IntPtr.Zero;
            pcpsiOptionalStatusIcon = CREDENTIAL_PROVIDER_STATUS_ICON.CPSI_NONE;
            try
            {
                // Not handed to LogonUI after all: wipe it (it holds the protected password) and free it.
                KerbSerializer.ZeroAndFree(buffer, size);
                lock (_sync)
                {
                    _generation++;
                    FailLocked(StatusPrepareFailed, LinkAction.TryAgain);
                }
                Render();
            }
            catch
            {
                // Already logged; nothing else to do.
            }
            return S_OK;
        }
        finally
        {
            // This call took the buffer out of the field, so only it can clear it (and it must, on every path).
            if (password is not null)
                Array.Clear(password);
        }
    }

    public int ReportResult(int ntsStatus, int ntsSubstatus, out IntPtr ppszOptionalStatusText, out CREDENTIAL_PROVIDER_STATUS_ICON pcpsiOptionalStatusIcon)
    {
        ppszOptionalStatusText = IntPtr.Zero;
        pcpsiOptionalStatusIcon = CREDENTIAL_PROVIDER_STATUS_ICON.CPSI_NONE;
        try
        {
            if (ntsStatus >= 0) // NT_SUCCESS
            {
                FailureCounter.Reset();
                lock (_sync)
                {
                    if (_phase == TilePhase.Submitted)
                    {
                        _phase = TilePhase.Idle;
                        _status = string.Empty;
                    }
                }
                ProviderLog.Write(_scenario, $"Windows accepted the logon (NTSTATUS 0x{ntsStatus:X8})");
                KeepDefaultSignInOption(); // logon or unlock: the only scenarios the provider offers
                return S_OK;
            }

            var rejection = ClassifyRejection(ntsStatus, ntsSubstatus);
            ProviderLog.Write(_scenario, $"Windows rejected the logon: NTSTATUS 0x{ntsStatus:X8}, substatus 0x{ntsSubstatus:X8} ({rejection})");
            var (tileText, link) = rejection switch
            {
                // The enrollment is loaded once per LogonUI instance, so a retry would decrypt and submit the same
                // wrong password again: it can't succeed and only adds to the account's bad-password count.
                Rejection.StoredPasswordWrong => (ReportResultText, LinkAction.None),
                // Locked out, disabled, password expired / must change, logon hours...: a retry can't help.
                Rejection.AccountState => (StatusUseOtherOption, LinkAction.None),
                _ => (StatusWindowsRefused, LinkAction.TryAgain),
            };
            CancellationTokenSource? cts;
            lock (_sync)
            {
                _generation++;
                cts = _cts; // normally none; never leave an attempt running whose result would be ignored
                FailLocked(tileText, link);
            }
            Cancel(cts);
            Render();
            if (rejection == Rejection.StoredPasswordWrong)
            {
                ppszOptionalStatusText = Marshal.StringToCoTaskMemUni(ReportResultText);
                pcpsiOptionalStatusIcon = CREDENTIAL_PROVIDER_STATUS_ICON.CPSI_ERROR;
            }
            // Otherwise no text of our own: LogonUI then shows Windows' message for the status, which says what
            // is actually wrong (as the Microsoft V2 sample does for the statuses it doesn't map).
            return S_OK;
        }
        catch (Exception ex)
        {
            Log("ReportResult", ex);
            if (ppszOptionalStatusText != IntPtr.Zero)
                Marshal.FreeCoTaskMem(ppszOptionalStatusText);
            ppszOptionalStatusText = IntPtr.Zero;
            pcpsiOptionalStatusIcon = CREDENTIAL_PROVIDER_STATUS_ICON.CPSI_NONE;
            return S_OK;
        }
    }

    /// <summary>
    /// After a logon or unlock with this tile, makes it the user's preselected sign-in option again. Windows switches
    /// the default to whatever was used last (for example the PIN, once), and then LogonUI would show the PIN box
    /// instead of this tile. Best effort and synchronous: LogonUI may exit right after a successful logon, and the
    /// registry write is quick. Needs SYSTEM or administrator rights, which LogonUI has.
    /// </summary>
    private void KeepDefaultSignInOption()
    {
        try
        {
            var setTile = TestHooks.SetDefaultTile ?? DefaultSignInOption.SetTile;
            setTile(_enrollment.UserSid);
            ProviderLog.Write(_scenario, "security key tile kept as the preselected sign-in option");
        }
        catch (Exception ex)
        {
            ProviderLog.WriteException(_scenario, "could not keep the security key tile as the preselected sign-in option", ex, includeStack: false);
        }
    }

    /// <summary>Why Windows refused the serialized logon (see <see cref="ReportResult"/>).</summary>
    private enum Rejection
    {
        /// <summary>The stored password (or user name) is wrong: re-enroll. No retry.</summary>
        StoredPasswordWrong,
        /// <summary>The account can't sign in right now whatever the password. No retry.</summary>
        AccountState,
        /// <summary>Anything else; a retry may work.</summary>
        Other,
    }

    private static Rejection ClassifyRejection(int status, int substatus)
    {
        if (IsAccountState(status))
            return Rejection.AccountState;
        if (IsWrongPassword(status) || IsWrongPassword(substatus))
            return Rejection.StoredPasswordWrong;
        return IsAccountState(substatus) ? Rejection.AccountState : Rejection.Other;
    }

    private static bool IsWrongPassword(int status) =>
        status is NtStatus.STATUS_LOGON_FAILURE or NtStatus.STATUS_WRONG_PASSWORD;

    private static bool IsAccountState(int status) =>
        status is NtStatus.STATUS_ACCOUNT_LOCKED_OUT
            or NtStatus.STATUS_ACCOUNT_DISABLED
            or NtStatus.STATUS_ACCOUNT_RESTRICTION
            or NtStatus.STATUS_ACCOUNT_EXPIRED
            or NtStatus.STATUS_PASSWORD_EXPIRED
            or NtStatus.STATUS_PASSWORD_MUST_CHANGE
            or NtStatus.STATUS_INVALID_LOGON_HOURS
            or NtStatus.STATUS_INVALID_WORKSTATION
            or NtStatus.STATUS_LOGON_TYPE_NOT_GRANTED
            or NtStatus.STATUS_NO_SUCH_USER;

    public int GetUserSid(out IntPtr sid)
    {
        sid = IntPtr.Zero;
        try
        {
            // Ties this credential to the enrolled user's tile (a sign-in option under that user).
            sid = Marshal.StringToCoTaskMemUni(_enrollment.UserSid);
            return S_OK;
        }
        catch (Exception ex)
        {
            Log("GetUserSid", ex);
            sid = IntPtr.Zero;
            return E_FAIL;
        }
    }

    // ===== Called by the provider (UI thread) =======================================================

    /// <summary>Cancels any unlock and drops a pending password, keeping the tile usable (provider UnAdvise).</summary>
    internal void Reset(string reason) => Stop(reason, shutdown: false);

    /// <summary>Like <see cref="Reset"/>, and the tile never starts another unlock (it was replaced).</summary>
    internal void Shutdown(string reason) => Stop(reason, shutdown: true);

    private void Stop(string reason, bool shutdown)
    {
        try
        {
            CancellationTokenSource? cts;
            lock (_sync)
            {
                _shutdown |= shutdown;
                _generation++; // also keeps the cancelled attempt from starting an automatic one
                cts = _cts;
                if (_phase != TilePhase.Failed)
                    ResetLocked();
                else
                    ClearOperationLocked();
                DropPasswordLocked(); // whatever the phase (a failed tile holds none, but never leave one behind)
            }
            Cancel(cts);
            ProviderLog.Write(_scenario, $"credential {(shutdown ? "shut down" : "reset")}: {reason}");
            if (shutdown)
                ReleaseEvents();
        }
        catch (Exception ex)
        {
            Log("Stop", ex);
        }
    }

    // ===== The unlock operation =====================================================================

    /// <summary>Starts a new operation's state (status "Connecting", no link; callers may change both). Caller holds
    /// _sync, has cancelled or retired any previous operation, and calls <see cref="Launch"/> after releasing it.</summary>
    private Ticket BeginOperationLocked(bool allowFewAttemptsLeft, bool requireWake, bool automatic, TimeSpan delay = default)
    {
        _generation++;
        _cts = new CancellationTokenSource();
        _requireWake = requireWake;
        if (!automatic)
            _restartStreak = 0; // the user acted: automatic attempts start over with the short delay
        DropPasswordLocked();
        _autoLogonPending = false;
        _phase = TilePhase.Running;
        _status = StatusConnecting;
        _link = LinkAction.None;
        return new Ticket(_generation, _cts.Token, allowFewAttemptsLeft, requireWake, automatic, delay);
    }

    private void Launch(Ticket ticket)
    {
        lock (OperationChainLock)
        {
            var previous = s_lastOperation;
            s_lastOperation = Task.Run(() => RunOperationAsync(ticket, previous));
        }
    }

    /// <summary>Background: one unlock attempt. Never throws; every outcome goes through On*.</summary>
    private async Task RunOperationAsync(Ticket ticket, Task previous)
    {
        long started = 0;
        try
        {
            if (ticket.Delay > TimeSpan.Zero)
                await Task.Delay(ticket.Delay, ticket.Token).ConfigureAwait(false);
            try
            {
                if (!previous.IsCompleted)
                {
                    ProviderLog.Write(_scenario, "waiting for the previous fingerprint request to finish");
                    await previous.WaitAsync(PreviousOperationWait, ticket.Token).ConfigureAwait(false);
                }
            }
            catch (TimeoutException)
            {
                ProviderLog.Write(_scenario, "the previous fingerprint request is still running; trying anyway");
            }
            catch (OperationCanceledException) when (ticket.Token.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception)
            {
                // The previous operation's own outcome is irrelevant here.
            }
            ticket.Token.ThrowIfCancellationRequested();

            var request = new UnlockRequest(ticket.AllowFewAttemptsLeft, ticket.RequireWake, stage => OnStage(ticket, stage));
            started = Environment.TickCount64;
            char[] password = await Unlocker.UnlockAsync(_enrollment, request, ticket.Token).ConfigureAwait(false);
            OnSuccess(ticket.Generation, password); // takes ownership: keeps the buffer or clears it
        }
        catch (OperationCanceledException) when (ticket.Token.IsCancellationRequested)
        {
            OnCancelled(ticket.Generation);
        }
        catch (LogonException ex)
        {
            OnFailure(ticket, ex, TimeSpan.FromMilliseconds(started == 0 ? 0 : Environment.TickCount64 - started));
        }
        catch (Exception ex)
        {
            OnUnexpected(ticket.Generation, ex);
        }
    }

    private void OnStage(Ticket ticket, LogonStage stage)
    {
        try
        {
            string text = stage switch
            {
                LogonStage.Connecting => StatusConnecting,
                LogonStage.WaitingForKey => StatusWaitingForKey,
                LogonStage.Connected => StatusConnected,
                LogonStage.WaitingForFinger => StatusWaitingForFinger,
                LogonStage.FingerAccepted => StatusSigningIn,
                _ => StatusConnecting,
            };
            bool kept;
            lock (_sync)
            {
                if (ticket.Generation != _generation || _phase != TilePhase.Running)
                    return;
                kept = KeepsStatus(ticket, stage);
                if (!kept)
                    _status = text;
                // The key is asking for the finger now: a click on "Try again" would only cancel that request
                // (which may cost an attempt), so the link goes away.
                if (stage is LogonStage.WaitingForFinger or LogonStage.FingerAccepted)
                    _link = LinkAction.None;
            }
            ProviderLog.Write(_scenario, kept ? $"stage {stage} (status kept)" : $"stage {stage}");
            RequestRender();
        }
        catch (Exception ex)
        {
            Log("OnStage", ex);
        }
    }

    /// <summary>Connection stages that leave the status alone: an attempt waiting for the key to be woken keeps
    /// "No finger detected..." (and its "Try again") until the key asks for the finger, and an automatic attempt keeps
    /// "Press the button..." instead of flashing "Connecting" every <see cref="Unlocker.WakeTimeout"/>.</summary>
    private static bool KeepsStatus(Ticket ticket, LogonStage stage) => stage switch
    {
        LogonStage.Connecting => ticket.RequireWake || ticket.Automatic,
        LogonStage.WaitingForKey or LogonStage.Connected => ticket.RequireWake,
        _ => false,
    };

    /// <summary>Takes ownership of <paramref name="password"/>: stores it in the tile (which clears it later) if
    /// this result is still current, and clears it right away otherwise.</summary>
    private void OnSuccess(int generation, char[] password)
    {
        bool current = false;
        try
        {
            FailureCounter.Reset(); // the key accepted a fingerprint, which resets its own counter too
            lock (_sync)
            {
                current = generation == _generation && !_shutdown && _phase == TilePhase.Running;
                if (current)
                {
                    ClearOperationLocked();
                    DropPasswordLocked(); // none expected while running
                    _phase = TilePhase.Ready;
                    _password = password;
                    _autoLogonPending = true;
                    _autoLogonDeadline = Environment.TickCount64 + (long)AutoLogonWindow.TotalMilliseconds;
                    _status = StatusSigningIn;
                    _link = LinkAction.None;
                }
            }
        }
        finally
        {
            if (!current)
                Array.Clear(password); // stale (or failed to store): never kept
        }
        if (!current)
        {
            ProviderLog.Write(_scenario, "fingerprint accepted after the tile was deselected; password discarded");
            return;
        }

        ProviderLog.Write(_scenario, "fingerprint accepted; asking LogonUI to sign in");
        bool posted = _owner.Post(() =>
        {
            Render();
            _owner.RequestAutoLogon(); // may re-enter GetCredentialCount / GetSerialization
        });
        if (!posted)
            ProviderLog.Write(_scenario, "could not reach the LogonUI thread to request auto-logon");
        _ = ExpireAutoLogonAsync(generation);
    }

    /// <summary>Drops a ready password LogonUI never asked for, and tells the user.</summary>
    private async Task ExpireAutoLogonAsync(int generation)
    {
        try
        {
            await Task.Delay(AutoLogonWindow + TimeSpan.FromMilliseconds(500)).ConfigureAwait(false);
            bool expired;
            lock (_sync)
            {
                expired = generation == _generation && _phase == TilePhase.Ready;
                if (expired)
                    FailLocked(StatusSignInNotStarted, LinkAction.TryAgain);
            }
            if (expired)
            {
                ProviderLog.Write(_scenario, "LogonUI did not ask for the credential in time; password dropped");
                RequestRender();
            }
        }
        catch (Exception ex)
        {
            Log("ExpireAutoLogon", ex);
        }
    }

    private void OnFailure(Ticket ticket, LogonException ex, TimeSpan ran)
    {
        try
        {
            if (TryStartAutomaticAttempt(ticket, ex, ran))
                return;

            int generation = ticket.Generation;
            string text = string.IsNullOrWhiteSpace(ex.Message) ? StatusGeneric : ex.Message;
            var link = LinkAction.TryAgain;
            switch (ex.Failure)
            {
                case LogonFailure.FewAttemptsLeft:
                    link = LinkAction.ContinueAnyway;
                    break;
                case LogonFailure.Busy:
                    text = StatusBusy;
                    break;
                case LogonFailure.FingerprintRejected:
                    // Counted even if the tile was deselected meanwhile: the attempt was used either way.
                    int failures = FailureCounter.Increment();
                    if (ex.UvRetries is null && failures >= 2)
                        text = $"{text} {CarefulSuffix}";
                    break;
            }

            bool current = Fail(generation, text, link);
            bool unexpected = ex.Failure is LogonFailure.Other or LogonFailure.Protocol;
            ProviderLog.WriteException(_scenario,
                $"unlock #{generation} failed ({ex.Failure}{(ex.UvRetries is int left ? $", {left} attempts left" : "")}, consecutive rejections {FailureCounter.Current}){(current ? "" : " after deselect; not shown")}",
                ex, includeStack: unexpected);
        }
        catch (Exception inner)
        {
            Log("OnFailure", inner);
        }
    }

    /// <summary>
    /// The only attempts the tile starts by itself. KeyNotFound (nobody woke the key in time, so no finger was asked
    /// for): the same kind of attempt again, status "Press the button..." (or, for an attempt waiting for the key to
    /// be woken, its "No finger detected..." and "Try again"). FingerprintTimeout (nobody touched the sensor) and
    /// Bluetooth (the link dropped): an attempt with RequireWake, so the next request needs a fresh button press.
    /// Never after a rejected finger or any other failure. The new attempt replaces the failed one (new generation)
    /// and starts after a delay, so attempts can neither pile up nor spin. Returns true when the failure was handled
    /// (a new attempt started, or the failed attempt was already stale); false to show it as usual.
    /// </summary>
    private bool TryStartAutomaticAttempt(Ticket ticket, LogonException ex, TimeSpan ran)
    {
        bool requireWake;
        switch (ex.Failure)
        {
            case LogonFailure.KeyNotFound:
                requireWake = ticket.RequireWake;
                break;
            case LogonFailure.FingerprintTimeout:
            case LogonFailure.Bluetooth:
                requireWake = true;
                break;
            default:
                return false;
        }

        Ticket? next = null;
        bool current;
        lock (_sync)
        {
            current = ticket.Generation == _generation && _phase == TilePhase.Running;
            if (current && _selected && !_shutdown)
            {
                if (ran >= QuickFailure)
                    _restartStreak = 0;
                var delay = RestartDelay * (1 << Math.Min(_restartStreak, MaxRestartBackoff));
                _restartStreak++;
                // AllowFewAttemptsLeft is not carried over: the user confirmed one request, not automatic ones.
                next = BeginOperationLocked(allowFewAttemptsLeft: false, requireWake, automatic: true, delay);
                if (requireWake)
                {
                    _status = StatusNoFinger;
                    SetLinkLocked(LinkAction.TryAgain);
                }
                else
                {
                    _status = StatusWaitingForKey;
                }
            }
        }

        if (!current)
        {
            ProviderLog.WriteException(_scenario, $"unlock #{ticket.Generation} failed ({ex.Failure}) after deselect; not shown", ex, includeStack: false);
            return true;
        }
        if (next is not { } n)
            return false; // not selected or shut down: no automatic attempt; Fail shows it (or drops it when shut down)

        ProviderLog.WriteException(_scenario,
            $"unlock #{ticket.Generation} failed ({ex.Failure}); unlock #{n.Generation} starts by itself in {(int)n.Delay.TotalMilliseconds} ms" +
            (n.RequireWake ? " and asks for a finger only after the key is woken" : ""),
            ex, includeStack: false);
        Launch(n);
        RequestRender();
        return true;
    }

    private void OnUnexpected(int generation, Exception ex)
    {
        try
        {
            bool current = Fail(generation, StatusGeneric, LinkAction.TryAgain);
            ProviderLog.WriteException(_scenario, $"unlock #{generation} failed unexpectedly{(current ? "" : " after deselect; not shown")}", ex, includeStack: true);
        }
        catch (Exception inner)
        {
            Log("OnUnexpected", inner);
        }
    }

    private void OnCancelled(int generation)
    {
        try
        {
            bool current;
            lock (_sync)
            {
                current = generation == _generation && _phase == TilePhase.Running;
                if (current)
                    ResetLocked();
            }
            ProviderLog.Write(_scenario, $"unlock #{generation} cancelled");
            if (current)
                RequestRender();
        }
        catch (Exception ex)
        {
            Log("OnCancelled", ex);
        }
    }

    /// <summary>Shows a failure if <paramref name="generation"/> is still the current operation.</summary>
    private bool Fail(int generation, string text, LinkAction link)
    {
        bool current;
        lock (_sync)
        {
            current = generation == _generation && !_shutdown && _phase == TilePhase.Running;
            if (current)
                FailLocked(text, link);
        }
        if (current)
            RequestRender();
        return current;
    }

    // ===== State helpers (caller holds _sync) =======================================================

    private void FailLocked(string text, LinkAction link)
    {
        ClearOperationLocked();
        DropPasswordLocked();
        _autoLogonPending = false;
        _phase = TilePhase.Failed;
        _status = text;
        SetLinkLocked(link);
    }

    private void ResetLocked()
    {
        ClearOperationLocked();
        DropPasswordLocked();
        _autoLogonPending = false;
        _phase = TilePhase.Idle;
        _status = string.Empty;
        _link = LinkAction.None;
    }

    private void ClearOperationLocked()
    {
        _cts = null;
        _requireWake = false;
    }

    /// <summary>Removes the ready password from the tile and clears it. Only ever clears the buffer that is in the
    /// field right now: <see cref="GetSerialization"/> takes the buffer out of the field (under <c>_sync</c>) before
    /// it packs it, so this can never clear a buffer the UI thread is reading.</summary>
    private void DropPasswordLocked()
    {
        char[]? password = _password;
        _password = null;
        if (password is not null)
            Array.Clear(password);
    }

    private void SetLinkLocked(LinkAction link)
    {
        _link = link;
        _linkText = link switch
        {
            LinkAction.ContinueAnyway => ContinueAnywayText,
            LinkAction.TryAgain => TryAgainText,
            _ => _linkText,
        };
    }

    private static void Cancel(CancellationTokenSource? cts)
    {
        if (cts is null)
            return;
        try
        {
            // Marks the token cancelled now and runs the callbacks (CTAP CANCEL etc.) on the thread pool,
            // not on LogonUI's thread.
            _ = cts.CancelAsync();
        }
        catch (ObjectDisposedException)
        {
        }
    }

    // ===== LogonUI field updates ====================================================================

    /// <summary>From a background thread: render on the LogonUI thread.</summary>
    private void RequestRender()
    {
        if (!_owner.Post(Render))
            ProviderLog.Write(_scenario, "could not reach the LogonUI thread to update the tile");
    }

    /// <summary>
    /// Pushes the status line and the command link to LogonUI. LogonUI thread only (COM methods and posted
    /// actions). Sends only what changed since the last push or since LogonUI read the fields.
    /// </summary>
    private void Render()
    {
        try
        {
            IntPtr events = _events;
            if (events == IntPtr.Zero)
                return;
            string status;
            string linkText;
            bool linkVisible;
            lock (_sync)
            {
                status = _status;
                linkText = _linkText;
                linkVisible = _link != LinkAction.None;
            }

            IntPtr self = Marshal.GetComInterfaceForObject(this, typeof(ICredentialProviderCredential2));
            Marshal.AddRef(events); // stays valid even if LogonUI re-enters UnAdvise during a call
            try
            {
                if (status != _shownStatus)
                {
                    Check(RawCalls.CredentialEvents.SetFieldString(events, self, SecurityKeyProvider.FieldStatus, status), "SetFieldString(status)");
                    _shownStatus = status;
                }
                if (linkVisible)
                {
                    if (linkText != _shownLinkText)
                    {
                        Check(RawCalls.CredentialEvents.SetFieldString(events, self, SecurityKeyProvider.FieldLink, linkText), "SetFieldString(link)");
                        _shownLinkText = linkText;
                    }
                    if (_shownLinkVisible != true)
                    {
                        Check(RawCalls.CredentialEvents.SetFieldState(events, self, SecurityKeyProvider.FieldLink,
                            CREDENTIAL_PROVIDER_FIELD_STATE.CPFS_DISPLAY_IN_SELECTED_TILE), "SetFieldState(link)");
                        _shownLinkVisible = true;
                    }
                }
                else if (_shownLinkVisible != false)
                {
                    Check(RawCalls.CredentialEvents.SetFieldState(events, self, SecurityKeyProvider.FieldLink,
                        CREDENTIAL_PROVIDER_FIELD_STATE.CPFS_HIDDEN), "SetFieldState(link)");
                    _shownLinkVisible = false;
                }
            }
            finally
            {
                Marshal.Release(events);
                Marshal.Release(self);
            }
        }
        catch (Exception ex)
        {
            Log("Render", ex);
        }
    }

    private void Check(int hr, string call)
    {
        if (hr < 0)
            ProviderLog.Write(_scenario, $"{call} returned 0x{hr:X8}");
    }

    private void ReleaseEvents()
    {
        IntPtr events = _events;
        _events = IntPtr.Zero;
        if (events != IntPtr.Zero)
            Marshal.Release(events);
    }

    private void Log(string context, Exception ex) => ProviderLog.WriteException(_scenario, context, ex, includeStack: true);
}
