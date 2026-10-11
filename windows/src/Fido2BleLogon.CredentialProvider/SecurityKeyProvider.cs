using System.Runtime.InteropServices;
using Fido2BleLogon.CredentialProvider.Interop;
using Fido2BleLogon.Logon;
using static Fido2BleLogon.CredentialProvider.Interop.HResults;

namespace Fido2BleLogon.CredentialProvider;

/// <summary>
/// The security key logon tile provider: the COM class LogonUI instantiates from the registered CLSID. It
/// enumerates exactly one credential, for the enrolled account, as a sign-in option under that user's tile
/// (V2 provider), on the logon and lock screens only: every other usage scenario, Credential UI
/// (CredUIPromptForWindowsCredentials) included, gets E_NOTIMPL. It stays out of the way (E_NOTIMPL or zero credentials) in Safe Mode, when the kill-switch
/// file exists, when nothing is enrolled or the enrollment can't be read, and when LogonUI does not list the
/// enrolled user, so the normal password and PIN tiles always remain available. In Safe Mode and with the
/// kill-switch file it is completely inert: it does not even write its log, so nothing on disk changes.
/// <para>
/// LogonUI calls every method on its UI thread. Each method catches everything and returns an HRESULT;
/// nothing may escape into LogonUI, where it would break the logon screen.
/// </para>
/// </summary>
[ComVisible(true)]
[Guid(ClassIdString)]
[ClassInterface(ClassInterfaceType.None)]
public sealed class SecurityKeyProvider : ICredentialProvider, ICredentialProviderSetUserArray
{
    /// <summary>The provider's CLSID: the single source of truth. scripts\install.ps1 and uninstall.ps1 carry
    /// the same value, and install.ps1 checks that regsvr32 registered exactly this CLSID.</summary>
    public const string ClassIdString = "35e15797-dd2e-44f3-b82c-839eeb10aebd";

    /// <summary><see cref="ClassIdString"/> as a <see cref="Guid"/> (used in the logon serialization).</summary>
    public static readonly Guid ClassId = new(ClassIdString);

    // Field layout of the tile.
    internal const uint FieldImage = 0;          // CPFT_TILE_IMAGE, CPFG_CREDENTIAL_PROVIDER_LOGO
    internal const uint FieldTitle = 1;          // CPFT_LARGE_TEXT "Security key fingerprint"
    internal const uint FieldStatus = 2;         // CPFT_SMALL_TEXT status line (selected tile only)
    internal const uint FieldLink = 3;           // CPFT_COMMAND_LINK "Try again" / "Continue anyway"
    internal const uint FieldProviderLabel = 4;  // CPFT_SMALL_TEXT, CPFG_CREDENTIAL_PROVIDER_LABEL (hidden)
    internal const uint FieldCount = 5;

    private readonly object _sync = new();

    // UI-thread state (LogonUI makes all its calls on one thread).
    private CREDENTIAL_PROVIDER_USAGE_SCENARIO _cpus;
    private bool _active;
    private Enrollment? _enrollment;
    private SecurityKeyCredential? _credential;
    private HashSet<string>? _userSids; // null until SetUserArray is called
    private string? _lastCountLog;

    // Shared with background threads; guarded by _sync.
    private IntPtr _events; // ICredentialProviderEvents*, AddRef'ed
    private nuint _adviseContext;
    private UiDispatcher? _dispatcher;

    // No log line here: the first log write sets up the log folder, which must not happen before
    // SetUsageScenario has checked Safe Mode and the kill switch.
    public SecurityKeyProvider()
    {
    }

    internal string Scenario => ScenarioName(_cpus);

    private static string KillSwitchPath => Path.Combine(EnrollmentStore.DirectoryPath, "disabled");

    // ----- ICredentialProvider ---------------------------------------------------------------------

    public int SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, uint dwFlags)
    {
        try
        {
            _cpus = cpus;
            _active = false;
            _enrollment = null;
            ReplaceCredential("new usage scenario");

            // Safe Mode and the kill-switch file: completely inert, not even a log line.
            if (IsSwitchedOff(out string? switchCheckFailure))
            {
                if (switchCheckFailure is not null)
                    ProviderLog.Write(Scenario, $"inactive: {switchCheckFailure}");
                return E_NOTIMPL;
            }

            // Logon and unlock only. Never Credential UI (CPUS_CREDUI): any program running as the user can open
            // that dialog and unpack the credential it returns, so offering the tile there would hand the stored
            // Windows password to whoever asks, one fingerprint later. Nothing is loaded or started for it.
            switch (cpus)
            {
                case CREDENTIAL_PROVIDER_USAGE_SCENARIO.CPUS_LOGON:
                case CREDENTIAL_PROVIDER_USAGE_SCENARIO.CPUS_UNLOCK_WORKSTATION:
                    break;
                default:
                    ProviderLog.Write(Scenario, $"scenario {cpus} not supported");
                    return E_NOTIMPL;
            }

            if (TryGetInactiveReason(out var reason))
            {
                _enrollment = null;
                ProviderLog.Write(Scenario, $"inactive: {reason}");
                return E_NOTIMPL;
            }

            _active = true;
            ProviderLog.Write(Scenario, $"active for {_enrollment!.QualifiedUserName} (flags 0x{dwFlags:X8})");
            return S_OK;
        }
        catch (Exception ex)
        {
            ProviderLog.WriteException(Scenario, "SetUsageScenario", ex, includeStack: true);
            _active = false;
            return E_NOTIMPL; // safest: stay off the logon screen
        }
    }

    public int SetSerialization(IntPtr pcpcs) => E_NOTIMPL;

    public int Advise(IntPtr pcpe, nuint upAdviseContext)
    {
        try
        {
            IntPtr old;
            lock (_sync)
            {
                old = _events;
                _events = IntPtr.Zero;
                if (pcpe != IntPtr.Zero)
                {
                    Marshal.AddRef(pcpe);
                    _events = pcpe;
                }
                _adviseContext = upAdviseContext;
            }
            if (old != IntPtr.Zero)
                Marshal.Release(old);
            EnsureDispatcher();
            return S_OK;
        }
        catch (Exception ex)
        {
            ProviderLog.WriteException(Scenario, "Advise", ex, includeStack: true);
            return S_OK;
        }
    }

    public int UnAdvise()
    {
        try
        {
            // The tile is going away: stop any fingerprint request (the transport sends CTAP CANCEL) and
            // drop a pending password before the window that carries results to this thread is destroyed.
            _credential?.Reset("provider UnAdvise");

            UiDispatcher? dispatcher;
            IntPtr events;
            lock (_sync)
            {
                dispatcher = _dispatcher;
                _dispatcher = null;
                events = _events;
                _events = IntPtr.Zero;
                _adviseContext = 0;
            }
            dispatcher?.Dispose(); // on this (the Advise) thread
            if (events != IntPtr.Zero)
                Marshal.Release(events);
            return S_OK;
        }
        catch (Exception ex)
        {
            ProviderLog.WriteException(Scenario, "UnAdvise", ex, includeStack: true);
            return S_OK;
        }
    }

    public int GetFieldDescriptorCount(out uint pdwCount)
    {
        pdwCount = FieldCount;
        return S_OK;
    }

    public int GetFieldDescriptorAt(uint dwIndex, out IntPtr ppcpfd)
    {
        ppcpfd = IntPtr.Zero;
        try
        {
            IntPtr descriptor = dwIndex switch
            {
                FieldImage => Descriptor(FieldImage, CREDENTIAL_PROVIDER_FIELD_TYPE.CPFT_TILE_IMAGE, "Image",
                    CredentialProviderConstants.CPFG_CREDENTIAL_PROVIDER_LOGO),
                FieldTitle => Descriptor(FieldTitle, CREDENTIAL_PROVIDER_FIELD_TYPE.CPFT_LARGE_TEXT, SecurityKeyCredential.LabelText, Guid.Empty),
                FieldStatus => Descriptor(FieldStatus, CREDENTIAL_PROVIDER_FIELD_TYPE.CPFT_SMALL_TEXT, "Status", Guid.Empty),
                FieldLink => Descriptor(FieldLink, CREDENTIAL_PROVIDER_FIELD_TYPE.CPFT_COMMAND_LINK, "Fingerprint action", Guid.Empty),
                // [TECHREF] "define a separate CPFT_SMALL_TEXT string field ... set the guidFieldType to
                // CPFG_CREDENTIAL_PROVIDER_LABEL" (the Microsoft V2 sample keeps it hidden).
                FieldProviderLabel => Descriptor(FieldProviderLabel, CREDENTIAL_PROVIDER_FIELD_TYPE.CPFT_SMALL_TEXT, SecurityKeyCredential.LabelText,
                    CredentialProviderConstants.CPFG_CREDENTIAL_PROVIDER_LABEL),
                _ => IntPtr.Zero,
            };
            if (descriptor == IntPtr.Zero)
                return E_INVALIDARG;
            ppcpfd = descriptor;
            return S_OK;
        }
        catch (Exception ex)
        {
            ProviderLog.WriteException(Scenario, "GetFieldDescriptorAt", ex, includeStack: true);
            ppcpfd = IntPtr.Zero;
            return E_OUTOFMEMORY;
        }
    }

    public int GetCredentialCount(out uint pdwCount, out uint pdwDefault, out int pbAutoLogonWithDefault)
    {
        pdwCount = 0;
        pdwDefault = CredentialProviderConstants.CREDENTIAL_PROVIDER_NO_DEFAULT;
        pbAutoLogonWithDefault = 0;
        try
        {
            if (!_active || _enrollment is null)
                return S_OK;
            if (_userSids is not null && !_userSids.Contains(NormalizeSid(_enrollment.UserSid)))
            {
                LogCount($"enrolled user {_enrollment.QualifiedUserName} is not among the {_userSids.Count} users LogonUI shows; no tile");
                return S_OK;
            }

            // Without the window that carries results back to this thread the tile could never finish, so
            // don't show it at all.
            EnsureDispatcher();
            bool hasDispatcher;
            lock (_sync)
                hasDispatcher = _dispatcher is not null;
            if (!hasDispatcher)
            {
                LogCount("no UI dispatcher window; no tile");
                return S_OK;
            }

            _credential ??= new SecurityKeyCredential(this, _cpus, _enrollment);
            pdwCount = 1;
            if (_credential.WantsAutoLogon)
            {
                // Only ever after the key returned the password (see SecurityKeyCredential.OnSuccess).
                pdwDefault = 0;
                pbAutoLogonWithDefault = 1;
                ProviderLog.Write(Scenario, "GetCredentialCount: 1 credential, default 0 with auto-logon");
                _lastCountLog = null;
            }
            else
            {
                // Ask LogonUI to preselect this tile for the enrolled user (alongside the UserTile value it may
                // or may not honor). Never auto-logon here: that needs a password from the key.
                pdwDefault = 0;
                LogCount("GetCredentialCount: 1 credential, default 0 (no auto-logon)");
            }
            return S_OK;
        }
        catch (Exception ex)
        {
            ProviderLog.WriteException(Scenario, "GetCredentialCount", ex, includeStack: true);
            pdwCount = 0;
            pdwDefault = CredentialProviderConstants.CREDENTIAL_PROVIDER_NO_DEFAULT;
            pbAutoLogonWithDefault = 0;
            return S_OK;
        }
    }

    public int GetCredentialAt(uint dwIndex, out IntPtr ppcpc)
    {
        ppcpc = IntPtr.Zero;
        try
        {
            if (dwIndex != 0 || _credential is null)
                return E_INVALIDARG;
            // The ICredentialProviderCredential2 pointer; the credential passes this same pointer as pcpc.
            ppcpc = Marshal.GetComInterfaceForObject(_credential, typeof(ICredentialProviderCredential2));
            return S_OK;
        }
        catch (Exception ex)
        {
            ProviderLog.WriteException(Scenario, "GetCredentialAt", ex, includeStack: true);
            ppcpc = IntPtr.Zero;
            return E_FAIL;
        }
    }

    // ----- ICredentialProviderSetUserArray ---------------------------------------------------------

    public int SetUserArray(IntPtr users)
    {
        var sids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            // Read the borrowed array now (it has no proxy/stub, so it must be used on this thread).
            if (users != IntPtr.Zero && RawCalls.UserArray.GetCount(users, out uint count) >= 0)
            {
                for (uint i = 0; i < count; i++)
                {
                    if (RawCalls.UserArray.GetAt(users, i, out IntPtr user) < 0 || user == IntPtr.Zero)
                        continue;
                    try
                    {
                        if (RawCalls.User.GetSid(user, out string? sid) >= 0 && !string.IsNullOrWhiteSpace(sid))
                            sids.Add(NormalizeSid(sid));
                    }
                    finally
                    {
                        Marshal.Release(user);
                    }
                }
            }
            ProviderLog.Write(Scenario, $"user array: {sids.Count} user(s)");
        }
        catch (Exception ex)
        {
            // Keep whatever was read; a missing enrolled SID just means no tile.
            ProviderLog.WriteException(Scenario, "SetUserArray", ex, includeStack: true);
        }
        _userSids = sids;
        _lastCountLog = null;
        return S_OK;
    }

    // ----- Called by the credential ----------------------------------------------------------------

    /// <summary>Makes sure the UI pump exists. UI thread only.</summary>
    internal void EnsureUiPump() => EnsureDispatcher();

    /// <summary>Runs <paramref name="action"/> on the LogonUI thread. Any thread; false if it can't be delivered.</summary>
    internal bool Post(Action action)
    {
        UiDispatcher? dispatcher;
        lock (_sync)
            dispatcher = _dispatcher;
        return dispatcher is not null && dispatcher.Post(action);
    }

    /// <summary>
    /// Asks LogonUI to re-enumerate so that it signs in with our (now ready) default tile. LogonUI thread only
    /// (a posted action). Holds no lock across the call, which can synchronously re-enter GetCredentialCount
    /// and GetSerialization.
    /// </summary>
    internal void RequestAutoLogon()
    {
        IntPtr events;
        nuint context;
        lock (_sync)
        {
            events = _events;
            context = _adviseContext;
            if (events != IntPtr.Zero)
                Marshal.AddRef(events); // keep it alive even if UnAdvise runs re-entrantly
        }
        if (events == IntPtr.Zero)
        {
            ProviderLog.Write(Scenario, "password ready, but LogonUI gave no events sink to request auto-logon");
            return;
        }
        try
        {
            ProviderLog.Write(Scenario, "calling CredentialsChanged");
            int hr = RawCalls.ProviderEvents.CredentialsChanged(events, context);
            if (hr < 0)
                ProviderLog.Write(Scenario, $"CredentialsChanged returned 0x{hr:X8}");
        }
        finally
        {
            Marshal.Release(events);
        }
    }

    // ----- Helpers ---------------------------------------------------------------------------------

    private void EnsureDispatcher()
    {
        lock (_sync)
        {
            if (_dispatcher is not null)
                return;
            _dispatcher = UiDispatcher.Create();
            if (_dispatcher is null)
                ProviderLog.Write(Scenario, "could not create the UI dispatcher window");
        }
    }

    private void ReplaceCredential(string reason)
    {
        var old = _credential;
        _credential = null;
        old?.Shutdown(reason);
    }

    /// <summary>
    /// True in Safe Mode or when the kill-switch file exists: the provider must then stay inert, without any log
    /// write (the log would set up its folder). <paramref name="failure"/> is set only when the kill-switch check
    /// itself failed, which is worth a log line (the provider stays inactive then too).
    /// </summary>
    private static bool IsSwitchedOff(out string? failure)
    {
        failure = null;
        if (NativeMethods.GetSystemMetrics(NativeMethods.SM_CLEANBOOT) != 0)
            return true;
        try
        {
            return File.Exists(KillSwitchPath);
        }
        catch (Exception ex)
        {
            failure = $"kill-switch check failed ({ex.GetType().Name}: {ex.Message})";
            return true;
        }
    }

    private static bool TryGetInactiveReason(out string reason, out Enrollment? enrollment)
    {
        enrollment = null;
        try
        {
            enrollment = TestHooks.LoadEnrollment is { } load ? load() : EnrollmentStore.Load();
        }
        catch (Exception ex)
        {
            reason = $"enrollment unreadable ({ex.GetType().Name}: {ex.Message})";
            return true;
        }
        if (enrollment is null)
        {
            reason = "nothing enrolled";
            return true;
        }
        reason = string.Empty;
        return false;
    }

    private bool TryGetInactiveReason(out string reason)
    {
        bool inactive = TryGetInactiveReason(out reason, out var enrollment);
        _enrollment = inactive ? null : enrollment;
        return inactive;
    }

    /// <summary>Logs a GetCredentialCount outcome once until it changes (LogonUI asks often).</summary>
    private void LogCount(string message)
    {
        if (message == _lastCountLog)
            return;
        _lastCountLog = message;
        ProviderLog.Write(Scenario, message);
    }

    private static IntPtr Descriptor(uint fieldId, CREDENTIAL_PROVIDER_FIELD_TYPE type, string? label, Guid guidFieldType) =>
        CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR.AllocCoTaskMem(fieldId, type, label, guidFieldType);

    /// <summary>The docs show SIDs from LogonUI wrapped in braces; compare without them.</summary>
    internal static string NormalizeSid(string sid) => sid.Trim().Trim('{', '}').Trim();

    internal static string ScenarioName(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus) => cpus switch
    {
        CREDENTIAL_PROVIDER_USAGE_SCENARIO.CPUS_LOGON => "logon",
        CREDENTIAL_PROVIDER_USAGE_SCENARIO.CPUS_UNLOCK_WORKSTATION => "unlock",
        CREDENTIAL_PROVIDER_USAGE_SCENARIO.CPUS_CREDUI => "credui",
        CREDENTIAL_PROVIDER_USAGE_SCENARIO.CPUS_CHANGE_PASSWORD => "change-password",
        CREDENTIAL_PROVIDER_USAGE_SCENARIO.CPUS_PLAP => "plap",
        _ => "-",
    };
}
