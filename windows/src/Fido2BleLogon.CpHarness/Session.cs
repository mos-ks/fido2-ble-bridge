using System.Runtime.InteropServices;
using Fido2BleLogon.CredentialProvider;
using Fido2BleLogon.CredentialProvider.Interop;
using static Fido2BleLogon.CredentialProvider.Interop.HResults;
using static Fido2BleLogon.CpHarness.NativeHost;

namespace Fido2BleLogon.CpHarness;

/// <summary>
/// Plays LogonUI against one provider instance: SetUsageScenario, SetUserArray, Advise, field descriptors,
/// GetCredentialCount / GetCredentialAt, credential Advise and the initial field reads, then whatever the
/// caller drives. All calls go through the raw vtables on this (STA) thread.
/// </summary>
internal sealed class Session : IDisposable
{
    public const nuint AdviseContext = 0xA11CE;

    private readonly IntPtr _providerEvents = Fakes.CreateProviderEvents();
    private readonly IntPtr _credentialEvents = Fakes.CreateCredentialEvents();
    private readonly IntPtr _userArray = Fakes.CreateUserArray();
    private bool _providerAdvised;
    private bool _credentialAdvised;

    private Session(ProviderClient provider) => Provider = provider;

    public ProviderClient Provider { get; }
    public CredentialClient? Credential { get; private set; }
    public IntPtr ProviderEventsObject => _providerEvents;
    public IntPtr CredentialEventsObject => _credentialEvents;

    /// <summary>Instantiates the provider class directly and takes its ICredentialProvider CCW pointer.</summary>
    public static Session CreateDirect()
    {
        var provider = new SecurityKeyProvider();
        return new Session(new ProviderClient(Marshal.GetComInterfaceForObject(provider, typeof(ICredentialProvider))));
    }

    /// <summary>CoCreateInstance(CLSID, CLSCTX_INPROC_SERVER): goes through the registered comhost.</summary>
    public static Session? CreateViaCom(out int hr)
    {
        hr = CoCreateInstance(new Guid(SecurityKeyProvider.ClassIdString), IntPtr.Zero, CLSCTX_INPROC_SERVER,
            CredentialProviderIids.ICredentialProvider, out IntPtr pointer);
        return hr < 0 || pointer == IntPtr.Zero ? null : new Session(new ProviderClient(pointer));
    }

    /// <summary>SetUsageScenario, then (optionally) SetUserArray and Advise. Returns the SetUsageScenario HRESULT.</summary>
    public int Start(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, uint flags, bool setUserArray, bool print)
    {
        int hr = Provider.SetUsageScenario(cpus, flags);
        Say(print, $"SetUsageScenario({cpus}, 0x{flags:X}) -> {Hr(hr)}");
        if (hr != S_OK)
            return hr;

        if (setUserArray)
        {
            int hrArray = Provider.SetUserArray(_userArray);
            Say(print, $"SetUserArray(1 user: {Fakes.QualifiedUserName} {Fakes.UserSid}) -> {Hr(hrArray)}");
        }
        else
        {
            Say(print, "SetUserArray not called");
        }

        int hrAdvise = Provider.Advise(_providerEvents, AdviseContext);
        _providerAdvised = hrAdvise == S_OK;
        Say(print, $"Advise(events, 0x{AdviseContext:X}) -> {Hr(hrAdvise)}");
        return hr;
    }

    /// <summary>Reads all field descriptors (and frees them, as LogonUI does). Returns them for checks.</summary>
    public List<FieldDescriptorInfo> ReadDescriptors(bool print)
    {
        var list = new List<FieldDescriptorInfo>();
        Provider.GetFieldDescriptorCount(out uint count);
        Say(print, $"GetFieldDescriptorCount -> {count}");
        for (uint i = 0; i < count; i++)
        {
            int hr = Provider.GetFieldDescriptorAt(i, out IntPtr descriptor);
            if (hr != S_OK || descriptor == IntPtr.Zero)
            {
                Say(print, $"  GetFieldDescriptorAt({i}) -> {Hr(hr)}");
                continue;
            }
            try
            {
                var fd = Marshal.PtrToStructure<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR>(descriptor);
                string label = RawCalls.TakeCoTaskMemString(fd.pszLabel) ?? "";
                var info = new FieldDescriptorInfo(fd.dwFieldID, fd.cpft, label, fd.guidFieldType);
                list.Add(info);
                Say(print, $"  field {info.Id}: {info.Type,-18} label=\"{info.Label}\" guidFieldType={GuidName(info.GuidFieldType)}");
            }
            finally
            {
                Marshal.FreeCoTaskMem(descriptor);
            }
        }
        return list;
    }

    /// <summary>GetCredentialCount; if there is a credential, GetCredentialAt(0), credential Advise and the
    /// initial field reads. Returns the count.</summary>
    public uint Enumerate(bool print, out uint defaultIndex, out int autoLogon)
    {
        Provider.GetCredentialCount(out uint count, out defaultIndex, out autoLogon);
        Say(print, $"GetCredentialCount -> count={count}, default={FormatDefault(defaultIndex)}, autoLogon={autoLogon}");
        if (count == 0 || Credential is not null)
            return count;

        int hr = Provider.GetCredentialAt(0, out IntPtr pointer);
        Say(print, $"GetCredentialAt(0) -> {Hr(hr)}");
        if (hr != S_OK || pointer == IntPtr.Zero)
            return count;
        Credential = new CredentialClient(pointer);

        hr = Credential.Advise(_credentialEvents);
        _credentialAdvised = hr == S_OK;
        Say(print, $"credential Advise(events) -> {Hr(hr)}");

        // What LogonUI reads to build the tile.
        for (uint field = 0; field < SecurityKeyProvider.FieldCount; field++)
        {
            Credential.GetFieldState(field, out var state, out var interactive);
            string text = "";
            if (field == SecurityKeyProvider.FieldImage)
            {
                int hrBitmap = Credential.GetBitmapValue(field, out IntPtr hbmp);
                if (hrBitmap == S_OK && hbmp != IntPtr.Zero)
                {
                    GetObjectW(hbmp, Marshal.SizeOf<BITMAP>(), out var bm);
                    text = $"bitmap {bm.bmWidth}x{Math.Abs(bm.bmHeight)}, {bm.bmBitsPixel} bpp";
                    LastBitmap = (bm.bmWidth, Math.Abs(bm.bmHeight), bm.bmBitsPixel);
                    DeleteObject(hbmp); // LogonUI owns it
                }
                else
                {
                    text = $"GetBitmapValue -> {Hr(hrBitmap)}";
                }
            }
            else
            {
                Credential.GetStringValue(field, out string? value);
                text = $"\"{value}\"";
                if (field == SecurityKeyProvider.FieldStatus)
                    Fakes.Status = value ?? "";
                if (field == SecurityKeyProvider.FieldLink)
                    Fakes.LinkText = value ?? "";
            }
            if (field == SecurityKeyProvider.FieldLink)
                Fakes.LinkVisible = state != CREDENTIAL_PROVIDER_FIELD_STATE.CPFS_HIDDEN;
            Say(print, $"  field {field}: {state}, {interactive}, {text}");
        }
        Credential.GetUserSid(out string? sid);
        UserSid = sid;
        Say(print, $"  GetUserSid -> {sid}");
        return count;
    }

    /// <summary>ICredentialProvider.UnAdvise now (Dispose then skips it).</summary>
    public int UnAdviseProvider()
    {
        _providerAdvised = false;
        return Provider.UnAdvise();
    }

    public (int Width, int Height, int Bpp)? LastBitmap { get; private set; }

    public string? UserSid { get; private set; }

    /// <summary>Tears down like LogonUI: deselect, credential UnAdvise and release, provider UnAdvise and release.</summary>
    public void Dispose()
    {
        try
        {
            if (Credential is not null)
            {
                if (_credentialAdvised)
                    Credential.UnAdvise();
                Credential.Dispose();
                Credential = null;
            }
            if (_providerAdvised)
                Provider.UnAdvise();
        }
        finally
        {
            Provider.Dispose();
        }
    }

    public static string Hr(int hr) => hr switch
    {
        S_OK => "S_OK",
        S_FALSE => "S_FALSE",
        E_NOTIMPL => "E_NOTIMPL",
        E_INVALIDARG => "E_INVALIDARG",
        E_NOINTERFACE => "E_NOINTERFACE",
        E_FAIL => "E_FAIL",
        _ => $"0x{hr:X8}",
    };

    public static string FormatDefault(uint index) =>
        index == CredentialProviderConstants.CREDENTIAL_PROVIDER_NO_DEFAULT ? "NONE" : index.ToString();

    private static string GuidName(Guid guid) =>
        guid == Guid.Empty ? "(none)"
        : guid == CredentialProviderConstants.CPFG_CREDENTIAL_PROVIDER_LOGO ? "CPFG_CREDENTIAL_PROVIDER_LOGO"
        : guid == CredentialProviderConstants.CPFG_CREDENTIAL_PROVIDER_LABEL ? "CPFG_CREDENTIAL_PROVIDER_LABEL"
        : guid.ToString();

    private static void Say(bool print, string text)
    {
        if (print)
            Console.WriteLine(text);
    }
}

/// <summary>A field descriptor as read back by the harness.</summary>
internal sealed record FieldDescriptorInfo(uint Id, CREDENTIAL_PROVIDER_FIELD_TYPE Type, string Label, Guid GuidFieldType);
