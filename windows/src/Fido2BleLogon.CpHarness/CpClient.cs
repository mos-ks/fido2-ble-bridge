using System.Runtime.InteropServices;
using Fido2BleLogon.CredentialProvider.Interop;

namespace Fido2BleLogon.CpHarness;

/// <summary>
/// Calls an ICredentialProvider through its raw vtable, the way native LogonUI does, so the harness goes
/// through the provider's COM callable wrapper (out-parameter marshaling, HRESULT conversion) whether the
/// provider was created directly or with CoCreateInstance. Slot numbers are those of credentialprovider.h.
/// Owns one reference to <see cref="Pointer"/>.
/// </summary>
internal sealed unsafe class ProviderClient(IntPtr pointer) : IDisposable
{
    public IntPtr Pointer { get; private set; } = pointer;

    private void* Slot(int index) => ((void***)Pointer)[0][index];

    public int SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, uint flags) =>
        ((delegate* unmanaged[Stdcall]<IntPtr, int, uint, int>)Slot(3))(Pointer, (int)cpus, flags);

    public int Advise(IntPtr events, nuint context) =>
        ((delegate* unmanaged[Stdcall]<IntPtr, IntPtr, nuint, int>)Slot(5))(Pointer, events, context);

    public int UnAdvise() => ((delegate* unmanaged[Stdcall]<IntPtr, int>)Slot(6))(Pointer);

    public int GetFieldDescriptorCount(out uint count)
    {
        uint c = 0;
        int hr = ((delegate* unmanaged[Stdcall]<IntPtr, uint*, int>)Slot(7))(Pointer, &c);
        count = c;
        return hr;
    }

    public int GetFieldDescriptorAt(uint index, out IntPtr descriptor)
    {
        IntPtr d = IntPtr.Zero;
        int hr = ((delegate* unmanaged[Stdcall]<IntPtr, uint, IntPtr*, int>)Slot(8))(Pointer, index, &d);
        descriptor = d;
        return hr;
    }

    public int GetCredentialCount(out uint count, out uint defaultIndex, out int autoLogon)
    {
        uint c = 0, d = 0;
        int a = 0;
        int hr = ((delegate* unmanaged[Stdcall]<IntPtr, uint*, uint*, int*, int>)Slot(9))(Pointer, &c, &d, &a);
        count = c;
        defaultIndex = d;
        autoLogon = a;
        return hr;
    }

    public int GetCredentialAt(uint index, out IntPtr credential)
    {
        IntPtr p = IntPtr.Zero;
        int hr = ((delegate* unmanaged[Stdcall]<IntPtr, uint, IntPtr*, int>)Slot(10))(Pointer, index, &p);
        credential = p;
        return hr;
    }

    /// <summary>QueryInterface for ICredentialProviderSetUserArray, then SetUserArray (slot 3).</summary>
    public int SetUserArray(IntPtr users)
    {
        int hr = Marshal.QueryInterface(Pointer, CredentialProviderIids.ICredentialProviderSetUserArray, out IntPtr setter);
        if (hr < 0)
            return hr;
        try
        {
            void* fn = ((void***)setter)[0][3];
            return ((delegate* unmanaged[Stdcall]<IntPtr, IntPtr, int>)fn)(setter, users);
        }
        finally
        {
            Marshal.Release(setter);
        }
    }

    public void Dispose()
    {
        if (Pointer != IntPtr.Zero)
            Marshal.Release(Pointer);
        Pointer = IntPtr.Zero;
    }
}

/// <summary>Calls an ICredentialProviderCredential(2) through its raw vtable. Owns one reference.</summary>
internal sealed unsafe class CredentialClient(IntPtr pointer) : IDisposable
{
    public IntPtr Pointer { get; private set; } = pointer;

    private void* Slot(int index) => ((void***)Pointer)[0][index];

    public int Advise(IntPtr events) => ((delegate* unmanaged[Stdcall]<IntPtr, IntPtr, int>)Slot(3))(Pointer, events);

    public int UnAdvise() => ((delegate* unmanaged[Stdcall]<IntPtr, int>)Slot(4))(Pointer);

    public int SetSelected(out int autoLogon)
    {
        int a = 0;
        int hr = ((delegate* unmanaged[Stdcall]<IntPtr, int*, int>)Slot(5))(Pointer, &a);
        autoLogon = a;
        return hr;
    }

    public int SetDeselected() => ((delegate* unmanaged[Stdcall]<IntPtr, int>)Slot(6))(Pointer);

    public int GetFieldState(uint field, out CREDENTIAL_PROVIDER_FIELD_STATE state, out CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE interactive)
    {
        int s = 0, i = 0;
        int hr = ((delegate* unmanaged[Stdcall]<IntPtr, uint, int*, int*, int>)Slot(7))(Pointer, field, &s, &i);
        state = (CREDENTIAL_PROVIDER_FIELD_STATE)s;
        interactive = (CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE)i;
        return hr;
    }

    /// <summary>GetStringValue; the CoTaskMem string is read and freed here.</summary>
    public int GetStringValue(uint field, out string? value)
    {
        IntPtr p = IntPtr.Zero;
        int hr = ((delegate* unmanaged[Stdcall]<IntPtr, uint, IntPtr*, int>)Slot(8))(Pointer, field, &p);
        value = RawCalls.TakeCoTaskMemString(p);
        return hr;
    }

    /// <summary>GetBitmapValue; the caller owns the returned HBITMAP (as LogonUI does).</summary>
    public int GetBitmapValue(uint field, out IntPtr hbitmap)
    {
        IntPtr h = IntPtr.Zero;
        int hr = ((delegate* unmanaged[Stdcall]<IntPtr, uint, IntPtr*, int>)Slot(9))(Pointer, field, &h);
        hbitmap = h;
        return hr;
    }

    public int CommandLinkClicked(uint field) => ((delegate* unmanaged[Stdcall]<IntPtr, uint, int>)Slot(17))(Pointer, field);

    /// <summary>GetSerialization; the caller owns rgbSerialization (and the optional status text is freed here).</summary>
    public int GetSerialization(out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE response,
        out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION serialization, out string? statusText, out CREDENTIAL_PROVIDER_STATUS_ICON icon)
    {
        int r = 0, i = 0;
        IntPtr text = IntPtr.Zero;
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION s = default;
        int hr = ((delegate* unmanaged[Stdcall]<IntPtr, int*, CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*, IntPtr*, int*, int>)Slot(18))(Pointer, &r, &s, &text, &i);
        response = (CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE)r;
        serialization = s;
        statusText = RawCalls.TakeCoTaskMemString(text);
        icon = (CREDENTIAL_PROVIDER_STATUS_ICON)i;
        return hr;
    }

    public int ReportResult(int status, int substatus, out string? statusText, out CREDENTIAL_PROVIDER_STATUS_ICON icon)
    {
        IntPtr text = IntPtr.Zero;
        int i = 0;
        int hr = ((delegate* unmanaged[Stdcall]<IntPtr, int, int, IntPtr*, int*, int>)Slot(19))(Pointer, status, substatus, &text, &i);
        statusText = RawCalls.TakeCoTaskMemString(text);
        icon = (CREDENTIAL_PROVIDER_STATUS_ICON)i;
        return hr;
    }

    /// <summary>QueryInterface for ICredentialProviderCredential2 (as LogonUI does), then GetUserSid (slot 20).</summary>
    public int GetUserSid(out string? sid)
    {
        sid = null;
        int hr = Marshal.QueryInterface(Pointer, CredentialProviderIids.ICredentialProviderCredential2, out IntPtr cred2);
        if (hr < 0)
            return hr;
        try
        {
            IntPtr p = IntPtr.Zero;
            void* fn = ((void***)cred2)[0][20];
            hr = ((delegate* unmanaged[Stdcall]<IntPtr, IntPtr*, int>)fn)(cred2, &p);
            sid = RawCalls.TakeCoTaskMemString(p);
            return hr;
        }
        finally
        {
            Marshal.Release(cred2);
        }
    }

    public void Dispose()
    {
        if (Pointer != IntPtr.Zero)
            Marshal.Release(Pointer);
        Pointer = IntPtr.Zero;
    }
}
