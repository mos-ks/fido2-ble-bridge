using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Fido2BleLogon.CredentialProvider.Interop;

namespace Fido2BleLogon.CpHarness;

/// <summary>
/// Hand-built native COM objects standing in for what LogonUI hands the provider: an ICredentialProviderEvents
/// sink, an ICredentialProviderCredentialEvents(2) sink and an ICredentialProviderUserArray with one
/// ICredentialProviderUser. Each has a real vtable in SDK order and a QueryInterface that answers its IIDs, so
/// the provider's RawCalls reach them exactly as they would reach LogonUI. They also record what the tile
/// currently shows (<see cref="Status"/>, <see cref="LinkText"/>, <see cref="LinkVisible"/>).
/// Single-threaded by design: the provider may only call them on the harness's STA thread, and
/// <see cref="WrongThreadCalls"/> counts any call that arrives on another thread.
/// </summary>
internal static unsafe class Fakes
{
    private enum Kind { ProviderEvents = 1, CredentialEvents = 2, UserArray = 3, User = 4 }

    private static readonly Guid IidUnknown = new("00000000-0000-0000-C000-000000000046");

    // ---- Configuration (set before use) ----
    public static string UserSid = "";
    public static string QualifiedUserName = "";
    public static string UserName = "";
    public static bool Verbose = true;
    public static int OwnerThreadId;

    // ---- What the "screen" shows, and what happened ----
    public static string Status = "";
    public static string LinkText = "";
    public static bool LinkVisible;
    public static int CredentialsChangedCount;
    public static int WrongThreadCalls;
    public static IntPtr LastPcpc;
    public static readonly List<string> StatusHistory = [];
    /// <summary>The link's text each time it was made visible.</summary>
    public static readonly List<string> LinkShown = [];

    private static IntPtr _user;

    /// <summary>Clears what was observed (not the configuration).</summary>
    public static void ResetObservations()
    {
        Status = "";
        LinkText = "";
        LinkVisible = false;
        CredentialsChangedCount = 0;
        WrongThreadCalls = 0;
        LastPcpc = IntPtr.Zero;
        StatusHistory.Clear();
        LinkShown.Clear();
    }

    public static IntPtr CreateProviderEvents() => Make(Kind.ProviderEvents,
    [
        (IntPtr)(delegate* unmanaged[Stdcall]<IntPtr, nuint, int>)&CredentialsChanged,
    ]);

    public static IntPtr CreateCredentialEvents() => Make(Kind.CredentialEvents,
    [
        (IntPtr)(delegate* unmanaged[Stdcall]<IntPtr, IntPtr, uint, int, int>)&SetFieldState,
        (IntPtr)(delegate* unmanaged[Stdcall]<IntPtr, IntPtr, uint, int, int>)&SetFieldInteractiveState,
        (IntPtr)(delegate* unmanaged[Stdcall]<IntPtr, IntPtr, uint, char*, int>)&SetFieldString,
        (IntPtr)(delegate* unmanaged[Stdcall]<IntPtr, IntPtr, uint, int, char*, int>)&SetFieldCheckbox,
        (IntPtr)(delegate* unmanaged[Stdcall]<IntPtr, IntPtr, uint, IntPtr, int>)&SetFieldBitmap,
        (IntPtr)(delegate* unmanaged[Stdcall]<IntPtr, IntPtr, uint, uint, int>)&SetFieldComboBoxSelectedItem,
        (IntPtr)(delegate* unmanaged[Stdcall]<IntPtr, IntPtr, uint, uint, int>)&DeleteFieldComboBoxItem,
        (IntPtr)(delegate* unmanaged[Stdcall]<IntPtr, IntPtr, uint, char*, int>)&AppendFieldComboBoxItem,
        (IntPtr)(delegate* unmanaged[Stdcall]<IntPtr, IntPtr, uint, uint, int>)&SetFieldSubmitButton,
        (IntPtr)(delegate* unmanaged[Stdcall]<IntPtr, IntPtr*, int>)&OnCreatingWindow,
        (IntPtr)(delegate* unmanaged[Stdcall]<IntPtr, int>)&BeginFieldUpdates,
        (IntPtr)(delegate* unmanaged[Stdcall]<IntPtr, int>)&EndFieldUpdates,
        (IntPtr)(delegate* unmanaged[Stdcall]<IntPtr, IntPtr, uint, uint, int>)&SetFieldOptions,
    ]);

    public static IntPtr CreateUserArray()
    {
        _user = Make(Kind.User,
        [
            (IntPtr)(delegate* unmanaged[Stdcall]<IntPtr, IntPtr*, int>)&GetSid,
            (IntPtr)(delegate* unmanaged[Stdcall]<IntPtr, Guid*, int>)&GetProviderID,
            (IntPtr)(delegate* unmanaged[Stdcall]<IntPtr, PROPERTYKEY*, IntPtr*, int>)&GetUserStringValue,
            (IntPtr)(delegate* unmanaged[Stdcall]<IntPtr, IntPtr, IntPtr, int>)&GetValue,
        ]);
        return Make(Kind.UserArray,
        [
            (IntPtr)(delegate* unmanaged[Stdcall]<IntPtr, Guid*, int>)&SetProviderFilter,
            (IntPtr)(delegate* unmanaged[Stdcall]<IntPtr, uint*, int>)&GetAccountOptions,
            (IntPtr)(delegate* unmanaged[Stdcall]<IntPtr, uint*, int>)&GetCount,
            (IntPtr)(delegate* unmanaged[Stdcall]<IntPtr, uint, IntPtr*, int>)&GetAt,
        ]);
    }

    /// <summary>Reference count of a fake object (to check the provider releases what it AddRef'ed).</summary>
    public static long RefCount(IntPtr obj) => Volatile.Read(ref RefSlot(obj));

    // Layout of a fake object: [0] vtable, [1] reference count, [2] kind. Never freed (harness lifetime).
    private static IntPtr Make(Kind kind, IntPtr[] methods)
    {
        var vtable = (IntPtr*)NativeMemory.AllocZeroed((nuint)((3 + methods.Length) * sizeof(IntPtr)));
        vtable[0] = (IntPtr)(delegate* unmanaged[Stdcall]<IntPtr, Guid*, IntPtr*, int>)&QueryInterface;
        vtable[1] = (IntPtr)(delegate* unmanaged[Stdcall]<IntPtr, uint>)&AddRef;
        vtable[2] = (IntPtr)(delegate* unmanaged[Stdcall]<IntPtr, uint>)&Release;
        for (int i = 0; i < methods.Length; i++)
            vtable[3 + i] = methods[i];
        var obj = (IntPtr*)NativeMemory.AllocZeroed((nuint)(3 * sizeof(IntPtr)));
        obj[0] = (IntPtr)vtable;
        obj[1] = 1;
        obj[2] = (int)kind;
        return (IntPtr)obj;
    }

    private static ref long RefSlot(IntPtr obj) => ref Unsafe.AsRef<long>((void*)((IntPtr*)obj + 1));

    private static Kind KindOf(IntPtr obj) => (Kind)(int)((IntPtr*)obj)[2];

    private static void CheckThread(string what)
    {
        if (OwnerThreadId != 0 && Environment.CurrentManagedThreadId != OwnerThreadId)
        {
            Interlocked.Increment(ref WrongThreadCalls);
            Console.WriteLine($"  !! {what} called on thread {Environment.CurrentManagedThreadId}, not the LogonUI thread");
        }
    }

    private static void Print(string text)
    {
        if (Verbose)
            Console.WriteLine(text);
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static int QueryInterface(IntPtr self, Guid* riid, IntPtr* ppv)
    {
        *ppv = IntPtr.Zero;
        Guid iid = *riid;
        bool ok = iid == IidUnknown || KindOf(self) switch
        {
            Kind.ProviderEvents => iid == CredentialProviderIids.ICredentialProviderEvents,
            Kind.CredentialEvents => iid == CredentialProviderIids.ICredentialProviderCredentialEvents
                                     || iid == CredentialProviderIids.ICredentialProviderCredentialEvents2,
            Kind.UserArray => iid == CredentialProviderIids.ICredentialProviderUserArray,
            Kind.User => iid == CredentialProviderIids.ICredentialProviderUser,
            _ => false,
        };
        if (!ok)
            return unchecked((int)0x80004002); // E_NOINTERFACE
        Interlocked.Increment(ref RefSlot(self));
        *ppv = self;
        return 0;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static uint AddRef(IntPtr self) => (uint)Interlocked.Increment(ref RefSlot(self));

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static uint Release(IntPtr self) => (uint)Interlocked.Decrement(ref RefSlot(self));

    // ----- ICredentialProviderEvents ---------------------------------------------------------------

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static int CredentialsChanged(IntPtr self, nuint context)
    {
        CheckThread("CredentialsChanged");
        CredentialsChangedCount++;
        Print($"  [LogonUI] CredentialsChanged(context=0x{context:X}): the provider asks for auto-logon");
        return 0;
    }

    // ----- ICredentialProviderCredentialEvents(2) --------------------------------------------------

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static int SetFieldState(IntPtr self, IntPtr pcpc, uint id, int state)
    {
        CheckThread("SetFieldState");
        LastPcpc = pcpc;
        if (id == 3)
        {
            bool visible = state != 0;
            if (visible && !LinkVisible)
                LinkShown.Add(LinkText);
            LinkVisible = visible;
            Print($"  [tile   ] link {(LinkVisible ? $"shown: \"{LinkText}\"" : "hidden")}");
        }
        else
        {
            Print($"  [tile   ] SetFieldState(field {id}, {(CREDENTIAL_PROVIDER_FIELD_STATE)state})");
        }
        return 0;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static int SetFieldInteractiveState(IntPtr self, IntPtr pcpc, uint id, int state)
    {
        CheckThread("SetFieldInteractiveState");
        Print($"  [tile   ] SetFieldInteractiveState(field {id}, {(CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE)state})");
        return 0;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static int SetFieldString(IntPtr self, IntPtr pcpc, uint id, char* psz)
    {
        CheckThread("SetFieldString");
        LastPcpc = pcpc;
        string value = psz == null ? "" : new string(psz);
        switch (id)
        {
            case 2:
                Status = value;
                StatusHistory.Add(value);
                Print($"  [tile   ] status: \"{value}\"");
                break;
            case 3:
                LinkText = value;
                Print($"  [tile   ] link text: \"{value}\"");
                break;
            default:
                Print($"  [tile   ] SetFieldString(field {id}) = \"{value}\"");
                break;
        }
        return 0;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static int SetFieldCheckbox(IntPtr self, IntPtr pcpc, uint id, int bChecked, char* label) => 0;

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static int SetFieldBitmap(IntPtr self, IntPtr pcpc, uint id, IntPtr hbmp)
    {
        Print($"  [tile   ] SetFieldBitmap(field {id})");
        return 0;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static int SetFieldComboBoxSelectedItem(IntPtr self, IntPtr pcpc, uint id, uint item) => 0;

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static int DeleteFieldComboBoxItem(IntPtr self, IntPtr pcpc, uint id, uint item) => 0;

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static int AppendFieldComboBoxItem(IntPtr self, IntPtr pcpc, uint id, char* item) => 0;

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static int SetFieldSubmitButton(IntPtr self, IntPtr pcpc, uint id, uint adjacent) => 0;

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static int OnCreatingWindow(IntPtr self, IntPtr* hwnd)
    {
        *hwnd = IntPtr.Zero;
        return 0;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static int BeginFieldUpdates(IntPtr self) => 0;

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static int EndFieldUpdates(IntPtr self) => 0;

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static int SetFieldOptions(IntPtr self, IntPtr cred, uint id, uint options) => 0;

    // ----- ICredentialProviderUserArray ------------------------------------------------------------

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static int SetProviderFilter(IntPtr self, Guid* guid) => 0;

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static int GetAccountOptions(IntPtr self, uint* options)
    {
        *options = 0;
        return 0;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static int GetCount(IntPtr self, uint* count)
    {
        *count = 1;
        return 0;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static int GetAt(IntPtr self, uint index, IntPtr* user)
    {
        if (index != 0)
        {
            *user = IntPtr.Zero;
            return unchecked((int)0x80070057); // E_INVALIDARG
        }
        Interlocked.Increment(ref RefSlot(_user));
        *user = _user;
        return 0;
    }

    // ----- ICredentialProviderUser -----------------------------------------------------------------

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static int GetSid(IntPtr self, IntPtr* sid)
    {
        *sid = Marshal.StringToCoTaskMemUni(UserSid);
        return 0;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static int GetProviderID(IntPtr self, Guid* id)
    {
        *id = CredentialProviderConstants.Identity_LocalUserProvider;
        return 0;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static int GetUserStringValue(IntPtr self, PROPERTYKEY* key, IntPtr* value)
    {
        static bool Is(PROPERTYKEY* k, PROPERTYKEY expected) => k->pid == expected.pid && k->fmtid == expected.fmtid;
        string result =
            Is(key, PropertyKeys.PKEY_Identity_QualifiedUserName) ? QualifiedUserName :
            Is(key, PropertyKeys.PKEY_Identity_PrimarySid) ? "{" + UserSid + "}" : // the docs show it in braces
            UserName;
        *value = Marshal.StringToCoTaskMemUni(result);
        return 0;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static int GetValue(IntPtr self, IntPtr key, IntPtr value) => unchecked((int)0x80004001); // E_NOTIMPL
}
