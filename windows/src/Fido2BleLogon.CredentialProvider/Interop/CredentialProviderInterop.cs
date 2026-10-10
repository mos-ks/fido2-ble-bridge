// COM interop for the Windows credential provider API: credentialprovider.h / credentialprovider.idl,
// plus the CPFG_* field GUIDs from shlguid.h and the PKEY_Identity_* property keys from propkey.h.
//
// Target: x64 only (the sizes and offsets below assume 8-byte pointers). Uses built-in .NET COM interop
// ([ComImport] interfaces with classic CCW/RCW marshaling), NOT the ComWrappers source generator, so the
// project must keep built-in COM interop enabled (no Native AOT, no trimming).
//
// SOURCES
// Vtable order, IIDs, enum values, struct layouts and GUID / PROPERTYKEY values were taken from the
// Windows SDK and cross-checked against independent sources. Method lists on Microsoft Learn are
// alphabetical and were never used for ordering.
//   [SDK]    Windows SDK 10.0.28000.0: um/credentialprovider.h (MIDL output), um/credentialprovider.idl,
//            um/ShlGuid.h, um/propkey.h, shared/winerror.h, shared/ntstatus.h
//            (NuGet Microsoft.Windows.SDK.CPP 10.0.28000.2705). The interfaces are identical in
//            SDK 10.0.16299.0 (github.com/tpn/winsdk-10), which only lacks CPFG_STYLE_LINK_AS_BUTTON.
//   [MINGW]  mingw-w64: mingw-w64-headers/include/credentialprovider.idl (independently written).
//   [RS]     microsoft/windows-rs: crates/libs/windows/src/Windows/Win32/{credentialprovider,shlguid,
//            propkey}/mod.rs (generated from Windows metadata).
//   [CPNET]  SteveSyfuhs/CredProvider.NET: midl/credentialprovider.idl and its TlbImp output
//            midl/CredProvider.NET.Interop2.dll (method order read from the assembly metadata).
//   [SAMPLE] microsoft/Windows-classic-samples: Samples/CredentialProvider (SampleV2CredentialProvider),
//            used for how the API is called in practice (allocation, Advise/UnAdvise, events).
//   [TECHREF] Microsoft, "Credential Provider driven Windows Logon Experience" (updated for Windows 10,
//            2016), used for the usage rules quoted in the comments below.
// Every interface below matches in [SDK], [MINGW], [RS] and [CPNET]. Every enum value, GUID and
// PROPERTYKEY matches [SDK] and [RS]; the CLSIDs also match [MINGW]. A test harness parsed the SDK
// header and compared each interface (method order, parameter count, IID), enum value, GUID and
// PROPERTYKEY in this file against it automatically. It also called every slot through raw function
// pointers in both directions (native caller -> our CCW, and our RCW / RawCalls -> a hand-built native
// object whose vtable follows the header).
// Not included: ICredentialProviderFilter ([TECHREF]: third-party providers should not use it) and
// IConnectableCredentialProviderCredential / IQueryContinueWithStatus (only for pre-logon access providers).
//
// TYPE MAPPING (exact on x64)
//   HRESULT -> int; every method is [PreserveSig]      DWORD, ULONG -> uint       NTSTATUS -> int
//   BOOL    -> int (0 or 1), never bool                UINT_PTR -> nuint
//   LPCWSTR (in)                                       -> [MarshalAs(UnmanagedType.LPWStr)] string
//   LPWSTR*, HBITMAP*, HWND*, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR**, I...** (out) -> out IntPtr
//   const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* (in) -> IntPtr (read with Marshal.PtrToStructure)
//   REFGUID / REFPROPERTYKEY                           -> ref Guid / ref PROPERTYKEY
//   interface pointer (in)                             -> IntPtr (see INTERFACE POINTERS AND THREADS)
//   HBITMAP / HWND (in)                                -> IntPtr. Do not copy CredProvider.NET's TlbImp
//                                                         signatures here: they use the RPC wire types.
//
// MEMORY RULES (standard COM: whoever receives an out value frees it)
//   * A string returned through out IntPtr must come from CoTaskMemAlloc (Marshal.StringToCoTaskMemUni).
//     Set it to IntPtr.Zero when returning a failure HRESULT.
//   * GetFieldDescriptorAt: CoTaskMemAlloc the descriptor and its pszLabel. Use
//     CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR.AllocCoTaskMem.
//   * GetSerialization: rgbSerialization must come from CoTaskMemAlloc. LogonUI frees it after success.
//   * An interface pointer returned through out IntPtr must be AddRef'ed. Marshal.GetComInterfaceForObject
//     and Marshal.QueryInterface already return AddRef'ed pointers.
//   * Strings LogonUI returns to us (ICredentialProviderUser.GetSid / GetStringValue) are freed with
//     Marshal.FreeCoTaskMem.
//
// EXCEPTIONS
//   The runtime turns an exception escaping one of these [PreserveSig] methods into its HResult. The
//   harness showed InvalidOperationException becoming 0x80131509. Out parameters point straight into
//   LogonUI's memory, so a value assigned before the throw is still what LogonUI sees, and a CoTaskMem
//   string assigned that way leaks. So: catch everything, set every out parameter to IntPtr.Zero / default
//   on failure, and keep each method short and non-blocking, because LogonUI calls them on its UI thread.
//
// INTERFACE POINTERS AND THREADS
//   The interface pointers LogonUI hands us are declared as raw IntPtr on purpose:
//   ICredentialProvider.Advise (ICredentialProviderEvents), ICredentialProviderCredential.Advise
//   (ICredentialProviderCredentialEvents), ICredentialProviderSetUserArray.SetUserArray
//   (ICredentialProviderUserArray) and ICredentialProviderUserArray.GetAt (ICredentialProviderUser).
//   Rule from [TECHREF]: do not pass the ICredentialProviderCredentialEvents object to other threads. A
//   worker with news for the tile (for example a FingerprintLogon.StageChanged handler) must hand the
//   update to the thread that received Advise, and that thread makes the call. LogonUI's thread pumps
//   window messages, so one way is a message-only window created on that thread in Advise, plus
//   PostMessage from the worker. CredentialsChanged has no documented thread rule ("asynchronous"), but
//   calling it from that same thread is always safe. Also from the docs: use
//   ICredentialProviderCredentialEvents2 to update a tile, and CredentialsChanged only to request
//   auto-logon or change the number of credentials.
//   Why not interface-typed parameters: the runtime would wrap each pointer in an RCW bound to the COM
//   apartment of the calling LogonUI thread, and using that RCW from a worker blocks or fails:
//     * The event sink interfaces are remotable (proxy/stub in OneCoreCommonProxyStub.dll). Unless
//       LogonUI's object is agile, the runtime marshals the call back to LogonUI's thread. The worker then
//       waits until that thread services it, and deadlocks if that thread is waiting for the worker. In
//       the harness, such a call ran on the creating STA thread only after that thread stopped being
//       busy (2 s).
//     * ICredentialProviderUserArray / ICredentialProviderUser are [local], with no proxy/stub. Their RCW
//       fails with E_NOINTERFACE in any other apartment (harness: InvalidCastException 0x80004002).
//     * The RCW's final Release runs on the finalizer thread unless Marshal.ReleaseComObject is called.
//   With IntPtr, Marshal.AddRef keeps a pointer and Marshal.Release drops it, in UnAdvise at the latest.
//   Call it on the right thread through the RawCalls helpers below. They make a plain vtable call on the
//   current thread, as C++ code does, and never switch threads themselves.

#nullable enable
#pragma warning disable CS1591 // Not every Win32 name below carries an XML doc comment.

using System;
using System.Runtime.InteropServices;

namespace Fido2BleLogon.CredentialProvider.Interop;

// ---------------------------------------------------------------------------------------------------
// Enumerations (credentialprovider.h). All are 32-bit ([v1_enum]).
// ---------------------------------------------------------------------------------------------------

/// <summary>CREDENTIAL_PROVIDER_USAGE_SCENARIO: passed to ICredentialProvider.SetUsageScenario.</summary>
public enum CREDENTIAL_PROVIDER_USAGE_SCENARIO
{
    CPUS_INVALID = 0,
    /// <summary>Logon screen. Per [TECHREF], unlocking may also arrive as CPUS_LOGON.</summary>
    CPUS_LOGON = 1,
    /// <summary>Lock screen of a signed-in user.</summary>
    CPUS_UNLOCK_WORKSTATION = 2,
    /// <summary>Ctrl+Alt+Del, "Change a password".</summary>
    CPUS_CHANGE_PASSWORD = 3,
    /// <summary>CredUIPromptForWindowsCredentials; dwFlags then carries CREDUIWIN_* flags.</summary>
    CPUS_CREDUI = 4,
    /// <summary>Pre-logon access provider (network connect before logon).</summary>
    CPUS_PLAP = 5,
}

/// <summary>CREDENTIAL_PROVIDER_FIELD_TYPE: CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR.cpft.</summary>
public enum CREDENTIAL_PROVIDER_FIELD_TYPE
{
    CPFT_INVALID = 0,
    CPFT_LARGE_TEXT = 1,
    CPFT_SMALL_TEXT = 2,
    CPFT_COMMAND_LINK = 3,
    CPFT_EDIT_TEXT = 4,
    CPFT_PASSWORD_TEXT = 5,
    CPFT_TILE_IMAGE = 6,
    CPFT_CHECKBOX = 7,
    CPFT_COMBOBOX = 8,
    CPFT_SUBMIT_BUTTON = 9,
}

/// <summary>CREDENTIAL_PROVIDER_FIELD_STATE: when a field is visible.</summary>
public enum CREDENTIAL_PROVIDER_FIELD_STATE
{
    CPFS_HIDDEN = 0,
    CPFS_DISPLAY_IN_SELECTED_TILE = 1,
    CPFS_DISPLAY_IN_DESELECTED_TILE = 2,
    CPFS_DISPLAY_IN_BOTH = 3,
}

/// <summary>CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE: whether a visible field accepts input.</summary>
public enum CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE
{
    CPFIS_NONE = 0,
    CPFIS_READONLY = 1,
    CPFIS_DISABLED = 2,
    CPFIS_FOCUSED = 3,
}

/// <summary>CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE: result of ICredentialProviderCredential.GetSerialization.</summary>
public enum CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE
{
    /// <summary>No credential; more input is needed and the user gets another chance on the tile.</summary>
    CPGSR_NO_CREDENTIAL_NOT_FINISHED = 0,
    /// <summary>No credential, but the credential's work is complete (do not retry).</summary>
    CPGSR_NO_CREDENTIAL_FINISHED = 1,
    /// <summary>A serialization was returned in pcpcs; LogonUI submits it.</summary>
    CPGSR_RETURN_CREDENTIAL_FINISHED = 2,
    /// <summary>No credential, work complete, and LogonUI should return (UnAdvise is called on all providers).</summary>
    CPGSR_RETURN_NO_CREDENTIAL_FINISHED = 3,
}

/// <summary>CREDENTIAL_PROVIDER_STATUS_ICON: icon next to an optional status text.</summary>
public enum CREDENTIAL_PROVIDER_STATUS_ICON
{
    CPSI_NONE = 0,
    CPSI_ERROR = 1,
    CPSI_WARNING = 2,
    CPSI_SUCCESS = 3,
}

/// <summary>CREDENTIAL_PROVIDER_ACCOUNT_OPTIONS (Windows 8+): from ICredentialProviderUserArray.GetAccountOptions.</summary>
[Flags]
public enum CREDENTIAL_PROVIDER_ACCOUNT_OPTIONS : uint
{
    CPAO_NONE = 0x0,
    /// <summary>LogonUI shows an empty ("Other user") tile for local accounts.</summary>
    CPAO_EMPTY_LOCAL = 0x1,
    /// <summary>LogonUI shows an empty tile for connected (Microsoft) accounts.</summary>
    CPAO_EMPTY_CONNECTED = 0x2,
}

/// <summary>CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS (Windows 8+).</summary>
[Flags]
public enum CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS : uint
{
    CPCFO_NONE = 0x0,
    CPCFO_ENABLE_PASSWORD_REVEAL = 0x1,
    CPCFO_IS_EMAIL_ADDRESS = 0x2,
    CPCFO_ENABLE_TOUCH_KEYBOARD_AUTO_INVOKE = 0x4,
    CPCFO_NUMBERS_ONLY = 0x8,
    CPCFO_SHOW_ENGLISH_KEYBOARD = 0x10,
}

// ---------------------------------------------------------------------------------------------------
// Structures. Offsets and sizes were checked with Marshal.OffsetOf / Marshal.SizeOf on x64.
// ---------------------------------------------------------------------------------------------------

/// <summary>
/// CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR. x64 layout (size 32, alignment 8):
/// <code>
///   offset  0  DWORD                           dwFieldID      4
///   offset  4  CREDENTIAL_PROVIDER_FIELD_TYPE  cpft           4
///   offset  8  LPWSTR                          pszLabel       8
///   offset 16  GUID                            guidFieldType  16
/// </code>
/// GetFieldDescriptorAt returns a CoTaskMemAlloc'ed descriptor whose pszLabel is also CoTaskMemAlloc'ed
/// (or null); LogonUI frees both. guidFieldType is Guid.Empty or one of the CPFG_* GUIDs.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR
{
    public uint dwFieldID;
    public CREDENTIAL_PROVIDER_FIELD_TYPE cpft;
    public IntPtr pszLabel;
    public Guid guidFieldType;

    /// <summary>
    /// Allocates a descriptor and its label with CoTaskMemAlloc, as GetFieldDescriptorAt must return them.
    /// Throws OutOfMemoryException (after freeing anything it allocated) if CoTaskMemAlloc fails.
    /// </summary>
    public static IntPtr AllocCoTaskMem(uint fieldId, CREDENTIAL_PROVIDER_FIELD_TYPE type, string? label, Guid guidFieldType)
    {
        IntPtr labelPtr = IntPtr.Zero;
        IntPtr block = IntPtr.Zero;
        try
        {
            if (label is not null)
                labelPtr = Marshal.StringToCoTaskMemUni(label);
            block = Marshal.AllocCoTaskMem(Marshal.SizeOf<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR>());
            var descriptor = new CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR
            {
                dwFieldID = fieldId,
                cpft = type,
                pszLabel = labelPtr,
                guidFieldType = guidFieldType,
            };
            Marshal.StructureToPtr(descriptor, block, fDeleteOld: false);
            return block;
        }
        catch
        {
            if (block != IntPtr.Zero) Marshal.FreeCoTaskMem(block);
            if (labelPtr != IntPtr.Zero) Marshal.FreeCoTaskMem(labelPtr);
            throw;
        }
    }
}

/// <summary>
/// CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION. x64 layout (size 32, alignment 8):
/// <code>
///   offset  0  ULONG  ulAuthenticationPackage  4
///   offset  4  GUID   clsidCredentialProvider  16   (GUID alignment is 4: no padding before it)
///   offset 20  ULONG  cbSerialization          4
///   offset 24  byte*  rgbSerialization         8
/// </code>
/// In GetSerialization, rgbSerialization is a CoTaskMemAlloc'ed buffer of cbSerialization bytes (for
/// example a packed KERB_INTERACTIVE_UNLOCK_LOGON) that LogonUI frees after a successful return.
/// ulAuthenticationPackage comes from LsaLookupAuthenticationPackage("Negotiate"), and
/// clsidCredentialProvider is the provider's own CLSID.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION
{
    public uint ulAuthenticationPackage;
    public Guid clsidCredentialProvider;
    public uint cbSerialization;
    public IntPtr rgbSerialization;
}

/// <summary>PROPERTYKEY (wtypes.h): GUID fmtid at offset 0, DWORD pid at offset 16; size 20, alignment 4.</summary>
[StructLayout(LayoutKind.Sequential)]
public struct PROPERTYKEY
{
    public Guid fmtid;
    public uint pid;

    public PROPERTYKEY(Guid fmtid, uint pid)
    {
        this.fmtid = fmtid;
        this.pid = pid;
    }
}

// ---------------------------------------------------------------------------------------------------
// Interfaces implemented by the provider (LogonUI calls these on our CCWs).
// Vtable slots 0-2 are IUnknown; the slot of each method is noted as [n].
// ---------------------------------------------------------------------------------------------------

/// <summary>ICredentialProvider (local). The provider object LogonUI creates from the registered CLSID.</summary>
[ComImport]
[Guid("d27c3481-5a1c-45b2-8aaa-c20ebbe8229e")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
public interface ICredentialProvider
{
    /// <summary>[3] Return E_NOTIMPL for scenarios the provider does not support.</summary>
    [PreserveSig] int SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, uint dwFlags);

    /// <summary>[4] pcpcs is a const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*. E_NOTIMPL is fine.</summary>
    [PreserveSig] int SetSerialization(IntPtr pcpcs);

    /// <summary>
    /// [5] pcpe is an ICredentialProviderEvents* that is only borrowed for this call. Marshal.AddRef it to
    /// keep it, and pass upAdviseContext back to CredentialsChanged. Return E_NOTIMPL if the provider never
    /// asks for re-enumeration.
    /// </summary>
    [PreserveSig] int Advise(IntPtr pcpe, nuint upAdviseContext);

    /// <summary>[6] Release the ICredentialProviderEvents kept from Advise; never call it after this.</summary>
    [PreserveSig] int UnAdvise();

    /// <summary>[7]</summary>
    [PreserveSig] int GetFieldDescriptorCount(out uint pdwCount);

    /// <summary>[8] ppcpfd: CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* from CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR.AllocCoTaskMem.</summary>
    [PreserveSig] int GetFieldDescriptorAt(uint dwIndex, out IntPtr ppcpfd);

    /// <summary>
    /// [9] pdwDefault: index of the default credential or CREDENTIAL_PROVIDER_NO_DEFAULT.
    /// pbAutoLogonWithDefault (BOOL): 1 makes LogonUI call GetSerialization on the default credential at once.
    /// [TECHREF] asks V2 providers not to pick a default tile (return CREDENTIAL_PROVIDER_NO_DEFAULT) unless
    /// they request auto-logon, typically right after CredentialsChanged.
    /// </summary>
    [PreserveSig] int GetCredentialCount(out uint pdwCount, out uint pdwDefault, out int pbAutoLogonWithDefault);

    /// <summary>
    /// [10] ppcpc: an AddRef'ed ICredentialProviderCredential*. Recommended:
    /// Marshal.GetComInterfaceForObject(credential, typeof(ICredentialProviderCredential2)). A CCW's
    /// ICredentialProviderCredential2 pointer is a valid ICredentialProviderCredential pointer (its vtable
    /// starts with the same 17 methods), and QueryInterface for ICredentialProviderCredential2 then returns
    /// the same pointer value, as it does for a C++ object. Pass that same interface (via
    /// Marshal.GetComInterfaceForObject with the same type) as pcpc in the credential events.
    /// </summary>
    [PreserveSig] int GetCredentialAt(uint dwIndex, out IntPtr ppcpc);
}

/// <summary>ICredentialProviderCredential (local). One tile/credential.</summary>
[ComImport]
[Guid("63913a93-40c1-481a-818d-4072ff8c70cc")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
public interface ICredentialProviderCredential
{
    /// <summary>
    /// [3] pcpce is an ICredentialProviderCredentialEvents* that is only borrowed for this call.
    /// Marshal.AddRef it to keep it, and call it only on this thread (see INTERFACE POINTERS AND THREADS).
    /// On Windows 8+ it also implements ICredentialProviderCredentialEvents2; the RawCalls helpers
    /// QueryInterface for the interface they need.
    /// </summary>
    [PreserveSig] int Advise(IntPtr pcpce);

    /// <summary>[4] Release the events pointer kept from Advise (Advise and UnAdvise come in pairs).</summary>
    [PreserveSig] int UnAdvise();

    /// <summary>
    /// [5] pbAutoLogon (BOOL): 1 makes LogonUI call GetSerialization right after selection. LogonUI can
    /// select a tile without any user action. Any return value other than S_OK makes LogonUI behave as if
    /// nothing was selected.
    /// </summary>
    [PreserveSig] int SetSelected(out int pbAutoLogon);

    /// <summary>[6]</summary>
    [PreserveSig] int SetDeselected();

    /// <summary>[7]</summary>
    [PreserveSig] int GetFieldState(uint dwFieldID, out CREDENTIAL_PROVIDER_FIELD_STATE pcpfs, out CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE pcpfis);

    /// <summary>[8] ppsz: CoTaskMemAlloc'ed string, IntPtr.Zero on failure.</summary>
    [PreserveSig] int GetStringValue(uint dwFieldID, out IntPtr ppsz);

    /// <summary>[9] phbmp: HBITMAP, IntPtr.Zero on failure. LogonUI takes ownership and frees it; do not delete it.</summary>
    [PreserveSig] int GetBitmapValue(uint dwFieldID, out IntPtr phbmp);

    /// <summary>[10] pbChecked (BOOL); ppszLabel: CoTaskMemAlloc'ed string.</summary>
    [PreserveSig] int GetCheckboxValue(uint dwFieldID, out int pbChecked, out IntPtr ppszLabel);

    /// <summary>[11] pdwAdjacentTo: ID of the field the submit button sits next to.</summary>
    [PreserveSig] int GetSubmitButtonValue(uint dwFieldID, out uint pdwAdjacentTo);

    /// <summary>[12]</summary>
    [PreserveSig] int GetComboBoxValueCount(uint dwFieldID, out uint pcItems, out uint pdwSelectedItem);

    /// <summary>[13] ppszItem: CoTaskMemAlloc'ed string.</summary>
    [PreserveSig] int GetComboBoxValueAt(uint dwFieldID, uint dwItem, out IntPtr ppszItem);

    /// <summary>
    /// [14] psz: LPCWSTR, may be null. The runtime copies it into an immutable managed string. If an edit
    /// field could ever carry a secret, change this parameter to IntPtr so the text can be zeroed.
    /// </summary>
    [PreserveSig] int SetStringValue(uint dwFieldID, [MarshalAs(UnmanagedType.LPWStr)] string? psz);

    /// <summary>[15] bChecked (BOOL).</summary>
    [PreserveSig] int SetCheckboxValue(uint dwFieldID, int bChecked);

    /// <summary>[16]</summary>
    [PreserveSig] int SetComboBoxSelectedValue(uint dwFieldID, uint dwSelectedItem);

    /// <summary>[17]</summary>
    [PreserveSig] int CommandLinkClicked(uint dwFieldID);

    /// <summary>
    /// [18] pcpcs points at LogonUI's struct; fill it (rgbSerialization from CoTaskMemAlloc).
    /// ppszOptionalStatusText: CoTaskMemAlloc'ed string or IntPtr.Zero.
    /// </summary>
    [PreserveSig] int GetSerialization(out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE pcpgsr, out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION pcpcs, out IntPtr ppszOptionalStatusText, out CREDENTIAL_PROVIDER_STATUS_ICON pcpsiOptionalStatusIcon);

    /// <summary>
    /// [19] Result of the logon attempt (NTSTATUS values, see NtStatus). LogonUI only; Credential UI never
    /// calls it. ppszOptionalStatusText: CoTaskMemAlloc'ed string or IntPtr.Zero.
    /// </summary>
    [PreserveSig] int ReportResult(int ntsStatus, int ntsSubstatus, out IntPtr ppszOptionalStatusText, out CREDENTIAL_PROVIDER_STATUS_ICON pcpsiOptionalStatusIcon);
}

/// <summary>
/// ICredentialProviderCredential2 (local, Windows 8+): ICredentialProviderCredential plus GetUserSid, which
/// ties the credential to a user tile.
/// <para>
/// Built-in COM interop does NOT include inherited interface methods in a derived interface's vtable.
/// The 17 base methods are therefore redeclared here (with <c>new</c>) in exactly the base order, and
/// GetUserSid comes last (slot 20). Implement the methods as public members of the class so that each one
/// serves both interfaces.
/// </para>
/// </summary>
[ComImport]
[Guid("fd672c54-40ea-4d6e-9b49-cfb1a7507bd7")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
public interface ICredentialProviderCredential2 : ICredentialProviderCredential
{
    /// <summary>[3]</summary>
    [PreserveSig] new int Advise(IntPtr pcpce);
    /// <summary>[4]</summary>
    [PreserveSig] new int UnAdvise();
    /// <summary>[5]</summary>
    [PreserveSig] new int SetSelected(out int pbAutoLogon);
    /// <summary>[6]</summary>
    [PreserveSig] new int SetDeselected();
    /// <summary>[7]</summary>
    [PreserveSig] new int GetFieldState(uint dwFieldID, out CREDENTIAL_PROVIDER_FIELD_STATE pcpfs, out CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE pcpfis);
    /// <summary>[8]</summary>
    [PreserveSig] new int GetStringValue(uint dwFieldID, out IntPtr ppsz);
    /// <summary>[9]</summary>
    [PreserveSig] new int GetBitmapValue(uint dwFieldID, out IntPtr phbmp);
    /// <summary>[10]</summary>
    [PreserveSig] new int GetCheckboxValue(uint dwFieldID, out int pbChecked, out IntPtr ppszLabel);
    /// <summary>[11]</summary>
    [PreserveSig] new int GetSubmitButtonValue(uint dwFieldID, out uint pdwAdjacentTo);
    /// <summary>[12]</summary>
    [PreserveSig] new int GetComboBoxValueCount(uint dwFieldID, out uint pcItems, out uint pdwSelectedItem);
    /// <summary>[13]</summary>
    [PreserveSig] new int GetComboBoxValueAt(uint dwFieldID, uint dwItem, out IntPtr ppszItem);
    /// <summary>[14]</summary>
    [PreserveSig] new int SetStringValue(uint dwFieldID, [MarshalAs(UnmanagedType.LPWStr)] string? psz);
    /// <summary>[15]</summary>
    [PreserveSig] new int SetCheckboxValue(uint dwFieldID, int bChecked);
    /// <summary>[16]</summary>
    [PreserveSig] new int SetComboBoxSelectedValue(uint dwFieldID, uint dwSelectedItem);
    /// <summary>[17]</summary>
    [PreserveSig] new int CommandLinkClicked(uint dwFieldID);
    /// <summary>[18]</summary>
    [PreserveSig] new int GetSerialization(out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE pcpgsr, out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION pcpcs, out IntPtr ppszOptionalStatusText, out CREDENTIAL_PROVIDER_STATUS_ICON pcpsiOptionalStatusIcon);
    /// <summary>[19]</summary>
    [PreserveSig] new int ReportResult(int ntsStatus, int ntsSubstatus, out IntPtr ppszOptionalStatusText, out CREDENTIAL_PROVIDER_STATUS_ICON pcpsiOptionalStatusIcon);

    /// <summary>
    /// [20] sid: CoTaskMemAlloc'ed string SID ("S-1-5-21-...") of the user this credential belongs to;
    /// LogonUI frees it. Per [TECHREF], the SID must be one of the users LogonUI enumerates (see
    /// ICredentialProviderSetUserArray), and S_FALSE with IntPtr.Zero puts the credential on the anonymous
    /// "Other user" tile instead.
    /// </summary>
    [PreserveSig] int GetUserSid(out IntPtr sid);
}

/// <summary>ICredentialProviderCredentialWithFieldOptions (local, Windows 8+). Optional, for password reveal and similar.</summary>
[ComImport]
[Guid("dbc6fb30-c843-49e3-a645-573e6f39446a")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
public interface ICredentialProviderCredentialWithFieldOptions
{
    /// <summary>[3]</summary>
    [PreserveSig] int GetFieldOptions(uint fieldID, out CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS options);
}

/// <summary>ICredentialProviderSetUserArray (local, Windows 8+). LogonUI calls it before GetCredentialCount.</summary>
[ComImport]
[Guid("095c1484-1c0c-4388-9c6d-500e61bf84bd")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
public interface ICredentialProviderSetUserArray
{
    /// <summary>
    /// [3] users is an ICredentialProviderUserArray* that is only borrowed for this call. Read it here
    /// (RawCalls.UserArray / RawCalls.User) or Marshal.AddRef it to keep it, as Microsoft's sample does.
    /// </summary>
    [PreserveSig] int SetUserArray(IntPtr users);
}

// ---------------------------------------------------------------------------------------------------
// Interfaces implemented by LogonUI (we call these). The declarations are exact, so they also work as RCWs
// created and used on the thread that received the pointer. RawCalls avoids the RCW lifetime problems
// (see INTERFACE POINTERS AND THREADS).
// ---------------------------------------------------------------------------------------------------

/// <summary>ICredentialProviderEvents (remotable). Given to ICredentialProvider.Advise.</summary>
[ComImport]
[Guid("34201e5a-a787-41a3-a5a4-bd6dcf2a854e")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
public interface ICredentialProviderEvents
{
    /// <summary>
    /// [3] Asynchronous. LogonUI re-enumerates this provider's credentials (GetCredentialCount ...).
    /// Pass the upAdviseContext received in Advise. Use it only for auto-logon or a changed credential count.
    /// </summary>
    [PreserveSig] int CredentialsChanged(nuint upAdviseContext);
}

/// <summary>
/// ICredentialProviderCredentialEvents (remotable). Given to ICredentialProviderCredential.Advise. Call it
/// only on the thread that received Advise ([TECHREF]).
/// pcpc must be the credential that received Advise ("this"): pass the same interface pointer that
/// GetCredentialAt returned (see ICredentialProvider.GetCredentialAt). Microsoft's V2 sample passes
/// nullptr only inside a BeginFieldUpdates/EndFieldUpdates batch.
/// </summary>
[ComImport]
[Guid("fa6fa76b-66b7-4b11-95f1-86171118e816")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
public interface ICredentialProviderCredentialEvents
{
    /// <summary>[3]</summary>
    [PreserveSig] int SetFieldState(IntPtr pcpc, uint dwFieldID, CREDENTIAL_PROVIDER_FIELD_STATE cpfs);
    /// <summary>[4]</summary>
    [PreserveSig] int SetFieldInteractiveState(IntPtr pcpc, uint dwFieldID, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis);
    /// <summary>[5] psz may be null ([unique]).</summary>
    [PreserveSig] int SetFieldString(IntPtr pcpc, uint dwFieldID, [MarshalAs(UnmanagedType.LPWStr)] string? psz);
    /// <summary>[6] bChecked (BOOL).</summary>
    [PreserveSig] int SetFieldCheckbox(IntPtr pcpc, uint dwFieldID, int bChecked, [MarshalAs(UnmanagedType.LPWStr)] string? pszLabel);
    /// <summary>[7] hbmp: HBITMAP.</summary>
    [PreserveSig] int SetFieldBitmap(IntPtr pcpc, uint dwFieldID, IntPtr hbmp);
    /// <summary>[8]</summary>
    [PreserveSig] int SetFieldComboBoxSelectedItem(IntPtr pcpc, uint dwFieldID, uint dwSelectedItem);
    /// <summary>[9]</summary>
    [PreserveSig] int DeleteFieldComboBoxItem(IntPtr pcpc, uint dwFieldID, uint dwItem);
    /// <summary>[10]</summary>
    [PreserveSig] int AppendFieldComboBoxItem(IntPtr pcpc, uint dwFieldID, [MarshalAs(UnmanagedType.LPWStr)] string pszItem);
    /// <summary>[11]</summary>
    [PreserveSig] int SetFieldSubmitButton(IntPtr pcpc, uint dwFieldID, uint dwAdjacentTo);
    /// <summary>[12] phwndOwner: the HWND any dialog must be parented to ([TECHREF]: mandatory).</summary>
    [PreserveSig] int OnCreatingWindow(out IntPtr phwndOwner);
}

/// <summary>
/// ICredentialProviderCredentialEvents2 (remotable, Windows 8+). QueryInterface the Advise pointer for it.
/// Base methods are redeclared first (see ICredentialProviderCredential2 for why).
/// </summary>
[ComImport]
[Guid("b53c00b6-9922-4b78-b1f4-ddfe774dc39b")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
public interface ICredentialProviderCredentialEvents2 : ICredentialProviderCredentialEvents
{
    /// <summary>[3]</summary>
    [PreserveSig] new int SetFieldState(IntPtr pcpc, uint dwFieldID, CREDENTIAL_PROVIDER_FIELD_STATE cpfs);
    /// <summary>[4]</summary>
    [PreserveSig] new int SetFieldInteractiveState(IntPtr pcpc, uint dwFieldID, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis);
    /// <summary>[5]</summary>
    [PreserveSig] new int SetFieldString(IntPtr pcpc, uint dwFieldID, [MarshalAs(UnmanagedType.LPWStr)] string? psz);
    /// <summary>[6]</summary>
    [PreserveSig] new int SetFieldCheckbox(IntPtr pcpc, uint dwFieldID, int bChecked, [MarshalAs(UnmanagedType.LPWStr)] string? pszLabel);
    /// <summary>[7]</summary>
    [PreserveSig] new int SetFieldBitmap(IntPtr pcpc, uint dwFieldID, IntPtr hbmp);
    /// <summary>[8]</summary>
    [PreserveSig] new int SetFieldComboBoxSelectedItem(IntPtr pcpc, uint dwFieldID, uint dwSelectedItem);
    /// <summary>[9]</summary>
    [PreserveSig] new int DeleteFieldComboBoxItem(IntPtr pcpc, uint dwFieldID, uint dwItem);
    /// <summary>[10]</summary>
    [PreserveSig] new int AppendFieldComboBoxItem(IntPtr pcpc, uint dwFieldID, [MarshalAs(UnmanagedType.LPWStr)] string pszItem);
    /// <summary>[11]</summary>
    [PreserveSig] new int SetFieldSubmitButton(IntPtr pcpc, uint dwFieldID, uint dwAdjacentTo);
    /// <summary>[12]</summary>
    [PreserveSig] new int OnCreatingWindow(out IntPtr phwndOwner);

    /// <summary>[13] Start a batch of field updates (pair with EndFieldUpdates).</summary>
    [PreserveSig] int BeginFieldUpdates();
    /// <summary>[14] Commit the batch.</summary>
    [PreserveSig] int EndFieldUpdates();
    /// <summary>[15]</summary>
    [PreserveSig] int SetFieldOptions(IntPtr credential, uint fieldID, CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS options);
}

/// <summary>ICredentialProviderUserArray (local, Windows 8+). Given to ICredentialProviderSetUserArray.SetUserArray.</summary>
[ComImport]
[Guid("90c119ae-0f18-4520-a1f1-114366a40fe8")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
public interface ICredentialProviderUserArray
{
    /// <summary>[3] Limit the array to users of one provider, e.g. Identity_LocalUserProvider.</summary>
    [PreserveSig] int SetProviderFilter(ref Guid guidProviderToFilterTo);
    /// <summary>[4]</summary>
    [PreserveSig] int GetAccountOptions(out CREDENTIAL_PROVIDER_ACCOUNT_OPTIONS credentialProviderAccountOptions);
    /// <summary>[5]</summary>
    [PreserveSig] int GetCount(out uint userCount);
    /// <summary>[6] user: AddRef'ed ICredentialProviderUser*; the caller must Marshal.Release it.</summary>
    [PreserveSig] int GetAt(uint userIndex, out IntPtr user);
}

/// <summary>ICredentialProviderUser (local, Windows 8+). One user shown by LogonUI.</summary>
[ComImport]
[Guid("13793285-3ea6-40fd-b420-15f47da41fbb")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
public interface ICredentialProviderUser
{
    /// <summary>[3] sid: CoTaskMemAlloc'ed string; free with Marshal.FreeCoTaskMem.</summary>
    [PreserveSig] int GetSid(out IntPtr sid);
    /// <summary>[4] providerID: e.g. Identity_LocalUserProvider for a local account.</summary>
    [PreserveSig] int GetProviderID(out Guid providerID);
    /// <summary>[5] key: one of PropertyKeys.*. stringValue: CoTaskMemAlloc'ed; free with Marshal.FreeCoTaskMem.</summary>
    [PreserveSig] int GetStringValue(ref PROPERTYKEY key, out IntPtr stringValue);
    /// <summary>[6] key: REFPROPERTYKEY (PROPERTYKEY*); value: PROPVARIANT* (24 bytes on x64; clear it with PropVariantClear).</summary>
    [PreserveSig] int GetValue(IntPtr key, IntPtr value);
}

// ---------------------------------------------------------------------------------------------------
// Constants and GUIDs
// ---------------------------------------------------------------------------------------------------

/// <summary>IIDs of the interfaces above, taken from their [Guid] attributes (for Marshal.QueryInterface).</summary>
public static class CredentialProviderIids
{
    public static readonly Guid ICredentialProvider = typeof(ICredentialProvider).GUID;
    public static readonly Guid ICredentialProviderCredential = typeof(ICredentialProviderCredential).GUID;
    public static readonly Guid ICredentialProviderCredential2 = typeof(ICredentialProviderCredential2).GUID;
    public static readonly Guid ICredentialProviderCredentialWithFieldOptions = typeof(ICredentialProviderCredentialWithFieldOptions).GUID;
    public static readonly Guid ICredentialProviderSetUserArray = typeof(ICredentialProviderSetUserArray).GUID;
    public static readonly Guid ICredentialProviderEvents = typeof(ICredentialProviderEvents).GUID;
    public static readonly Guid ICredentialProviderCredentialEvents = typeof(ICredentialProviderCredentialEvents).GUID;
    public static readonly Guid ICredentialProviderCredentialEvents2 = typeof(ICredentialProviderCredentialEvents2).GUID;
    public static readonly Guid ICredentialProviderUserArray = typeof(ICredentialProviderUserArray).GUID;
    public static readonly Guid ICredentialProviderUser = typeof(ICredentialProviderUser).GUID;
}

/// <summary>Constants from credentialprovider.h and the CPFG_* field GUIDs from shlguid.h.</summary>
public static class CredentialProviderConstants
{
    /// <summary>#define CREDENTIAL_PROVIDER_NO_DEFAULT ((DWORD)-1), for GetCredentialCount's pdwDefault.</summary>
    public const uint CREDENTIAL_PROVIDER_NO_DEFAULT = 0xFFFFFFFF;

    /// <summary>Identity_LocalUserProvider {A198529B-730F-4089-B646-A12557F5665E}: provider ID of local accounts.</summary>
    public static readonly Guid Identity_LocalUserProvider = new(0xA198529B, 0x730F, 0x4089, 0xB6, 0x46, 0xA1, 0x25, 0x57, 0xF5, 0x66, 0x5E);

    // guidFieldType values (shlguid.h). The SDK comment and Microsoft Learn spell the first one
    // "954sd" (a typo); the DEFINE_GUID value is 0x954d.

    /// <summary>{da15bbe8-954d-4fd3-b0f4-1fb5b90b174b}: user name entered into a text box.</summary>
    public static readonly Guid CPFG_LOGON_USERNAME = new(0xda15bbe8, 0x954d, 0x4fd3, 0xb0, 0xf4, 0x1f, 0xb5, 0xb9, 0x0b, 0x17, 0x4b);
    /// <summary>{60624cfa-a477-47b1-8a8e-3a4a19981827}: password entered into a text box.</summary>
    public static readonly Guid CPFG_LOGON_PASSWORD = new(0x60624cfa, 0xa477, 0x47b1, 0x8a, 0x8e, 0x3a, 0x4a, 0x19, 0x98, 0x18, 0x27);
    /// <summary>{3e1ecf69-568c-4d96-9d59-46444174e2d6}: user name from a smart card.</summary>
    public static readonly Guid CPFG_SMARTCARD_USERNAME = new(0x3e1ecf69, 0x568c, 0x4d96, 0x9d, 0x59, 0x46, 0x44, 0x41, 0x74, 0xe2, 0xd6);
    /// <summary>{4fe5263b-9181-46c1-b0a4-9dedd4db7dea}: smart card PIN.</summary>
    public static readonly Guid CPFG_SMARTCARD_PIN = new(0x4fe5263b, 0x9181, 0x46c1, 0xb0, 0xa4, 0x9d, 0xed, 0xd4, 0xdb, 0x7d, 0xea);
    /// <summary>
    /// {2d837775-f6cd-464e-a745-482fd0b47493} (Windows 8+): put on a CPFT_TILE_IMAGE field to make it the
    /// provider's icon under "Sign-in options" ([TECHREF] recommends 72x72 px).
    /// </summary>
    public static readonly Guid CPFG_CREDENTIAL_PROVIDER_LOGO = new(0x2d837775, 0xf6cd, 0x464e, 0xa7, 0x45, 0x48, 0x2f, 0xd0, 0xb4, 0x74, 0x93);
    /// <summary>
    /// {286bbff3-bad4-438f-b007-79b7267c3d48} (Windows 8+): put on a CPFT_SMALL_TEXT field to make it the
    /// provider's name, shown when hovering its icon under "Sign-in options".
    /// </summary>
    public static readonly Guid CPFG_CREDENTIAL_PROVIDER_LABEL = new(0x286bbff3, 0xbad4, 0x438f, 0xb0, 0x07, 0x79, 0xb7, 0x26, 0x7c, 0x3d, 0x48);
    /// <summary>{0b7b0ad8-cc36-4d59-802b-82f714fa7022}</summary>
    public static readonly Guid CPFG_STANDALONE_SUBMIT_BUTTON = new(0x0b7b0ad8, 0xcc36, 0x4d59, 0x80, 0x2b, 0x82, 0xf7, 0x14, 0xfa, 0x70, 0x22);
    /// <summary>{088fa508-94a6-4430-a4cb-6fc6e3c0b9e2} (not in SDK 10.0.16299): show a command link as a button.</summary>
    public static readonly Guid CPFG_STYLE_LINK_AS_BUTTON = new(0x088fa508, 0x94a6, 0x4430, 0xa4, 0xcb, 0x6f, 0xc6, 0xe3, 0xc0, 0xb9, 0xe2);
}

/// <summary>
/// The PROPERTYKEYs (propkey.h) that ICredentialProviderUser.GetStringValue documents. Copy one into a
/// local variable to pass it by ref. Sample results from the docs for a local user: UserName "lisa",
/// QualifiedUserName "lisa-pc\lisa", ProviderID "{A198529B-730F-4089-B646-A12557F5665E}". The docs show
/// PrimarySid as "{S-1-5-21-...}", so trim braces before comparing SIDs.
/// </summary>
public static class PropertyKeys
{
    /// <summary>System.Identity.DisplayName {7D683FC9-D155-45A8-BB1F-89D19BCB792F}, 100: friendly name.</summary>
    public static readonly PROPERTYKEY PKEY_Identity_DisplayName = new(new Guid(0x7D683FC9, 0xD155, 0x45A8, 0xBB, 0x1F, 0x89, 0xD1, 0x9B, 0xCB, 0x79, 0x2F), 100);
    /// <summary>System.Identity.LogonStatusString {F18DEDF3-337F-42C0-9E03-CEE08708A8C3}, 100: e.g. "Locked" (Logon UI only).</summary>
    public static readonly PROPERTYKEY PKEY_Identity_LogonStatusString = new(new Guid(0xF18DEDF3, 0x337F, 0x42C0, 0x9E, 0x03, 0xCE, 0xE0, 0x87, 0x08, 0xA8, 0xC3), 100);
    /// <summary>System.Identity.PrimarySid {2B1B801E-C0C1-4987-9EC5-72FA89814787}, 100: the user's SID.</summary>
    public static readonly PROPERTYKEY PKEY_Identity_PrimarySid = new(new Guid(0x2B1B801E, 0xC0C1, 0x4987, 0x9E, 0xC5, 0x72, 0xFA, 0x89, 0x81, 0x47, 0x87), 100);
    /// <summary>System.Identity.ProviderID {74A7DE49-FA11-4D3D-A006-DB7E08675916}, 100: provider GUID as a string.</summary>
    public static readonly PROPERTYKEY PKEY_Identity_ProviderID = new(new Guid(0x74A7DE49, 0xFA11, 0x4D3D, 0xA0, 0x06, 0xDB, 0x7E, 0x08, 0x67, 0x59, 0x16), 100);
    /// <summary>System.Identity.QualifiedUserName {DA520E51-F4E9-4739-AC82-02E0A95C9030}, 100: "DOMAIN\user", used to pack the logon.</summary>
    public static readonly PROPERTYKEY PKEY_Identity_QualifiedUserName = new(new Guid(0xDA520E51, 0xF4E9, 0x4739, 0xAC, 0x82, 0x02, 0xE0, 0xA9, 0x5C, 0x90, 0x30), 100);
    /// <summary>System.Identity.UserName {C4322503-78CA-49C6-9ACC-A68E2AFD7B6B}, 100: user name.</summary>
    public static readonly PROPERTYKEY PKEY_Identity_UserName = new(new Guid(0xC4322503, 0x78CA, 0x49C6, 0x9A, 0xCC, 0xA6, 0x8E, 0x2A, 0xFD, 0x7B, 0x6B), 100);
}

/// <summary>CLSIDs of the in-box providers (credentialprovider.h coclasses). Informational, e.g. for logging.</summary>
public static class CredentialProviderClsids
{
    public static readonly Guid CLSID_PasswordCredentialProvider = new("60b78e88-ead8-445c-9cfd-0b87f74ea6cd");
    public static readonly Guid CLSID_V1PasswordCredentialProvider = new("6f45dc1e-5384-457a-bc13-2cd81b0d28ed");
    public static readonly Guid CLSID_PINLogonCredentialProvider = new("cb82ea12-9f71-446d-89e1-8d0924e1256e");
    public static readonly Guid CLSID_NPCredentialProvider = new("3dd6bec0-8193-4ffe-ae25-e08e39ea4063");
    public static readonly Guid CLSID_SmartcardCredentialProvider = new("8fd7e19c-3bf7-489b-a72c-846ab3678c96");
    public static readonly Guid CLSID_V1SmartcardCredentialProvider = new("8bf9a910-a8ff-457f-999f-a5ca10b4a885");
    public static readonly Guid CLSID_SmartcardPinProvider = new("94596c7e-3744-41ce-893e-bbf09122f76a");
    public static readonly Guid CLSID_SmartcardReaderSelectionProvider = new("1b283861-754f-4022-ad47-a5eaaa618894");
    public static readonly Guid CLSID_SmartcardWinRTProvider = new("1ee7337f-85ac-45e2-a23c-37c753209769");
    public static readonly Guid CLSID_GenericCredentialProvider = new("25cbb996-92ed-457e-b28c-4774084bd562");
    public static readonly Guid CLSID_RASProvider = new("5537e283-b1e7-4ef8-9c6e-7ab0afe5056d");
    public static readonly Guid CLSID_OnexCredentialProvider = new("07aa0886-cc8d-4e19-a410-1c75af686e62");
    public static readonly Guid CLSID_OnexPlapSmartcardCredentialProvider = new("33c86cd6-705f-4ba1-9adb-67070b837775");
    public static readonly Guid CLSID_VaultProvider = new("503739d0-4c5e-4cfd-b3ba-d881334f0df2");
    public static readonly Guid CLSID_WinBioCredentialProvider = new("bec09223-b018-416d-a0ac-523971b639f5");
    public static readonly Guid CLSID_V1WinBioCredentialProvider = new("ac3ac249-e820-4343-a65b-377ac634dc09");
}

/// <summary>HRESULT values used by these interfaces (winerror.h, Win32 definitions).</summary>
public static class HResults
{
    public const int S_OK = 0;
    public const int S_FALSE = 1;
    public const int E_NOTIMPL = unchecked((int)0x80004001);
    public const int E_NOINTERFACE = unchecked((int)0x80004002);
    public const int E_POINTER = unchecked((int)0x80004003);
    public const int E_ABORT = unchecked((int)0x80004004);
    public const int E_FAIL = unchecked((int)0x80004005);
    public const int E_UNEXPECTED = unchecked((int)0x8000FFFF);
    public const int E_ACCESSDENIED = unchecked((int)0x80070005);
    public const int E_OUTOFMEMORY = unchecked((int)0x8007000E);
    public const int E_INVALIDARG = unchecked((int)0x80070057);
    public const int CLASS_E_NOAGGREGATION = unchecked((int)0x80040110);
    public const int CLASS_E_CLASSNOTAVAILABLE = unchecked((int)0x80040111);
}

/// <summary>NTSTATUS values commonly passed to ICredentialProviderCredential.ReportResult (ntstatus.h).</summary>
public static class NtStatus
{
    public const int STATUS_SUCCESS = 0;
    public const int STATUS_NO_SUCH_USER = unchecked((int)0xC0000064);
    /// <summary>Usually the substatus of STATUS_LOGON_FAILURE when the password is wrong (e.g. changed since enrollment).</summary>
    public const int STATUS_WRONG_PASSWORD = unchecked((int)0xC000006A);
    public const int STATUS_LOGON_FAILURE = unchecked((int)0xC000006D);
    public const int STATUS_ACCOUNT_RESTRICTION = unchecked((int)0xC000006E);
    public const int STATUS_INVALID_LOGON_HOURS = unchecked((int)0xC000006F);
    public const int STATUS_INVALID_WORKSTATION = unchecked((int)0xC0000070);
    public const int STATUS_PASSWORD_EXPIRED = unchecked((int)0xC0000071);
    public const int STATUS_ACCOUNT_DISABLED = unchecked((int)0xC0000072);
    public const int STATUS_LOGON_TYPE_NOT_GRANTED = unchecked((int)0xC000015B);
    public const int STATUS_ACCOUNT_EXPIRED = unchecked((int)0xC0000193);
    public const int STATUS_PASSWORD_MUST_CHANGE = unchecked((int)0xC0000224);
    public const int STATUS_ACCOUNT_LOCKED_OUT = unchecked((int)0xC0000234);
}

// ---------------------------------------------------------------------------------------------------
// Raw vtable calls on the IntPtr interface pointers LogonUI hands us
// ---------------------------------------------------------------------------------------------------

/// <summary>
/// Direct vtable calls on interface pointers implemented by LogonUI, made on the current thread as C++ code
/// would. No RCW is created, the runtime does no apartment marshaling, and no thread switch happens.
/// Call the CredentialEvents helpers only on the thread that received Advise (see INTERFACE POINTERS AND
/// THREADS in the file header).
/// <para>
/// Each helper first calls QueryInterface for the interface it needs. A pointer of the wrong kind
/// therefore returns E_NOINTERFACE instead of jumping through the wrong vtable, and the
/// ICredentialProviderCredentialEvents2 helpers work on the plain pointer from Advise. A null pointer
/// returns E_POINTER. Every helper returns the callee's HRESULT. A dangling (already released) pointer
/// cannot be detected; keep it AddRef'ed until UnAdvise.
/// </para>
/// </summary>
public static class RawCalls
{
    /// <summary>Vtable slot numbers (0-2 are IUnknown QueryInterface / AddRef / Release).</summary>
    public static class Slots
    {
        public const int ICredentialProviderEvents_CredentialsChanged = 3;

        public const int ICredentialProviderCredentialEvents_SetFieldState = 3;
        public const int ICredentialProviderCredentialEvents_SetFieldInteractiveState = 4;
        public const int ICredentialProviderCredentialEvents_SetFieldString = 5;
        public const int ICredentialProviderCredentialEvents_SetFieldCheckbox = 6;
        public const int ICredentialProviderCredentialEvents_SetFieldBitmap = 7;
        public const int ICredentialProviderCredentialEvents_SetFieldComboBoxSelectedItem = 8;
        public const int ICredentialProviderCredentialEvents_DeleteFieldComboBoxItem = 9;
        public const int ICredentialProviderCredentialEvents_AppendFieldComboBoxItem = 10;
        public const int ICredentialProviderCredentialEvents_SetFieldSubmitButton = 11;
        public const int ICredentialProviderCredentialEvents_OnCreatingWindow = 12;
        public const int ICredentialProviderCredentialEvents2_BeginFieldUpdates = 13;
        public const int ICredentialProviderCredentialEvents2_EndFieldUpdates = 14;
        public const int ICredentialProviderCredentialEvents2_SetFieldOptions = 15;

        public const int ICredentialProviderUserArray_SetProviderFilter = 3;
        public const int ICredentialProviderUserArray_GetAccountOptions = 4;
        public const int ICredentialProviderUserArray_GetCount = 5;
        public const int ICredentialProviderUserArray_GetAt = 6;

        public const int ICredentialProviderUser_GetSid = 3;
        public const int ICredentialProviderUser_GetProviderID = 4;
        public const int ICredentialProviderUser_GetStringValue = 5;
        public const int ICredentialProviderUser_GetValue = 6;
    }

    // Native signatures. "self" is the interface pointer; x64 has a single calling convention.
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int NoArgsFn(IntPtr self);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int UIntPtrFn(IntPtr self, nuint value);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int FieldInt32Fn(IntPtr self, IntPtr pcpc, uint fieldId, int value);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int FieldUInt32Fn(IntPtr self, IntPtr pcpc, uint fieldId, uint value);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int FieldPointerFn(IntPtr self, IntPtr pcpc, uint fieldId, IntPtr value);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int FieldStringFn(IntPtr self, IntPtr pcpc, uint fieldId, [MarshalAs(UnmanagedType.LPWStr)] string? value);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int FieldCheckboxFn(IntPtr self, IntPtr pcpc, uint fieldId, int bChecked, [MarshalAs(UnmanagedType.LPWStr)] string? label);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int OutPointerFn(IntPtr self, out IntPtr value);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int OutUInt32Fn(IntPtr self, out uint value);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int OutGuidFn(IntPtr self, out Guid value);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int RefGuidFn(IntPtr self, ref Guid value);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int UInt32OutPointerFn(IntPtr self, uint index, out IntPtr value);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int RefKeyOutPointerFn(IntPtr self, ref PROPERTYKEY key, out IntPtr value);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int TwoPointersFn(IntPtr self, IntPtr a, IntPtr b);

    /// <summary>
    /// QueryInterface for <paramref name="iid"/> and read vtable slot <paramref name="slot"/>. On success
    /// the caller owns <paramref name="typed"/> (one reference) and must Marshal.Release it.
    /// </summary>
    private static int Resolve(IntPtr self, Guid iid, int slot, out IntPtr typed, out IntPtr function)
    {
        typed = IntPtr.Zero;
        function = IntPtr.Zero;
        if (self == IntPtr.Zero)
            return HResults.E_POINTER;
        int hr = Marshal.QueryInterface(self, in iid, out IntPtr result);
        if (hr < 0)
            return hr;
        if (result == IntPtr.Zero)
            return HResults.E_NOINTERFACE;
        typed = result;
        IntPtr vtable = Marshal.ReadIntPtr(typed);
        function = Marshal.ReadIntPtr(vtable, slot * IntPtr.Size);
        return HResults.S_OK;
    }

    private static T Fn<T>(IntPtr function) where T : Delegate => Marshal.GetDelegateForFunctionPointer<T>(function);

    /// <summary>ICredentialProviderEvents (the pointer from ICredentialProvider.Advise).</summary>
    public static class ProviderEvents
    {
        public static int CredentialsChanged(IntPtr events, nuint upAdviseContext)
        {
            int hr = Resolve(events, CredentialProviderIids.ICredentialProviderEvents, Slots.ICredentialProviderEvents_CredentialsChanged, out IntPtr p, out IntPtr f);
            if (hr < 0) return hr;
            try { return Fn<UIntPtrFn>(f)(p, upAdviseContext); }
            finally { Marshal.Release(p); }
        }
    }

    /// <summary>
    /// ICredentialProviderCredentialEvents / ICredentialProviderCredentialEvents2 (the pointer from
    /// ICredentialProviderCredential.Advise). For pcpc pass this credential's own interface pointer, the
    /// same interface GetCredentialAt returned (Marshal.GetComInterfaceForObject, then Marshal.Release).
    /// </summary>
    public static class CredentialEvents
    {
        private static readonly Guid Events = CredentialProviderIids.ICredentialProviderCredentialEvents;
        private static readonly Guid Events2 = CredentialProviderIids.ICredentialProviderCredentialEvents2;

        public static int SetFieldState(IntPtr events, IntPtr pcpc, uint fieldId, CREDENTIAL_PROVIDER_FIELD_STATE state)
        {
            int hr = Resolve(events, Events, Slots.ICredentialProviderCredentialEvents_SetFieldState, out IntPtr p, out IntPtr f);
            if (hr < 0) return hr;
            try { return Fn<FieldInt32Fn>(f)(p, pcpc, fieldId, (int)state); }
            finally { Marshal.Release(p); }
        }

        public static int SetFieldInteractiveState(IntPtr events, IntPtr pcpc, uint fieldId, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE state)
        {
            int hr = Resolve(events, Events, Slots.ICredentialProviderCredentialEvents_SetFieldInteractiveState, out IntPtr p, out IntPtr f);
            if (hr < 0) return hr;
            try { return Fn<FieldInt32Fn>(f)(p, pcpc, fieldId, (int)state); }
            finally { Marshal.Release(p); }
        }

        /// <summary>value may be null. LogonUI copies the string during the call.</summary>
        public static int SetFieldString(IntPtr events, IntPtr pcpc, uint fieldId, string? value)
        {
            int hr = Resolve(events, Events, Slots.ICredentialProviderCredentialEvents_SetFieldString, out IntPtr p, out IntPtr f);
            if (hr < 0) return hr;
            try { return Fn<FieldStringFn>(f)(p, pcpc, fieldId, value); }
            finally { Marshal.Release(p); }
        }

        public static int SetFieldCheckbox(IntPtr events, IntPtr pcpc, uint fieldId, bool isChecked, string? label)
        {
            int hr = Resolve(events, Events, Slots.ICredentialProviderCredentialEvents_SetFieldCheckbox, out IntPtr p, out IntPtr f);
            if (hr < 0) return hr;
            try { return Fn<FieldCheckboxFn>(f)(p, pcpc, fieldId, isChecked ? 1 : 0, label); }
            finally { Marshal.Release(p); }
        }

        public static int SetFieldBitmap(IntPtr events, IntPtr pcpc, uint fieldId, IntPtr hbmp)
        {
            int hr = Resolve(events, Events, Slots.ICredentialProviderCredentialEvents_SetFieldBitmap, out IntPtr p, out IntPtr f);
            if (hr < 0) return hr;
            try { return Fn<FieldPointerFn>(f)(p, pcpc, fieldId, hbmp); }
            finally { Marshal.Release(p); }
        }

        public static int SetFieldComboBoxSelectedItem(IntPtr events, IntPtr pcpc, uint fieldId, uint selectedItem)
        {
            int hr = Resolve(events, Events, Slots.ICredentialProviderCredentialEvents_SetFieldComboBoxSelectedItem, out IntPtr p, out IntPtr f);
            if (hr < 0) return hr;
            try { return Fn<FieldUInt32Fn>(f)(p, pcpc, fieldId, selectedItem); }
            finally { Marshal.Release(p); }
        }

        public static int DeleteFieldComboBoxItem(IntPtr events, IntPtr pcpc, uint fieldId, uint item)
        {
            int hr = Resolve(events, Events, Slots.ICredentialProviderCredentialEvents_DeleteFieldComboBoxItem, out IntPtr p, out IntPtr f);
            if (hr < 0) return hr;
            try { return Fn<FieldUInt32Fn>(f)(p, pcpc, fieldId, item); }
            finally { Marshal.Release(p); }
        }

        public static int AppendFieldComboBoxItem(IntPtr events, IntPtr pcpc, uint fieldId, string item)
        {
            int hr = Resolve(events, Events, Slots.ICredentialProviderCredentialEvents_AppendFieldComboBoxItem, out IntPtr p, out IntPtr f);
            if (hr < 0) return hr;
            try { return Fn<FieldStringFn>(f)(p, pcpc, fieldId, item); }
            finally { Marshal.Release(p); }
        }

        public static int SetFieldSubmitButton(IntPtr events, IntPtr pcpc, uint fieldId, uint adjacentTo)
        {
            int hr = Resolve(events, Events, Slots.ICredentialProviderCredentialEvents_SetFieldSubmitButton, out IntPtr p, out IntPtr f);
            if (hr < 0) return hr;
            try { return Fn<FieldUInt32Fn>(f)(p, pcpc, fieldId, adjacentTo); }
            finally { Marshal.Release(p); }
        }

        public static int OnCreatingWindow(IntPtr events, out IntPtr hwndOwner)
        {
            hwndOwner = IntPtr.Zero;
            int hr = Resolve(events, Events, Slots.ICredentialProviderCredentialEvents_OnCreatingWindow, out IntPtr p, out IntPtr f);
            if (hr < 0) return hr;
            try { return Fn<OutPointerFn>(f)(p, out hwndOwner); }
            finally { Marshal.Release(p); }
        }

        /// <summary>ICredentialProviderCredentialEvents2 (Windows 8+); E_NOINTERFACE if unavailable.</summary>
        public static int BeginFieldUpdates(IntPtr events)
        {
            int hr = Resolve(events, Events2, Slots.ICredentialProviderCredentialEvents2_BeginFieldUpdates, out IntPtr p, out IntPtr f);
            if (hr < 0) return hr;
            try { return Fn<NoArgsFn>(f)(p); }
            finally { Marshal.Release(p); }
        }

        /// <summary>ICredentialProviderCredentialEvents2 (Windows 8+); E_NOINTERFACE if unavailable.</summary>
        public static int EndFieldUpdates(IntPtr events)
        {
            int hr = Resolve(events, Events2, Slots.ICredentialProviderCredentialEvents2_EndFieldUpdates, out IntPtr p, out IntPtr f);
            if (hr < 0) return hr;
            try { return Fn<NoArgsFn>(f)(p); }
            finally { Marshal.Release(p); }
        }

        /// <summary>ICredentialProviderCredentialEvents2 (Windows 8+); E_NOINTERFACE if unavailable.</summary>
        public static int SetFieldOptions(IntPtr events, IntPtr credential, uint fieldId, CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS options)
        {
            int hr = Resolve(events, Events2, Slots.ICredentialProviderCredentialEvents2_SetFieldOptions, out IntPtr p, out IntPtr f);
            if (hr < 0) return hr;
            try { return Fn<FieldUInt32Fn>(f)(p, credential, fieldId, (uint)options); }
            finally { Marshal.Release(p); }
        }
    }

    /// <summary>ICredentialProviderUserArray (the pointer from ICredentialProviderSetUserArray.SetUserArray).</summary>
    public static class UserArray
    {
        private static readonly Guid Iid = CredentialProviderIids.ICredentialProviderUserArray;

        public static int SetProviderFilter(IntPtr userArray, Guid providerId)
        {
            int hr = Resolve(userArray, Iid, Slots.ICredentialProviderUserArray_SetProviderFilter, out IntPtr p, out IntPtr f);
            if (hr < 0) return hr;
            try { return Fn<RefGuidFn>(f)(p, ref providerId); }
            finally { Marshal.Release(p); }
        }

        public static int GetAccountOptions(IntPtr userArray, out CREDENTIAL_PROVIDER_ACCOUNT_OPTIONS options)
        {
            options = CREDENTIAL_PROVIDER_ACCOUNT_OPTIONS.CPAO_NONE;
            int hr = Resolve(userArray, Iid, Slots.ICredentialProviderUserArray_GetAccountOptions, out IntPtr p, out IntPtr f);
            if (hr < 0) return hr;
            try
            {
                hr = Fn<OutUInt32Fn>(f)(p, out uint raw);
                options = (CREDENTIAL_PROVIDER_ACCOUNT_OPTIONS)raw;
                return hr;
            }
            finally { Marshal.Release(p); }
        }

        public static int GetCount(IntPtr userArray, out uint count)
        {
            count = 0;
            int hr = Resolve(userArray, Iid, Slots.ICredentialProviderUserArray_GetCount, out IntPtr p, out IntPtr f);
            if (hr < 0) return hr;
            try { return Fn<OutUInt32Fn>(f)(p, out count); }
            finally { Marshal.Release(p); }
        }

        /// <summary>user: AddRef'ed ICredentialProviderUser*; Marshal.Release it when done.</summary>
        public static int GetAt(IntPtr userArray, uint index, out IntPtr user)
        {
            user = IntPtr.Zero;
            int hr = Resolve(userArray, Iid, Slots.ICredentialProviderUserArray_GetAt, out IntPtr p, out IntPtr f);
            if (hr < 0) return hr;
            try { return Fn<UInt32OutPointerFn>(f)(p, index, out user); }
            finally { Marshal.Release(p); }
        }
    }

    /// <summary>ICredentialProviderUser (from UserArray.GetAt). String results are read and freed here.</summary>
    public static class User
    {
        private static readonly Guid Iid = CredentialProviderIids.ICredentialProviderUser;

        public static int GetSid(IntPtr user, out string? sid)
        {
            sid = null;
            int hr = Resolve(user, Iid, Slots.ICredentialProviderUser_GetSid, out IntPtr p, out IntPtr f);
            if (hr < 0) return hr;
            try
            {
                hr = Fn<OutPointerFn>(f)(p, out IntPtr text);
                sid = TakeCoTaskMemString(text);
                return hr;
            }
            finally { Marshal.Release(p); }
        }

        public static int GetProviderID(IntPtr user, out Guid providerId)
        {
            providerId = Guid.Empty;
            int hr = Resolve(user, Iid, Slots.ICredentialProviderUser_GetProviderID, out IntPtr p, out IntPtr f);
            if (hr < 0) return hr;
            try { return Fn<OutGuidFn>(f)(p, out providerId); }
            finally { Marshal.Release(p); }
        }

        /// <summary>key: one of PropertyKeys.*.</summary>
        public static int GetStringValue(IntPtr user, PROPERTYKEY key, out string? value)
        {
            value = null;
            int hr = Resolve(user, Iid, Slots.ICredentialProviderUser_GetStringValue, out IntPtr p, out IntPtr f);
            if (hr < 0) return hr;
            try
            {
                hr = Fn<RefKeyOutPointerFn>(f)(p, ref key, out IntPtr text);
                value = TakeCoTaskMemString(text);
                return hr;
            }
            finally { Marshal.Release(p); }
        }

        /// <summary>key: PROPERTYKEY*; value: PROPVARIANT* owned by the caller (PropVariantClear it).</summary>
        public static int GetValue(IntPtr user, IntPtr key, IntPtr value)
        {
            int hr = Resolve(user, Iid, Slots.ICredentialProviderUser_GetValue, out IntPtr p, out IntPtr f);
            if (hr < 0) return hr;
            try { return Fn<TwoPointersFn>(f)(p, key, value); }
            finally { Marshal.Release(p); }
        }
    }

    /// <summary>Copies a CoTaskMemAlloc'ed LPWSTR into a managed string and frees it. Zero gives null.</summary>
    public static string? TakeCoTaskMemString(IntPtr text)
    {
        if (text == IntPtr.Zero)
            return null;
        try { return Marshal.PtrToStringUni(text); }
        finally { Marshal.FreeCoTaskMem(text); }
    }
}
