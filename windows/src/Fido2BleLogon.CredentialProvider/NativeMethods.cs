using System.Runtime.InteropServices;

// Every P/Invoke in this assembly targets a Windows DLL. Load them from System32 only, never from the assembly's
// own folder first (secur32.dll is not a KnownDLL), so a DLL planted next to the provider can't be picked up.
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]

namespace Fido2BleLogon.CredentialProvider;

/// <summary>Win32 entry points used by the provider (message window, GDI tile image, LSA, CredProtect).</summary>
internal static partial class NativeMethods
{
    // ---- System metrics (Safe Mode detection) ----------------------------------------------------
    public const int SM_CLEANBOOT = 67;

    [LibraryImport("user32.dll")]
    public static partial int GetSystemMetrics(int nIndex);

    [LibraryImport("kernel32.dll")]
    public static partial uint GetCurrentThreadId();

    // ---- Message-only window ---------------------------------------------------------------------
    public const uint WM_APP = 0x8000;
    public static readonly IntPtr HWND_MESSAGE = new(-3);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WNDCLASSEXW
    {
        public uint cbSize;
        public uint style;
        public IntPtr lpfnWndProc;
        public int cbClsExtra;
        public int cbWndExtra;
        public IntPtr hInstance;
        public IntPtr hIcon;
        public IntPtr hCursor;
        public IntPtr hbrBackground;
        [MarshalAs(UnmanagedType.LPWStr)] public string? lpszMenuName;
        [MarshalAs(UnmanagedType.LPWStr)] public string lpszClassName;
        public IntPtr hIconSm;
    }

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern ushort RegisterClassExW(ref WNDCLASSEXW lpwcx);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int UnregisterClassW([MarshalAs(UnmanagedType.LPWStr)] string lpClassName, IntPtr hInstance);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CreateWindowExW(uint dwExStyle, [MarshalAs(UnmanagedType.LPWStr)] string lpClassName,
        [MarshalAs(UnmanagedType.LPWStr)] string? lpWindowName, uint dwStyle, int x, int y, int nWidth, int nHeight,
        IntPtr hWndParent, IntPtr hMenu, IntPtr hInstance, IntPtr lpParam);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DestroyWindow(IntPtr hWnd);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern IntPtr DefWindowProcW(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool PostMessageW(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    [LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    public static partial IntPtr GetModuleHandleW(string? lpModuleName);

    // ---- GDI: tile image (32-bpp top-down DIB section) -------------------------------------------
    public const uint BI_RGB = 0;
    public const uint DIB_RGB_COLORS = 0;

    [StructLayout(LayoutKind.Sequential)]
    public struct BITMAPINFOHEADER
    {
        public uint biSize;
        public int biWidth;
        public int biHeight;
        public ushort biPlanes;
        public ushort biBitCount;
        public uint biCompression;
        public uint biSizeImage;
        public int biXPelsPerMeter;
        public int biYPelsPerMeter;
        public uint biClrUsed;
        public uint biClrImportant;
    }

    [DllImport("gdi32.dll", SetLastError = true)]
    public static extern IntPtr CreateDIBSection(IntPtr hdc, ref BITMAPINFOHEADER pbmi, uint usage,
        out IntPtr ppvBits, IntPtr hSection, uint offset);

    [DllImport("gdi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DeleteObject(IntPtr ho);

    // ---- LSA: Negotiate authentication package ---------------------------------------------------
    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [DllImport("secur32.dll")]
    public static extern int LsaConnectUntrusted(out IntPtr LsaHandle);

    [DllImport("secur32.dll")]
    public static extern int LsaLookupAuthenticationPackage(IntPtr LsaHandle, ref LSA_STRING PackageName, out uint AuthenticationPackage);

    [DllImport("secur32.dll")]
    public static extern int LsaDeregisterLogonProcess(IntPtr LsaHandle);

    // ---- CredProtect -----------------------------------------------------------------------------
    public const int ERROR_INSUFFICIENT_BUFFER = 122;

    /// <summary>CRED_PROTECTION_TYPE.CredUnprotected.</summary>
    public const int CredUnprotected = 0;

    // Raw pointers, not strings: the password must never become a (non-wipeable) managed string. Both take a
    // NUL-terminated UTF-16 buffer the caller owns and clears.
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern unsafe bool CredProtectW([MarshalAs(UnmanagedType.Bool)] bool fAsSelf,
        char* pszCredentials, uint cchCredentials, char* pszProtectedCredentials, ref uint pcchMaxChars, out int ProtectionType);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern unsafe bool CredIsProtectedW(char* pszProtectedCredentials, out int pProtectionType);
}
