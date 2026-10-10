using System.Runtime.InteropServices;

namespace Fido2BleLogon.CpHarness;

/// <summary>Win32 entry points the harness needs: COM activation, a message pump, GDI and CredUnprotect.</summary>
internal static class NativeHost
{
    // ---- COM -------------------------------------------------------------------------------------
    public const uint CLSCTX_INPROC_SERVER = 0x1;

    [DllImport("ole32.dll")]
    public static extern int CoCreateInstance(in Guid rclsid, IntPtr pUnkOuter, uint dwClsContext, in Guid riid, out IntPtr ppv);

    [DllImport("ole32.dll")]
    public static extern void CoTaskMemFree(IntPtr pv);

    // ---- Message pump ----------------------------------------------------------------------------
    public const uint QS_ALLINPUT = 0x04FF;
    public const uint PM_REMOVE = 0x0001;

    [StructLayout(LayoutKind.Sequential)]
    public struct MSG
    {
        public IntPtr hwnd;
        public uint message;
        public IntPtr wParam;
        public IntPtr lParam;
        public uint time;
        public int ptX;
        public int ptY;
    }

    [DllImport("user32.dll")]
    public static extern uint MsgWaitForMultipleObjects(uint nCount, IntPtr[]? pHandles,
        [MarshalAs(UnmanagedType.Bool)] bool bWaitAll, uint dwMilliseconds, uint dwWakeMask);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool PeekMessageW(out MSG lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax, uint wRemoveMsg);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool TranslateMessage(ref MSG lpMsg);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern IntPtr DispatchMessageW(ref MSG lpMsg);

    // ---- GDI -------------------------------------------------------------------------------------
    [StructLayout(LayoutKind.Sequential)]
    public struct BITMAP
    {
        public int bmType;
        public int bmWidth;
        public int bmHeight;
        public int bmWidthBytes;
        public ushort bmPlanes;
        public ushort bmBitsPixel;
        public IntPtr bmBits;
    }

    [DllImport("gdi32.dll")]
    public static extern int GetObjectW(IntPtr h, int c, out BITMAP pv);

    [DllImport("gdi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DeleteObject(IntPtr ho);

    // ---- CredProtect -----------------------------------------------------------------------------
    public const int ERROR_INSUFFICIENT_BUFFER = 122;
    public const int CredUnprotected = 0;

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CredIsProtectedW([MarshalAs(UnmanagedType.LPWStr)] string pszProtectedCredentials, out int pProtectionType);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CredUnprotectW([MarshalAs(UnmanagedType.Bool)] bool fAsSelf,
        [MarshalAs(UnmanagedType.LPWStr)] string pszProtectedCredentials, uint cchProtectedCredentials,
        IntPtr pszCredentials, ref uint pcchMaxChars);

    /// <summary>Dispatches all pending window messages on the current thread (as LogonUI's loop would).</summary>
    public static void PumpMessages()
    {
        while (PeekMessageW(out var msg, IntPtr.Zero, 0, 0, PM_REMOVE))
        {
            TranslateMessage(ref msg);
            DispatchMessageW(ref msg);
        }
    }

    /// <summary>Pumps messages until <paramref name="done"/> is true or the timeout passes. Returns <paramref name="done"/>().</summary>
    public static bool PumpUntil(Func<bool> done, int timeoutMs, Action? onTick = null)
    {
        long deadline = Environment.TickCount64 + timeoutMs;
        while (true)
        {
            PumpMessages();
            onTick?.Invoke();
            PumpMessages();
            if (done())
                return true;
            long remaining = deadline - Environment.TickCount64;
            if (remaining <= 0)
                return done();
            MsgWaitForMultipleObjects(0, null, false, (uint)Math.Min(remaining, 50), QS_ALLINPUT);
        }
    }
}
