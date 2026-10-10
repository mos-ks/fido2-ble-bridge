using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Fido2BleLogon.CredentialProvider;

/// <summary>
/// Runs work on the thread LogonUI calls us on. LogonUI's event interfaces (ICredentialProviderEvents,
/// ICredentialProviderCredentialEvents) may only be called on the thread that received Advise ([TECHREF]),
/// while BLE / UnlockAsync work runs on thread-pool threads. So a message-only window is created on the
/// LogonUI thread; background code <see cref="Post"/>s an action, PostMessage wakes the window, and its
/// [UnmanagedCallersOnly] WndProc runs the queued actions on that thread. LogonUI pumps messages for its UI
/// thread, so no private message loop is needed. The WndProc is a static method, so there is no delegate to
/// keep alive.
/// </summary>
internal sealed unsafe class UiDispatcher : IDisposable
{
    private static readonly ConcurrentDictionary<IntPtr, UiDispatcher> ByWindow = new();

    private readonly ConcurrentQueue<Action> _queue = new();
    private readonly string _className;
    private readonly IntPtr _hInstance;
    private IntPtr _hwnd;
    private volatile bool _disposed;

    private UiDispatcher(string className, IntPtr hInstance, IntPtr hwnd)
    {
        _className = className;
        _hInstance = hInstance;
        _hwnd = hwnd;
        ThreadId = NativeMethods.GetCurrentThreadId();
    }

    /// <summary>The OS thread that owns the window (where posted actions run).</summary>
    public uint ThreadId { get; }

    /// <summary>Creates the window on the current thread. Returns null if it could not be created.</summary>
    public static UiDispatcher? Create()
    {
        try
        {
            var hInstance = NativeMethods.GetModuleHandleW(null);
            var className = "Fido2BleLogonCpDispatcher_" + Guid.NewGuid().ToString("N");
            var wc = new NativeMethods.WNDCLASSEXW
            {
                cbSize = (uint)Marshal.SizeOf<NativeMethods.WNDCLASSEXW>(),
                lpfnWndProc = (IntPtr)(delegate* unmanaged[Stdcall]<IntPtr, uint, IntPtr, IntPtr, IntPtr>)&WndProc,
                hInstance = hInstance,
                lpszClassName = className,
            };
            if (NativeMethods.RegisterClassExW(ref wc) == 0)
            {
                ProviderLog.Write("dispatcher", $"RegisterClassExW failed (error {Marshal.GetLastPInvokeError()})");
                return null;
            }

            var hwnd = NativeMethods.CreateWindowExW(0, className, null, 0, 0, 0, 0, 0,
                NativeMethods.HWND_MESSAGE, IntPtr.Zero, hInstance, IntPtr.Zero);
            if (hwnd == IntPtr.Zero)
            {
                ProviderLog.Write("dispatcher", $"CreateWindowExW failed (error {Marshal.GetLastPInvokeError()})");
                NativeMethods.UnregisterClassW(className, hInstance);
                return null;
            }

            var dispatcher = new UiDispatcher(className, hInstance, hwnd);
            ByWindow[hwnd] = dispatcher;
            return dispatcher;
        }
        catch (Exception ex)
        {
            ProviderLog.WriteException("dispatcher", "UiDispatcher.Create", ex, includeStack: true);
            return null;
        }
    }

    /// <summary>Queues an action for the dispatcher thread. Safe from any thread; false if it can't be delivered.</summary>
    public bool Post(Action action)
    {
        if (_disposed)
            return false;
        _queue.Enqueue(action);
        var hwnd = _hwnd;
        return hwnd != IntPtr.Zero && NativeMethods.PostMessageW(hwnd, NativeMethods.WM_APP, IntPtr.Zero, IntPtr.Zero);
    }

    private void Drain()
    {
        while (!_disposed && _queue.TryDequeue(out var action))
        {
            try
            {
                action();
            }
            catch (Exception ex)
            {
                ProviderLog.WriteException("dispatcher", "queued action", ex, includeStack: true);
            }
        }
    }

    /// <summary>Destroys the window. Must be called on the thread that created it (UnAdvise).</summary>
    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        var hwnd = _hwnd;
        _hwnd = IntPtr.Zero;
        try
        {
            if (hwnd != IntPtr.Zero)
            {
                ByWindow.TryRemove(hwnd, out _);
                NativeMethods.DestroyWindow(hwnd);
            }
            NativeMethods.UnregisterClassW(_className, _hInstance);
        }
        catch (Exception ex)
        {
            ProviderLog.WriteException("dispatcher", "UiDispatcher.Dispose", ex, includeStack: true);
        }
        // Drop actions that never ran so whatever they captured can be collected.
        while (_queue.TryDequeue(out _))
        {
        }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static IntPtr WndProc(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam)
    {
        try
        {
            if (msg == NativeMethods.WM_APP)
            {
                if (ByWindow.TryGetValue(hwnd, out var dispatcher))
                    dispatcher.Drain();
                return IntPtr.Zero;
            }
            return NativeMethods.DefWindowProcW(hwnd, msg, wParam, lParam);
        }
        catch
        {
            // An exception escaping an UnmanagedCallersOnly method would terminate LogonUI.
            return IntPtr.Zero;
        }
    }
}
