using System.Runtime.InteropServices;

namespace Fido2BleLogon.CredentialProvider;

/// <summary>
/// Draws the provider's "Sign-in options" icon in code: fingerprint-like ridges (concentric arcs, open at the
/// bottom, with a few breaks) on a transparent background, as a 72x72 32-bpp top-down DIB section with
/// pre-multiplied BGRA. A fresh HBITMAP is made for every GetBitmapValue call and handed to LogonUI, which
/// owns and frees it, so there is no shared GDI handle for the provider to keep alive.
/// </summary>
internal static class TileImage
{
    public const int Size = 72; // [TECHREF]: recommended size for a V2 provider icon

    // Ridge color (Windows 11 light accent blue), readable on LogonUI's dark and Credential UI's light background.
    private const byte Red = 0x4C, Green = 0xC2, Blue = 0xFF;

    /// <summary>Creates a new HBITMAP. Returns false (and <paramref name="hbmp"/> == Zero) on any failure.</summary>
    public static bool TryCreate(out IntPtr hbmp)
    {
        hbmp = IntPtr.Zero;
        IntPtr bitmap = IntPtr.Zero;
        try
        {
            var header = new NativeMethods.BITMAPINFOHEADER
            {
                biSize = (uint)Marshal.SizeOf<NativeMethods.BITMAPINFOHEADER>(),
                biWidth = Size,
                biHeight = -Size, // negative: top-down rows
                biPlanes = 1,
                biBitCount = 32,
                biCompression = NativeMethods.BI_RGB,
            };
            bitmap = NativeMethods.CreateDIBSection(IntPtr.Zero, ref header, NativeMethods.DIB_RGB_COLORS, out var bits, IntPtr.Zero, 0);
            if (bitmap == IntPtr.Zero || bits == IntPtr.Zero)
                return false;

            byte[] pixels = Render();
            Marshal.Copy(pixels, 0, bits, pixels.Length);
            hbmp = bitmap;
            bitmap = IntPtr.Zero;
            return true;
        }
        catch (Exception ex)
        {
            ProviderLog.WriteException("tile", "TileImage.TryCreate", ex, includeStack: true);
            hbmp = IntPtr.Zero;
            return false;
        }
        finally
        {
            if (bitmap != IntPtr.Zero)
                NativeMethods.DeleteObject(bitmap);
        }
    }

    /// <summary>Pre-multiplied BGRA pixels, row by row from the top.</summary>
    internal static byte[] Render()
    {
        var buffer = new byte[Size * Size * 4];
        const double cx = Size / 2.0;
        const double cy = Size / 2.0 + 2.0;   // slightly low, like a fingertip
        const double stretch = 1.2;           // taller than wide
        const double firstRadius = 5.0;
        const double spacing = 5.8;
        const double halfWidth = 1.4;
        const int rings = 5;
        // One break per ring (degrees; 0 = right, 90 = down) so the ridges don't read as a target.
        double[] breaks = [-140, -35, -105, 160, -65];

        for (int y = 0; y < Size; y++)
        {
            for (int x = 0; x < Size; x++)
            {
                double dx = x + 0.5 - cx;
                double dy = (y + 0.5 - cy) / stretch;
                double r = Math.Sqrt(dx * dx + dy * dy);
                int ring = (int)Math.Round((r - firstRadius) / spacing);
                if (ring < 0 || ring >= rings)
                    continue;

                double coverage = Math.Clamp(halfWidth + 0.5 - Math.Abs(r - (firstRadius + ring * spacing)), 0, 1);
                if (coverage <= 0)
                    continue;

                double angle = Math.Atan2(dy, dx) * 180 / Math.PI;
                if (ring >= 1 && angle > 52 && angle < 128)
                    continue; // open at the bottom
                if (ring >= 1 && AngleDistance(angle, breaks[ring]) < 13)
                    continue;

                byte alpha = (byte)Math.Round(255 * coverage);
                int i = (y * Size + x) * 4;
                buffer[i + 0] = (byte)(Blue * alpha / 255);
                buffer[i + 1] = (byte)(Green * alpha / 255);
                buffer[i + 2] = (byte)(Red * alpha / 255);
                buffer[i + 3] = alpha;
            }
        }
        return buffer;
    }

    private static double AngleDistance(double a, double b)
    {
        double d = Math.Abs(a - b) % 360;
        return d > 180 ? 360 - d : d;
    }
}
