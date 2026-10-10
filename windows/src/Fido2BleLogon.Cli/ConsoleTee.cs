using System.Text;

namespace Fido2BleLogon.Cli;

/// <summary>Copies console output to a log file, so a run in a separate elevated window can be read afterwards.</summary>
internal sealed class ConsoleTee : IDisposable
{
    private readonly TextWriter _originalOut;
    private readonly StreamWriter _file;

    private ConsoleTee(string path)
    {
        _originalOut = Console.Out;
        _file = new StreamWriter(path, append: false, Encoding.UTF8) { AutoFlush = true };
        Console.SetOut(TextWriter.Synchronized(new TeeWriter(_originalOut, _file)));
    }

    public static ConsoleTee Start(string path) => new(path);

    public void Dispose()
    {
        Console.SetOut(_originalOut);
        _file.Dispose();
    }

    private sealed class TeeWriter(TextWriter console, TextWriter file) : TextWriter
    {
        public override Encoding Encoding => console.Encoding;
        public override void Write(char value) { console.Write(value); file.Write(value); }
        public override void Write(string? value) { console.Write(value); file.Write(value); }
        public override void WriteLine(string? value) { console.WriteLine(value); file.WriteLine(value); }
        public override void Flush() { console.Flush(); file.Flush(); }
    }
}
