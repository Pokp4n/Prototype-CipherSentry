CipherSentry Stage 5.5E.2: ETW -> Python JSONL streamer

Contents:
  etw/LiveEtwStreamer/Program.cs
  etw/LiveEtwStreamer/LiveEtwStreamer.csproj
  etw/LiveEtwStreamer/.gitignore

Extract this ZIP into your CLEAN integration worktree:
 C:\dev\CipherSentry\Prototype-CipherSentry-ETW-Integration

The standalone project uses TraceEvent v4.0.0 and .NET 10.
It does not modify the previous LiveEtwProbe or its CSV captures.

NORMAL POWERSHELL (compile; no elevation):
 dotnet build "C:\dev\CipherSentry\Prototype-CipherSentry-ETW-Integration\etw\LiveEtwStreamer\LiveEtwStreamer.csproj"

It streams only named ETW writes inside
 C:\dev\CipherSentry\Experiments\CipherSentry-ETW
and never triggers CipherSentry's RiskEngine or containment.

Future (after verified build):
 An --self-test mode allows validating JSONL without ETW or elevation.
 Live mode needs an Administrator PowerShell terminal and Python receiver.

Caveats: ETW event PID is not independently verified writer identity;
 FileKey can be ambiguous; not all ETW writes provide filenames;
 flushing and queueing can change observed timing; ETW event loss needs
 separate evaluation; not a production-grade ransomware detector.
