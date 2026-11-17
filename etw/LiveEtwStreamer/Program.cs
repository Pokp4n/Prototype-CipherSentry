using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

// CipherSentry Stage 5.5E.2 â€” experimental ETW -> Python JSON Lines producer.
// Read-only and scoped to the local ETW experiment folder.
// STDOUT: ONLY schema-v1 Write JSON Lines. STDERR: all diagnostics.
// Does NOT score ransomware or control/terminate processes.
// Each reported ETW PID is UNVERIFIED evidence, never action authorization.

const string SessionName = "CipherSentry-LiveEtwStreamer";
const string Root = @"C:\dev\CipherSentry\Experiments\CipherSentry-ETW";
const int DurationSeconds = 45;
const int FlushEveryMilliseconds = 250;
const int ChannelCapacity = 8192;

Console.OutputEncoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);

static string Utc(DateTime value) =>
    value.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);

static string JsonWrite(DateTime eventTime, DateTime callbackTime, int pid,
    ulong fileKey, ulong fileObject, int ioSize, string? filename, bool priorMapping)
{
    return JsonSerializer.Serialize(new
    {
        schema = 1,
        kind = "Write",
        event_time_utc = Utc(eventTime),
        callback_time_utc = Utc(callbackTime),
        reported_pid = pid,
        file_key = $"0x{fileKey:X16}",
        file_object = $"0x{fileObject:X16}",
        io_size = ioSize,
        filename,
        details = priorMapping ? "reader-prior-key-candidate" : "no-reader-prior-key-candidate",
    });
}

static bool IsNamedFileInsideRoot(string? filename, string root)
{
    if (string.IsNullOrWhiteSpace(filename) || !Path.IsPathFullyQualified(filename))
        return false;
    try
    {
        string relative = Path.GetRelativePath(root, Path.GetFullPath(filename));
        return relative != "." && relative != ".." &&
               !relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal) &&
               !Path.IsPathRooted(relative);
    }
    catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
    {
        return false;
    }
}

// The self-test is synthetic. It starts NO ETW session and performs NO file I/O.
if (args.Length == 1 && args[0] == "--self-test")
{
    Console.Error.WriteLine("SELF-TEST ONLY â€” emitting synthetic JSONL, not real ETW data.");
    var now = DateTime.UtcNow;
    string fake = Path.Combine(Root, "synthetic-selftest", "etw-writer-test.txt");
    Console.Out.WriteLine(JsonWrite(now.AddMilliseconds(-200), now, 22208,
        1, 2, 25, fake, priorMapping: true));
    Console.Out.WriteLine(JsonWrite(now.AddMilliseconds(-180), now, 4,
        1, 2, 4096, fake, priorMapping: true));
    await Console.Out.FlushAsync();
    return;
}
if (args.Length != 0)
{
    Console.Error.WriteLine("Usage: LiveEtwStreamer [--self-test]");
    Environment.ExitCode = 2;
    return;
}
if (!OperatingSystem.IsWindows() || TraceEventSession.IsElevated() != true)
{
    Console.Error.WriteLine("Run the live mode in Administrator PowerShell on Windows.");
    Environment.ExitCode = 2;
    return;
}
if (TraceEventSession.GetActiveSessionNames().Any(name =>
    string.Equals(name, SessionName, StringComparison.OrdinalIgnoreCase)))
{
    Console.Error.WriteLine($"ETW session '{SessionName}' is already running. Not replacing it.");
    Environment.ExitCode = 2;
    return;
}

// This bounded queue protects TraceEvent callbacks from blocking on Python stdout.
// A full queue is reported as stream loss; records are never silently overwritten.
var channel = Channel.CreateBounded<string>(new BoundedChannelOptions(ChannelCapacity)
{
    SingleReader = true,
    SingleWriter = true,
    FullMode = BoundedChannelFullMode.Wait,
});

long totalWrites = 0;
long namedWritesInRoot = 0;
long queuedWrites = 0;
long queueDropped = 0;
long readerPriorCandidates = 0;
long nameEvents = 0;
long createNameEvents = 0;
long rundownNameEvents = 0;
long flushRequests = 0;
var knownNames = new Dictionary<ulong, (DateTime timestamp, string name)>();

// Any stdout exception is surfaced at the end of the session.
var sender = Task.Run(async () =>
{
    await foreach (string line in channel.Reader.ReadAllAsync())
    {
        await Console.Out.WriteLineAsync(line);
        await Console.Out.FlushAsync();
    }
});

Exception? sessionFailure = null;
try
{
    using var session = new TraceEventSession(SessionName);
    using var stopTimer = new CancellationTokenSource();

    // Important: TraceEvent kernel provider must be enabled BEFORE source callbacks.
    session.EnableKernelProvider(
        KernelTraceEventParser.Keywords.Process |
        KernelTraceEventParser.Keywords.DiskFileIO |
        KernelTraceEventParser.Keywords.FileIO |
        KernelTraceEventParser.Keywords.FileIOInit);

    session.Source.Kernel.FileIOName += data =>
    {
        nameEvents++;
        if (!string.IsNullOrWhiteSpace(data.FileName))
            knownNames[data.FileKey] = (data.TimeStamp, data.FileName);
    };
    session.Source.Kernel.FileIOFileCreate += data =>
    {
        createNameEvents++;
        if (!string.IsNullOrWhiteSpace(data.FileName))
            knownNames[data.FileKey] = (data.TimeStamp, data.FileName);
    };
    session.Source.Kernel.FileIOFileRundown += _ => rundownNameEvents++;
    session.Source.Kernel.FileIOWrite += data =>
    {
        totalWrites++;
        string? filename = string.IsNullOrWhiteSpace(data.FileName) ? null : data.FileName;
        if (!IsNamedFileInsideRoot(filename, Root))
            return; // Do not stream system-wide private file paths or unresolved filenames.

        namedWritesInRoot++;
        bool hasPrior = knownNames.TryGetValue(data.FileKey, out var mapping) &&
                        mapping.timestamp <= data.TimeStamp;
        if (hasPrior)
            readerPriorCandidates++;

        // Reported PID and FileKey correlation are *observations*, not independently
        // verified identities or sufficient grounds for stopping an application.
        string line = JsonWrite(data.TimeStamp, DateTime.UtcNow, data.ProcessID,
            data.FileKey, data.FileObject, data.IoSize, filename, hasPrior);
        if (channel.Writer.TryWrite(line))
            queuedWrites++;
        else
            queueDropped++;
    };

    Console.CancelKeyPress += (_, e) =>
    {
        e.Cancel = true;
        session.Dispose();
    };

    Console.Error.WriteLine("=== CipherSentry LIVE ETW JSONL streamer (read-only) ===");
    Console.Error.WriteLine($"Scoped folder: {Root}");
    Console.Error.WriteLine($"Duration: {DurationSeconds}s; periodic flush: {FlushEveryMilliseconds}ms");
    Console.Error.WriteLine("STDOUT is reserved for JSONL. Run the harmless two-writer probe now.");
    Console.Error.WriteLine("Listening for events ...");

    var stopper = Task.Run(async () =>
    {
        try
        {
            await Task.Delay(TimeSpan.FromSeconds(DurationSeconds), stopTimer.Token);
            session.Dispose();
        }
        catch (OperationCanceledException) { }
        catch (ObjectDisposedException) { }
    });
    var flusher = Task.Run(async () =>
    {
        try
        {
            while (!stopTimer.IsCancellationRequested)
            {
                await Task.Delay(FlushEveryMilliseconds, stopTimer.Token);
                session.Flush();
                Interlocked.Increment(ref flushRequests);
            }
        }
        catch (OperationCanceledException) { }
        catch (ObjectDisposedException) { }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Periodic ETW flushing stopped: {ex.GetType().Name}: {ex.Message}");
        }
    });

    try
    {
        session.Source.Process();
    }
    finally
    {
        stopTimer.Cancel();
    }
    await Task.WhenAll(stopper, flusher);
}
catch (Exception ex)
{
    sessionFailure = ex;
    Console.Error.WriteLine($"ETW streaming failed: {ex.GetType().Name}: {ex.Message}");
}
finally
{
    channel.Writer.TryComplete();
}

try
{
    await sender;
}
catch (Exception ex)
{
    sessionFailure ??= ex;
    Console.Error.WriteLine($"Python pipeline/stdout failed: {ex.GetType().Name}: {ex.Message}");
}

Console.Error.WriteLine("\n=== C# Live ETW Streamer Summary ===");
Console.Error.WriteLine($"All observed system Write callbacks: {totalWrites}");
Console.Error.WriteLine($"Named Write callbacks inside scope: {namedWritesInRoot}");
Console.Error.WriteLine($"JSONL records queued: {queuedWrites}");
Console.Error.WriteLine($"Stream queue records dropped: {queueDropped}");
Console.Error.WriteLine($"Reader-prior FileKey candidates inside scope: {readerPriorCandidates}");
Console.Error.WriteLine($"FileIOName: {nameEvents}; FileCreateName: {createNameEvents}; FileRundown: {rundownNameEvents}");
Console.Error.WriteLine($"Periodic flush calls completed: {flushRequests}");
Console.Error.WriteLine("No risk scoring; no process containment; event PID attribution remains UNVERIFIED.");
if (sessionFailure is not null || queueDropped != 0)
    Environment.ExitCode = 1;
