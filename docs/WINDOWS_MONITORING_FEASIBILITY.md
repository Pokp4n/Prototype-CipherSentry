# Windows monitoring and process-attribution feasibility

## Decision for this iteration

Retain the real user-mode folder watcher for path-level observations and **alert-only** assessment. Keep cooperative lab telemetry visibly separate. Investigate ETW next in a controlled Windows environment; do not add a kernel driver simply to make the prototype appear complete.

No live ETW collector, Sysmon integration, signature verifier, or arbitrary-process containment is implemented in this update. The current `CollectorCapabilities`/`MonitorProtocol` boundary makes replacing the folder adapter possible without coupling the Qt dashboard to a particular event provider.

## What the technologies can establish

| Technology | Useful information | Limitation and prototype decision |
| --- | --- | --- |
| Directory notifications / watchdog | Changed path and create/modify/rename/delete notifications; file sampling can add entropy observations | The documented directory-notification record does not contain a writer PID. Keep writer attribution unavailable. |
| psutil | Metadata for a known PID: name, executable, parent, and creation time where permitted | Describing a process does not prove it wrote a file. Collect context only after independently establishing the PID. |
| ETW file and process/thread providers | OS tracing can expose file-operation fields and identifiers for correlation | Provider/version decoding, thread/process identity, filenames, event loss, permissions, and timestamps require a Windows feasibility test. |
| Sysmon | Supplementary process and selected file/security events; process GUID can help avoid PID-reuse confusion | Not a complete stream of every file read/write. Do not infer that FileCreate covers every modification. No integration added yet. |
| Filesystem minifilter | Advanced kernel-level interception path | Adds driver development, signing, deployment, and reliability work. Postpone unless a justified requirement and feasibility review demand it. |

## Reviewed official API facts

Microsoft's official documentation source files were read from the MicrosoftDocs repositories. These establish API semantics, not ransomware detection accuracy.

- [`FILE_NOTIFY_INFORMATION`](https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-file_notify_information) describes `NextEntryOffset`, `Action`, `FileNameLength`, and `FileName`. It has no process-ID field. [Reviewed source](https://github.com/MicrosoftDocs/sdk-api/blob/docs/sdk-api-src/content/winnt/ns-winnt-file_notify_information.md).
- [`ReadDirectoryChangesW`](https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-readdirectorychangesw) documents that an overflowing change buffer can be discarded even when the call returns success; a synchronous returned byte count of zero requires attention. File notifications cannot be assumed complete. [Reviewed source](https://github.com/MicrosoftDocs/sdk-api/blob/docs/sdk-api-src/content/winbase/nf-winbase-readdirectorychangesw.md).
- [`FileIo_ReadWrite`](https://learn.microsoft.com/windows/win32/etw/fileio-readwrite) includes `TTID` (the thread performing the operation), `FileObject`, `FileKey`, and `IoSize`. Its documentation describes matching the file key with `FileIo_Name` information to determine a filename. A practical adapter must also establish the relevant process/thread lifetime. [Reviewed source](https://github.com/MicrosoftDocs/win32/blob/docs/desktop-src/ETW/fileio-readwrite.md); [`FileIo_Name` source](https://github.com/MicrosoftDocs/win32/blob/docs/desktop-src/ETW/fileio-name.md).
- [`EVENT_HEADER.ProcessId`](https://learn.microsoft.com/windows/win32/api/evntcons/ns-evntcons-event_header) identifies the process generating the event. This general header field should not be assumed to identify the file writer for every provider/event; validate the specific event semantics. [Reviewed source](https://github.com/MicrosoftDocs/sdk-api/blob/docs/sdk-api-src/content/evntcons/ns-evntcons-event_header.md).
- [`StartTraceW`](https://learn.microsoft.com/windows/win32/api/evntrace/nf-evntrace-starttracew) documents tracing-session permissions and states that only administrators and LocalSystem services can control an NT Kernel Logger session. Permissions vary by tracing design; do not claim standard-user support for a collector before testing it. [Reviewed source](https://github.com/MicrosoftDocs/sdk-api/blob/docs/sdk-api-src/content/evntrace/nf-evntrace-starttracew.md).
- [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) documents Event 1 process creation and its `ProcessGUID`, and Event 11 file creation/overwrite. These are useful supplementary events, not proof of complete per-write coverage. [Reviewed source](https://github.com/MicrosoftDocs/sysinternals/blob/live/sysinternals/downloads/sysmon.md).

The cited ETW class documentation includes historical schema details. Do not hard-code a layout from a page and assume it applies to every Windows build or event version. Inspect the chosen provider's actual metadata and decode event versions deliberately.

## Controlled feasibility test

The supplied probe already compares a harmless writer with the current folder adapter:

```powershell
.venv\Scripts\python.exe -m scripts.attribution_probe --files 12 --output .ciphersentry\attribution-windows.json
```

Its ground-truth pipe is independent of the monitoring callback. It records the real writer identity, expected fixture modifications, and the collector's original observations. It reports missing/duplicate observations, delivery delays, and correct/unknown/incorrect attribution. Ground truth is never used to fill an unknown collector PID.

This probe establishes the current adapter's boundary. To validate a future ETW adapter:

1. Record the Windows build, provider GUID/name, event IDs and versions, enabled flags, and required privileges.
2. Collect process/thread start and end data as needed; distinguish a new process reusing an old PID.
3. Resolve file identifiers to paths and explicitly report unresolved or out-of-order records.
4. Run isolated harmless writers first, then two concurrent writers using different and overlapping directories. Compare emitted operations to independent ground truth.
5. Test writes, renames, deletes, and reads where required. Do not count a source as supporting an operation it never reports.
6. Measure missing, duplicate, delayed, and incorrectly attributed events under burst load; record trace-loss counters and collector errors.
7. Test permission denial, process exit, filename-resolution gaps, and PID reuse. Missing information must prevent automatic action rather than trigger guessing.

Do not claim process-level detection merely because a trace session opens, an event has a PID-looking field, or one event correlates successfully.

## Go/no-go gate for response

Even successful external attribution is insufficient by itself to enable the present lab-only response path. A separate implementation and review must establish policy exclusions, identity revalidation at action time, permission checks, detailed outcome logging, resumption, cleanup, and bounded failure handling on Windows. Until that gate is complete, externally observed applications stay alert-only.

For INNOVATEX, a technically honest fallback is real folder monitoring, explained alert-only decisions, an independent report showing current attribution limits, and a separately labelled owned-worker simulation demonstrating pause/release. This retains a functioning prototype while making the unresolved Windows work visible.
