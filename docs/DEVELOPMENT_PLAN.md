# Development plan through INNOVATEX

The target is a credible, understandable Windows desktop research prototype for **29–30 December 2026**. The agreed scope is early identification of file-encrypting ransomware-like activity with explanations and safe response. The numerical rules and collector choice remain experimental engineering decisions.

## Priorities

| Priority | Work | Completion evidence |
| --- | --- | --- |
| Must have | Preserve the working native app, real folder collection, event history, explicit missing evidence, configurable five-indicator assessment, alert-only response, and controlled tests | Reproducible tests and a documented desktop walkthrough |
| Must have | Compare a harmless writer's known identity with independent monitoring output | A report of correct/unknown/incorrect identity, observed/missing/duplicate modifications, delays, permissions, and host OS |
| Requires feasibility testing | Windows ETW file/process collection and correlation | A Windows-only experiment that maps observed operations to stable process identity without guessing |
| Requires feasibility testing | Signature validation, sampling strategies, permissions, dropped events, and process response behaviour | Measured failure cases and documented operational limits |
| Optional improvement | Better evidence search, longer-run storage performance, retention/export convenience, packaged executable | Added only after core validation is stable |
| Postpone | Arbitrary-application automatic containment, kernel driver, online learning, enterprise networking, family identification, recovery | Outside the current safe implementation boundary or stated scope |

## Why this sequence

The dashboard is already native and functional. More visual features will not resolve attribution uncertainty. First establish what the collector observes, which evidence is missing, and whether a stable writer identity can be supported. Keep the response policy alert-only for ordinary applications while that work proceeds.

The current update separates collection, process metadata, scoring, response decisions, OS actions, storage, and Qt presentation. This permits a future Windows collector to replace the folder adapter without rebuilding the dashboard or inventing writer identities.

## Milestones

| Target | Deliverable | Decision gate |
| --- | --- | --- |
| Early November 2026 | Run source application and independent attribution probe on Windows; evaluate ETW provider fields, permissions, filenames, and thread/process correlation | Select a collector only after controlled ground-truth comparison; if attribution is unresolved, retain alert-only folder monitoring |
| November 2026 | Measure the five indicators, missing-data cases, and legitimate high-I/O overlap; implement any justified context rule | Record assumptions and calibration workloads; do not claim that every indicator improves results |
| Early December 2026 | Integrate the selected evidence path with explanations and separately reviewed response safety | Continue restricting actions to controlled workers unless the full attribution/safety gate is passed |
| 14 December 2026 | Core-feature freeze | Freeze scope, event schema, configuration, and demo workflow; log defects rather than adding major components |
| 18 December 2026 | Stable showcase demo | Clean Windows setup, repeatable default alert-only and optional lab-response walkthroughs, exports, and recovery after app close |
| 19–28 December 2026 | Testing, fixes, documentation, and rehearsals | Repeated fresh-fixture runs; documented failures and limitations; backup demo recordings if the live machine fails |
| 29–30 December 2026 | INNOVATEX FYP1 showcase | Demonstrate observed evidence and decisions; clearly label simulation and remaining research work |

## ETW go/no-go criteria

ETW means **Event Tracing for Windows**, the operating system's event tracing facility. A successful subscription alone is insufficient. Before claiming process-level detection, confirm the provider/version, operation meaning, filename mapping, stable process identity, event ordering and loss, and required privileges against an independent writer log.

If those checks cannot be completed within the schedule, the feasible showcase is: real folder observations with unknown writer identity; explainable alert-only assessment; a separate, labelled cooperative lab demonstrating safe child-process response; and an honest attribution experiment showing the collector's current limits. That is more useful than assigning a guessed PID.

## Work still required before the showcase

1. Execute the Windows source launch and full test procedure in [TESTING.md](TESTING.md).
2. Run and retain independent Windows attribution reports for each candidate collector.
3. Extend the supplied text-edit and ZIP-creation controls with representative Windows archive applications, backup/copy, and legitimate encryption workloads on disposable files.
4. Separate development/calibration workloads from held-out evaluation; freeze rules before scoring the latter.
5. Measure notification quality, false alerts, unnecessary intervention, detection/response latency, file impact, and resource overhead together.
6. Rehearse alert review, acknowledgement, optional worker pause/release, export, and clean shutdown.

See [EVALUATION_PLAN.md](EVALUATION_PLAN.md) for metric definitions and [WINDOWS_MONITORING_FEASIBILITY.md](WINDOWS_MONITORING_FEASIBILITY.md) for collector options.
