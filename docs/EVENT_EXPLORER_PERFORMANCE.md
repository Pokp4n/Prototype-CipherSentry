# Event Explorer performance investigation

Investigation started 31 October 2026; validation continued 1 November 2026 on the existing Windows laptop and Python 3.12.10 / PySide6 6.8.3 environment.

## Findings

The table was rebuilt unnecessarily while no evidence arrived. The controller's one-second resource update emits `changed`; `MainWindow.refresh()` marked event data dirty on every such update. The 300 ms table timer then loaded and decoded the latest 500 SQLite records and recreated all five items in every event row. Lab elapsed-time updates and navigation also invalidated the evidence table.

Four columns used `QHeaderView.ResizeToContents`. Replacing each item triggered further content-size calculations. Disabling painting with `setUpdatesEnabled(False)` did not suppress these calculations. The instrumented 60-row baseline made 72,000 delegate size requests per table rebuild. At 500 rows it made 5,000,000 requests per rebuild. This synchronous work blocked Qt's GUI thread, explaining why interaction could stall despite modest overall CPU and memory readings.

The complete nested event/assessment record was also stored in every cell, although the details dialog reads it only from column zero. An isolated experiment storing it once gave a small improvement; removing repeated automatic sizing gave the large improvement. Both measurements are retained in the baseline report.

SQLite was not the primary bottleneck. `recent_events(500)` already uses a bounded query ordered by `timestamp DESC, id DESC`, with an existing matching index. Its 60-row baseline median was approximately 3.4 ms, compared with approximately 889 ms for the table rebuild. No database schema, query, assessment, or original evidence was changed.

Nested scrolling was inspected at both supported sizes. At 1480 x 980, the outer page had no vertical scrolling. At the 1140 x 760 minimum size, its range was 303 pixels because the filters, table, and response audit need additional space. The expensive rebuild occurred at both sizes, so nested scrolling did not explain that cost. The outer scroll area remains to keep the response audit accessible at smaller sizes.

## Changes

Only `ciphersentry/ui/window.py` changes application behavior:

- Short event columns have stable widths calculated from the current font, with manual resizing retained. The file column stretches; long text is elided and full paths remain in tooltips and details. Per-cell automatic width scans are removed.
- Resource and lab status updates refresh ancillary information without invalidating event records. New evidence invalidates a bounded cache of the latest 500 original records.
- Search and risk filters operate on that cache. The existing search fields, case-insensitive matching, legacy Elevated filter, and chronological order are preserved.
- Hidden event tables defer population until navigation. Identical visible row IDs do not trigger replacement, including when a different filter yields the same results.
- The full original record is attached once per row, in column zero, for the unchanged details dialog.
- When new rows arrive, selection is restored by event ID and the scrolled top event remains anchored. A view already at the top continues following the newest events.
- Audit updates remain independent of event data. Unchanged alert rows are not rebuilt during those updates; acknowledgement still refreshes status and audit text.

`tests/test_event_explorer.py` adds seven functional regressions. They check idle queries and item identity, search/risk filtering, timestamp/ID ordering, hidden-page deferral, selection/scroll anchoring, actual double-click details, acknowledgement, and complete JSON/CSV exports from 510 original records. Raw database rows are compared before and after display/filter/export operations.

`scripts/profile_event_explorer.py` is a repeatable profiling harness. It creates isolated synthetic SQLite evidence under a fresh `.ciphersentry/event-explorer-profile-*` directory. Its synthetic metadata is only a display fixture: it does not launch or control any process and does not modify the normal application database.

SHA-256 comparisons confirm that the risk engine, controller, process identity, containment, response policy, storage, requirements, and project dependency configuration are unchanged. Alert-only remains the default. No commits or pushes were performed.

## Measurements

The [before report](validation/event-explorer-before.json) and [after report](validation/event-explorer-after.json) contain raw measurements, dependency versions, source hashes, geometry, operation counts, and limitations. Both used Windows, Qt offscreen, the Fusion style, Segoe UI 10, and the same synthetic evidence generator.

| Operation at 1480 x 980 | Before | After |
| --- | ---: | ---: |
| Unchanged refresh, 60 rows, median of 10 cycles | 893.764 ms | 1.110 ms |
| Forced table population, 60 rows, median of 10 | 889.301 ms | 20.592 ms |
| Event-record queries during idle sample, 60 rows | 4 | 0 |
| Event-table rebuilds during idle sample, 60 rows | 4 | 0 |
| Cell-size requests during idle sample, 60 rows | 288,000 | 0 |
| Unchanged refresh, 500 rows, one cycle | 56,678.212 ms | 2.181 ms |
| Forced table population, 500 rows, one sample | 56,936.268 ms | 178.941 ms |

At 1140 x 760, the median unchanged 60-row refresh fell from 907.567 ms to 1.066 ms. All four after-cases recorded zero idle event-record queries, zero event-table rebuilds, and zero cell-size requests. Required population still costs time when evidence or the selected rows actually change; it is bounded to the existing 500-row display limit. Export remains independent of that limit.

These are instrumented handler timings, not screen-frame-rate or Task Manager measurements. The Python counting delegate adds overhead to size requests. Host conditions also varied: query-only timing increased between runs even though database code was unchanged. The reduction in work counts is therefore stronger evidence than any exact speedup ratio.

The requested idle interval was 3.5 seconds. Baseline work could overrun that interval: the 60-row sample took about 4.37 seconds and the 500-row sample about 57.7 seconds. One minimum-size 500-row isolated-population timing spans the interrupted overnight run and is an extreme wall-time outlier; it is retained in the raw data but excluded from comparisons. Other 500-row timings are single samples because the original layout was very slow. No CPU or memory reduction is claimed from the user's one Task Manager observation.

## Validation and remaining limitation

The complete Windows suite finished with **159 passed, 3 failed, and 2 skipped in 110.01 seconds**. The [JUnit report](validation/event-explorer-tests.xml) retains all outcomes. The skipped tests are the POSIX-only named-pipe test and unavailable Windows symlink creation; they are not counted as passes.

The three failures are existing live-worker completion deadlines:

- `tests/test_controller.py::test_suspicious_lab_is_contained_then_resumes_to_completion` — exceeded the 9-second wait after release.
- `tests/test_controller.py::test_default_alert_only_reports_high_risk_without_containment` — exceeded the 10-second completion wait.
- `tests/test_ui.py::test_default_alert_only_review_acknowledgement_export_and_rule_settings` — exceeded the 9-second completion wait.

The two controller tests do not construct `MainWindow`, so their timeouts also occur without the modified Event Explorer. The full suite is **not entirely passing**, and these live-worker delays remain unresolved within the requested scope.

The focused command `python -m pytest -q tests/test_event_explorer.py tests/test_ui.py` finished with **9 passed and 1 failed in 53.75 seconds**: all seven new Event Explorer regressions and two existing UI tests passed; one existing UI test timed out waiting for its live simulation to finish. An isolated rerun reproduced that timeout in 14.40 seconds without changing its deadline or assertions. No existing test was changed or skipped to hide these results.

A separate profile of that journey completed all 60 events, but took approximately 13.33 seconds after entering the completion wait, exceeding the existing 9-second test deadline. The entire profiled run took 14.758 seconds; approximately 12.4 seconds was spent in unchanged process-identity validation. Windows `psutil` parent-process enumeration and suspended-status queries dominated that path. This is a separate remaining source of main-thread delay during a live lab run. The requested boundary prevents changing those checks in this UI task; no check was removed, cached, weakened, or moved to another thread.

Offscreen tests cannot confirm mouse-wheel/touchpad feel, Windows compositor behavior, display scaling, or usability of manual column resizing. These require the manual checks below. The page-level scrollbar at minimum window size is intentionally retained and should also be checked interactively.

## Reproduce

From PowerShell in `C:\dev\CipherSentry\Prototype-CipherSentry-main`:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_event_explorer.py tests/test_ui.py
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m scripts.profile_event_explorer --output .ciphersentry\event-explorer-profile-repeat.json
.\.venv\Scripts\python.exe -m ciphersentry
```

The profiler measures the currently installed source. Repeating it after this change does not regenerate the historical baseline. Use a new output path to preserve the saved before/after reports.

For manual verification:

1. Open Event Explorer with at least 60 saved events. Leave it idle for several seconds, scroll midway through the table, and select a row. Check that periodic resource-label changes do not move the selection or scroll position.
2. Search by filename, process name, operation, and source. Apply each risk filter, including legacy Elevated. Clear the filters and confirm newest-first ordering.
3. Double-click a file cell and inspect the original event and assessment. Export JSON and CSV with a filter active; exports should still contain the full evidence history.
4. Resize the window to its minimum and back to its normal size. Check the table's scrollbar, the outer scrollbar needed to reach Response audit, long-path tooltips, and manual column resizing at the Windows scaling you use.
5. With Alert-only selected, run a harmless lab scenario. View Event Explorer while new records arrive: a scrolled view should keep its event anchor; a view at the top should show new records. The separate live-worker verification overhead described above may still affect responsiveness under this workload.

No destructive fixtures, personal-document monitoring, endpoint-security changes, or dependency upgrades are required.
