"""Expose pytest's JUnit results in the GitHub Actions job summary."""
from __future__ import annotations

import html
import os
from pathlib import Path
import sys
import xml.etree.ElementTree as ET


def render_summary(report: Path) -> str:
    title = "## Desktop prototype test results\n\n"
    if not report.is_file():
        return title + "No JUnit report was produced. Check the setup and pytest steps.\n"
    try:
        root = ET.parse(report).getroot()
    except (ET.ParseError, OSError) as error:
        return title + f"Could not read the JUnit report: <pre>{html.escape(str(error))}</pre>\n"
    cases = list(root.iter("testcase"))
    failed = [case for case in cases if case.find("failure") is not None]
    errors = [case for case in cases if case.find("error") is not None]
    skipped = [case for case in cases if case.find("skipped") is not None]
    passed = sum(not any(case.find(tag) is not None for tag in ("failure", "error", "skipped")) for case in cases)
    summary = [title, f"**{passed} passed, {len(failed)} failed, {len(errors)} errors, {len(skipped)} skipped.**\n\n"]
    # Bound summary size; the uploaded XML retains complete output.
    for case in (failed + errors)[:20]:
        name = f"{case.get('classname', '')}.{case.get('name', '')}"
        summary.append(f"<h3>{html.escape(name)}</h3>\n")
        for tag in ("failure", "error"):
            for problem in case.findall(tag):
                detail = problem.text or problem.get("message", "No traceback recorded.")
                summary.append(f"<pre>{html.escape(detail[:12000])}</pre>\n\n")
    if failed or errors:
        summary.append("See the uploaded test-results artifact for the complete JUnit report.\n")
    return "".join(summary)


if __name__ == "__main__":
    report = Path(sys.argv[1])
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as output:
        output.write(render_summary(report))
