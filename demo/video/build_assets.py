"""Collect REAL project data for the demo video (nothing in the video is mocked).

Runs the narrated demo and the test suite, measures the source tree, and writes
``demo/video/assets.js`` (``window.ASSETS = {...}``) for storyboard.html.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent / "assets.js"

TREE = [
    ("security/", "Security layer (no Spark dependency)", [
        "security/crypto.py", "security/policy.py", "security/audit.py", "security/anomaly.py"]),
    ("pipeline/", "Spark pipeline", [
        "pipeline/spark_session.py", "pipeline/ingest.py", "pipeline/gateway.py", "pipeline/context.py"]),
    ("entry points", "Presentation only: no security logic", [
        "demo/run_demo.py", "demo/scenario.py", "cli.py", "app.py"]),
    ("tests/ + docs/", "Evidence", [
        "tests/test_crypto.py", "tests/test_policy.py", "tests/test_audit.py",
        "tests/test_anomaly.py", "tests/test_spark_key_isolation.py",
        "tests/test_end_to_end.py", "tests/test_cli.py",
        "docs/architecture.md", "docs/threat-model.md", "docs/test-cases.md"]),
]


def run(cmd: list[str], env: dict) -> str:
    return subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True, check=True).stdout


def split_sections(text: str) -> dict[str, list[str]]:
    """Split demo stdout on its '  N. TITLE' banners."""
    sections: dict[str, list[str]] = {}
    current = "preamble"
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = re.match(r"^  (\d)\. (.+)$", line)
        if m and i > 0 and lines[i - 1].startswith("====="):
            current = m.group(1)
            sections[current] = [m.group(2)]
            continue
        if line.startswith("=====") or line.strip() == "DONE":
            continue
        sections.setdefault(current, []).append(line)
    return {k: [l for l in v] for k, v in sections.items()}


def main() -> None:
    env = {**os.environ}
    env.setdefault("SECURELAKEHOUSE_PASSPHRASE", "video-demo-passphrase")
    py = sys.executable

    demo = run([py, "demo/run_demo.py"], env)
    sections = split_sections(demo)

    pytest_out = run([py, "-m", "pytest", "-q", "-p", "no:cacheprovider"], env)
    summary = [l for l in pytest_out.splitlines() if " passed" in l][-1].strip()
    collected = run([py, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider"], env)
    per_file = Counter(l.split("::")[0] for l in collected.splitlines() if "::" in l)

    tree = []
    for group, label, files in TREE:
        tree.append({
            "group": group, "label": label,
            "files": [{"path": f, "lines": sum(1 for _ in (ROOT / f).open(encoding="utf-8"))}
                      for f in files],
        })

    assets = {
        "demo": sections,
        "tests": {"summary": summary, "per_file": dict(sorted(per_file.items()))},
        "tree": tree,
    }
    OUT.write_text("window.ASSETS = " + json.dumps(assets, indent=1) + ";\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}: demo sections={list(sections)} tests='{summary}'")


if __name__ == "__main__":
    main()
