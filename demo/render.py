"""Plain-text table rendering shared by the demo and the CLI."""

from __future__ import annotations

from typing import Any, Mapping, Sequence


def format_table(rows: Sequence[Mapping[str, Any]], columns: Sequence[str], max_width: int = 32) -> str:
    """Render rows as a fixed-width text table."""
    def cell(v: Any) -> str:
        s = "NULL" if v is None else str(v)
        return s if len(s) <= max_width else s[: max_width - 3] + "..."

    widths = {c: len(c) for c in columns}
    for r in rows:
        for c in columns:
            widths[c] = max(widths[c], len(cell(r.get(c))))
    header = " | ".join(c.ljust(widths[c]) for c in columns)
    sep = "-+-".join("-" * widths[c] for c in columns)
    body = [" | ".join(cell(r.get(c)).ljust(widths[c]) for c in columns) for r in rows]
    return "\n".join([header, sep, *body]) if rows else header + "\n" + sep + "\n(no rows)"


def banner(title: str) -> str:
    line = "=" * 78
    return f"\n{line}\n  {title}\n{line}"
