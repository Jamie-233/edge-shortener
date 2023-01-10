"""Command-line entry point."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .lint import Issue, lint


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="netlint",
        description="Lint Cisco IOS / Huawei VRP configs for common security and hygiene mistakes.",
    )
    parser.add_argument("files", nargs="+", help="config file(s) to lint")
    parser.add_argument("--max-warnings", type=int, default=0,
                        help="exit non-zero if more than this many warnings (default 0)")
    args = parser.parse_args(argv)

    exit_code = 0
    for path in args.files:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
        issues = lint(text)
        errors = [i for i in issues if i.severity == "error"]
        warnings = [i for i in issues if i.severity == "warning"]
        print(f"{path}: {len(errors)} error(s), {len(warnings)} warning(s)")
        for i in issues:
            print(f"  [{i.severity.upper()}] {i.rule}: {i.detail}")
        if errors or len(warnings) > args.max_warnings:
            exit_code = 1
    return exit_code


if __name__ == "__main__":
    sys.exit(_main())
