#!/usr/bin/env python3
"""Fast, dependency-free tour of the Strategic Defense workshop.

The tour reveals exercise answers and is intended for evaluation, instructor
rehearsal, or learners choosing the quick path. Use docs/participant-guide.md
for the evidence-first experience.
"""

from __future__ import annotations

import argparse
import io
import os
import sys
import time
from argparse import Namespace
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import workshop  # noqa: E402

WIDTH = 78


class Style:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def paint(self, text: str, *codes: str) -> str:
        if not self.enabled or not codes:
            return text
        return "".join(codes) + text + "\x1b[0m"

    BOLD = "\x1b[1m"
    DIM = "\x1b[2m"
    RED = "\x1b[31m"
    GREEN = "\x1b[32m"
    YELLOW = "\x1b[33m"
    CYAN = "\x1b[36m"


STEPS = [
    {
        "part": "SETUP",
        "title": "Verify the offline bundle",
        "narration": "Validate fixtures, OCSF semantics, detector behavior, and infrastructure policy markers.",
        "command": "python3 tools/workshop.py verify",
        "function": workshop.command_verify,
        "args": Namespace(),
    },
    {
        "part": "PART A · IAM",
        "title": "Find excessive agent authority",
        "narration": "Wildcard actions/resources and role delegation define potential impact if another control fails.",
        "command": "python3 tools/workshop.py iam",
        "function": workshop.command_iam,
        "args": Namespace(),
    },
    {
        "part": "PART A · INVOCATIONS",
        "title": "Classify evidence, not keywords",
        "narration": "Compare benign security discussion, direct/indirect attacks, disclosure, and distinct PII outcomes.",
        "command": "python3 tools/workshop.py prompts",
        "function": workshop.command_prompts,
        "args": Namespace(evidence=False),
    },
    {
        "part": "PART B · OCSF",
        "title": "Orient to a common event model",
        "narration": "Authentication and API Activity records preserve identity, source, cloud, session, and provider claims.",
        "command": "python3 tools/workshop.py schema",
        "function": workshop.command_schema,
        "args": Namespace(),
    },
    {
        "part": "PART B · TIMELINE",
        "title": "Follow one federation subject",
        "narration": "The feature branch reaches Azure, AWS, and GCP, followed by secret access and policy change.",
        "command": "python3 tools/workshop.py timeline",
        "function": workshop.command_timeline,
        "args": Namespace(),
    },
    {
        "part": "PART B · DETECTION",
        "title": "Expose the tuning problem",
        "narration": "The starter correctly finds the attack and also flags an expected release. The full lab asks you to tune and test it.",
        "command": "python3 tools/workshop.py detect",
        "function": workshop.command_detect,
        "args": Namespace(config=None, show_suppressed=False),
    },
]


def run_step(step: dict, style: Style, index: int) -> int:
    print()
    print(style.paint("=" * WIDTH, Style.CYAN))
    print(style.paint(f"{index}/{len(STEPS)}  {step['part']} — {step['title']}", Style.BOLD))
    print(style.paint(step["narration"], Style.DIM))
    print(style.paint("$ " + step["command"], Style.CYAN))
    print()
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        exit_code = step["function"](step["args"])
    for line in buffer.getvalue().rstrip().splitlines():
        if line.startswith("PASS:"):
            print(style.paint("  " + line, Style.GREEN))
        elif line.startswith("FAIL:") or line.startswith("ALERT "):
            print(style.paint("  " + line, Style.RED, Style.BOLD))
        else:
            print("  " + line)
    return exit_code


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fast", action="store_true", help="run with no pauses")
    parser.add_argument("--auto", action="store_true", help="pause for --delay seconds")
    parser.add_argument("--delay", type=float, default=5.0)
    parser.add_argument("--no-color", action="store_true")
    args = parser.parse_args()
    style = Style(
        enabled=not args.no_color
        and sys.stdout.isatty()
        and not os.environ.get("NO_COLOR")
    )

    print(style.paint("STRATEGIC DEFENSE — QUICK TOUR", Style.CYAN, Style.BOLD))
    print("For the evidence-first experience, use docs/participant-guide.md.")
    failures = 0
    for index, step in enumerate(STEPS, start=1):
        failures += run_step(step, style, index) != 0
        if args.auto and not args.fast:
            time.sleep(max(0.0, args.delay))
        elif not args.fast and not args.auto:
            try:
                input("\nPress Enter to continue ")
            except EOFError:
                pass

    print()
    if failures:
        print(style.paint(f"Tour completed with {failures} failing step(s).", Style.RED))
        return 1
    print(style.paint("Tour complete. Continue with the participant guide to tune the detector.", Style.GREEN))
    return 0


if __name__ == "__main__":
    sys.exit(main())
