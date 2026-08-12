#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify that each commit in a range has a DCO 1.1 sign-off.

The sign-off email must match the commit author email. This is a local,
deterministic check; it does not claim that a GitHub App or branch rule is
installed.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass


REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/+\-]*$")
SIGNOFF_RE = re.compile(
    r"Signed-off-by:[ \t]+[^<>\r\n]+[ \t]+<([^<>\s]+@[^<>\s]+)>[ \t]*",
    flags=re.IGNORECASE,
)


class GateError(RuntimeError):
    """A deterministic DCO validation failure."""


@dataclass(frozen=True)
class Commit:
    sha: str
    author_email: str
    message: str


def git(*args: str) -> str:
    try:
        proc = subprocess.run(
            ["git", *args],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        raise GateError(f"cannot execute git: {exc}") from exc
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or "git failed"
        raise GateError(f"git {' '.join(args)}: {detail}")
    return proc.stdout.strip()


def resolve_commit(ref: str) -> str:
    if REF_RE.fullmatch(ref) is None:
        raise GateError(f"unsafe or unsupported revision name: {ref!r}")
    resolved = git("rev-parse", "--verify", f"{ref}^{{commit}}")
    if re.fullmatch(r"[0-9a-f]{40}", resolved) is None:
        raise GateError(f"git did not resolve {ref!r} to one full commit SHA")
    return resolved


def read_commit(sha: str) -> Commit:
    raw = git("show", "-s", "--format=%H%x00%ae%x00%B", sha, "--")
    fields = raw.split("\0", 2)
    if len(fields) != 3:
        raise GateError(f"{sha[:12]}: cannot parse commit identity/message")
    return Commit(sha=fields[0], author_email=fields[1], message=fields[2])


def parsed_trailers(message: str) -> list[str]:
    try:
        proc = subprocess.run(
            ["git", "interpret-trailers", "--parse"],
            input=message,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        raise GateError(f"cannot execute git interpret-trailers: {exc}") from exc
    if proc.returncode != 0:
        detail = proc.stderr.strip() or "git interpret-trailers failed"
        raise GateError(detail)
    return proc.stdout.splitlines()


def validate_commit(commit: Commit) -> None:
    author = commit.author_email.strip().casefold()
    if not author or "@" not in author:
        raise GateError(f"{commit.sha[:12]}: commit author email is absent")
    signoffs: list[str] = []
    for trailer in parsed_trailers(commit.message):
        match = SIGNOFF_RE.fullmatch(trailer)
        if match is not None:
            signoffs.append(match.group(1).casefold())
    if not signoffs:
        raise GateError(f"{commit.sha[:12]}: missing valid Signed-off-by trailer")
    if author not in signoffs:
        raise GateError(
            f"{commit.sha[:12]}: no Signed-off-by email matches author "
            f"{commit.author_email!r}"
        )


def check_range(base_ref: str, head_ref: str) -> int:
    base = resolve_commit(base_ref)
    head = resolve_commit(head_ref)
    merge_base = git("merge-base", base, head)
    if re.fullmatch(r"[0-9a-f]{40}", merge_base) is None:
        raise GateError("base and head do not have one valid merge base")
    commits = [
        sha
        for sha in git("rev-list", "--reverse", f"{merge_base}..{head}", "--").splitlines()
        if sha
    ]
    if not commits:
        raise GateError("DCO range contains no contribution commits")
    for sha in commits:
        validate_commit(read_commit(sha))
    print(
        "DCO sign-off gate: PASS: "
        f"{len(commits)} commit(s), merge-base={merge_base}, head={head}"
    )
    return len(commits)


def self_test() -> None:
    validate_commit(
        Commit(
            sha="1" * 40,
            author_email="dev@example.com",
            message="Subject\n\nSigned-off-by: Dev Example <dev@example.com>\n",
        )
    )
    validate_commit(
        Commit(
            sha="2" * 40,
            author_email="DEV@example.com",
            message=(
                "Subject\n\nSigned-off-by: Reviewer <reviewer@example.com>\n"
                "Signed-off-by: Dev Example <dev@EXAMPLE.com>\n"
            ),
        )
    )

    def reject(label: str, commit: Commit) -> None:
        try:
            validate_commit(commit)
        except GateError:
            return
        raise GateError(f"self-test mutation was accepted: {label}")

    reject(
        "missing trailer",
        Commit("3" * 40, "dev@example.com", "Subject only\n"),
    )
    reject(
        "malformed trailer",
        Commit("4" * 40, "dev@example.com", "Signed-off-by: dev@example.com\n"),
    )
    reject(
        "different email",
        Commit(
            "5" * 40,
            "author@example.com",
            "Signed-off-by: Other Person <other@example.com>\n",
        ),
    )
    reject(
        "sign-off text outside trailer block",
        Commit(
            "6" * 40,
            "dev@example.com",
            (
                "Subject\n\nSigned-off-by: Dev Example <dev@example.com>\n\n"
                "This paragraph follows the quoted sign-off text.\n"
            ),
        ),
    )
    print("DCO sign-off gate self-test: PASS")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check-range")
    check.add_argument("base")
    check.add_argument("head")
    sub.add_parser("self-test")
    args = parser.parse_args(argv[1:])
    try:
        if args.command == "self-test":
            self_test()
        else:
            check_range(args.base, args.head)
    except GateError as exc:
        print(f"DCO sign-off gate: FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
