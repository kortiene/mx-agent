#!/usr/bin/env python3
"""Populate GitHub labels, milestones, and roadmap issues from docs.

Intended to run inside GitHub Actions with GITHUB_TOKEN and GITHUB_REPOSITORY.
The script is idempotent by exact issue title: if an issue with the same title
already exists, it updates labels/milestone instead of creating a duplicate.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

API = os.environ.get("GITHUB_API_URL", "https://api.github.com")
TOKEN = os.environ.get("GITHUB_TOKEN")
REPO = os.environ.get("GITHUB_REPOSITORY")
ROOT = Path(__file__).resolve().parents[1]
BACKLOG = ROOT / "docs" / "github-issue-backlog.md"

LABELS: dict[str, str] = {
    "type:feature": "New functionality or implementation work",
    "type:bug": "Incorrect behavior or regression",
    "type:docs": "Documentation work",
    "type:security": "Security hardening or security-sensitive work",
    "type:testing": "Testing, integration tests, or test infrastructure",
    "type:ci": "Continuous integration, automation, or release workflow",
    "area:cli": "Command-line interface",
    "area:daemon": "Long-running local daemon",
    "area:ipc": "Local IPC between CLI and daemon",
    "area:matrix": "Matrix protocol/client integration",
    "area:protocol": "mx-agent event schemas and protocol types",
    "area:policy": "Authorization policy engine",
    "area:security": "Credential, trust, signing, or RCE boundary",
    "area:sandbox": "Sandboxing and process isolation",
    "area:streaming": "stdin/stdout/stderr/PTY streaming",
    "area:tasks": "Task DAG and invocation state",
    "area:tools": "Named tools and capability discovery",
    "area:docs": "Documentation",
    "area:ci": "CI and repository automation",
    "priority:p0": "Critical path for MVP or security",
    "priority:p1": "Important but not immediately blocking",
    "priority:p2": "Useful follow-up or polish",
    "status:blocked": "Blocked by another task or decision",
    "good-first-issue": "Suitable for first-time contributors",
    "roadmap:auto": "Generated from docs/github-issue-backlog.md",
}

LABEL_COLORS: dict[str, str] = {
    "type:feature": "0e8a16",
    "type:bug": "d73a4a",
    "type:docs": "0075ca",
    "type:security": "b60205",
    "type:testing": "5319e7",
    "type:ci": "1d76db",
    "area:cli": "c5def5",
    "area:daemon": "c5def5",
    "area:ipc": "c5def5",
    "area:matrix": "c5def5",
    "area:protocol": "c5def5",
    "area:policy": "c5def5",
    "area:security": "c5def5",
    "area:sandbox": "c5def5",
    "area:streaming": "c5def5",
    "area:tasks": "c5def5",
    "area:tools": "c5def5",
    "area:docs": "c5def5",
    "area:ci": "c5def5",
    "priority:p0": "b60205",
    "priority:p1": "fbca04",
    "priority:p2": "d4c5f9",
    "status:blocked": "000000",
    "good-first-issue": "7057ff",
    "roadmap:auto": "ededed",
}


class RoadmapIssue:
    def __init__(self, title, milestone, labels, body):
        self.title = title
        self.milestone = milestone
        self.labels = labels
        self.body = body


def request(method: str, path: str, data: dict[str, Any] | None = None) -> Any:
    if not TOKEN or not REPO:
        raise SystemExit("GITHUB_TOKEN and GITHUB_REPOSITORY are required")

    body = None if data is None else json.dumps(data).encode("utf-8")
    req = urllib.request.Request(
        f"{API}{path}",
        data=body,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {TOKEN}",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
            "User-Agent": "mx-agent-roadmap-populator",
        },
    )
    for attempt in range(5):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", errors="replace")
            if e.code in {403, 429, 500, 502, 503, 504} and attempt < 4:
                wait = 2**attempt
                print(f"{method} {path} -> {e.code}; retrying in {wait}s", file=sys.stderr)
                time.sleep(wait)
                continue
            raise RuntimeError(f"{method} {path} failed: {e.code} {raw}") from e


def paginate(path: str) -> list[Any]:
    out: list[Any] = []
    sep = "&" if "?" in path else "?"
    page = 1
    while True:
        items = request("GET", f"{path}{sep}per_page=100&page={page}")
        if not items:
            break
        out.extend(items)
        if len(items) < 100:
            break
        page += 1
    return out


def parse_backlog() -> tuple[list[str], list[RoadmapIssue]]:
    text = BACKLOG.read_text()
    milestones: list[str] = []
    issues: list[RoadmapIssue] = []
    current_milestone: str | None = None

    parts = re.split(r"(?m)^## Milestone (\d+) — (.+)$", text)
    # parts: preamble, num, name, content, num, name, content...
    for i in range(1, len(parts), 3):
        number = parts[i].strip()
        name = parts[i + 1].strip()
        content = parts[i + 2]
        current_milestone = f"{number}. {name}"
        milestones.append(current_milestone)

        issue_blocks = re.split(r"(?m)^### (\d+)\. (.+)$", content)
        for j in range(1, len(issue_blocks), 3):
            issue_no = issue_blocks[j].strip()
            issue_title = issue_blocks[j + 1].strip()
            block = issue_blocks[j + 2].strip()
            labels = ["roadmap:auto"]
            m = re.search(r"(?m)^Labels:\s*(.+)$", block)
            if m:
                labels += re.findall(r"`([^`]+)`", m.group(1))
            title = f"Phase issue {issue_no}: {issue_title}"
            body = (
                f"Roadmap source: `docs/github-issue-backlog.md`\n\n"
                f"Milestone: **{current_milestone}**\n\n"
                f"## Backlog Entry\n\n{block}\n"
            )
            issues.append(RoadmapIssue(title=title, milestone=current_milestone, labels=sorted(set(labels)), body=body))

    return milestones, issues


def ensure_labels() -> None:
    existing = {label["name"]: label for label in paginate(f"/repos/{REPO}/labels")}
    for name, description in LABELS.items():
        payload = {"name": name, "color": LABEL_COLORS.get(name, "ededed"), "description": description}
        if name in existing:
            request("PATCH", f"/repos/{REPO}/labels/{urllib.parse.quote(name, safe='')}", payload)
            print(f"updated label: {name}")
        else:
            request("POST", f"/repos/{REPO}/labels", payload)
            print(f"created label: {name}")


def ensure_milestones(names: list[str]) -> dict[str, int]:
    existing = {m["title"]: m for m in paginate(f"/repos/{REPO}/milestones?state=all")}
    result: dict[str, int] = {}
    for title in names:
        if title in existing:
            result[title] = existing[title]["number"]
            print(f"found milestone: {title}")
        else:
            created = request("POST", f"/repos/{REPO}/milestones", {"title": title, "state": "open"})
            result[title] = created["number"]
            print(f"created milestone: {title}")
    return result


def ensure_issues(issues: list[RoadmapIssue], milestone_numbers: dict[str, int]) -> None:
    existing = {issue["title"]: issue for issue in paginate(f"/repos/{REPO}/issues?state=all") if "pull_request" not in issue}
    for item in issues:
        payload = {
            "title": item.title,
            "body": item.body,
            "labels": item.labels,
            "milestone": milestone_numbers[item.milestone],
        }
        if item.title in existing:
            number = existing[item.title]["number"]
            request("PATCH", f"/repos/{REPO}/issues/{number}", payload)
            print(f"updated issue #{number}: {item.title}")
        else:
            created = request("POST", f"/repos/{REPO}/issues", payload)
            print(f"created issue #{created['number']}: {item.title}")


def main() -> None:
    milestones, issues = parse_backlog()
    print(f"parsed {len(milestones)} milestones and {len(issues)} issues")
    if "--dry-run" in sys.argv:
        for m in milestones:
            print(f"milestone: {m}")
        for it in issues:
            print(f"issue: {it.title} | {it.milestone} | {','.join(it.labels)}")
        return
    ensure_labels()
    milestone_numbers = ensure_milestones(milestones)
    ensure_issues(issues, milestone_numbers)


if __name__ == "__main__":
    main()
