"""Coding-agent runner invocation shared by the one-shot and phased drivers.

Maps neutral options onto a `pi`/`claude` print-mode command, optionally wraps it
in a timeout, and runs it. Two run helpers exist:

- `run_runner` streams combined output to stdout (and optionally tees it to a
  per-issue log), returning only the exit code — used by the legacy one-shot
  `issue.py` path.
- `run_agent_capture` streams to stdout, tees to a transcript file, and also
  returns the captured text so a phase can parse the agent's structured reply —
  used by the phased orchestrator.

Unix-only, standard library only.
"""

from __future__ import annotations

import datetime
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Sequence

from adw._exec import note

RUNNERS = ("pi", "claude")


def build_runner_command(
    runner: str,
    runner_bin: str,
    *,
    json_mode: bool,
    model: str,
    thinking: str,
    passthru: Sequence[str],
    prompt: str,
) -> list[str]:
    """Map the neutral options onto the runner's print-mode invocation."""

    cmd = [runner_bin, "-p"]
    if runner == "pi":
        if json_mode:
            cmd += ["--mode", "json"]
        if model:
            cmd += ["--model", model]
        if thinking:
            cmd += ["--thinking", thinking]
    else:  # claude
        if json_mode:
            cmd += ["--output-format", "stream-json", "--verbose"]
        if model:
            cmd += ["--model", model]
    cmd += list(passthru)
    cmd.append(prompt)
    return cmd


def wrap_timeout(cmd: Sequence[str], timeout: int) -> list[str]:
    """Prefix a command with `timeout --signal=INT N` when requested/available."""

    if timeout > 0:
        if shutil.which("timeout"):
            return ["timeout", "--signal=INT", str(timeout), *cmd]
        note("--timeout requested but 'timeout' not found; running without it")
    return list(cmd)


def run_runner(
    cmd: Sequence[str],
    log_dir: str,
    issue: "int | str",
    *,
    env: "dict[str, str] | None" = None,
) -> int:
    """Run the runner, optionally teeing combined output to a per-issue log."""

    if not log_dir:
        return subprocess.run(list(cmd), check=False, env=env).returncode

    os.makedirs(log_dir, exist_ok=True)
    stamp = _stamp()
    log_file = Path(log_dir) / f"issue-{issue}-{stamp}.log"
    note(f"logging transcript to {log_file}")
    rc, _ = _stream_to(cmd, log_file, env=env)
    return rc


def run_agent_capture(
    cmd: Sequence[str],
    transcript_path: "str | Path",
    *,
    env: "dict[str, str] | None" = None,
) -> "tuple[int, str]":
    """Run an agent phase, teeing output to `transcript_path`; return (rc, text)."""

    path = Path(transcript_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    return _stream_to(cmd, path, env=env)


def _stream_to(
    cmd: Sequence[str],
    log_file: Path,
    *,
    env: "dict[str, str] | None",
) -> "tuple[int, str]":
    """Stream a process's combined output to stdout and `log_file`; capture text."""

    chunks: list[str] = []
    with open(log_file, "w", encoding="utf-8") as handle:
        proc = subprocess.Popen(
            list(cmd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, env=env
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
            handle.write(line)
            chunks.append(line)
        rc = proc.wait()
    return rc, "".join(chunks)


def _stamp() -> str:
    """Return a filesystem-safe UTC-ish timestamp for log filenames."""

    return datetime.datetime.now().strftime("%Y%m%dT%H%M%S")
