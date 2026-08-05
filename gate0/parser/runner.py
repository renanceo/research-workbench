from __future__ import annotations

import json
import os
import resource
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from jsonschema import Draft202012Validator


WORKER = Path(__file__).with_name("worker.py").resolve()
PARSER_SCHEMA = WORKER.parents[2] / "contracts" / "v1" / "parser-output.schema.json"
PARSER_VALIDATOR = Draft202012Validator(json.loads(PARSER_SCHEMA.read_text()))


@dataclass(frozen=True)
class ParserLimits:
    timeout_seconds: float = 5.0
    cpu_seconds: int = 3
    memory_bytes: int = 512 * 1024 * 1024
    output_bytes: int = 2 * 1024 * 1024
    open_files: int = 32
    process_count: int = 16
    max_file_bytes: int = 20_000_000
    max_pages: int = 200
    max_page_points: int = 20_000
    max_text_chars: int = 1_000_000
    max_decoded_bytes: int = 100_000_000


class ParserIsolationError(RuntimeError):
    pass


def _limit_process(limits: ParserLimits) -> None:
    resource.setrlimit(resource.RLIMIT_CPU, (limits.cpu_seconds, limits.cpu_seconds))
    # macOS rejects practical RLIMIT_AS/RLIMIT_DATA values for this interpreter.
    # Linux isolated runners enforce the hard address-space cap here.
    if sys.platform != "darwin":
        resource.setrlimit(resource.RLIMIT_AS, (limits.memory_bytes, limits.memory_bytes))
        resource.setrlimit(resource.RLIMIT_NPROC, (limits.process_count, limits.process_count))
    resource.setrlimit(resource.RLIMIT_FSIZE, (limits.output_bytes, limits.output_bytes))
    resource.setrlimit(resource.RLIMIT_NOFILE, (limits.open_files, limits.open_files))


def _sandbox_profile(
    workspace: Path,
    python: Path,
    forbidden_read_roots: tuple[Path, ...],
) -> str:
    workspace = workspace.resolve()
    venv = python.parent.parent.resolve()
    denied_reads = "\n".join(
        f'(deny file-read* (subpath "{path.resolve()}"))'
        for path in forbidden_read_roots
        if path.exists()
    )
    return f"""(version 1)
(allow default)
(deny network*)
(deny file-write*)
(allow file-write* (subpath "{workspace}"))
{denied_reads}
(allow file-read* (subpath "{venv}"))
(allow file-read* (literal "{WORKER}"))
(allow file-read* (subpath "{workspace}"))
"""


def _rejected(document_sha256: str, code: str) -> dict[str, object]:
    return {
        "schema_version": "parser-output-1.0",
        "status": "rejected",
        "document_sha256": document_sha256,
        "page_count": 0,
        "text": "",
        "warnings": [],
        "error_code": code,
    }


class IsolatedParser:
    def __init__(
        self,
        python: Path,
        limits: ParserLimits | None = None,
        forbidden_read_roots: tuple[Path, ...] | None = None,
    ) -> None:
        self.python = python.absolute()
        self.limits = limits or ParserLimits()
        home = Path.home()
        self.forbidden_read_roots = forbidden_read_roots or (
            home / ".ssh",
            home / ".aws",
            home / ".config",
            home / ".codex",
            home / "Library" / "Keychains",
        )

    def parse(self, source: Path) -> dict[str, object]:
        import hashlib

        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        if source.stat().st_size > self.limits.max_file_bytes:
            return _rejected(digest, "INPUT_TOO_LARGE")
        try:
            return self._run(source=source)
        except subprocess.TimeoutExpired:
            return _rejected(digest, "PARSER_TIMEOUT")
        except (json.JSONDecodeError, ParserIsolationError):
            return _rejected(digest, "PARSER_PROTOCOL_ERROR")

    def probe_network(self) -> dict[str, object]:
        return self._run(extra_args=["--probe-network"])

    def probe_environment(self) -> dict[str, object]:
        return self._run(extra_args=["--probe-environment"])

    def probe_read(self, path: Path) -> dict[str, object]:
        return self._run(extra_args=["--probe-read", str(path)])

    def _run(
        self,
        source: Path | None = None,
        extra_args: list[str] | None = None,
    ) -> dict[str, object]:
        with tempfile.TemporaryDirectory(prefix="rw-parser-") as temp_name:
            workspace = Path(temp_name).resolve()
            input_path = workspace / "input.pdf"
            if source is not None:
                shutil.copyfile(source, input_path)
            profile = workspace / "parser.sb"
            profile.write_text(
                _sandbox_profile(workspace, self.python, self.forbidden_read_roots)
            )

            worker_command = [str(self.python), "-I", str(WORKER)]
            if sys.platform == "darwin":
                command = [
                    "/usr/bin/sandbox-exec",
                    "-f",
                    str(profile),
                    *worker_command,
                ]
            else:
                command = worker_command
            if source is not None:
                command.extend(
                    [
                        str(input_path),
                        "--max-file-bytes", str(self.limits.max_file_bytes),
                        "--max-pages", str(self.limits.max_pages),
                        "--max-page-points", str(self.limits.max_page_points),
                        "--max-text-chars", str(self.limits.max_text_chars),
                        "--max-decoded-bytes", str(self.limits.max_decoded_bytes),
                    ]
                )
            command.extend(extra_args or [])
            for protected in self.forbidden_read_roots:
                command.extend(["--forbid-read-root", str(protected)])
            completed = subprocess.run(
                command,
                cwd=workspace,
                env={"PATH": "/usr/bin:/bin", "PYTHONHASHSEED": "0"},
                capture_output=True,
                timeout=self.limits.timeout_seconds,
                preexec_fn=lambda: _limit_process(self.limits),
                check=False,
            )
            if completed.returncode != 0:
                diagnostic = completed.stderr.decode("utf-8", "replace")[:500]
                raise ParserIsolationError(
                    f"isolated parser exited with status {completed.returncode}: {diagnostic}"
                )
            if len(completed.stdout) > self.limits.output_bytes:
                raise ParserIsolationError("isolated parser output exceeded limit")
            payload = json.loads(completed.stdout)
            if source is not None:
                errors = list(PARSER_VALIDATOR.iter_errors(payload))
                if errors:
                    raise ParserIsolationError("isolated parser returned an invalid contract")
            return payload
