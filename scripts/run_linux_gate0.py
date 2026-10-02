from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


def command(args: list[str], timeout: float = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def require(args: list[str], timeout: float = 120) -> str:
    result = command(args, timeout)
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(args)}\n{result.stderr[-2000:]}"
        )
    return result.stdout.strip()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def restricted_run_args(
    image: str,
    *,
    name: str | None = None,
    remove: bool = True,
    memory: str = "768m",
    pids: int = 64,
    cpus: str = "1.0",
    tmpfs: str = "128m",
    extra: list[str] | None = None,
) -> list[str]:
    args = ["docker", "run"]
    if remove:
        args.append("--rm")
    if name:
        args.extend(["--name", name])
    args.extend(
        [
            "--network", "none",
            "--read-only",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true",
            "--pids-limit", str(pids),
            "--memory", memory,
            "--memory-swap", memory,
            "--cpus", cpus,
            "--tmpfs", f"/tmp:rw,noexec,nosuid,size={tmpfs}",
            "--ulimit", "nofile=64:64",
        ]
    )
    args.extend(extra or [])
    args.append(image)
    return args


def inspect_container(name: str) -> dict[str, Any]:
    return json.loads(require(["docker", "inspect", name]))[0]


def remove_container(name: str) -> None:
    command(["docker", "rm", "-f", name], timeout=30)


def named_probe(
    image: str,
    mode: str,
    *,
    memory: str,
    pids: int = 16,
    cpus: str = "0.5",
    tmpfs: str = "8m",
    extra: list[str] | None = None,
    timeout: float = 20,
) -> tuple[subprocess.CompletedProcess[str], dict[str, Any], list[str]]:
    name = f"gate0-{mode}-{uuid.uuid4().hex[:10]}"
    args = restricted_run_args(
        image,
        name=name,
        remove=False,
        memory=memory,
        pids=pids,
        cpus=cpus,
        tmpfs=tmpfs,
        extra=extra,
    )
    args.extend(["python", "linux/exhaustion_worker.py", mode])
    try:
        result = command(args, timeout=timeout)
        state = inspect_container(name)["State"]
        return result, state, args
    finally:
        remove_container(name)


def json_output(result: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    try:
        return json.loads(result.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        return {}


def parser_version() -> str:
    source = (ROOT / "gate0" / "parser" / "worker.py").read_text(encoding="utf-8")
    match = re.search(r'^PARSER_VERSION = "([^"]+)"$', source, re.MULTILINE)
    if match is None:
        raise RuntimeError("PARSER_VERSION not found in gate0/parser/worker.py")
    return match.group(1)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", action="store_true")
    args = parser.parse_args()

    commit_id = require(["git", "rev-parse", "HEAD"])
    if require(["git", "status", "--porcelain"]):
        raise RuntimeError("worktree must be clean before a commit-bound run")
    image = f"research-workbench-gate0:{commit_id[:12]}"
    if args.build:
        require(
            [
                "docker", "build",
                "--build-arg", f"SOURCE_COMMIT={commit_id}",
                "--tag", image,
                "--file", "linux/Dockerfile",
                ".",
            ],
            timeout=600,
        )

    image_inspect = json.loads(require(["docker", "image", "inspect", image]))[0]
    revision = image_inspect["Config"]["Labels"]["org.opencontainers.image.revision"]
    if revision != commit_id:
        raise RuntimeError("container revision label does not match HEAD")

    unit_args = restricted_run_args(image)
    unit_result = command(unit_args, timeout=180)
    unit_count_match = re.search(r"Ran (\d+) tests", unit_result.stderr)
    unit_test_count = int(unit_count_match.group(1)) if unit_count_match else 0
    unit_pass = unit_result.returncode == 0 and unit_test_count >= 40 and "OK" in unit_result.stderr

    isolation_args = restricted_run_args(image)
    isolation_args.extend(["python", "linux/exhaustion_worker.py", "isolation"])
    isolation_result = command(isolation_args, timeout=30)
    isolation = json_output(isolation_result)
    isolation_pass = isolation_result.returncode == 0 and all(isolation.values())

    memory_result, memory_state, memory_args = named_probe(image, "memory", memory="64m")
    memory_pass = memory_result.returncode != 0 and bool(memory_state.get("OOMKilled"))

    cpu_result, cpu_state, cpu_args = named_probe(
        image,
        "cpu",
        memory="128m",
        extra=["--ulimit", "cpu=1:1"],
    )
    cpu_pass = cpu_result.returncode != 0 and int(cpu_state.get("ExitCode", 0)) != 0

    pids_result, pids_state, pids_args = named_probe(image, "pids", memory="128m", pids=16)
    pids_payload = json_output(pids_result)
    pids_pass = pids_result.returncode == 0 and pids_payload.get("pid_limit_enforced") is True

    disk_result, disk_state, disk_args = named_probe(image, "disk", memory="128m", tmpfs="8m")
    disk_payload = json_output(disk_result)
    disk_pass = disk_result.returncode == 0 and disk_payload.get("tmpfs_quota_enforced") is True

    output_result, output_state, output_args = named_probe(
        image,
        "output",
        memory="128m",
        extra=["--ulimit", "fsize=1048576:1048576"],
    )
    output_limit_observed = "File too large" in output_result.stderr or "Errno 27" in output_result.stderr
    output_pass = (
        output_result.returncode != 0
        and int(output_state.get("ExitCode", 0)) != 0
        and output_limit_observed
    )

    wall_name = f"gate0-wall-{uuid.uuid4().hex[:10]}"
    wall_args = restricted_run_args(
        image,
        name=wall_name,
        remove=False,
        memory="128m",
        pids=16,
        cpus="0.5",
        tmpfs="8m",
    )
    wall_args.extend(["python", "linux/exhaustion_worker.py", "sleep"])
    started = time.monotonic()
    process = subprocess.Popen(wall_args, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    wall_timeout_triggered = False
    try:
        process.communicate(timeout=1.0)
    except subprocess.TimeoutExpired:
        wall_timeout_triggered = True
        command(["docker", "kill", wall_name], timeout=15)
        process.communicate(timeout=15)
    elapsed = time.monotonic() - started
    wall_state = inspect_container(wall_name)["State"]
    remove_container(wall_name)
    wall_pass = wall_timeout_triggered and elapsed < 10 and int(wall_state.get("ExitCode", 0)) != 0

    residue_write_args = restricted_run_args(image, memory="128m", pids=16, tmpfs="8m")
    residue_write_args.extend(["python", "linux/exhaustion_worker.py", "residue-write"])
    residue_write = command(residue_write_args, timeout=30)
    residue_check_args = restricted_run_args(image, memory="128m", pids=16, tmpfs="8m")
    residue_check_args.extend(["python", "linux/exhaustion_worker.py", "residue-check"])
    residue_check = command(residue_check_args, timeout=30)
    residue_pass = (
        residue_write.returncode == 0
        and residue_check.returncode == 0
        and json_output(residue_check).get("prior_task_residue_absent") is True
    )

    checks = {
        "existing_40_tests": unit_pass,
        "non_root_read_only_no_network_no_host_credentials": isolation_pass,
        "memory_oom_kill": memory_pass,
        "cpu_hard_limit": cpu_pass,
        "pid_limit": pids_pass,
        "temporary_disk_quota": disk_pass,
        "output_file_limit": output_pass,
        "wall_clock_timeout": wall_pass,
        "cross_task_residue_cleanup": residue_pass,
    }
    passed = all(checks.values())

    tracked_tree = require(["git", "ls-tree", "-r", commit_id])
    fixture_lines = require(["git", "ls-tree", "-r", commit_id, "fixtures"])
    fixture_paths = require(
        ["git", "ls-tree", "-r", "--name-only", commit_id, "fixtures"]
    ).splitlines()
    fixture_sha256 = {
        path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
        for path in fixture_paths
    }
    runtime_args = restricted_run_args(image)
    runtime_args.extend(
        [
            "python",
            "-c",
            (
                "import importlib.metadata as m,json,platform;"
                "print(json.dumps({'python':platform.python_version(),"
                "'jsonschema':m.version('jsonschema'),'pypdf':m.version('pypdf'),"
                "'reportlab':m.version('reportlab')}))"
            ),
        ]
    )
    runtime = json.loads(require(runtime_args))
    base_image = json.loads(require(["docker", "image", "inspect", "python:3.11-slim-bookworm"]))[0]
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    evidence = {
        "run_id": f"gate0-linux-{now.strftime('%Y%m%dT%H%M%SZ')}",
        "executed_at": now.isoformat().replace("+00:00", "Z"),
        "environment_category": "local_colima_linux_isolated_container",
        "commit_id": commit_id,
        "source_tree_manifest_sha256": sha256_text(tracked_tree),
        "fixture_git_manifest_sha256": sha256_text(fixture_lines),
        "fixture_sha256": fixture_sha256,
        "container_image": image,
        "container_image_id": image_inspect["Id"],
        "container_rootfs_layers": image_inspect["RootFS"]["Layers"],
        "container_revision_label": revision,
        "base_image": {
            "reference": "python:3.11-slim-bookworm",
            "image_id": base_image["Id"],
            "repo_digests": base_image.get("RepoDigests", []),
        },
        "docker_version": require(["docker", "version", "--format", "{{.Server.Version}}"]),
        "linux_kernel": require(
            restricted_run_args(image) + ["python", "-c", "import platform; print(platform.release())"]
        ),
        "contract_versions": {"public_contract": "1.0", "parser_output": "parser-output-1.0"},
        "parser_version": parser_version(),
        "runtime": runtime,
        "commands": {
            "unit_tests": unit_args,
            "isolation": isolation_args,
            "memory": memory_args,
            "cpu": cpu_args,
            "pids": pids_args,
            "disk": disk_args,
            "output": output_args,
            "wall_clock": wall_args,
            "residue_write": residue_write_args,
            "residue_check": residue_check_args,
            "runtime": runtime_args,
        },
        "checks": checks,
        "observations": {
            "unit_test_returncode": unit_result.returncode,
            "unit_test_count": unit_test_count,
            "unit_test_stderr_sha256": sha256_text(unit_result.stderr),
            "isolation": isolation,
            "memory": {"returncode": memory_result.returncode, "state": memory_state},
            "cpu": {"returncode": cpu_result.returncode, "state": cpu_state},
            "pids": {"returncode": pids_result.returncode, "state": pids_state, "payload": pids_payload},
            "disk": {"returncode": disk_result.returncode, "state": disk_state, "payload": disk_payload},
            "output": {
                "returncode": output_result.returncode,
                "state": output_state,
                "file_too_large_observed": output_limit_observed,
                "stderr_sha256": sha256_text(output_result.stderr),
            },
            "wall_clock": {"timeout_triggered": wall_timeout_triggered, "elapsed_seconds": elapsed, "state": wall_state},
            "residue": json_output(residue_check),
        },
        "result": "pass" if passed else "fail",
        "complete_gate0": False,
        "aat_authorized": False,
        "public_paid_launch_authorized": False,
    }
    output_path = ROOT / "evidence" / f"GATE0_LINUX_RUN_{now.strftime('%Y%m%dT%H%M%SZ')}.json"
    output_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print(output_path)
    print(json.dumps(checks, indent=2, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
