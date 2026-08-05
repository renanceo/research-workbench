from __future__ import annotations

import json
import os
import socket
import sys
import time
from pathlib import Path


def emit(**values: object) -> None:
    print(json.dumps(values, sort_keys=True), flush=True)


def isolation_probe() -> None:
    network_denied = False
    try:
        socket.create_connection(("192.0.2.1", 9), timeout=0.2)
    except OSError:
        network_denied = True

    root_read_only = False
    try:
        Path("/gate0-write-probe").write_text("forbidden")
    except OSError:
        root_read_only = True

    emit(
        non_root=os.geteuid() != 0,
        network_denied=network_denied,
        root_read_only=root_read_only,
        docker_socket_absent=not Path("/var/run/docker.sock").exists(),
        host_home_absent=not Path("/host-home").exists(),
        production_credentials_absent=not any(
            key in os.environ
            for key in ("DATABASE_URL", "PAYMENT_SECRET", "AWS_SECRET_ACCESS_KEY", "OPENAI_API_KEY")
        ),
    )


def exhaust_memory() -> None:
    chunks = []
    while True:
        chunks.append(bytearray(8 * 1024 * 1024))


def exhaust_cpu() -> None:
    value = 1
    while True:
        value = (value * 3 + 1) % 1_000_000_007


def exhaust_processes() -> None:
    children: list[int] = []
    try:
        while True:
            pid = os.fork()
            if pid == 0:
                time.sleep(30)
                os._exit(0)
            children.append(pid)
    except (BlockingIOError, OSError):
        emit(pid_limit_enforced=True, children_created=len(children))
    finally:
        for pid in children:
            try:
                os.kill(pid, 9)
                os.waitpid(pid, 0)
            except OSError:
                pass


def exhaust_disk() -> None:
    try:
        with Path("/tmp/disk-exhaustion").open("wb") as handle:
            block = b"x" * (1024 * 1024)
            while True:
                handle.write(block)
                handle.flush()
    except OSError as exc:
        emit(tmpfs_quota_enforced=True, errno=exc.errno)


def exhaust_output_file() -> None:
    with Path("/tmp/output-exhaustion").open("wb") as handle:
        while True:
            handle.write(b"x" * (1024 * 1024))
            handle.flush()


def residue_write() -> None:
    Path("/tmp/prior-task-secret").write_text("must not survive")
    emit(residue_written=True)


def residue_check() -> None:
    emit(prior_task_residue_absent=not Path("/tmp/prior-task-secret").exists())


def main() -> None:
    modes = {
        "isolation": isolation_probe,
        "memory": exhaust_memory,
        "cpu": exhaust_cpu,
        "pids": exhaust_processes,
        "disk": exhaust_disk,
        "output": exhaust_output_file,
        "residue-write": residue_write,
        "residue-check": residue_check,
        "sleep": lambda: time.sleep(60),
    }
    try:
        mode = sys.argv[1]
        action = modes[mode]
    except (IndexError, KeyError):
        raise SystemExit("unknown exhaustion mode") from None
    action()


if __name__ == "__main__":
    main()

