from __future__ import annotations

import datetime as dt
import hashlib
import json
import re

from run_linux_gate0 import ROOT, command, require, restricted_run_args, sha256_text


def main() -> int:
    commit_id = require(["git", "rev-parse", "HEAD"])
    if require(["git", "status", "--porcelain"]):
        raise RuntimeError("worktree must be clean before a commit-bound AAT run")

    image = f"research-workbench-gate0:{commit_id[:12]}"
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

    test_args = restricted_run_args(image)
    test_result = command(test_args, timeout=240)
    count_match = re.search(r"Ran (\d+) tests", test_result.stderr)
    test_count = int(count_match.group(1)) if count_match else 0
    tests_pass = test_result.returncode == 0 and test_count >= 55 and "OK" in test_result.stderr

    vector_args = restricted_run_args(image)
    vector_args.extend(["python", "scripts/aat_golden_vector.py"])
    vector_result = command(vector_args, timeout=240)
    try:
        vector = json.loads(vector_result.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        vector = {}
    assertions = vector.get("assertions", {})
    vector_pass = vector_result.returncode == 0 and bool(assertions) and all(assertions.values())

    version_args = restricted_run_args(image)
    version_args.extend(
        [
            "python", "-c",
            "import importlib.metadata as m, json, platform; print(json.dumps({'python': platform.python_version(), 'jsonschema': m.version('jsonschema'), 'pypdf': m.version('pypdf'), 'reportlab': m.version('reportlab')}, sort_keys=True))",
        ]
    )
    version_result = command(version_args, timeout=60)
    dependency_versions = json.loads(version_result.stdout.strip()) if version_result.returncode == 0 else {}

    passed = tests_pass and vector_pass and revision == commit_id
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    fixture_manifest = vector.get("fixture_sha256", {})
    evidence = {
        "run_id": f"gate0-aat-golden-{now.strftime('%Y%m%dT%H%M%SZ')}",
        "executed_at": now.isoformat().replace("+00:00", "Z"),
        "environment_category": "local_colima_linux_isolated_container",
        "source_commit": commit_id,
        "source_tree_manifest_sha256": sha256_text(require(["git", "ls-tree", "-r", commit_id])),
        "container_image": image,
        "container_image_id": image_inspect["Id"],
        "container_revision_label": revision,
        "container_rootfs_layers": image_inspect["RootFS"]["Layers"],
        "dependency_versions": dependency_versions,
        "fixture_sha256": fixture_manifest,
        "fixture_manifest_sha256": hashlib.sha256(json.dumps(fixture_manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        "commands": {"full_regression": test_args, "aat_vector": vector_args, "versions": version_args},
        "test_result": {
            "passed": tests_pass,
            "tests_run": test_count,
            "returncode": test_result.returncode,
            "stderr_sha256": hashlib.sha256(test_result.stderr.encode()).hexdigest(),
        },
        "aat_vector": vector,
        "checks": assertions,
        "result": "pass" if passed else "fail",
        "complete_gate0": passed,
        "gate1_configuration_freeze_authorized": passed,
        "gate1_performance_score_recorded": False,
        "gate1_configuration_modified": False,
        "public_paid_launch_authorized": False,
        "limitations": [
            "The frozen AAT adapter proves known-case integration fidelity only.",
            "AAT is protocol-development evidence and is excluded from Gate 1 performance scoring.",
            "Public paid alpha remains blocked pending a separate launch authorization decision.",
        ],
    }
    output_path = ROOT / "evidence" / f"GATE0_AAT_GOLDEN_RUN_{now.strftime('%Y%m%dT%H%M%SZ')}.json"
    output_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print(output_path)
    print(json.dumps({"result": evidence["result"], "tests_run": test_count, "checks": assertions}, indent=2, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
