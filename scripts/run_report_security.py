from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path

from run_linux_gate0 import ROOT, command, require, restricted_run_args, sha256_text


def main() -> int:
    commit_id = require(["git", "rev-parse", "HEAD"])
    if require(["git", "status", "--porcelain"]):
        raise RuntimeError("worktree must be clean before a commit-bound run")

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
    test_args.extend(["python", "-m", "unittest", "tests.test_report_pipeline", "-v"])
    test_result = command(test_args, timeout=180)
    test_pass = test_result.returncode == 0 and "Ran 10 tests" in test_result.stderr and "OK" in test_result.stderr

    vector_args = restricted_run_args(image)
    vector_args.extend(["python", "scripts/report_security_vector.py"])
    vector_result = command(vector_args, timeout=120)
    try:
        vector = json.loads(vector_result.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        vector = {}
    vector_pass = (
        vector_result.returncode == 0
        and bool(vector.get("assertions"))
        and all(vector["assertions"].values())
    )
    passed = test_pass and vector_pass

    fixture_paths = require(
        ["git", "ls-tree", "-r", "--name-only", commit_id, "fixtures/report-security"]
    ).splitlines()
    fixture_sha256 = {
        path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
        for path in fixture_paths
    }
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    evidence = {
        "run_id": f"gate0-report-security-{now.strftime('%Y%m%dT%H%M%SZ')}",
        "executed_at": now.isoformat().replace("+00:00", "Z"),
        "environment_category": "local_colima_linux_isolated_container",
        "source_commit": commit_id,
        "source_tree_manifest_sha256": sha256_text(require(["git", "ls-tree", "-r", commit_id])),
        "container_image": image,
        "container_image_id": image_inspect["Id"],
        "container_revision_label": revision,
        "container_rootfs_layers": image_inspect["RootFS"]["Layers"],
        "fixture_sha256": fixture_sha256,
        "versions": vector.get("versions", {}),
        "commands": {"tests": test_args, "security_vector": vector_args},
        "test_result": {
            "passed": test_pass,
            "tests_run": 10,
            "returncode": test_result.returncode,
            "stderr_sha256": hashlib.sha256(test_result.stderr.encode()).hexdigest(),
        },
        "security_vector": vector,
        "checks": {
            "schema_and_resource_rejection_before_persistence": test_pass,
            "raw_and_presentation_storage_isolation": vector.get("assertions", {}).get("raw_and_presentation_databases_separate", False),
            "raw_and_sanitized_hashes_distinct": vector.get("assertions", {}).get("raw_and_sanitized_hashes_are_distinct", False),
            "unified_safe_semantics_across_ui_review_admin_export": vector.get("assertions", {}).get("safe_body_equal_across_all_paths", False),
            "human_review_revalidation": vector.get("assertions", {}).get("semantic_equal_after_human_resave", False),
            "pdf_active_content_absent": vector.get("assertions", {}).get("pdf_has_no_active_content", False),
            "html_script_inert": vector.get("assertions", {}).get("script_not_executable_in_html", False),
        },
        "result": "pass" if passed else "fail",
        "aat_golden_case_authorized": passed,
        "complete_gate0": False,
        "public_paid_launch_authorized": False,
        "gate1_configuration_modified": False,
    }
    output_path = ROOT / "evidence" / f"GATE0_REPORT_SECURITY_RUN_{now.strftime('%Y%m%dT%H%M%SZ')}.json"
    output_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print(output_path)
    print(json.dumps(evidence["checks"], indent=2, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
