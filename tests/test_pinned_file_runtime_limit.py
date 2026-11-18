"""Controlled characterization of pre-execution pins, not a sandbox escape.

Only disposable repository files are touched. A working OS sandbox is mandatory.
The final xfail is emitted only after observing a real passing receipt for the
runtime-rewritten check; setup/controls fail normally rather than being masked.
"""
import hashlib
import subprocess
import sys

import pytest

from nlip_receipts import ReceiptLedger, ToolCallProposal, Type3ReceiptExtension
from nlip_receipts.git_artifact import run_git, sandbox_available


def test_pinned_check_can_be_rewritten_inside_snapshot(tmp_path):
    if not sandbox_available():
        pytest.skip("Real OS sandbox required; do not substitute unsandboxed execution")
    work, destination = tmp_path / "work", tmp_path / "destination.git"
    work.mkdir()
    run_git(str(work), "init", "-b", "main")
    run_git(str(work), "config", "user.name", "Pin limitation test")
    run_git(str(work), "config", "user.email", "pin-test@example.invalid")
    subprocess.run(["git", "init", "-q", "--bare", str(destination)], check=True)
    driver = "import app\nexec(open('checks.py').read())\n"
    checks = "assert app.add(2, 3) == 5\n"
    wrong_app = "def add(a, b):\n    return -999\n"
    for path, text in {"driver.py": driver, "checks.py": checks, "app.py": wrong_app}.items():
        (work / path).write_text(text)
    run_git(str(work), "add", ".")
    run_git(str(work), "commit", "-qm", "Failing control with original pinned checks")
    ledger = ReceiptLedger(tmp_path / "ledger.db")
    ledger.register_caller_secret("test", "synthetic-pin-test-secret")
    ledger.set_policy(repo_id="test", destination="local", profile_id="p",
                      command=[sys.executable, "driver.py"], allowed_callers=["test"],
                      pinned_file_sha256={name: hashlib.sha256(text.encode()).hexdigest()
                                          for name, text in {"driver.py": driver, "checks.py": checks}.items()})
    ext = Type3ReceiptExtension(ledger=ledger, repos={"test": str(work)},
                               destinations={"local": str(destination)}, verify_sandbox="required")
    def verify():
        return ext.handle_proposal(ToolCallProposal(operation="verify", repo_id="test",
            destination="local", profile_id="p", artifact_ref="HEAD", caller_id="test",
            caller_secret="synthetic-pin-test-secret"))
    control, control_receipt = verify()
    assert control.reason_code == "VERIFICATION_CHECK_FAILED"
    assert control_receipt is not None and control_receipt.exit_code != 0

    # Only the unpinned application changes in Git. On import it rewrites the
    # still-correct pinned check inside the sandbox before the driver reads it.
    (work / "app.py").write_text("from pathlib import Path\n"
        "Path('checks.py').write_text('assert True\\n')\n"
        "print('runtime-check-rewritten')\n" + wrong_app)
    run_git(str(work), "add", "app.py")
    run_git(str(work), "commit", "-qm", "Rewrite check only during sandbox execution")
    assert (work / "checks.py").read_text() == checks
    decision, receipt = verify()
    assert (work / "checks.py").read_text() == checks  # host source remains untouched
    assert run_git(str(work), "show", "HEAD:checks.py").decode() == checks
    assert run_git(str(destination), "for-each-ref").strip() == b""  # no publication attempted
    assert receipt is not None, decision.reason_code
    if decision.reason_code == "VERIFICATION_PASSED":
        assert receipt.status == "passed" and receipt.exit_code == 0
        assert receipt.output_sha256 == hashlib.sha256(b"runtime-check-rewritten\n").hexdigest()
        pytest.xfail("Observed pre-execution-only pin: sandbox-local check rewrite earned passing receipt")
    assert decision.reason_code == "VERIFICATION_CHECK_FAILED"
