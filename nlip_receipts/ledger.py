"""SE-protected SQLite ledger for policies, HMAC-authenticated verification receipts, and audit logs."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
import uuid
from contextlib import closing
from pathlib import Path
from typing import Optional

from .schemas import PolicyConfig, Type3Decision, VerificationReceipt

_DDL = (
    """CREATE TABLE IF NOT EXISTS meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS caller_credentials (
        caller_id TEXT PRIMARY KEY,
        secret_hmac TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS policies (
        repo_id TEXT NOT NULL,
        destination TEXT NOT NULL,
        profile_id TEXT NOT NULL,
        command_json TEXT NOT NULL,
        allowed_callers_json TEXT NOT NULL,
        pinned_files_json TEXT NOT NULL DEFAULT '{}',
        ttl_seconds REAL NOT NULL,
        single_use INTEGER NOT NULL,
        allow_tree_equiv INTEGER NOT NULL DEFAULT 0,
        allowed_branches_json TEXT NOT NULL DEFAULT '["main"]',
        policy_epoch INTEGER NOT NULL,
        updated_at REAL NOT NULL,
        PRIMARY KEY (repo_id, destination, profile_id)
    )""",
    """CREATE TABLE IF NOT EXISTS receipts (
        receipt_id TEXT PRIMARY KEY,
        issuer_id TEXT NOT NULL,
        caller_id TEXT NOT NULL,
        repo_id TEXT NOT NULL,
        destination TEXT NOT NULL,
        commit_oid TEXT NOT NULL,
        tree_oid TEXT NOT NULL,
        profile_id TEXT NOT NULL,
        command_sha256 TEXT NOT NULL,
        env_fingerprint TEXT NOT NULL,
        status TEXT NOT NULL,
        exit_code INTEGER NOT NULL,
        duration_ms REAL NOT NULL,
        output_sha256 TEXT NOT NULL,
        policy_epoch INTEGER NOT NULL,
        issued_at REAL NOT NULL,
        expires_at REAL NOT NULL,
        consumed INTEGER NOT NULL DEFAULT 0,
        hmac_tag TEXT NOT NULL
    )""",
    """CREATE INDEX IF NOT EXISTS idx_receipts_repo_tree
       ON receipts (repo_id, destination, tree_oid, profile_id, issued_at)""",
    """CREATE TABLE IF NOT EXISTS decisions (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        decision_id TEXT NOT NULL,
        recorded_at REAL NOT NULL,
        action TEXT NOT NULL,
        reason_code TEXT NOT NULL,
        operation TEXT NOT NULL,
        repo_id TEXT NOT NULL,
        caller_id TEXT NOT NULL,
        destination TEXT NOT NULL,
        commit_oid TEXT NOT NULL,
        tree_oid TEXT NOT NULL,
        receipt_id TEXT,
        conversation_id TEXT,
        sco_refs_json TEXT NOT NULL,
        latency_ms REAL NOT NULL,
        prev_hash TEXT NOT NULL,
        entry_hash TEXT NOT NULL
    )""",
)


class ReceiptLedger:
    """Thread-safe SQLite ledger owned exclusively by the Type-3 Security Extension."""

    def __init__(
        self,
        db_path: Path | str,
        hmac_key: Optional[bytes] = None,
        *,
        strict_caller_auth: bool = True,
    ):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._hmac_key = hmac_key or secrets.token_bytes(32)
        self.strict_caller_auth = strict_caller_auth
        self._init_db()
        self._restrict_permissions()

    def _restrict_permissions(self) -> None:
        """Keep the ledger owner-only, including files created by older versions with the default
        umask. Fails closed if a group- or world-writable ledger cannot be tightened."""
        mode = self.db_path.stat().st_mode & 0o777
        if mode & 0o077:
            try:
                os.chmod(self.db_path, 0o600)
            except OSError as exc:
                if mode & 0o022:
                    raise PermissionError(
                        f"ledger {self.db_path} is group/world-writable and could not be restricted"
                    ) from exc

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        if not self.db_path.exists():
            # Create the file 0600 before SQLite opens it, rather than chmod-ing afterwards.
            os.close(os.open(self.db_path, os.O_CREAT | os.O_WRONLY, 0o600))
        with self._lock, closing(self._connect()) as conn:
            conn.isolation_level = None
            conn.execute("BEGIN IMMEDIATE")  # serialize concurrent first-open migrations
            try:
                for stmt in _DDL:
                    conn.execute(stmt)
                dcols = {r["name"] for r in conn.execute("PRAGMA table_info(decisions)")}
                if "conversation_id" not in dcols:
                    conn.execute("ALTER TABLE decisions ADD COLUMN conversation_id TEXT")
                cols = {r["name"] for r in conn.execute("PRAGMA table_info(policies)")}
                if "allowed_branches_json" not in cols:
                    conn.execute(
                        "ALTER TABLE policies ADD COLUMN allowed_branches_json TEXT NOT NULL DEFAULT '[\"main\"]'"
                    )
                    # Ledgers from before sandboxed verify: retire every receipt they hold by
                    # advancing each policy epoch, so nothing verified unsandboxed can be spent.
                    conn.execute("UPDATE policies SET policy_epoch = policy_epoch + 1")
                conn.execute(
                    "INSERT OR IGNORE INTO meta (key, value) VALUES ('issuer_id', ?)",
                    (f"nlip-se-{uuid.uuid4().hex[:12]}",),
                )
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise

    def issuer_id(self) -> str:
        with self._lock, closing(self._connect()) as conn:
            row = conn.execute("SELECT value FROM meta WHERE key = 'issuer_id'").fetchone()
            return str(row["value"]) if row else "nlip-se-unknown"

    def _compute_receipt_hmac(self, rec: VerificationReceipt) -> str:
        fields = [
            rec.receipt_id,
            rec.issuer_id,
            rec.caller_id,
            rec.repo_id,
            rec.destination,
            rec.commit_oid,
            rec.tree_oid,
            rec.profile_id,
            rec.command_sha256,
            rec.env_fingerprint,
            rec.status,
            str(rec.exit_code),
            f"{rec.duration_ms:.3f}",
            rec.output_sha256,
            str(rec.policy_epoch),
            f"{rec.issued_at:.6f}",
            f"{rec.expires_at:.6f}",
        ]
        canonical = "|".join(f"{len(f)}:{f}" for f in fields).encode("utf-8")
        return hmac.new(self._hmac_key, canonical, hashlib.sha256).hexdigest()

    def verify_receipt_hmac(self, rec: VerificationReceipt) -> bool:
        expected = self._compute_receipt_hmac(rec)
        return hmac.compare_digest(expected, rec.hmac_tag or "")

    # ── Caller Credential Verification (ECMA-434 §7.2.1) ────────────────────
    def register_caller_secret(self, caller_id: str, secret: str) -> None:
        msg = f"caller|{len(caller_id)}:{caller_id}|{len(secret)}:{secret}".encode("utf-8")
        tag = hmac.new(self._hmac_key, msg, hashlib.sha256).hexdigest()
        with self._lock, closing(self._connect()) as conn, conn:
            conn.execute(
                """INSERT INTO caller_credentials (caller_id, secret_hmac)
                   VALUES (?, ?)
                   ON CONFLICT(caller_id) DO UPDATE SET secret_hmac = excluded.secret_hmac""",
                (caller_id, tag),
            )

    def verify_caller_secret(self, caller_id: str, secret: Optional[str]) -> bool:
        """If a secret is registered for `caller_id`, verify `secret` via HMAC.
        With `strict_caller_auth=True` (the default), unprovisioned caller identities fail closed
        (`False`). `strict_caller_auth=False` accepts any unprovisioned `caller_id` as asserted,
        which makes caller binding (Confused-Deputy protection) advisory only.
        """
        with self._lock, closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT secret_hmac FROM caller_credentials WHERE caller_id = ?",
                (caller_id,),
            ).fetchone()
        if not row:
            return not self.strict_caller_auth
        if not secret:
            return False
        msg = f"caller|{len(caller_id)}:{caller_id}|{len(secret)}:{secret}".encode("utf-8")
        candidate = hmac.new(self._hmac_key, msg, hashlib.sha256).hexdigest()
        return hmac.compare_digest(str(row["secret_hmac"]), candidate)

    # ── Policy Management ───────────────────────────────────────────────────
    def set_policy(
        self,
        *,
        repo_id: str,
        destination: str,
        profile_id: str = "default",
        command: list[str],
        allowed_callers: list[str],
        pinned_file_sha256: Optional[dict[str, str]] = None,
        ttl_seconds: float = 900.0,
        single_use: bool = True,
        allow_tree_equivalent_commits: bool = False,
        allowed_branches: Optional[list[str]] = None,
    ) -> PolicyConfig:
        now = time.time()
        pinned = pinned_file_sha256 or {}
        branches = list(allowed_branches) if allowed_branches is not None else ["main"]
        with self._lock, closing(self._connect()) as conn:
            conn.isolation_level = None
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    """INSERT INTO policies (
                        repo_id, destination, profile_id, command_json, allowed_callers_json,
                        pinned_files_json, ttl_seconds, single_use, allow_tree_equiv,
                        allowed_branches_json, policy_epoch, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
                    ON CONFLICT(repo_id, destination, profile_id) DO UPDATE SET
                        command_json = excluded.command_json,
                        allowed_callers_json = excluded.allowed_callers_json,
                        pinned_files_json = excluded.pinned_files_json,
                        ttl_seconds = excluded.ttl_seconds,
                        single_use = excluded.single_use,
                        allow_tree_equiv = excluded.allow_tree_equiv,
                        allowed_branches_json = excluded.allowed_branches_json,
                        policy_epoch = policies.policy_epoch + 1,
                        updated_at = excluded.updated_at
                    RETURNING policy_epoch
                    """,
                    (
                        repo_id,
                        destination,
                        profile_id,
                        json.dumps(command),
                        json.dumps(allowed_callers),
                        json.dumps(pinned, sort_keys=True),
                        float(ttl_seconds),
                        1 if single_use else 0,
                        1 if allow_tree_equivalent_commits else 0,
                        json.dumps(branches),
                        now,
                    ),
                ).fetchone()
                next_epoch = int(row["policy_epoch"])
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        return PolicyConfig(
            repo_id=repo_id,
            destination=destination,
            profile_id=profile_id,
            command=command,
            allowed_callers=allowed_callers,
            pinned_file_sha256=pinned,
            ttl_seconds=ttl_seconds,
            single_use=single_use,
            allow_tree_equivalent_commits=allow_tree_equivalent_commits,
            allowed_branches=branches,
            policy_epoch=next_epoch,
        )

    def get_policy(self, repo_id: str, destination: str, profile_id: str = "default") -> Optional[PolicyConfig]:
        with self._lock, closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT * FROM policies WHERE repo_id = ? AND destination = ? AND profile_id = ?",
                (repo_id, destination, profile_id),
            ).fetchone()
        if not row:
            return None
        return PolicyConfig(
            repo_id=row["repo_id"],
            destination=row["destination"],
            profile_id=row["profile_id"],
            command=json.loads(row["command_json"]),
            allowed_callers=json.loads(row["allowed_callers_json"]),
            pinned_file_sha256=json.loads(row["pinned_files_json"] or "{}"),
            ttl_seconds=float(row["ttl_seconds"]),
            single_use=bool(row["single_use"]),
            allow_tree_equivalent_commits=bool(row["allow_tree_equiv"]),
            allowed_branches=json.loads(row["allowed_branches_json"] or '["main"]'),
            policy_epoch=int(row["policy_epoch"]),
        )

    def revoke_policy(self, repo_id: str, destination: str, profile_id: str = "default") -> bool:
        """Delete a policy. Later `verify`/`publish` calls fail closed with POLICY_NOT_FOUND, and
        receipts issued under it can no longer be consumed (`mark_consumed` needs the live policy).
        Returns True if a policy was removed."""
        with self._lock, closing(self._connect()) as conn, conn:
            cur = conn.execute(
                "DELETE FROM policies WHERE repo_id = ? AND destination = ? AND profile_id = ?",
                (repo_id, destination, profile_id),
            )
            return cur.rowcount > 0

    def disable_destination(self, destination: str) -> int:
        """Revoke every policy that publishes to `destination`. Returns the number removed."""
        with self._lock, closing(self._connect()) as conn, conn:
            return conn.execute("DELETE FROM policies WHERE destination = ?", (destination,)).rowcount

    def clear_repo(self, repo_id: str) -> tuple[int, int]:
        """Purge policies and receipts for `repo_id`. The hash-chained decision log is kept, since
        deleting rows from it would break the chain. Returns (policies_removed, receipts_removed)."""
        with self._lock, closing(self._connect()) as conn, conn:
            pol = conn.execute("DELETE FROM policies WHERE repo_id = ?", (repo_id,)).rowcount
            rec = conn.execute("DELETE FROM receipts WHERE repo_id = ?", (repo_id,)).rowcount
            return pol, rec

    # ── Receipt Issuance & Lookup ───────────────────────────────────────────
    def issue_receipt(
        self,
        *,
        caller_id: str,
        repo_id: str,
        destination: str = "origin",
        commit_oid: str,
        tree_oid: str,
        profile_id: str,
        command_sha256: str,
        env_fingerprint: str,
        status: str,
        exit_code: int,
        duration_ms: float,
        output_sha256: str,
        policy_epoch: int,
        ttl_seconds: float,
        issued_at: Optional[float] = None,
    ) -> VerificationReceipt:
        now = issued_at if issued_at is not None else time.time()
        rec = VerificationReceipt(
            receipt_id=f"rcpt-{uuid.uuid4().hex[:16]}",
            issuer_id=self.issuer_id(),
            caller_id=caller_id,
            repo_id=repo_id,
            destination=destination,
            commit_oid=commit_oid,
            tree_oid=tree_oid,
            profile_id=profile_id,
            command_sha256=command_sha256,
            env_fingerprint=env_fingerprint,
            status=status,  # type: ignore[arg-type]
            exit_code=exit_code,
            duration_ms=duration_ms,
            output_sha256=output_sha256,
            policy_epoch=policy_epoch,
            issued_at=now,
            expires_at=now + float(ttl_seconds),
            consumed=False,
        )
        rec.hmac_tag = self._compute_receipt_hmac(rec)
        with self._lock, closing(self._connect()) as conn, conn:
            conn.execute(
                """INSERT INTO receipts (
                    receipt_id, issuer_id, caller_id, repo_id, destination, commit_oid, tree_oid,
                    profile_id, command_sha256, env_fingerprint, status, exit_code,
                    duration_ms, output_sha256, policy_epoch, issued_at, expires_at,
                    consumed, hmac_tag
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    rec.receipt_id,
                    rec.issuer_id,
                    rec.caller_id,
                    rec.repo_id,
                    rec.destination,
                    rec.commit_oid,
                    rec.tree_oid,
                    rec.profile_id,
                    rec.command_sha256,
                    rec.env_fingerprint,
                    rec.status,
                    rec.exit_code,
                    rec.duration_ms,
                    rec.output_sha256,
                    rec.policy_epoch,
                    rec.issued_at,
                    rec.expires_at,
                    0,
                    rec.hmac_tag,
                ),
            )
        return rec

    def _row_to_receipt(self, row: sqlite3.Row) -> VerificationReceipt:
        return VerificationReceipt(
            receipt_id=row["receipt_id"],
            issuer_id=row["issuer_id"],
            caller_id=row["caller_id"],
            repo_id=row["repo_id"],
            destination=row["destination"],
            commit_oid=row["commit_oid"],
            tree_oid=row["tree_oid"],
            profile_id=row["profile_id"],
            command_sha256=row["command_sha256"],
            env_fingerprint=row["env_fingerprint"],
            status=row["status"],
            exit_code=int(row["exit_code"]),
            duration_ms=float(row["duration_ms"]),
            output_sha256=row["output_sha256"],
            policy_epoch=int(row["policy_epoch"]),
            issued_at=float(row["issued_at"]),
            expires_at=float(row["expires_at"]),
            consumed=bool(row["consumed"]),
            hmac_tag=row["hmac_tag"],
        )

    def get_receipt(self, receipt_id: str) -> Optional[VerificationReceipt]:
        with self._lock, closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT * FROM receipts WHERE receipt_id = ?",
                (receipt_id,),
            ).fetchone()
        return self._row_to_receipt(row) if row else None

    def latest_receipt_for_tree(
        self,
        repo_id: str,
        tree_oid: str,
        profile_id: str,
        destination: Optional[str] = None,
    ) -> Optional[VerificationReceipt]:
        """Return the most recent verification receipt for `(repo_id, [destination,] tree_oid, profile_id)`.
        Used to enforce the superseding-failure invariant: a newer failed run on the same tree
        invalidates any older passing receipt for that tree.
        """
        with self._lock, closing(self._connect()) as conn:
            if destination is not None:
                row = conn.execute(
                    """SELECT * FROM receipts
                       WHERE repo_id = ? AND destination = ? AND tree_oid = ? AND profile_id = ?
                       ORDER BY rowid DESC LIMIT 1""",
                    (repo_id, destination, tree_oid, profile_id),
                ).fetchone()
            else:
                row = conn.execute(
                    """SELECT * FROM receipts
                       WHERE repo_id = ? AND tree_oid = ? AND profile_id = ?
                       ORDER BY rowid DESC LIMIT 1""",
                    (repo_id, tree_oid, profile_id),
                ).fetchone()
        return self._row_to_receipt(row) if row else None

    def mark_consumed(
        self,
        receipt_id: str,
        *,
        expected_epoch: Optional[int] = None,
        now: Optional[float] = None,
    ) -> bool:
        """Atomically consume `receipt_id` inside an immediate transaction, re-verifying against
        the live `policies` row that `policy_epoch` has not rotated, `status == 'passed'`,
        `now <= expires_at`, `consumed = 0`, and no newer row (`rowid`) superseded the tree.
        """
        current_time = now if now is not None else time.time()
        with self._lock, closing(self._connect()) as conn:
            conn.isolation_level = None
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT rowid, * FROM receipts WHERE receipt_id = ?",
                    (receipt_id,),
                ).fetchone()
                if (
                    not row
                    or int(row["consumed"]) != 0
                    or row["status"] != "passed"
                    or current_time > float(row["expires_at"])
                ):
                    conn.execute("ROLLBACK")
                    return False
                pol_row = conn.execute(
                    "SELECT policy_epoch FROM policies WHERE repo_id = ? AND destination = ? AND profile_id = ?",
                    (row["repo_id"], row["destination"], row["profile_id"]),
                ).fetchone()
                if not pol_row or int(row["policy_epoch"]) != int(pol_row["policy_epoch"]):
                    conn.execute("ROLLBACK")
                    return False
                if expected_epoch is not None and int(pol_row["policy_epoch"]) != int(expected_epoch):
                    conn.execute("ROLLBACK")
                    return False
                latest = conn.execute(
                    """SELECT status FROM receipts
                       WHERE repo_id = ? AND destination = ? AND tree_oid = ? AND profile_id = ?
                       ORDER BY rowid DESC LIMIT 1""",
                    (row["repo_id"], row["destination"], row["tree_oid"], row["profile_id"]),
                ).fetchone()
                if latest and latest["status"] != "passed":
                    conn.execute("ROLLBACK")
                    return False
                cur = conn.execute(
                    "UPDATE receipts SET consumed = 1 WHERE receipt_id = ? AND consumed = 0",
                    (receipt_id,),
                )
                conn.execute("COMMIT")
                return cur.rowcount == 1
            except BaseException:
                conn.execute("ROLLBACK")
                raise

    # ── Audit Log (ECMA-434 §7.2.4) ─────────────────────────────────────────
    def record_decision(self, decision: Type3Decision) -> str:
        now = time.time()
        with self._lock, closing(self._connect()) as conn:
            conn.isolation_level = None
            conn.execute("BEGIN IMMEDIATE")
            try:
                last = conn.execute(
                    "SELECT entry_hash FROM decisions ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                prev_hash = str(last["entry_hash"]) if last else ("0" * 64)
                sco_json = json.dumps(decision.sco_refs)
                fields = [
                    prev_hash,
                    decision.decision_id,
                    f"{now:.6f}",
                    decision.action,
                    decision.reason_code,
                    decision.operation,
                    decision.repo_id,
                    decision.caller_id,
                    decision.destination,
                    decision.commit_oid,
                    decision.tree_oid,
                    decision.receipt_id or "",
                    decision.conversation_id or "",
                    sco_json,
                    f"{decision.latency_ms:.3f}",
                ]
                payload = "|".join(f"{len(f)}:{f}" for f in fields).encode("utf-8")
                entry_hash = hashlib.sha256(payload).hexdigest()
                conn.execute(
                    """INSERT INTO decisions (
                        decision_id, recorded_at, action, reason_code, operation,
                        repo_id, caller_id, destination, commit_oid, tree_oid,
                        receipt_id, conversation_id, sco_refs_json, latency_ms, prev_hash, entry_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        decision.decision_id,
                        now,
                        decision.action,
                        decision.reason_code,
                        decision.operation,
                        decision.repo_id,
                        decision.caller_id,
                        decision.destination,
                        decision.commit_oid,
                        decision.tree_oid,
                        decision.receipt_id,
                        decision.conversation_id,
                        sco_json,
                        decision.latency_ms,
                        prev_hash,
                        entry_hash,
                    ),
                )
                conn.execute("COMMIT")
                return entry_hash
            except BaseException:
                conn.execute("ROLLBACK")
                raise

    def list_decisions(self, limit: int = 50) -> list[dict]:
        with self._lock, closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT * FROM decisions ORDER BY seq DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]
