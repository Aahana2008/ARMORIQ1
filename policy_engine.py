from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from datetime import datetime
import os

# ── Structured Policy Model ──────────────────────────────────────────────────
# This is NOT hardcoded if/else. It's a data-driven policy model.
# Each agent has a named policy with enforceable constraints.

@dataclass
class AgentPolicy:
    agent_id: str
    allowed_read_dirs: List[str]
    allowed_write_dirs: List[str]
    allowed_file_extensions: List[str]
    max_files_per_session: int
    max_file_size_kb: int
    can_quarantine: bool
    can_delete: bool
    can_write_reports: bool
    requires_score_above: float = 0.0   # for quarantine actions
    trusted_by: List[str] = field(default_factory=list)  # delegation

AGENT_POLICIES: Dict[str, AgentPolicy] = {
    "agent-detect": AgentPolicy(
        agent_id="agent-detect",
        allowed_read_dirs=["rtl_designs"],
        allowed_write_dirs=[],
        allowed_file_extensions=[".v", ".vh"],
        max_files_per_session=10,
        max_file_size_kb=500,
        can_quarantine=False,
        can_delete=False,
        can_write_reports=False,
    ),
    "agent-analysis": AgentPolicy(
        agent_id="agent-analysis",
        allowed_read_dirs=["rtl_designs", "outputs"],
        allowed_write_dirs=["outputs"],
        allowed_file_extensions=[".v", ".vh", ".json"],
        max_files_per_session=10,
        max_file_size_kb=500,
        can_quarantine=False,
        can_delete=False,
        can_write_reports=True,
    ),
    "agent-monitor": AgentPolicy(
        agent_id="agent-monitor",
        allowed_read_dirs=["rtl_designs", "outputs"],
        allowed_write_dirs=["outputs", "quarantine"],
        allowed_file_extensions=[".v", ".vh", ".json", ".txt"],
        max_files_per_session=10,
        max_file_size_kb=500,
        can_quarantine=True,
        can_delete=False,
        can_write_reports=True,
        requires_score_above=0.75,   # only quarantine CRITICAL designs
    ),
}

# ── Audit Log ────────────────────────────────────────────────────────────────
class AuditLogger:
    def __init__(self, log_path="audit_log.txt"):
        self.log_path = log_path

    def log(self, agent_id: str, action: str, target: str,
            allowed: bool, reason: str):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        status = "ALLOWED" if allowed else "BLOCKED"
        line = f"[{ts}] [{status}] agent={agent_id} action={action} target={target} reason={reason}\n"
        with open(self.log_path, "a") as f:
            f.write(line)
        print(line.strip())  # also print to console
        return {"ts": ts, "agent": agent_id, "action": action,
                "target": target, "allowed": allowed, "reason": reason}

# ── Policy Enforcer ───────────────────────────────────────────────────────────
class PolicyEnforcer:
    """
    Sits between agent reasoning and execution.
    Every action must pass through check() before it runs.
    """

    def __init__(self):
        self.logger = AuditLogger()
        self.session_counts: Dict[str, int] = {}

    def _count(self, agent_id: str) -> int:
        return self.session_counts.get(agent_id, 0)

    def _increment(self, agent_id: str):
        self.session_counts[agent_id] = self._count(agent_id) + 1

    def check(self, agent_id: str, action: str,
              filepath: str = "", score: float = 0.0) -> Tuple[bool, str]:
        """
        Evaluate a proposed action against the agent's policy.
        Returns (allowed: bool, reason: str)
        """
        policy = AGENT_POLICIES.get(agent_id)
        if not policy:
            reason = f"No policy found for agent '{agent_id}'"
            self.logger.log(agent_id, action, filepath, False, reason)
            return False, reason

        # ── Rule 1: Session file limit ────────────────────────────────────
        if self._count(agent_id) >= policy.max_files_per_session:
            reason = f"Session limit reached ({policy.max_files_per_session} files max)"
            self.logger.log(agent_id, action, filepath, False, reason)
            return False, reason

        # ── Rule 2: File extension ────────────────────────────────────────
        if filepath:
            ext = os.path.splitext(filepath)[1].lower()
            if ext and ext not in policy.allowed_file_extensions:
                reason = f"File type '{ext}' not permitted for {agent_id}"
                self.logger.log(agent_id, action, filepath, False, reason)
                return False, reason

        # ── Rule 3: File size ─────────────────────────────────────────────
        if filepath and os.path.exists(filepath):
            size_kb = os.path.getsize(filepath) / 1024
            if size_kb > policy.max_file_size_kb:
                reason = f"File too large ({size_kb:.1f}KB > {policy.max_file_size_kb}KB limit)"
                self.logger.log(agent_id, action, filepath, False, reason)
                return False, reason

        # ── Rule 4: Directory scope (READ) ────────────────────────────────
        if action == "read":
            allowed_dirs = [os.path.abspath(d) for d in policy.allowed_read_dirs]
            abs_path = os.path.abspath(filepath)
            if not any(abs_path.startswith(d) for d in allowed_dirs):
                reason = f"READ outside allowed dirs. Permitted: {policy.allowed_read_dirs}"
                self.logger.log(agent_id, action, filepath, False, reason)
                return False, reason

        # ── Rule 5: Directory scope (WRITE) ──────────────────────────────
        if action in ("write", "report"):
            if not policy.can_write_reports:
                reason = f"Agent {agent_id} is not permitted to write reports"
                self.logger.log(agent_id, action, filepath, False, reason)
                return False, reason
            allowed_dirs = [os.path.abspath(d) for d in policy.allowed_write_dirs]
            abs_path = os.path.abspath(filepath)
            if not any(abs_path.startswith(d) for d in allowed_dirs):
                reason = f"WRITE outside allowed dirs. Permitted: {policy.allowed_write_dirs}"
                self.logger.log(agent_id, action, filepath, False, reason)
                return False, reason

        # ── Rule 6: Quarantine permission + score threshold ───────────────
        if action == "quarantine":
            if not policy.can_quarantine:
                reason = f"Agent {agent_id} does not have quarantine permission"
                self.logger.log(agent_id, action, filepath, False, reason)
                return False, reason
            if score < policy.requires_score_above:
                reason = f"Score {score:.3f} below quarantine threshold ({policy.requires_score_above})"
                self.logger.log(agent_id, action, filepath, False, reason)
                return False, reason

        # ── Rule 7: Delete is never allowed ──────────────────────────────
        if action == "delete":
            reason = "DELETE is prohibited for all agents"
            self.logger.log(agent_id, action, filepath, False, reason)
            return False, reason

        # ── Rule 8: Protected files (golden models) ───────────────────────
        if filepath and os.path.basename(filepath).startswith("golden_"):
            reason = "Protected golden reference file — requires human approval"
            self.logger.log(agent_id, action, filepath, False, reason)
            return False, reason

        # ── All checks passed ─────────────────────────────────────────────
        self._increment(agent_id)
        reason = "All policy checks passed"
        self.logger.log(agent_id, action, filepath, True, reason)
        return True, reason
    
    