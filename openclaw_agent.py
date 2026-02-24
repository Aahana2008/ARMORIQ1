import os
import shutil
import json
from datetime import datetime
from policy_engine import PolicyEnforcer, AGENT_POLICIES

# Import your existing ArmorIQ components
from armoriq_ht_detection import (
    CompetitionVerilogParser,
    EnhancedGraphBuilder,
    HybridTrojanDetectionSystem,
    MCPServerRegistry,
    DetectionAgent,
    AnalysisAgent,
    MonitorAgent
)

class ArmorIQOpenClawAgent:
    """
    OpenClaw-based autonomous agent that:
    1. Watches rtl_designs/ for Verilog files
    2. Runs ArmorIQ detection pipeline
    3. Enforces policy before every real action
    4. Writes reports to outputs/
    5. Quarantines critical threats to quarantine/
    """

    def __init__(self):
        self.enforcer = PolicyEnforcer()
        self.mcp = MCPServerRegistry()
        self.parser = CompetitionVerilogParser()
        self.builder = EnhancedGraphBuilder(48)
        self.detector = HybridTrojanDetectionSystem()

        # Create output directories if they don't exist
        os.makedirs("rtl_designs", exist_ok=True)
        os.makedirs("outputs", exist_ok=True)
        os.makedirs("quarantine", exist_ok=True)

        self.results = []

    # ── ACTION: Read a file ───────────────────────────────────────────────────
    def action_read_file(self, agent_id: str, filepath: str) -> tuple:
        allowed, reason = self.enforcer.check(agent_id, "read", filepath)
        if not allowed:
            return None, reason
        with open(filepath, "r", errors="ignore") as f:
            return f.read(), reason

    # ── ACTION: Write a report ────────────────────────────────────────────────
    def action_write_report(self, agent_id: str,
                             filepath: str, content: dict) -> tuple:
        allowed, reason = self.enforcer.check(agent_id, "write", filepath)
        if not allowed:
            return False, reason
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w") as f:
            json.dump(content, f, indent=2, default=str)
        return True, reason

    # ── ACTION: Quarantine a file ─────────────────────────────────────────────
    def action_quarantine_file(self, agent_id: str,
                                src: str, score: float) -> tuple:
        allowed, reason = self.enforcer.check(
            agent_id, "quarantine", src, score=score)
        if not allowed:
            return False, reason
        dest = os.path.join("quarantine", os.path.basename(src))
        shutil.move(src, dest)
        return True, f"Moved to quarantine: {dest}"

    # ── ACTION: Delete (always blocked — for demo) ────────────────────────────
    def action_delete_file(self, agent_id: str, filepath: str) -> tuple:
        allowed, reason = self.enforcer.check(agent_id, "delete", filepath)
        return allowed, reason   # will always be False

    # ── MAIN PIPELINE ─────────────────────────────────────────────────────────
    def run(self):
        print("\n" + "="*60)
        print("  ArmorIQ x OpenClaw — Autonomous RTL Security Agent")
        print("="*60 + "\n")

        # Step 1: Discover files
        verilog_files = [
            os.path.join("rtl_designs", f)
            for f in os.listdir("rtl_designs")
            if f.endswith((".v", ".vh"))
        ]
        print(f"[DISCOVERY] Found {len(verilog_files)} RTL files\n")

        modules, graphs, filenames = [], [], []

        # Step 2: Detection Agent reads and parses files
        for filepath in verilog_files:
            content, reason = self.action_read_file("agent-detect", filepath)
            if content is None:
                print(f"  ✗ BLOCKED read: {filepath} — {reason}\n")
                continue

            print(f"  ✓ Reading: {filepath}")
            mod = self.parser.parse(content)
            self.mcp.call("mcp-parse", "tokenize", {"file": filepath})
            graph = self.builder.build(mod)
            self.mcp.call("mcp-graph", "build", {"nodes": len(mod.signals)})
            modules.append(mod)
            graphs.append(graph)
            filenames.append(filepath)

        if not modules:
            print("[ERROR] No files could be read. Check policies.\n")
            return

        # Step 3: Run ArmorIQ detection pipeline
        det_agent = DetectionAgent(self.mcp, self.detector)
        ana_agent = AnalysisAgent(self.mcp)
        mon_agent = MonitorAgent(self.mcp)

        predictions = det_agent.run(modules, graphs)
        for i, p in enumerate(predictions):
            p['filename'] = filenames[i]

        fingerprints = ana_agent.run(modules, predictions)
        summary = mon_agent.run(modules, predictions)

        # Step 4: Analysis Agent writes reports (policy checked)
        for pred, fp in zip(predictions, fingerprints):
            report_path = os.path.join(
                "outputs",
                os.path.basename(pred['filename']).replace(".v", "_report.json")
            )
            success, reason = self.action_write_report(
                "agent-analysis", report_path,
                {"verdict": pred, "fingerprint": fp}
            )
            if success:
                print(f"  ✓ Report written: {report_path}")
            else:
                print(f"  ✗ BLOCKED report: {reason}")

        # Step 5: Monitor Agent quarantines critical threats (policy checked)
        print("\n[QUARANTINE EVALUATION]\n")
        for pred in predictions:
            score = pred['hybrid_score']
            src = pred['filename']

            if pred['prediction'] == 1:
                success, reason = self.action_quarantine_file(
                    "agent-monitor", src, score)
                if success:
                    print(f"  ✓ QUARANTINED: {src} (score={score:.3f})")
                else:
                    print(f"  ✗ BLOCKED quarantine: {src} — {reason}")

        # Step 6: Demonstrate explicitly blocked actions for the demo
        print("\n[DEMO — INTENTIONAL POLICY VIOLATIONS]\n")

        # Attempt 1: Detection agent tries to quarantine (not permitted)
        _, r = self.action_quarantine_file(
            "agent-detect", filenames[0], 0.9)
        print(f"  agent-detect tries quarantine → {r}")

        # Attempt 2: Any agent tries to delete
        _, r = self.action_delete_file("agent-monitor", filenames[0])
        print(f"  agent-monitor tries delete → {r}")

        # Attempt 3: Read a protected golden file
        _, r = self.action_read_file(
            "agent-detect", "rtl_designs/golden_reference.v")
        print(f"  agent-detect reads golden file → {r}")

        # Attempt 4: Analysis agent tries to write outside allowed dir
        _, r = self.action_write_report(
            "agent-analysis", "rtl_designs/injected_report.json", {})
        print(f"  agent-analysis writes to source dir → {r}")

        print("\n[COMPLETE] Audit log written to audit_log.txt\n")
        return summary