
import os
import re
import warnings
import json
import time
import uuid
import asyncio
import threading
import queue
from typing import Dict, List, Tuple, Optional, Any
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

import numpy as np
warnings.filterwarnings("ignore")

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.data import Data, Batch
from torch_geometric.nn import GATConv, global_mean_pool, global_max_pool, global_add_pool

import streamlit as st
import networkx as nx
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from scipy import stats

# ─────────────────────────────────────────────────────────────────────────────
# STREAMLIT CONFIG
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="ArmorIQ™ — Hardware Trojan Intelligence",
    layout="wide",
    initial_sidebar_state="expanded",
    page_icon="🛡️"
)

# ArmorIQ v2 CSS — Light-Navy theme, high readability, clear section identity
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@400;500;600;700&family=Space+Grotesk:wght@500;700&display=swap');

:root {
    /* Base palette — navy-white, easy on the eyes */
    --bg:           #f0f4f8;
    --bg-deep:      #e2e8f1;
    --surface:      #ffffff;
    --surface-2:    #f7f9fc;
    --border:       #d0d8e8;
    --border-strong:#b0bcd0;
    --text:         #1a2540;
    --text-2:       #4a5880;
    --text-muted:   #8898b0;

    /* Accent colours — vivid but accessible */
    --blue:         #1a6fff;
    --blue-soft:    #e8f1ff;
    --teal:         #00b4d8;
    --teal-soft:    #e0f7fc;
    --red:          #e63950;
    --red-soft:     #fff0f2;
    --green:        #16a34a;
    --green-soft:   #f0fdf4;
    --amber:        #d97706;
    --amber-soft:   #fffbeb;
    --purple:       #7c3aed;
    --purple-soft:  #f5f0ff;

    /* MCP identity colour */
    --mcp:          #0e7490;
    --mcp-soft:     #ecfeff;
    --mcp-border:   #67e8f9;

    /* Agent identity colour */
    --agent:        #7c3aed;
    --agent-soft:   #f5f0ff;
    --agent-border: #c4b5fd;
}

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
    background-color: var(--bg) !important;
    color: var(--text) !important;
}

#MainMenu, footer, header { visibility: hidden; }
.stApp { background-color: var(--bg) !important; }

/* ── Sidebar ── */
section[data-testid="stSidebar"] {
    background: var(--surface) !important;
    border-right: 1px solid var(--border);
}
section[data-testid="stSidebar"] * { color: var(--text) !important; }
section[data-testid="stSidebar"] .stRadio label,
section[data-testid="stSidebar"] .stCheckbox label { font-size: 0.9rem; }

/* ── Expanders ── */
.streamlit-expanderHeader {
    background: var(--surface-2) !important;
    color: var(--text) !important;
    border: 1px solid var(--border) !important;
    border-radius: 6px !important;
    font-family: 'Space Grotesk', sans-serif !important;
    font-weight: 600 !important;
    font-size: 0.9rem !important;
}

/* ── Metrics ── */
div[data-testid="metric-container"] {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 1rem 1.2rem;
    box-shadow: 0 1px 3px rgba(0,0,0,0.06);
}
div[data-testid="metric-container"] label {
    color: var(--text-muted) !important;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.12em;
}
div[data-testid="metric-container"] div[data-testid="stMetricValue"] {
    color: var(--blue) !important;
    font-family: 'Space Grotesk', sans-serif;
    font-size: 2rem !important;
    font-weight: 700;
}

/* ── Progress bar ── */
div[data-testid="stProgress"] > div > div { background: var(--blue) !important; }

/* ── Buttons ── */
.stButton > button {
    background: var(--blue) !important;
    color: #fff !important;
    border: none !important;
    font-family: 'Space Grotesk', sans-serif !important;
    font-weight: 600 !important;
    font-size: 0.88rem !important;
    border-radius: 6px !important;
    padding: 0.5rem 1.2rem !important;
    transition: background 0.18s;
}
.stButton > button:hover { background: #1458cc !important; }

/* ── File uploader ── */
div[data-testid="stFileUploader"] {
    background: var(--surface) !important;
    border: 2px dashed var(--border-strong) !important;
    border-radius: 10px !important;
}

/* ── Dataframe ── */
div[data-testid="stDataFrame"] {
    border: 1px solid var(--border) !important;
    border-radius: 8px !important;
    background: var(--surface) !important;
}

/* ════════════════════════════════════════
   ARMORIQ HEADER
════════════════════════════════════════ */
.aiq-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 24px 0 20px;
    border-bottom: 2px solid var(--border);
    margin-bottom: 28px;
}
.aiq-logo-block {}
.aiq-logo {
    font-family: 'Space Grotesk', sans-serif;
    font-size: 2.6rem;
    font-weight: 700;
    color: var(--blue);
    letter-spacing: -1px;
    line-height: 1;
}
.aiq-logo span.tm { font-size: 0.9rem; vertical-align: super; color: var(--text-muted); }
.aiq-tagline {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.72rem;
    color: var(--text-muted);
    letter-spacing: 0.18em;
    text-transform: uppercase;
    margin-top: 5px;
}
.aiq-badges { display: flex; gap: 8px; align-items: center; }
.aiq-badge {
    background: var(--blue-soft);
    color: var(--blue);
    border: 1px solid #b8d0ff;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.68rem;
    padding: 5px 12px;
    border-radius: 20px;
    font-weight: 600;
    letter-spacing: 0.06em;
    text-transform: uppercase;
}
.aiq-badge.teal {
    background: var(--teal-soft);
    color: var(--mcp);
    border-color: var(--mcp-border);
}
.aiq-badge.purple {
    background: var(--agent-soft);
    color: var(--agent);
    border-color: var(--agent-border);
}

/* ════════════════════════════════════════
   SECTION HEADERS
════════════════════════════════════════ */
.sec-header {
    font-family: 'Space Grotesk', sans-serif;
    font-size: 1.1rem;
    font-weight: 700;
    color: var(--text);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    border-left: 4px solid var(--blue);
    padding-left: 12px;
    margin: 32px 0 16px;
}
.sec-header.mcp-hdr  { border-left-color: var(--mcp);   color: var(--mcp);   }
.sec-header.agent-hdr{ border-left-color: var(--agent); color: var(--agent); }

/* ════════════════════════════════════════
   MCP PANEL  (teal identity)
════════════════════════════════════════ */
.mcp-outer {
    background: var(--mcp-soft);
    border: 1.5px solid var(--mcp-border);
    border-radius: 12px;
    padding: 0;
    overflow: hidden;
    margin-bottom: 16px;
}
.mcp-outer-header {
    background: var(--mcp);
    color: #fff;
    font-family: 'Space Grotesk', sans-serif;
    font-weight: 700;
    font-size: 0.85rem;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    padding: 10px 18px;
    display: flex;
    align-items: center;
    gap: 8px;
}
.mcp-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
    gap: 1px;
    background: var(--mcp-border);
}
.mcp-server-card {
    background: var(--surface);
    padding: 12px 16px;
    display: flex;
    flex-direction: column;
    gap: 3px;
}
.mcp-server-name {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.8rem;
    font-weight: 600;
    color: var(--mcp);
}
.mcp-server-cap {
    font-size: 0.77rem;
    color: var(--text-2);
    font-family: 'Inter', sans-serif;
}
.mcp-server-meta {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-top: 4px;
}
.mcp-dot { width: 7px; height: 7px; border-radius: 50%; display: inline-block; }
.mcp-dot.online  { background: var(--green); }
.mcp-dot.busy    { background: var(--amber); }
.mcp-dot.offline { background: var(--red); }
.mcp-req-count {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.7rem;
    color: var(--text-muted);
}

/* ════════════════════════════════════════
   AI AGENT PANEL  (purple identity)
════════════════════════════════════════ */
.agent-outer {
    background: var(--agent-soft);
    border: 1.5px solid var(--agent-border);
    border-radius: 12px;
    overflow: hidden;
    margin-bottom: 16px;
}
.agent-outer-header {
    background: var(--agent);
    color: #fff;
    font-family: 'Space Grotesk', sans-serif;
    font-weight: 700;
    font-size: 0.85rem;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    padding: 10px 18px;
    display: flex;
    align-items: center;
    gap: 8px;
}
.agent-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 14px 16px;
    margin: 10px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.78rem;
}
.agent-card.has-alert {
    border-color: var(--red);
    background: var(--red-soft);
}
.agent-card.is-clean {
    border-color: var(--green);
    background: var(--green-soft);
}
.agent-card.is-active {
    border-color: var(--blue);
    background: var(--blue-soft);
}
.agent-header-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 10px;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--border);
}
.agent-name {
    font-family: 'Space Grotesk', sans-serif;
    font-size: 0.9rem;
    font-weight: 700;
    color: var(--agent);
}
.agent-status-pill {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.65rem;
    font-weight: 600;
    padding: 2px 10px;
    border-radius: 20px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
}
.pill-idle     { background: #e5e7eb; color: #6b7280; }
.pill-active   { background: var(--blue-soft); color: var(--blue); }
.pill-alerting { background: var(--red-soft);  color: var(--red);  }
.pill-done     { background: var(--green-soft);color: var(--green);}

.log-line {
    color: var(--text-muted);
    font-size: 0.73rem;
    padding: 2px 0 2px 10px;
    border-left: 2px solid var(--border);
    margin: 2px 0;
    line-height: 1.5;
}
.log-line .ts { color: var(--blue); }
.log-line.ok   { color: var(--green); border-left-color: var(--green); }
.log-line.warn { color: var(--amber); border-left-color: var(--amber); }
.log-line.err  { color: var(--red);   border-left-color: var(--red);   }

/* ════════════════════════════════════════
   VERDICT CARDS
════════════════════════════════════════ */
.verdict-red {
    background: var(--red-soft);
    border: 1.5px solid var(--red);
    border-left: 5px solid var(--red);
    border-radius: 10px;
    padding: 18px 20px;
    margin: 10px 0;
}
.verdict-green {
    background: var(--green-soft);
    border: 1.5px solid #86efac;
    border-left: 5px solid var(--green);
    border-radius: 10px;
    padding: 18px 20px;
    margin: 10px 0;
}
.verdict-title-red   { font-family: 'Space Grotesk',sans-serif; font-size:1.3rem; font-weight:700; color:var(--red); }
.verdict-title-green { font-family: 'Space Grotesk',sans-serif; font-size:1.3rem; font-weight:700; color:var(--green); }
.verdict-sub { font-family:'JetBrains Mono',monospace; font-size:0.75rem; color:var(--text-2); margin-top:5px; }

/* ════════════════════════════════════════
   HT TYPE CHIPS
════════════════════════════════════════ */
.ht-type-chip {
    display: inline-block;
    background: var(--red-soft);
    border: 1px solid var(--red);
    color: var(--red);
    font-family: 'Space Grotesk', sans-serif;
    font-size: 0.8rem;
    font-weight: 600;
    padding: 5px 14px;
    border-radius: 6px;
    margin: 4px;
}
.ht-type-desc {
    font-size: 0.75rem;
    color: var(--text-2);
    margin-top: 4px;
    font-family: 'Inter', sans-serif;
}

/* ════════════════════════════════════════
   ANOMALY LOG LINES
════════════════════════════════════════ */
.anomaly-line {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.78rem;
    padding: 5px 10px;
    border-radius: 4px;
    margin: 3px 0;
}
.anomaly-line.crit { background: var(--red-soft);   color: var(--red);   border-left: 3px solid var(--red);   }
.anomaly-line.high { background: var(--amber-soft);  color: var(--amber); border-left: 3px solid var(--amber); }
.anomaly-line.med  { background: var(--blue-soft);   color: var(--blue);  border-left: 3px solid var(--blue);  }
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# ENUMS & CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────
class AgentState(Enum):
    IDLE       = "IDLE"
    ACTIVE     = "ACTIVE"
    ALERTING   = "ALERTING"
    COMPLETE   = "COMPLETE"

class ThreatLevel(Enum):
    CRITICAL  = ("CRITICAL",  "#ff2d4a")
    HIGH      = ("HIGH",      "#ff6600")
    MEDIUM    = ("MEDIUM",    "#ffaa00")
    LOW       = ("LOW",       "#00e5ff")
    CLEAN     = ("CLEAN",     "#00ff88")

TRADITIONAL_TROJAN_TYPES = {
    "Combinational":    "Logic-only trojan; no state; triggered by rare input pattern",
    "Sequential":       "FSM-based trojan; triggered after N clock cycles",
    "Functional":       "Modifies circuit function; always-on malicious behavior",
    "Parametric":       "Alters timing/power; not functionally detectable",
    "Covert Channel":   "Side-channel leak via power/EM emanation",
    "Kill Switch":      "Disables circuit on trigger condition",
    "Data Leakage":     "Exfiltrates secret keys or sensitive registers",
}


# ─────────────────────────────────────────────────────────────────────────────
# DATA STRUCTURES
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class VerilogSignal:
    name: str
    signal_type: str
    width: int = 1
    is_clock: bool = False
    is_reset: bool = False
    fanin: int = 0
    fanout: int = 0
    toggle_rate: float = 0.0

@dataclass
class VerilogModule:
    name: str
    signals: Dict[str, VerilogSignal]
    assignments: List[Tuple[str, str]]
    always_blocks: List[str]
    instances: List[str] = field(default_factory=list)
    parameters: Dict[str, str] = field(default_factory=dict)

@dataclass
class AgentMessage:
    agent_id: str
    agent_name: str
    timestamp: str
    level: str      # ok | info | warn | alert
    content: str
    data: Any = None

@dataclass
class MCPServer:
    server_id: str
    name: str
    capability: str
    status: str = "online"   # online | busy | offline
    requests_served: int = 0
    last_heartbeat: str = ""


# ─────────────────────────────────────────────────────────────────────────────
# MCP SERVER REGISTRY
# ─────────────────────────────────────────────────────────────────────────────
class MCPServerRegistry:
    """
    Model Context Protocol server registry.
    Each server exposes a specialized capability that AI agents call.
    """

    def __init__(self):
        self.servers: Dict[str, MCPServer] = {
            "mcp-parse":    MCPServer("mcp-parse",    "ArmorIQ/RTL-Parser",          "Verilog tokenisation & AST extraction"),
            "mcp-graph":    MCPServer("mcp-graph",    "ArmorIQ/Graph-Builder",        "Netlist → PyG graph construction"),
            "mcp-gnn":      MCPServer("mcp-gnn",      "ArmorIQ/GNN-Inference",        "4-layer GAT trojan scoring"),
            "mcp-stat":     MCPServer("mcp-stat",     "ArmorIQ/Statistical-Analyzer", "Structural anomaly & outlier detection"),
            "mcp-golden":   MCPServer("mcp-golden",   "ArmorIQ/Golden-Reference",     "Golden-model diff & deviation scoring"),
            "mcp-classify": MCPServer("mcp-classify", "ArmorIQ/HT-Classifier",        "Hybrid ensemble binary classification"),
            "mcp-report":   MCPServer("mcp-report",   "ArmorIQ/Report-Generator",     "JSON/CSV/Markdown report synthesis"),
            "mcp-monitor":  MCPServer("mcp-monitor",  "ArmorIQ/Live-Monitor",         "Real-time threat feed & dashboarding"),
        }
        self.call_log: List[Dict] = []

    def call(self, server_id: str, method: str, params: Dict = None) -> Dict:
        """Simulate an MCP tool call"""
        if server_id not in self.servers:
            return {"error": f"Unknown MCP server: {server_id}"}

        srv = self.servers[server_id]
        srv.status = "busy"
        srv.requests_served += 1
        srv.last_heartbeat = datetime.now().strftime("%H:%M:%S")

        call_record = {
            "server": server_id,
            "method": method,
            "params": list(params.keys()) if params else [],
            "ts": srv.last_heartbeat
        }
        self.call_log.append(call_record)

        # Simulate latency
        time.sleep(0.02)
        srv.status = "online"
        return {"status": "ok", "server": server_id, "method": method}

    def get_server_data(self) -> List[Dict]:
        """Return server data as plain dicts for rendering"""
        result = []
        for srv in self.servers.values():
            result.append({
                "name": srv.name,
                "capability": srv.capability,
                "status": srv.status,
                "requests": srv.requests_served,
                "heartbeat": srv.last_heartbeat,
            })
        return result


# ─────────────────────────────────────────────────────────────────────────────
# AI AGENT BASE + SPECIALIZED AGENTS
# ─────────────────────────────────────────────────────────────────────────────
class BaseAgent:
    """Base AI agent with MCP tool-calling capability"""

    def __init__(self, agent_id: str, name: str, mcp: MCPServerRegistry):
        self.agent_id  = agent_id
        self.name      = name
        self.mcp       = mcp
        self.state     = AgentState.IDLE
        self.log: List[AgentMessage] = []

    def emit(self, level: str, content: str, data: Any = None):
        msg = AgentMessage(
            agent_id=self.agent_id,
            agent_name=self.name,
            timestamp=datetime.now().strftime("%H:%M:%S.%f")[:-3],
            level=level,
            content=content,
            data=data
        )
        self.log.append(msg)
        return msg

    def run(self, *args, **kwargs):
        raise NotImplementedError


class MonitorAgent(BaseAgent):
    """
    Real-time monitor: watches all other agents, aggregates threat feeds,
    raises global alerts, updates live dashboard metrics.
    """

    def __init__(self, mcp: MCPServerRegistry):
        super().__init__("agent-monitor", "🛰️  MONITOR AGENT", mcp)
        self.threat_feed: List[Dict] = []

    def run(self, modules: List[VerilogModule], predictions: List[Dict]) -> Dict:
        self.state = AgentState.ACTIVE
        self.emit("info", "Monitor Agent online — initialising threat feed")
        self.mcp.call("mcp-monitor", "subscribe", {"feed": "global"})

        summary = {
            "total": len(predictions),
            "trojans": 0,
            "clean": 0,
            "critical": 0,
            "threat_events": []
        }

        for mod, pred in zip(modules, predictions):
            score = pred["hybrid_score"]
            fname = pred.get("filename", mod.name)

            if score >= 0.75:
                level = ThreatLevel.CRITICAL
                summary["critical"] += 1
                summary["trojans"] += 1
                self.emit("alert", f"CRITICAL THREAT detected in '{fname}' — score {score:.3f}", {"file": fname, "score": score})
            elif score >= 0.50:
                level = ThreatLevel.HIGH
                summary["trojans"] += 1
                self.emit("warn", f"HIGH THREAT in '{fname}' — score {score:.3f}", {"file": fname, "score": score})
            elif score >= 0.30:
                level = ThreatLevel.MEDIUM
                summary["trojans"] += 1
                self.emit("warn", f"MEDIUM THREAT in '{fname}' — score {score:.3f}")
            else:
                level = ThreatLevel.CLEAN
                summary["clean"] += 1
                self.emit("ok", f"'{fname}' assessed CLEAN — score {score:.3f}")

            event = {
                "file": fname, "module": mod.name,
                "score": score, "level": level.value[0],
                "color": level.value[1],
                "signals": len(mod.signals),
                "anomalies": pred["anomalies"].get("score", 0)
            }
            summary["threat_events"].append(event)
            self.threat_feed.append(event)

        self.mcp.call("mcp-monitor", "push_summary", summary)
        self.emit("info", f"Threat feed updated — {summary['trojans']} HT-infested / {summary['clean']} HT-free")
        self.state = AgentState.COMPLETE
        return summary


class AnalysisAgent(BaseAgent):
    """
    Deep analysis: runs multi-pass structural analysis, classifies
    hardware trojan type (combinational/sequential/functional/etc).
    """

    def __init__(self, mcp: MCPServerRegistry):
        super().__init__("agent-analysis", "🔬  ANALYSIS AGENT", mcp)

    def classify_trojan_type(self, module: VerilogModule, pred: Dict) -> List[str]:
        """Heuristically classify which traditional HT types are present"""
        detected = []
        anomalies = pred["anomalies"]

        # Sequential trojan — wide counter signals
        if anomalies.get("rare_signals"):
            detected.append("Sequential")
            self.emit("warn", f"Sequential HT pattern: wide counter signals detected → {anomalies['rare_signals'][:3]}")

        # Combinational trojan — complex logic in always blocks
        if anomalies.get("complex_logic"):
            detected.append("Combinational")
            self.emit("warn", f"Combinational HT pattern: {len(anomalies['complex_logic'])} high-complexity logic blocks")

        # Data leakage — isolated wide regs with no fanout
        if anomalies.get("isolated_signals"):
            detected.append("Data Leakage")
            self.emit("alert", f"Potential Data Leakage HT: {len(anomalies['isolated_signals'])} isolated signals")

        # Kill switch — high fanout from single suspicious signal
        if anomalies.get("high_fanout"):
            detected.append("Kill Switch")
            for name, fo in anomalies["high_fanout"][:2]:
                self.emit("alert", f"Kill Switch candidate: '{name}' → {fo} fanout connections")

        # Parametric / covert — unusual bit widths
        if anomalies.get("unusual_widths"):
            detected.append("Parametric")
            self.emit("warn", f"Parametric HT pattern: unusual signal widths detected")

        # Functional — suspicious naming
        if anomalies.get("suspicious_names"):
            detected.append("Functional")
            self.emit("alert", f"Functional HT names: {anomalies['suspicious_names'][:3]}")

        return list(set(detected)) if detected else ["No HT Pattern"]

    def run(self, modules: List[VerilogModule], predictions: List[Dict]) -> List[Dict]:
        self.state = AgentState.ACTIVE
        self.emit("info", "Analysis Agent initialised — loading structural models")
        self.mcp.call("mcp-stat", "configure", {"depth": "full", "golden": True})

        results = []
        for mod, pred in zip(modules, predictions):
            self.emit("info", f"Analysing '{mod.name}' ({len(mod.signals)} signals)")
            self.mcp.call("mcp-graph", "analyze", {"module": mod.name})

            ht_types = self.classify_trojan_type(mod, pred)

            # Compute structural fingerprint
            total_bits = sum(s.width for s in mod.signals.values())
            avg_fanout = np.mean([s.fanout for s in mod.signals.values()]) if mod.signals else 0

            fingerprint = {
                "module": mod.name,
                "file": pred.get("filename", mod.name),
                "ht_types": ht_types,
                "gnn_score": pred["gnn_score"],
                "stat_score": pred["statistical_score"],
                "hybrid_score": pred["hybrid_score"],
                "total_bits": total_bits,
                "avg_fanout": avg_fanout,
                "signal_density": len(mod.signals) / max(len(mod.always_blocks), 1),
                "is_trojan": pred["prediction"] == 1
            }
            results.append(fingerprint)

            if pred["prediction"] == 1:
                self.emit("alert", f"Trojan fingerprint: {', '.join(ht_types)}")
            else:
                self.emit("ok", f"'{mod.name}' — No significant trojan fingerprint")

        self.mcp.call("mcp-report", "store_fingerprints", {"count": len(results)})
        self.state = AgentState.COMPLETE
        self.emit("info", "Analysis complete — results written to MCP report server")
        return results


class DetectionAgent(BaseAgent):
    """
    Primary detection agent: orchestrates GNN + statistical scoring,
    applies adaptive thresholds, issues verdicts.
    """

    def __init__(self, mcp: MCPServerRegistry, detector):
        super().__init__("agent-detect", "⚡  DETECTION AGENT", mcp)
        self.detector = detector

    def run(self, modules: List[VerilogModule], graphs: List[Data],
            golden_features: Optional[Dict] = None) -> List[Dict]:
        self.state = AgentState.ACTIVE
        self.emit("info", "Detection Agent online — calling GNN inference server")
        self.mcp.call("mcp-gnn", "load_checkpoint", {"arch": "GAT-4L-256H"})

        predictions = []
        for i, (mod, graph) in enumerate(zip(modules, graphs)):
            self.emit("info", f"[{i+1}/{len(modules)}] Scoring '{mod.name}'")
            self.mcp.call("mcp-gnn", "infer", {"nodes": len(mod.signals)})
            self.mcp.call("mcp-stat", "analyze", {"signals": len(mod.signals)})

            pred = self.detector.predict(mod, graph, golden_features)
            pred["filename"] = pred.get("filename", mod.name)

            hs = pred["hybrid_score"]
            if hs > 0.75:
                self.emit("alert", f"VERDICT: HT-INFESTED  score={hs:.3f}  '{mod.name}'")
            elif hs > 0.50:
                self.emit("warn",  f"VERDICT: HT-INFESTED  score={hs:.3f}  '{mod.name}'")
            else:
                self.emit("ok",    f"VERDICT: HT-FREE      score={hs:.3f}  '{mod.name}'")

            self.mcp.call("mcp-classify", "commit_verdict", {"file": pred.get("filename")})
            predictions.append(pred)

        self.state = AgentState.COMPLETE
        self.emit("info", f"Detection complete — {len(predictions)} designs evaluated")
        return predictions


# ─────────────────────────────────────────────────────────────────────────────
# VERILOG PARSER (enhanced)
# ─────────────────────────────────────────────────────────────────────────────
class CompetitionVerilogParser:
    def __init__(self):
        self.signal_pattern  = re.compile(r'(input|output|wire|reg|inout)\s*(?:\[(\d+):(\d+)\])?\s*([\w,\s]+);')
        self.assign_pattern  = re.compile(r'assign\s+(\w+)\s*=\s*([^;]+);')
        self.always_pattern  = re.compile(r'always\s*@\((.*?)\)(.*?)(?=always|endmodule|$)', re.S)
        self.module_pattern  = re.compile(r'module\s+(\w+)')
        self.instance_pattern = re.compile(r'(\w+)\s+(?:#\(.*?\))?\s*(\w+)\s*\(', re.S)
        self.param_pattern   = re.compile(r'parameter\s+(\w+)\s*=\s*([^;]+);')

    def parse(self, content: str) -> VerilogModule:
        content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        content = re.sub(r'//.*', '', content)

        module_match = self.module_pattern.search(content)
        module_name  = module_match.group(1) if module_match else "unknown"

        signals, assignments, always_blocks, instances, parameters = {}, [], [], [], {}

        for m in self.signal_pattern.finditer(content):
            stype = m.group(1)
            hi = int(m.group(2)) if m.group(2) else 0
            lo = int(m.group(3)) if m.group(3) else 0
            width = abs(hi - lo) + 1
            for name in m.group(4).split(","):
                name = name.strip()
                if name:
                    signals[name] = VerilogSignal(
                        name, stype, width,
                        bool(re.search(r'clk|clock', name, re.I)),
                        bool(re.search(r'rst|reset', name, re.I))
                    )

        for m in self.assign_pattern.finditer(content):
            assignments.append((m.group(1).strip(), m.group(2).strip()))
        for m in self.always_pattern.finditer(content):
            always_blocks.append(m.group(0))
        for m in self.instance_pattern.finditer(content):
            instances.append(f"{m.group(1)} {m.group(2)}")
        for m in self.param_pattern.finditer(content):
            parameters[m.group(1)] = m.group(2).strip()

        return VerilogModule(module_name, signals, assignments, always_blocks, instances, parameters)


# ─────────────────────────────────────────────────────────────────────────────
# STATISTICAL DETECTOR
# ─────────────────────────────────────────────────────────────────────────────
class StatisticalTrojanDetector:
    def __init__(self):
        self.suspicious_patterns = [
            r'trigger', r'payload', r'malicious', r'trojan', r'backdoor',
            r'secret', r'hidden', r'rare', r'low_prob', r'attack',
            r'leak', r'covert', r'kill', r'bypass', r'shadow', r'ghost'
        ]

    def compute_structural_features(self, module: VerilogModule) -> Dict[str, float]:
        f = {
            'num_signals': len(module.signals),
            'num_assignments': len(module.assignments),
            'num_always_blocks': len(module.always_blocks),
            'num_instances': len(module.instances),
        }
        st = defaultdict(int)
        for sig in module.signals.values():
            st[sig.signal_type] += 1
        f['input_ratio']  = st['input']  / max(len(module.signals), 1)
        f['output_ratio'] = st['output'] / max(len(module.signals), 1)
        f['reg_ratio']    = st['reg']    / max(len(module.signals), 1)

        fanins  = [s.fanin  for s in module.signals.values()]
        fanouts = [s.fanout for s in module.signals.values()]
        widths  = [s.width  for s in module.signals.values()]
        f['avg_fanin']  = np.mean(fanins)  if fanins  else 0
        f['max_fanin']  = np.max(fanins)   if fanins  else 0
        f['avg_fanout'] = np.mean(fanouts) if fanouts else 0
        f['max_fanout'] = np.max(fanouts)  if fanouts else 0
        f['avg_width']  = np.mean(widths)  if widths  else 0
        f['max_width']  = np.max(widths)   if widths  else 0

        td = sum(len(re.findall(r'if|case|for|while', b)) for b in module.always_blocks)
        f['logic_complexity'] = td
        return f

    def analyze(self, module: VerilogModule, golden_features: Optional[Dict] = None) -> Dict:
        a = {k: [] for k in ['suspicious_names','unusual_widths','high_fanout',
                              'isolated_signals','complex_logic','rare_signals','golden_deviation']}
        a['score'] = 0.0

        for name in module.signals:
            for pat in self.suspicious_patterns:
                if re.search(pat, name, re.I):
                    a['suspicious_names'].append(name); a['score'] += 0.4; break

        widths = [s.width for s in module.signals.values()]
        if widths:
            mu, sd = np.mean(widths), np.std(widths)
            for name, sig in module.signals.items():
                if sig.width > mu + 2.5*sd and sig.width > 8:
                    a['unusual_widths'].append((name, sig.width)); a['score'] += 0.15

        fanouts = [s.fanout for s in module.signals.values() if s.fanout > 0]
        if fanouts:
            thr = np.percentile(fanouts, 90) if len(fanouts) > 5 else 10
            for name, sig in module.signals.items():
                if sig.fanout > thr and sig.fanout > 8:
                    a['high_fanout'].append((name, sig.fanout)); a['score'] += 0.20

        for name, sig in module.signals.items():
            if sig.fanin == 0 and sig.fanout == 0 and sig.signal_type not in ['input','output']:
                a['isolated_signals'].append(name); a['score'] += 0.25

        for block in module.always_blocks:
            c = len(re.findall(r'if|case', block))
            if c > 7:
                a['complex_logic'].append(c); a['score'] += 0.30

        for name, sig in module.signals.items():
            if re.search(r'cnt|counter|count', name, re.I) and sig.width > 16:
                a['rare_signals'].append(name); a['score'] += 0.20

        if golden_features:
            cf = self.compute_structural_features(module)
            for key in ['num_signals', 'num_assignments', 'logic_complexity']:
                if key in golden_features and key in cf:
                    dev = abs(cf[key] - golden_features[key]) / max(golden_features[key], 1)
                    if dev > 0.20:
                        a['golden_deviation'].append((key, dev)); a['score'] += 0.30*dev

        a['score'] = min(a['score'], 1.0)
        ni = sum(len(v) if isinstance(v, list) else 0 for v in a.values())
        a['confidence'] = min(ni / 10.0, 1.0)
        return a


# ─────────────────────────────────────────────────────────────────────────────
# GRAPH BUILDER
# ─────────────────────────────────────────────────────────────────────────────
class EnhancedGraphBuilder:
    def __init__(self, feature_dim=48):
        self.feature_dim = feature_dim
        self.type_map = {'input':0,'output':1,'wire':2,'reg':3,'inout':4}

    def _sigs(self, expr):
        kw = {'if','else','case','default','begin','end','posedge','negedge'}
        return [s for s in re.findall(r'\b[a-zA-Z_]\w*\b', expr) if s not in kw]

    def _graph_metrics(self, G, node):
        try:
            bc = nx.betweenness_centrality(G).get(node, 0) if len(G)>1 else 0
            cc = nx.closeness_centrality(G).get(node, 0)   if nx.is_weakly_connected(G) else 0
            pr = nx.pagerank(G).get(node, 0) * 10          if len(G)>1 else 0
            cl = nx.clustering(G.to_undirected()).get(node, 0)
        except:
            bc, cc, pr, cl = 0,0,0,0
        return {'betweenness':bc,'closeness':cc,'pagerank':pr,'clustering':cl}

    def build(self, module: VerilogModule) -> Data:
        node_map = {n:i for i,n in enumerate(module.signals)}
        n = len(node_map)
        if n == 0:
            return Data(x=torch.zeros((1,self.feature_dim)),
                        edge_index=torch.zeros((2,0),dtype=torch.long),
                        edge_attr=torch.zeros((0,1)))

        x = torch.zeros((n, self.feature_dim))
        edges, eattrs = [], []
        G = nx.DiGraph(); [G.add_node(nm) for nm in module.signals]
        fanin, fanout = defaultdict(int), defaultdict(int)

        for tgt, expr in module.assignments:
            for src in self._sigs(expr):
                if src in node_map and tgt in node_map:
                    edges.append((node_map[src], node_map[tgt])); eattrs.append(0)
                    G.add_edge(src, tgt); fanout[src]+=1; fanin[tgt]+=1

        for block in module.always_blocks:
            for lhs, rhs in re.findall(r'(\w+)\s*<=\s*([^;]+);', block):
                for src in self._sigs(rhs):
                    if src in node_map and lhs in node_map:
                        edges.append((node_map[src],node_map[lhs])); eattrs.append(1)
                        G.add_edge(src,lhs); fanout[src]+=1; fanin[lhs]+=1
            for lhs, rhs in re.findall(r'(\w+)\s*=\s*([^;]+);', block):
                for src in self._sigs(rhs):
                    if src in node_map and lhs in node_map:
                        edges.append((node_map[src],node_map[lhs])); eattrs.append(2)
                        G.add_edge(src,lhs); fanout[src]+=1; fanin[lhs]+=1

        all_widths  = [s.width for s in module.signals.values()]
        all_fanouts = [fanout[nm] for nm in module.signals]
        mw, sw = (np.mean(all_widths), np.std(all_widths)+1e-6) if all_widths else (0,1)
        mf, sf = (np.mean(all_fanouts),np.std(all_fanouts)+1e-6) if all_fanouts else (0,1)

        for name, idx in node_map.items():
            sig = module.signals[name]
            ti = self.type_map.get(sig.signal_type, 2)
            x[idx, ti] = 1
            x[idx, 5]  = min(sig.width/64.0,1.0)
            x[idx, 6]  = 1 if sig.width>32 else 0
            x[idx, 7]  = np.log2(sig.width+1)/8.0
            x[idx, 8]  = 1 if sig.is_clock else 0
            x[idx, 9]  = 1 if sig.is_reset else 0
            x[idx,10]  = min(fanin[name]/20.0,1.0)
            x[idx,11]  = min(fanout[name]/20.0,1.0)
            x[idx,12]  = min(fanin[name],10)
            x[idx,13]  = min(fanout[name],10)
            for fi,(pat) in enumerate([
                r'temp|tmp|aux',r'cnt|counter',r'state|status|mode',r'enable|en\b|valid',
                r'trigger|trig|fire',r'payload|data|secret',r'sel|mux|select',
                r'flag|bit|indicator',r'leak|covert|kill',
            ], start=14):
                x[idx,fi] = 1 if re.search(pat,name,re.I) else 0
            x[idx,23] = 1 if len(name)>20 else 0
            gm = self._graph_metrics(G, name)
            x[idx,24] = gm['betweenness']
            x[idx,25] = gm['closeness']
            x[idx,26] = gm['pagerank']
            x[idx,27] = gm['clustering']
            x[idx,28] = 1 if (fanin[name]==0 and fanout[name]==0) else 0
            x[idx,29] = 1 if (fanin[name]==0 and sig.signal_type not in['input']) else 0
            x[idx,30] = 1 if (fanout[name]==0 and sig.signal_type not in['output']) else 0
            x[idx,31] = (sig.width - mw) / sw
            x[idx,32] = (fanout[name] - mf) / sf
            x[idx,33] = 1 if fanout[name]>15 else 0
            x[idx,34] = 1 if (sig.width>16 and fanout[name]==1) else 0
            x[idx,35] = 1 if fanin[name]>10 else 0
            x[idx,36] = 1 if re.search(r'\d+$', name) else 0

            module.signals[name].fanin  = fanin[name]
            module.signals[name].fanout = fanout[name]

        ei = torch.tensor(edges,dtype=torch.long).t() if edges else torch.zeros((2,0),dtype=torch.long)
        ea = torch.tensor(eattrs,dtype=torch.float).unsqueeze(1) if eattrs else torch.zeros((0,1))
        return Data(x=x, edge_index=ei, edge_attr=ea)


# ─────────────────────────────────────────────────────────────────────────────
# GNN MODEL
# ─────────────────────────────────────────────────────────────────────────────
class ArmorIQ_GNN(nn.Module):
    def __init__(self, input_dim=48, hidden_dim=256, num_layers=4):
        super().__init__()
        self.embed = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.BatchNorm1d(hidden_dim), nn.ELU(), nn.Dropout(0.15)
        )
        self.gat_layers  = nn.ModuleList([GATConv(hidden_dim,hidden_dim//8,heads=8,dropout=0.15,concat=True) for _ in range(num_layers)])
        self.batch_norms = nn.ModuleList([nn.BatchNorm1d(hidden_dim) for _ in range(num_layers)])
        pool_dim = hidden_dim * 3
        self.classifier = nn.Sequential(
            nn.Linear(pool_dim,hidden_dim*2), nn.ELU(), nn.Dropout(0.3),
            nn.Linear(hidden_dim*2,hidden_dim), nn.ELU(), nn.Dropout(0.3),
            nn.Linear(hidden_dim,hidden_dim//2), nn.ELU(),
            nn.Linear(hidden_dim//2,2)
        )

    def forward(self, data):
        x,ei,batch = data.x, data.edge_index, data.batch
        x = self.embed(x)
        for i,(gat,bn) in enumerate(zip(self.gat_layers,self.batch_norms)):
            xp = x; x = F.elu(gat(x,ei)); x = bn(x)
            if i>0: x = x+xp
            x = F.dropout(x,p=0.15,training=self.training)
        g = torch.cat([global_mean_pool(x,batch),global_max_pool(x,batch),global_add_pool(x,batch)],dim=1)
        out = self.classifier(g)
        return out, g


# ─────────────────────────────────────────────────────────────────────────────
# HYBRID DETECTOR
# ─────────────────────────────────────────────────────────────────────────────
class HybridTrojanDetectionSystem:
    def __init__(self, gnn_weight=0.6, stat_weight=0.4):
        self.gnn_weight  = gnn_weight
        self.stat_weight = stat_weight
        self.gnn_model   = ArmorIQ_GNN(48,256,4); self.gnn_model.eval()
        self.stat_det    = StatisticalTrojanDetector()

    def predict(self, module: VerilogModule, graph: Data, golden: Optional[Dict]=None) -> Dict:
        batch = Batch.from_data_list([graph])
        with torch.no_grad():
            out, emb = self.gnn_model(batch)
            probs     = F.softmax(out,dim=1)
            gnn_pred  = out.argmax(dim=1).item()
            gnn_conf  = probs[0,gnn_pred].item()
            gnn_score = probs[0,1].item()

        stat_res   = self.stat_det.analyze(module, golden)
        stat_score = stat_res['score']
        stat_conf  = stat_res.get('confidence',0.5)

        hybrid = self.gnn_weight*gnn_score + self.stat_weight*stat_score
        pred   = 1 if hybrid>0.5 else 0
        conf   = (gnn_conf+stat_conf)/2 if gnn_pred==(1 if stat_score>0.5 else 0) else abs(hybrid-0.5)*2

        return {
            'prediction': pred, 'confidence': conf,
            'hybrid_score': hybrid, 'gnn_score': gnn_score,
            'gnn_confidence': gnn_conf, 'statistical_score': stat_score,
            'statistical_confidence': stat_conf, 'anomalies': stat_res,
            'embedding': emb[0].numpy(), 'method': 'hybrid'
        }


# ─────────────────────────────────────────────────────────────────────────────
# PLOTLY GRAPH
# ─────────────────────────────────────────────────────────────────────────────
def create_dark_graph(module: VerilogModule, highlight: List[str]=None):
    G = nx.DiGraph()
    for nm, sig in module.signals.items():
        G.add_node(nm, **{k:v for k,v in vars(sig).items() if k!='name'})
    for src, expr in module.assignments:
        for tgt in re.findall(r'\b\w+\b', expr):
            if tgt in module.signals and src in module.signals:
                G.add_edge(src, tgt)

    pos = nx.spring_layout(G,k=2.5,iterations=50,seed=42) if len(G)>0 else {}

    ex,ey = [],[]
    for u,v in G.edges():
        if u in pos and v in pos:
            x0,y0=pos[u]; x1,y1=pos[v]
            ex.extend([x0,x1,None]); ey.extend([y0,y1,None])

    hl = set(highlight or [])
    nx_,ny_,colors,sizes,hover = [],[],[],[],[]
    for nd in G.nodes():
        if nd not in pos: continue
        sig = module.signals[nd]
        nx_.append(pos[nd][0]); ny_.append(pos[nd][1])
        color = ('#e63950' if nd in hl else
                 '#f59e0b' if sig.is_clock else
                 '#f97316' if sig.is_reset else
                 '#ef4444' if sig.fanout>10 else
                 '#94a3b8' if (sig.fanin==0 and sig.fanout==0) else
                 {'input':'#16a34a','output':'#1a6fff','reg':'#7c3aed','wire':'#64748b'}.get(sig.signal_type,'#94a3b8'))
        colors.append(color)
        sizes.append(18+min(G.degree(nd)*3,50))
        h  = f"<b>{nd}</b><br>Type: {sig.signal_type}<br>Width: {sig.width}b<br>"
        h += f"Fan-in: {sig.fanin} | Fan-out: {sig.fanout}"
        if nd in hl: h += "<br><b style='color:#e63950'>⚠ SUSPICIOUS</b>"
        hover.append(h)

    fig = go.Figure(
        data=[
            go.Scatter(x=ex,y=ey,mode='lines',line=dict(width=0.8,color='#cbd5e1'),hoverinfo='none'),
            go.Scatter(x=nx_,y=ny_,mode='markers+text',
                       text=[n for n in G.nodes() if n in pos],
                       textposition="top center",textfont=dict(size=8,color='#475569'),
                       hovertext=hover,hoverinfo='text',
                       marker=dict(color=colors,size=sizes,line=dict(width=1.5,color='#ffffff'),opacity=0.9))
        ],
        layout=go.Layout(
            title=dict(text=f'Netlist Graph — {module.name}',font=dict(size=14,color='#1a2540',family='Space Grotesk')),
            showlegend=False, hovermode='closest',
            margin=dict(b=20,l=5,r=5,t=45),
            xaxis=dict(showgrid=False,zeroline=False,showticklabels=False),
            yaxis=dict(showgrid=False,zeroline=False,showticklabels=False),
            plot_bgcolor='#f8fafc', paper_bgcolor='#ffffff', height=600
        )
    )
    st.plotly_chart(fig, use_container_width=True)

    st.markdown("""
    <div style="display:flex;flex-wrap:wrap;gap:14px;padding:10px 14px;
        background:#f8fafc;border:1px solid #e2e8f1;border-radius:8px;
        font-family:'Inter',sans-serif;font-size:0.8rem;color:#1a2540;margin-top:4px;">
        <span><span style="color:#16a34a;font-size:1.1rem;">●</span> Input</span>
        <span><span style="color:#1a6fff;font-size:1.1rem;">●</span> Output</span>
        <span><span style="color:#7c3aed;font-size:1.1rem;">●</span> Register</span>
        <span><span style="color:#64748b;font-size:1.1rem;">●</span> Wire</span>
        <span><span style="color:#f59e0b;font-size:1.1rem;">●</span> Clock</span>
        <span><span style="color:#f97316;font-size:1.1rem;">●</span> Reset</span>
        <span><span style="color:#ef4444;font-size:1.1rem;">●</span> High Fan-out</span>
        <span><span style="color:#e63950;font-size:1.1rem;">●</span> ⚠ Suspicious</span>
    </div>""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# AGENT LOG RENDERER
# ─────────────────────────────────────────────────────────────────────────────
def render_mcp_panel(mcp: "MCPServerRegistry"):
    """Render MCP server registry using native Streamlit — no raw HTML strings"""
    servers = mcp.get_server_data()

    # Header bar
    st.markdown(
        "<div style='background:#0e7490;color:#fff;font-family:\"Space Grotesk\",sans-serif;"
        "font-weight:700;font-size:0.85rem;letter-spacing:0.1em;text-transform:uppercase;"
        "padding:10px 18px;border-radius:8px 8px 0 0;margin-bottom:1px;'>"
        "🔌 &nbsp;MCP SERVER REGISTRY &nbsp;"
        "<span style='font-weight:400;opacity:0.75;font-size:0.78rem;'>"
        "— Model Context Protocol · 8 Active Servers</span></div>",
        unsafe_allow_html=True
    )

    # Render as a clean native grid using columns
    cols_per_row = 4
    rows = [servers[i:i+cols_per_row] for i in range(0, len(servers), cols_per_row)]

    for row in rows:
        cols = st.columns(len(row))
        for col, srv in zip(cols, row):
            with col:
                dot_color = "#16a34a" if srv["status"]=="online" else "#d97706" if srv["status"]=="busy" else "#e63950"
                status_txt = srv["status"].upper()
                req_txt = f"{srv['requests']} call{'s' if srv['requests']!=1 else ''}"
                hb = f" · {srv['heartbeat']}" if srv['heartbeat'] else ""

                st.markdown(
                    f"<div style='background:#fff;border:1px solid #a5f3fc;"
                    f"border-radius:8px;padding:12px 14px;height:100%;'>"
                    f"<div style='font-family:\"JetBrains Mono\",monospace;font-size:0.8rem;"
                    f"font-weight:600;color:#0e7490;margin-bottom:4px;'>{srv['name']}</div>"
                    f"<div style='font-size:0.75rem;color:#4a5880;font-family:\"Inter\",sans-serif;"
                    f"margin-bottom:8px;line-height:1.4;'>{srv['capability']}</div>"
                    f"<div style='display:flex;align-items:center;gap:6px;'>"
                    f"<span style='width:8px;height:8px;border-radius:50%;background:{dot_color};"
                    f"display:inline-block;flex-shrink:0;'></span>"
                    f"<span style='font-family:\"JetBrains Mono\",monospace;font-size:0.68rem;"
                    f"color:#0e7490;font-weight:600;'>{status_txt}</span>"
                    f"<span style='font-family:\"JetBrains Mono\",monospace;font-size:0.68rem;"
                    f"color:#8898b0;'>{req_txt}{hb}</span>"
                    f"</div></div>",
                    unsafe_allow_html=True
                )

    st.markdown("<div style='margin-bottom:8px;'></div>", unsafe_allow_html=True)


def render_agent_log(agent: BaseAgent):
    pill_map = {
        "IDLE":     ("#e5e7eb", "#6b7280", "○ Idle"),
        "ACTIVE":   ("#dbeafe", "#1a6fff", "◉ Active"),
        "ALERTING": ("#fee2e2", "#e63950", "⚠ Alerting"),
        "COMPLETE": ("#dcfce7", "#16a34a", "✓ Done"),
    }
    pill_bg, pill_color, pill_txt = pill_map.get(agent.state.value, ("#e5e7eb","#6b7280","Idle"))

    has_alert = any(m.level == "alert" for m in agent.log)
    is_clean  = agent.state == AgentState.COMPLETE and not has_alert and not any(m.level=="warn" for m in agent.log)

    if has_alert:
        card_bg, card_border = "#fff0f2", "#e63950"
    elif is_clean:
        card_bg, card_border = "#f0fdf4", "#16a34a"
    elif agent.state == AgentState.ACTIVE:
        card_bg, card_border = "#eff6ff", "#1a6fff"
    else:
        card_bg, card_border = "#ffffff", "#d0d8e8"

    lines_html = ""
    for msg in agent.log[-18:]:
        if msg.level == "alert":
            line_color, border_c = "#e63950", "#e63950"
        elif msg.level == "warn":
            line_color, border_c = "#d97706", "#d97706"
        elif msg.level == "ok":
            line_color, border_c = "#16a34a", "#16a34a"
        else:
            line_color, border_c = "#8898b0", "#d0d8e8"

        lines_html += (
            f"<div style='font-family:\"JetBrains Mono\",monospace;font-size:0.72rem;"
            f"color:{line_color};padding:2px 0 2px 10px;"
            f"border-left:2px solid {border_c};margin:2px 0;line-height:1.5;'>"
            f"<span style='color:#1a6fff;'>[{msg.timestamp}]</span> {msg.content}</div>"
        )

    if not lines_html:
        lines_html = "<div style='font-size:0.75rem;color:#8898b0;font-style:italic;padding:4px 0;'>No activity yet</div>"

    st.markdown(
        f"<div style='background:{card_bg};border:1px solid {card_border};"
        f"border-radius:10px;padding:14px 16px;margin:4px 0;'>"
        f"<div style='display:flex;justify-content:space-between;align-items:center;"
        f"margin-bottom:10px;padding-bottom:8px;border-bottom:1px solid #e2e8f1;'>"
        f"<span style='font-family:\"Space Grotesk\",sans-serif;font-size:0.9rem;"
        f"font-weight:700;color:#7c3aed;'>{agent.name}</span>"
        f"<span style='font-family:\"JetBrains Mono\",monospace;font-size:0.65rem;"
        f"font-weight:600;padding:2px 10px;border-radius:20px;text-transform:uppercase;"
        f"letter-spacing:0.08em;background:{pill_bg};color:{pill_color};'>{pill_txt}</span>"
        f"</div>"
        f"{lines_html}"
        f"</div>",
        unsafe_allow_html=True
    )


# ─────────────────────────────────────────────────────────────────────────────
# THREAT TIMELINE
# ─────────────────────────────────────────────────────────────────────────────
def render_threat_timeline(events: List[Dict]):
    if not events: return
    df = pd.DataFrame(events)
    df['rank'] = range(len(df))

    fig = go.Figure()
    color_map = {
        'CRITICAL':'#e63950','HIGH':'#d97706','MEDIUM':'#2563eb',
        'LOW':'#0891b2','CLEAN':'#16a34a'
    }
    for _, row in df.iterrows():
        c = color_map.get(row['level'], '#4a6080')
        fig.add_trace(go.Scatter(
            x=[row['score']], y=[row['rank']],
            mode='markers+text',
            marker=dict(size=18, color=c, symbol='diamond',
                        line=dict(width=1, color='#060b14')),
            text=[f"  {row['file']}"],
            textfont=dict(size=10, color=c),
            textposition='middle right',
            hovertemplate=f"<b>{row['file']}</b><br>Score: {row['score']:.3f}<br>Level: {row['level']}<extra></extra>",
            name=row['level'], showlegend=False
        ))

    fig.update_layout(
        title=dict(text='Threat Timeline — Score vs Design', font=dict(size=14,color='#1a2540',family='Space Grotesk')),
        xaxis=dict(title='Hybrid Threat Score', range=[0,1], gridcolor='#e2e8f1',
                   tickformat='.0%', color='#4a5880', zeroline=False),
        yaxis=dict(showticklabels=False, gridcolor='#e2e8f1', zeroline=False),
        plot_bgcolor='#ffffff', paper_bgcolor='#f7f9fc', height=320,
        margin=dict(l=10,r=140,t=45,b=40),
        shapes=[dict(type='line',x0=0.5,x1=0.5,y0=-0.5,y1=len(df)-0.5,
                     line=dict(color='#e63950',width=1.5,dash='dot'))]
    )
    st.plotly_chart(fig, use_container_width=True)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN APPLICATION
# ─────────────────────────────────────────────────────────────────────────────
def main():
    # ── HEADER ──────────────────────────────────────────────────────────────
    st.markdown("""
    <div class="aiq-header">
        <div class="aiq-logo-block">
            <div class="aiq-logo">ArmorIQ<span class="tm">™</span></div>
            <div class="aiq-tagline">Hardware Trojan Intelligence Platform · v2.0</div>
        </div>
        <div class="aiq-badges">
            <span class="aiq-badge">GNN · Statistical · Hybrid</span>
            <span class="aiq-badge teal">🔌 MCP Servers</span>
            <span class="aiq-badge purple">🤖 AI Agents</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # ── SIDEBAR ──────────────────────────────────────────────────────────────
    with st.sidebar:
        st.markdown('<div style="font-family:\'Space Grotesk\',sans-serif;font-size:1.1rem;font-weight:700;color:#1a6fff;letter-spacing:0.05em;text-transform:uppercase;margin-bottom:16px;">⚙ Configuration</div>', unsafe_allow_html=True)

        method = st.radio("Detection Engine", ["Hybrid (GNN + Statistical)", "GNN Only", "Statistical Only"], index=0)
        gnn_w  = st.slider("GNN Weight", 0.0, 1.0, 0.6, 0.1) if "Hybrid" in method else (1.0 if "GNN" in method else 0.0)
        stat_w = 1.0 - gnn_w

        st.markdown("---")
        st.markdown("**Visualisation**")
        show_graph   = st.checkbox("Netlist Graph",        value=True)
        show_anomaly = st.checkbox("Anomaly Analysis",     value=True)
        show_agents  = st.checkbox("AI Agent Logs",        value=True)
        show_mcp     = st.checkbox("MCP Server Registry",  value=True)
        show_types   = st.checkbox("HT Type Taxonomy",     value=True)

        st.markdown("---")
        use_golden = st.checkbox("Golden Model Reference", value=False)

        st.markdown("---")
        st.markdown('<div style="font-family:\'JetBrains Mono\',monospace;font-size:0.72rem;color:#8898b0;text-transform:uppercase;letter-spacing:0.1em;margin-bottom:6px;">Architecture</div>', unsafe_allow_html=True)
        st.code("""ArmorIQ v2.0
├── MCP Server Registry (8 servers)
│   ├── RTL-Parser
│   ├── Graph-Builder
│   ├── GNN-Inference
│   ├── Statistical-Analyzer
│   ├── Golden-Reference
│   ├── HT-Classifier
│   ├── Report-Generator
│   └── Live-Monitor
├── AI Agents
│   ├── Detection Agent ⚡
│   ├── Analysis Agent 🔬
│   └── Monitor Agent 🛰️
└── GNN: 4-layer GAT (256H)""", language="text")

    # ── FILE UPLOAD ──────────────────────────────────────────────────────────
    st.markdown('<div class="sec-header">Upload RTL Designs</div>', unsafe_allow_html=True)
    files = st.file_uploader("Upload Verilog RTL (.v / .vh)", type=["v","vh"], accept_multiple_files=True)

    if not files:
        # Landing info
        c1,c2,c3 = st.columns(3)
        for col, icon, title, body in [
            (c1,"⚡","Detection Agent","Orchestrates GNN + statistical pipeline via MCP tool calls. Issues binary HT verdicts with confidence scores."),
            (c2,"🔬","Analysis Agent","Classifies trojan type (Combinational / Sequential / Functional / Kill Switch / Data Leakage / Parametric). Produces structural fingerprints."),
            (c3,"🛰️","Monitor Agent","Aggregates real-time threat feed, raises global alerts, drives dashboard metrics across all designs."),
        ]:
            with col:
                st.markdown(
                    f"<div style='background:#eff6ff;border:1px solid #1a6fff;"
                    f"border-radius:10px;padding:16px;margin:4px 0;'>"
                    f"<div style='font-family:\"Space Grotesk\",sans-serif;font-size:0.9rem;"
                    f"font-weight:700;color:#7c3aed;margin-bottom:8px;'>{icon}&nbsp; {title}</div>"
                    f"<div style='font-size:0.82rem;color:#4a5880;font-family:\"Inter\",sans-serif;"
                    f"line-height:1.5;'>{body}</div>"
                    f"</div>",
                    unsafe_allow_html=True
                )

        st.markdown('<div class="sec-header">Traditional HT Taxonomy</div>', unsafe_allow_html=True)
        df_tax = pd.DataFrame([(k,v) for k,v in TRADITIONAL_TROJAN_TYPES.items()], columns=["HT Type","Description"])
        st.dataframe(df_tax, use_container_width=True, hide_index=True)
        return

    # ── INITIALISE ───────────────────────────────────────────────────────────
    mcp      = MCPServerRegistry()
    parser   = CompetitionVerilogParser()
    builder  = EnhancedGraphBuilder(48)
    detector = HybridTrojanDetectionSystem(gnn_weight=gnn_w, stat_weight=stat_w)

    det_agent  = DetectionAgent(mcp, detector)
    ana_agent  = AnalysisAgent(mcp)
    mon_agent  = MonitorAgent(mcp)

    # ── PARSING ──────────────────────────────────────────────────────────────
    modules, graphs = [], []
    prog = st.progress(0)
    sta  = st.empty()

    for idx, f in enumerate(files):
        sta.markdown(f'<div style="font-family:\'JetBrains Mono\',monospace;font-size:0.82rem;color:#1a6fff;padding:6px 0;">◉ Parsing {f.name}…</div>', unsafe_allow_html=True)
        prog.progress((idx+1)/len(files))
        try:
            content = f.read().decode("utf-8", errors="ignore")
            mod = parser.parse(content)
            mcp.call("mcp-parse", "tokenize", {"file": f.name})
            modules.append(mod)
            mcp.call("mcp-graph", "build", {"nodes": len(mod.signals)})
            graphs.append(builder.build(mod))
        except Exception as e:
            st.error(f"Parse error — {f.name}: {e}")

    prog.empty(); sta.empty()

    if not modules:
        st.error("No designs could be parsed."); return

    # ── RUN AGENTS ───────────────────────────────────────────────────────────
    with st.spinner("🤖 AI Agents running…"):
        predictions  = det_agent.run(modules, graphs, None if not use_golden else {})
        for i,p in enumerate(predictions):
            p['filename'] = files[i].name

        fingerprints = ana_agent.run(modules, predictions)
        monitor_sum  = mon_agent.run(modules, predictions)

    st.success(f"✅ Analysis complete — {len(modules)} design(s) processed by 3 AI agents via {len(mcp.call_log)} MCP calls")

    # ── GLOBAL KPI BAR ───────────────────────────────────────────────────────
    st.markdown('<div class="sec-header">Global Threat Summary</div>', unsafe_allow_html=True)
    k1,k2,k3,k4,k5 = st.columns(5)
    total   = len(predictions)
    trojans = sum(1 for p in predictions if p['prediction']==1)
    clean   = total - trojans
    avg_conf= np.mean([p['confidence'] for p in predictions])
    crit    = monitor_sum['critical']

    k1.metric("Total Designs",    total)
    k2.metric("HT-Infested 🚨",  trojans, delta=f"{trojans/total*100:.0f}%")
    k3.metric("HT-Free ✅",      clean,   delta=f"{clean/total*100:.0f}%")
    k4.metric("Critical Threats", crit)
    k5.metric("Avg Confidence",  f"{avg_conf*100:.1f}%")

    # ── THREAT TIMELINE ──────────────────────────────────────────────────────
    st.markdown('<div class="sec-header">Threat Timeline</div>', unsafe_allow_html=True)
    render_threat_timeline(monitor_sum['threat_events'])

    # ── AGENT LOGS ───────────────────────────────────────────────────────────
    if show_agents:
        st.markdown('<div class="sec-header agent-hdr">🤖 AI Agent Activity Logs</div>', unsafe_allow_html=True)
        ac1,ac2,ac3 = st.columns(3)
        with ac1: render_agent_log(det_agent)
        with ac2: render_agent_log(ana_agent)
        with ac3: render_agent_log(mon_agent)

    # ── MCP SERVER STATUS ────────────────────────────────────────────────────
    if show_mcp:
        st.markdown('<div class="sec-header mcp-hdr">🔌 MCP Server Registry</div>', unsafe_allow_html=True)
        render_mcp_panel(mcp)
        with st.expander("📋 MCP Call Trace"):
            cdf = pd.DataFrame(mcp.call_log)
            st.dataframe(cdf, use_container_width=True, hide_index=True)

    # ── INDIVIDUAL DESIGNS ───────────────────────────────────────────────────
    st.markdown('<div class="sec-header">Individual Design Reports</div>', unsafe_allow_html=True)

    for module, pred, fp in zip(modules, predictions, fingerprints):
        fname = pred.get('filename', module.name)
        is_ht = pred['prediction'] == 1

        icon    = "🚨" if is_ht else "✅"
        verdict = "HARDWARE TROJAN DETECTED" if is_ht else "DESIGN CLEAN — HT-FREE"
        vcard   = "verdict-red" if is_ht else "verdict-green"
        vtitle  = "verdict-title-red" if is_ht else "verdict-title-green"

        with st.expander(f"{icon}  {fname}", expanded=is_ht):
            # Verdict banner
            st.markdown(f"""<div class="{vcard}">
                <div class="{vtitle}">{icon}&nbsp; {verdict}</div>
                <div style="font-family:'JetBrains Mono',monospace;font-size:0.75rem;color:#4a5880;margin-top:5px;">
                    Module: {module.name} &nbsp;·&nbsp; Hybrid Score: {pred['hybrid_score']*100:.1f}% &nbsp;·&nbsp;
                    Confidence: {pred['confidence']*100:.1f}%
                </div>
            </div>""", unsafe_allow_html=True)

            st.markdown("")

            # KPIs
            c1,c2,c3,c4 = st.columns(4)
            c1.metric("Hybrid Score",        f"{pred['hybrid_score']*100:.1f}%")
            c2.metric("GNN Score",           f"{pred['gnn_score']*100:.1f}%")
            c3.metric("Statistical Score",   f"{pred['statistical_score']*100:.1f}%")
            c4.metric("Confidence",          f"{pred['confidence']*100:.1f}%")

            # HT Type classification
            if show_types and is_ht:
                st.markdown("**Detected HT Pattern Types:**")
                ht_types = fp.get('ht_types', [])
                type_cols = st.columns(max(len(ht_types),1))
                for i, ht in enumerate(ht_types):
                    with type_cols[i % len(type_cols)]:
                        desc = TRADITIONAL_TROJAN_TYPES.get(ht, "Unknown pattern")
                        st.markdown(
                            f"<div style='background:#fff0f2;border:1px solid #e63950;"
                            f"border-radius:8px;padding:12px;margin:4px 0;'>"
                            f"<div style='font-family:\"Space Grotesk\",sans-serif;font-weight:700;"
                            f"color:#e63950;font-size:0.9rem;'>⚠ {ht}</div>"
                            f"<div style='font-size:0.78rem;color:#4a5880;margin-top:4px;"
                            f"font-family:\"Inter\",sans-serif;'>{desc}</div>"
                            f"</div>",
                            unsafe_allow_html=True
                        )

            # Module stats
            c1,c2,c3,c4,c5 = st.columns(5)
            c1.metric("Signals",      len(module.signals))
            c2.metric("Assignments",  len(module.assignments))
            c3.metric("Always Blks",  len(module.always_blocks))
            c4.metric("Instances",    len(module.instances))
            c5.metric("Parameters",   len(module.parameters))

            # Anomaly panel
            if show_anomaly and pred['statistical_score'] > 0:
                st.markdown("**Anomaly Breakdown:**")
                a = pred['anomalies']
                cats = []
                for label, key, sev in [
                    ("Suspicious Names","suspicious_names","CRITICAL"),
                    ("Unusual Widths","unusual_widths","MEDIUM"),
                    ("High Fan-out","high_fanout","HIGH"),
                    ("Isolated Signals","isolated_signals","HIGH"),
                    ("Complex Logic","complex_logic","MEDIUM"),
                    ("Rare Signals","rare_signals","MEDIUM"),
                ]:
                    v = a.get(key,[])
                    if isinstance(v,list) and v:
                        cats.append({'Category':label,'Count':len(v),'Severity':sev})

                if cats:
                    adf = pd.DataFrame(cats)
                    fig = px.bar(adf,x='Category',y='Count',color='Severity',
                                 color_discrete_map={'CRITICAL':'#e63950','HIGH':'#d97706','MEDIUM':'#1a6fff'},
                                 title='Anomaly Distribution')
                    fig.update_layout(plot_bgcolor='#ffffff', paper_bgcolor='#f7f9fc',
                                      font=dict(color='#1a2540', family='Inter'),
                                      height=280, margin=dict(t=40,b=20))
                    st.plotly_chart(fig, use_container_width=True)

                col1,col2 = st.columns(2)
                with col1:
                    if a.get('suspicious_names'):
                        st.markdown(f'<div style="font-family:\'JetBrains Mono\',monospace;font-size:0.78rem;padding:5px 10px;border-radius:4px;margin:3px 0;background:#fff0f2;color:#e63950;border-left:3px solid #e63950;">⚠ Suspicious names: {", ".join(a["suspicious_names"][:5])}</div>', unsafe_allow_html=True)
                    if a.get('high_fanout'):
                        for nm,fo in a['high_fanout'][:3]:
                            st.markdown(f'<div style="font-family:\'JetBrains Mono\',monospace;font-size:0.78rem;padding:5px 10px;border-radius:4px;margin:3px 0;background:#fffbeb;color:#d97706;border-left:3px solid #d97706;">Fan-out {nm}: {fo}</div>', unsafe_allow_html=True)
                with col2:
                    if a.get('isolated_signals'):
                        st.markdown(f'<div style="font-family:\'JetBrains Mono\',monospace;font-size:0.78rem;padding:5px 10px;border-radius:4px;margin:3px 0;background:#eff6ff;color:#1a6fff;border-left:3px solid #1a6fff;">Isolated: {", ".join(a["isolated_signals"][:5])}</div>', unsafe_allow_html=True)
                    if a.get('unusual_widths'):
                        for nm,w in a['unusual_widths'][:3]:
                            st.markdown(f'<div style="font-family:\'JetBrains Mono\',monospace;font-size:0.78rem;padding:5px 10px;border-radius:4px;margin:3px 0;background:#fffbeb;color:#d97706;border-left:3px solid #d97706;">Width outlier {nm}: {w}b</div>', unsafe_allow_html=True)

            # Netlist graph
            if show_graph:
                st.markdown("**Netlist Signal Dependency Graph:**")
                hl = pred['anomalies'].get('suspicious_names',[]) if is_ht else []
                create_dark_graph(module, hl)

            # Signal table
            if st.checkbox(f"Signal detail table", key=f"sig_{fname}"):
                sdf = pd.DataFrame([{
                    'Signal': nm, 'Type': s.signal_type, 'Width': s.width,
                    'Fan-in': s.fanin, 'Fan-out': s.fanout,
                    'Clock': '✓' if s.is_clock else '',
                    'Reset': '✓' if s.is_reset else '',
                    'Flag': '⚠' if nm in (pred['anomalies'].get('suspicious_names',[])) else ''
                } for nm,s in module.signals.items()])
                st.dataframe(sdf, use_container_width=True, hide_index=True)

    # ── COMPARATIVE DASHBOARD ────────────────────────────────────────────────
    if len(modules) > 1:
        st.markdown('<div class="sec-header">Comparative Analysis</div>', unsafe_allow_html=True)
        df = pd.DataFrame([{
            'Module': m.name, 'File': p.get('filename',m.name),
            'Verdict': 'HT-Infested' if p['prediction']==1 else 'HT-Free',
            'Hybrid %': p['hybrid_score']*100,
            'GNN %': p['gnn_score']*100,
            'Stat %': p['statistical_score']*100,
            'Confidence %': p['confidence']*100,
            'Signals': len(m.signals),
        } for m,p in zip(modules,predictions)])

        c1,c2 = st.columns(2)
        with c1:
            fig = px.bar(df,x='Module',y='Hybrid %',color='Verdict',
                         color_discrete_map={'HT-Free':'#16a34a','HT-Infested':'#e63950'},
                         title='Hybrid Threat Score per Design')
            fig.update_layout(plot_bgcolor='#ffffff', paper_bgcolor='#f7f9fc',
                              font=dict(color='#1a2540',family='Inter'), height=320, margin=dict(t=40))
            st.plotly_chart(fig, use_container_width=True)
        with c2:
            melted = df[['Module','GNN %','Stat %','Hybrid %']].melt('Module',var_name='Method',value_name='Score')
            fig = px.line(melted,x='Module',y='Score',color='Method',markers=True,
                          color_discrete_map={'GNN %':'#1a6fff','Stat %':'#d97706','Hybrid %':'#e63950'},
                          title='Method Comparison')
            fig.update_layout(plot_bgcolor='#ffffff', paper_bgcolor='#f7f9fc',
                              font=dict(color='#1a2540',family='Inter'), height=320, margin=dict(t=40))
            st.plotly_chart(fig, use_container_width=True)

        st.dataframe(df, use_container_width=True, hide_index=True)

    # ── EXPORT ───────────────────────────────────────────────────────────────
    st.markdown('<div class="sec-header">Export</div>', unsafe_allow_html=True)
    ex1,ex2 = st.columns(2)

    report = {
        'platform': 'ArmorIQ™ v2.0',
        'architecture': {'gnn': '4-layer GAT 256H', 'agents': 3, 'mcp_servers': 8},
        'mcp_calls': len(mcp.call_log),
        'summary': {
            'total': total, 'trojans': trojans, 'clean': clean,
            'critical': crit, 'avg_confidence': float(avg_conf)
        },
        'designs': [{
            'file': p.get('filename',m.name), 'module': m.name,
            'verdict': 'HT-Infested' if p['prediction']==1 else 'HT-Free',
            'hybrid_score': float(p['hybrid_score']),
            'gnn_score': float(p['gnn_score']),
            'statistical_score': float(p['statistical_score']),
            'confidence': float(p['confidence']),
            'ht_types': fp.get('ht_types',[]),
            'signals': len(m.signals),
            'anomaly_count': sum(len(v) if isinstance(v,list) else 0
                                 for v in p['anomalies'].values()),
        } for m,p,fp in zip(modules,predictions,fingerprints)]
    }

    with ex1:
        st.download_button("📄 Download JSON Report",
            data=json.dumps(report,indent=2),
            file_name=f"armoriq_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json")
    with ex2:
        if len(predictions)>1:
            cdf = pd.DataFrame(report['designs'])
            st.download_button("📊 Download CSV Results",
                data=cdf.to_csv(index=False),
                file_name=f"armoriq_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv")


if __name__ == "__main__":
    main()
