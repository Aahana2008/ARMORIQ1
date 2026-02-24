# Monitor Agent creates a delegation token for Analysis Agent
token = delegation_manager.delegate(
    from_agent = "agent-monitor",
    to_agent   = "agent-analysis",
    actions    = ["read"],           # can only read, not write
    dirs       = ["rtl_designs"],    # only this folder
    max_files  = 3                   # only 3 files
)

print(f"Token created: {token}")

# This works — file 1
ok, reason = delegation_manager.check_delegated(
    token, "agent-analysis", "read", "rtl_designs/design1.v")
print(f"File 1: {reason}")   # ALLOWED

# This works — file 2  
ok, reason = delegation_manager.check_delegated(
    token, "agent-analysis", "read", "rtl_designs/design2.v")
print(f"File 2: {reason}")   # ALLOWED

# This works — file 3
ok, reason = delegation_manager.check_delegated(
    token, "agent-analysis", "read", "rtl_designs/design3.v")
print(f"File 3: {reason}")   # ALLOWED

# THIS GETS BLOCKED — token used up
ok, reason = delegation_manager.check_delegated(
    token, "agent-analysis", "read", "rtl_designs/design4.v")
print(f"File 4: {reason}")   # BLOCKED — token expired

# THIS GETS BLOCKED — wrong action type
ok, reason = delegation_manager.check_delegated(
    token, "agent-analysis", "write", "outputs/report.json")
print(f"Write attempt: {reason}")   # BLOCKED — not in delegated scope
```

That's literally the whole delegation demo. Run it, it prints ALLOWED/BLOCKED, done.

---

## Phase 7 — What I Was Saying

This is just the **submission packaging**. Three things:

**Thing 1: Architecture Diagram**
Open PowerPoint or Google Slides. Draw boxes and arrows like this:
```
[User] → [OpenClaw Agent] → [PolicyEnforcer] → BLOCKED ✗
                                    ↓
                                 ALLOWED
                                    ↓
                           [MCP Servers]
                                    ↓
                    [Detection] [Analysis] [Monitor]
                                    ↓
                    [rtl_designs] [outputs] [quarantine]