#!/usr/bin/env python3
"""
agentverif — OpenClaw skill v1.0.0
OWASP LLM Top 10 scanner + cryptographic verification for skills.

Homepage: https://agentverif.com

Commands (invoked as: python skill.py <command> [args]):
  scan [--last 1h|24h|7d] [--since ISO]  OWASP scan, score 0-100
  verify <license_id_or_zip>             VERIFIED / TAMPERED / UNSIGNED / REVOKED
  sign <zip_path>                        Sign ZIP — OWASP scan runs first
  revoke <license_id>                    Revoke license (needs AGENTVERIF_API_KEY)
  status                                 Trust score + active violations
  report                                 Full violation report by severity
  taint-check <text>                     LLM01 prompt injection check
  output-check <text>                    LLM02 insecure output check
  diff <session1> <session2>             Compare two scan sessions
  badge                                  Print AgentVerif certified badge

Exit codes:
  0  Clean — no violations or certificate valid
  1  Violations found or certificate invalid
  2  Error — bad args or agentverif-sign not installed
"""

import importlib.util
import json
import os
import re
import sys
import hashlib
import datetime
import pathlib

# ---------------------------------------------------------------------------
# Dependency check — never auto-install; instruct the user instead
# ---------------------------------------------------------------------------

if importlib.util.find_spec("agentverif_sign") is None:
    print(json.dumps({
        "error": "agentverif-sign is not installed",
        "fix": "pip install agentverif-sign",
        "docs": "https://agentverif.com/docs",
    }, indent=2))
    sys.exit(2)

# ---------------------------------------------------------------------------
# Direct imports from agentverif_sign — no subprocess, no CLI wrapping
# ---------------------------------------------------------------------------

from agentverif_sign.scanner import scan_zip           # POST to api.agentverif.com/scan
from agentverif_sign.signer import sign_zip, inject_signature  # hash + SIGNATURE.json
from agentverif_sign.verifier import verify_zip        # local hash + optional registry
from agentverif_sign.models import VerifyResult, ScanResult

# ---------------------------------------------------------------------------
# State directory — persists sessions across invocations
# ---------------------------------------------------------------------------

STATE_DIR = pathlib.Path.home() / ".openclaw" / "agentverif"
STATE_DIR.mkdir(parents=True, exist_ok=True)

SESSIONS_FILE = STATE_DIR / "sessions.json"

AGENT_META = {
    "skill": "agentverif",
    "version": "1.0.0",
    "homepage": "https://agentverif.com",
    "issuer": "agentverif.com",
}

# ---------------------------------------------------------------------------
# OWASP LLM Top 10 — inline detection patterns (self-contained, no imports)
# ---------------------------------------------------------------------------
# Each entry: (rule_id, severity, title, pattern_list, fix)
# Severities: CRITICAL, ERROR, WARN

OWASP_RULES = [
    # LLM01 — Prompt Injection
    # Detects attempts to override system instructions via user-controlled input.
    (
        "LLM01",
        "CRITICAL",
        "Prompt Injection",
        [
            r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?",
            r"disregard\s+(all\s+)?(previous|prior|above)\s+",
            r"forget\s+(everything|all|your)\s+(you\s+)?(were\s+)?(told|instructed|trained)",
            r"you\s+are\s+now\s+(a|an)\s+\w+\s+(without\s+)?(restrictions?|limits?|filters?)",
            r"jailbreak",
            r"dan\s+mode",
            r"pretend\s+(you\s+)?(have\s+)?(no|zero)\s+(restrictions?|limits?|guidelines?)",
            r"act\s+as\s+(if\s+you\s+)?(have\s+)?(no|zero)\s+(restrictions?|limits?)",
            r"override\s+(your\s+)?(safety|content|ethical)\s+(filters?|guidelines?|rules?)",
            r"system\s+prompt\s*[:=]",
            r"\[SYSTEM\]",
            r"<\|im_start\|>",
            r"<\|endoftext\|>",
        ],
        "Sanitise all user-controlled input before inserting into prompts. "
        "Use a separate trust boundary between system instructions and user content.",
    ),
    # LLM02 — Insecure Output Handling
    # Detects patterns that blindly execute or relay LLM output.
    (
        "LLM02",
        "ERROR",
        "Insecure Output Handling",
        [
            r"eval\s*\(",
            r"exec\s*\(",
            r"subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True",
            r"os\.system\s*\(",
            r"__import__\s*\(",
            r"compile\s*\([^)]+exec",
            r"render_template_string\s*\(",   # Flask — XSS via LLM output
            r"innerHTML\s*=",                  # DOM XSS
            r"document\.write\s*\(",
        ],
        "Validate and encode LLM output before rendering or executing it. "
        "Never pass raw LLM responses to eval/exec/shell commands.",
    ),
    # LLM06 — Sensitive Information Disclosure
    # Detects hardcoded credentials or secret patterns in skill code.
    (
        "LLM06",
        "CRITICAL",
        "Sensitive Information Disclosure",
        [
            r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*=\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
            r"(?i)password\s*=\s*['\"][^'\"]{6,}['\"]",
            r"(?i)PRIVATE\s+KEY",
            r"(?i)BEGIN\s+RSA\s+PRIVATE",
            r"sk-[A-Za-z0-9]{32,}",          # OpenAI key pattern
            r"xoxb-[0-9]+-[A-Za-z0-9]+",     # Slack bot token
            r"ghp_[A-Za-z0-9]{36}",           # GitHub PAT
            r"AKIA[0-9A-Z]{16}",              # AWS access key
        ],
        "Remove all hardcoded credentials. Use environment variables or a secrets manager. "
        "Rotate any exposed secrets immediately.",
    ),
    # LLM08 — Excessive Agency
    # Detects patterns that grant the LLM unrestricted system access.
    (
        "LLM08",
        "ERROR",
        "Excessive Agency",
        [
            r"sudo\s+rm\s+-rf",
            r"chmod\s+777",
            r"os\.remove\s*\([^)]*\*",        # wildcard file deletion
            r"shutil\.rmtree\s*\(",
            r"DROP\s+TABLE",                   # SQL without safeguard
            r"TRUNCATE\s+TABLE",
            r"allow_any\s*=\s*True",
            r"unsafe_allow_html\s*=\s*True",
            r"verify\s*=\s*False",             # TLS verification disabled
            r"ssl_verify\s*=\s*False",
            r"check_hostname\s*=\s*False",
        ],
        "Apply least-privilege to all agent actions. Require explicit confirmation "
        "before destructive operations. Never disable TLS verification.",
    ),
]

# Compiled patterns for efficiency
_COMPILED_RULES = [
    (rid, sev, title, [re.compile(p, re.IGNORECASE) for p in patterns], fix)
    for rid, sev, title, patterns, fix in OWASP_RULES
]

# Severity → score penalty
_SEVERITY_PENALTY = {"CRITICAL": 25, "ERROR": 15, "WARN": 5}

# ---------------------------------------------------------------------------
# Session helpers
# ---------------------------------------------------------------------------

def _load_sessions() -> dict:
    if SESSIONS_FILE.exists():
        try:
            return json.loads(SESSIONS_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _save_sessions(sessions: dict) -> None:
    SESSIONS_FILE.write_text(json.dumps(sessions, indent=2))


def _session_id() -> str:
    now = datetime.datetime.now(datetime.timezone.utc)
    return now.strftime("%Y%m%dT%H%M%SZ")


# ---------------------------------------------------------------------------
# Core OWASP scanner (inline — no subprocess, no network)
# ---------------------------------------------------------------------------

def _scan_text(text: str) -> list[dict]:
    """Run all OWASP rules against text. Returns list of violation dicts."""
    violations = []
    for rid, sev, title, patterns, fix in _COMPILED_RULES:
        for pattern in patterns:
            match = pattern.search(text)
            if match:
                violations.append({
                    "rule": rid,
                    "severity": sev,
                    "title": title,
                    "match": match.group(0)[:120],
                    "fix": fix,
                })
                break  # one violation per rule per text block
    return violations


def _score_from_violations(violations: list[dict]) -> int:
    """Compute 0-100 score. 100 = clean. Each violation deducts penalty."""
    penalty = sum(_SEVERITY_PENALTY.get(v["severity"], 5) for v in violations)
    return max(0, 100 - penalty)


# ---------------------------------------------------------------------------
# Command implementations
# ---------------------------------------------------------------------------

def cmd_scan(args: list[str]) -> None:
    """Scan conversation context / text piped via stdin."""
    # Read text from stdin (OpenClaw pipes session context here)
    text = sys.stdin.read() if not sys.stdin.isatty() else ""

    # Optional: filter by time window (--last 1h|24h|7d)
    # For session-level scanning the window is informational only.
    time_window = "session"
    if "--last" in args:
        idx = args.index("--last")
        time_window = args[idx + 1] if idx + 1 < len(args) else "session"

    violations = _scan_text(text)
    score = _score_from_violations(violations)

    # Persist session
    sessions = _load_sessions()
    sid = _session_id()
    sessions[sid] = {
        "timestamp": sid,
        "score": score,
        "violations": violations,
        "window": time_window,
    }
    _save_sessions(sessions)

    result = {
        **AGENT_META,
        "session_id": sid,
        "score": score,
        "passed": score >= 70,
        "violation_count": len(violations),
        "violations": violations,
        "summary": f"Score {score}/100 — {'CLEAN' if score >= 70 else 'FAILED (need ≥70)'}",
    }
    print(json.dumps(result, indent=2))
    sys.exit(0 if score >= 70 else 1)


def cmd_status(args: list[str]) -> None:
    """Print latest trust score and active violation count."""
    sessions = _load_sessions()
    if not sessions:
        print(json.dumps({**AGENT_META, "status": "no_sessions", "score": None}))
        sys.exit(0)

    latest_sid = sorted(sessions)[-1]
    latest = sessions[latest_sid]
    print(json.dumps({
        **AGENT_META,
        "session_id": latest_sid,
        "score": latest["score"],
        "passed": latest["score"] >= 70,
        "active_violations": latest["violation_count"],
        "fingerprint": hashlib.sha256(latest_sid.encode()).hexdigest()[:16],
    }, indent=2))
    sys.exit(0 if latest["score"] >= 70 else 1)


def cmd_report(args: list[str]) -> None:
    """Print full violation report grouped by severity."""
    sessions = _load_sessions()
    if not sessions:
        print(json.dumps({**AGENT_META, "report": "No scan sessions found."}))
        sys.exit(0)

    latest = sessions[sorted(sessions)[-1]]
    violations = latest.get("violations", [])

    grouped: dict[str, list] = {"CRITICAL": [], "ERROR": [], "WARN": []}
    for v in violations:
        grouped.setdefault(v["severity"], []).append(v)

    print(json.dumps({
        **AGENT_META,
        "score": latest["score"],
        "report": grouped,
        "total": len(violations),
    }, indent=2))
    sys.exit(0 if latest["score"] >= 70 else 1)


def cmd_taint_check(args: list[str]) -> None:
    """LLM01 prompt injection check on a string or stdin."""
    text = " ".join(args) if args else sys.stdin.read()
    rid, sev, title, patterns, fix = _COMPILED_RULES[0]  # LLM01 only
    hits = []
    for pattern in patterns:
        m = pattern.search(text)
        if m:
            hits.append(m.group(0)[:120])
    tainted = len(hits) > 0
    print(json.dumps({
        **AGENT_META,
        "rule": "LLM01",
        "tainted": tainted,
        "matches": hits,
        "fix": fix if tainted else None,
    }, indent=2))
    sys.exit(1 if tainted else 0)


def cmd_output_check(args: list[str]) -> None:
    """LLM02 insecure output check on a string or stdin."""
    text = " ".join(args) if args else sys.stdin.read()
    rid, sev, title, patterns, fix = _COMPILED_RULES[1]  # LLM02 only
    hits = []
    for pattern in patterns:
        m = pattern.search(text)
        if m:
            hits.append(m.group(0)[:120])
    unsafe = len(hits) > 0
    print(json.dumps({
        **AGENT_META,
        "rule": "LLM02",
        "unsafe": unsafe,
        "matches": hits,
        "fix": fix if unsafe else None,
    }, indent=2))
    sys.exit(1 if unsafe else 0)


def cmd_diff(args: list[str]) -> None:
    """Compare two sessions — show regressions and improvements."""
    if len(args) < 2:
        print(json.dumps({"error": "Usage: diff <session1> <session2>"}))
        sys.exit(2)
    sessions = _load_sessions()
    s1_id, s2_id = args[0], args[1]
    s1 = sessions.get(s1_id)
    s2 = sessions.get(s2_id)
    if not s1 or not s2:
        print(json.dumps({
            "error": "Session not found",
            "available": sorted(sessions.keys()),
        }))
        sys.exit(2)

    delta = s2["score"] - s1["score"]
    s1_rules = {v["rule"] for v in s1.get("violations", [])}
    s2_rules = {v["rule"] for v in s2.get("violations", [])}

    print(json.dumps({
        **AGENT_META,
        "session_a": s1_id,
        "session_b": s2_id,
        "score_a": s1["score"],
        "score_b": s2["score"],
        "delta": delta,
        "trend": "improved" if delta > 0 else ("regressed" if delta < 0 else "unchanged"),
        "new_violations": sorted(s2_rules - s1_rules),
        "fixed_violations": sorted(s1_rules - s2_rules),
    }, indent=2))
    sys.exit(0)


def cmd_badge(args: list[str]) -> None:
    """Print AgentVerif certified badge in text, markdown, and HTML."""
    print(json.dumps({
        **AGENT_META,
        "badge_text": "✅ AgentVerif Certified",
        "badge_markdown": "[![AgentVerif](https://img.shields.io/badge/agentverif-certified-16a34a?style=flat-square)](https://agentverif.com)",
        "badge_html": '<a href="https://agentverif.com"><img src="https://img.shields.io/badge/agentverif-certified-16a34a?style=flat-square" alt="AgentVerif Certified"></a>',
        "badge_url": "https://agentverif.com/badge",
        "verify_url": "https://verify.agentverif.com",
    }, indent=2))
    sys.exit(0)


# ---------------------------------------------------------------------------
# New commands — verify, sign, revoke (direct agentverif_sign imports)
# ---------------------------------------------------------------------------

def cmd_verify(args: list[str]) -> None:
    """Verify a skill certificate via agentverif_sign.verifier directly."""
    if not args:
        print(json.dumps({"error": "Usage: verify <license_id_or_zip>"}))
        sys.exit(2)

    target = args[0]
    offline = "--offline" in args

    # If target is a zip file, verify its embedded SIGNATURE.json
    if target.endswith(".zip"):
        result = verify_zip(target, offline=offline)
    else:
        # License ID — verify against registry (online by default)
        # verify_zip accepts a license_id string when not a zip path
        result = verify_zip(target, offline=offline)

    status = result.status
    print(json.dumps({
        **AGENT_META,
        "status": status,
        "license_id": result.license_id,
        "tier": result.tier,
        "badge": result.badge,
        "message": result.message,
        "verify_url": result.verify_url,
        "offline": result.offline,
    }, indent=2))

    # Exit 0 for safe statuses, 1 for anything that blocks execution
    sys.exit(0 if status in ("VERIFIED", "UNREGISTERED") else 1)


def cmd_sign(args: list[str]) -> None:
    """Sign a skill ZIP — OWASP scan runs first via agentverif_sign.scanner."""
    if not args:
        print(json.dumps({"error": "Usage: sign <zip_path> [--tier indie|pro|enterprise]"}))
        sys.exit(2)

    zip_path = args[0]

    # Parse optional tier flag
    tier = "indie"
    if "--tier" in args:
        idx = args.index("--tier")
        if idx + 1 < len(args):
            tier = args[idx + 1]

    if not os.path.isfile(zip_path):
        print(json.dumps({"error": f"File not found: {zip_path}"}))
        sys.exit(2)

    # Run OWASP scan via the real scanner (POSTs to api.agentverif.com/scan)
    scan_url = os.environ.get("AGENTVERIF_SCAN_URL", "https://api.agentverif.com/scan")
    scan_result = scan_zip(zip_path, scan_url)

    if not scan_result.passed:
        print(json.dumps({
            **AGENT_META,
            "error": "SCAN_FAILED",
            "score": scan_result.score,
            "message": f"Score {scan_result.score}/100 — need ≥70 to sign.",
            "violations": [v.get("title", v.get("rule")) for v in (scan_result.violations or [])],
            "fix": "Fix the violations above, then re-run sign.",
        }, indent=2))
        sys.exit(1)

    # Build signature record and inject into zip
    record = sign_zip(zip_path, tier=tier, scan_result=scan_result)
    inject_signature(zip_path, record)

    print(json.dumps({
        **AGENT_META,
        "status": "SIGNED",
        "license_id": record.license_id,
        "tier": record.tier,
        "scan_score": scan_result.score,
        "scan_source": scan_result.source,
        "zip_hash": record.zip_hash,
        "verify_url": f"https://verify.agentverif.com/?id={record.license_id}",
    }, indent=2))
    sys.exit(0)


def cmd_revoke(args: list[str]) -> None:
    """Revoke a license via api.agentverif.com — requires AGENTVERIF_API_KEY."""
    import urllib.request

    if not args:
        print(json.dumps({"error": "Usage: revoke <license_id>"}))
        sys.exit(2)

    api_key = os.environ.get("AGENTVERIF_API_KEY")
    if not api_key:
        print(json.dumps({
            "error": "AGENTVERIF_API_KEY not set",
            "message": "Set the AGENTVERIF_API_KEY environment variable to revoke licenses.",
            "docs": "https://agentverif.com/docs#revoke",
        }, indent=2))
        sys.exit(2)

    license_id = args[0]
    payload = json.dumps({"license_id": license_id}).encode()

    req = urllib.request.Request(
        "https://api.agentverif.com/revoke",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read())
            print(json.dumps({**AGENT_META, **body}, indent=2))
            sys.exit(0)
    except urllib.request.HTTPError as exc:
        try:
            body = json.loads(exc.read())
        except Exception:
            body = {"http_error": exc.code}
        print(json.dumps({**AGENT_META, "error": "revoke_failed", **body}, indent=2))
        sys.exit(1)
    except Exception as exc:
        print(json.dumps({**AGENT_META, "error": str(exc)}))
        sys.exit(1)


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

COMMANDS = {
    "scan": cmd_scan,
    "verify": cmd_verify,
    "sign": cmd_sign,
    "revoke": cmd_revoke,
    "status": cmd_status,
    "report": cmd_report,
    "taint-check": cmd_taint_check,
    "output-check": cmd_output_check,
    "diff": cmd_diff,
    "badge": cmd_badge,
}

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({
            "error": "No command given",
            "commands": sorted(COMMANDS),
            "docs": "https://agentverif.com/docs",
        }, indent=2))
        sys.exit(2)

    command = sys.argv[1]
    handler = COMMANDS.get(command)
    if handler is None:
        print(json.dumps({
            "error": f"Unknown command: {command}",
            "commands": sorted(COMMANDS),
        }, indent=2))
        sys.exit(2)

    handler(sys.argv[2:])
