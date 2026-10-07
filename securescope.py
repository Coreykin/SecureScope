#!/usr/bin/env python3
"""SecureScope: a transparent STRIDE-oriented scanner for Python web apps."""

from __future__ import annotations

import argparse
import html
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    stride: str
    severity: str
    pattern: re.Pattern[str]
    recommendation: str
    explanation: str


@dataclass
class Finding:
    rule_id: str
    title: str
    stride: str
    severity: str
    file: str
    line: int
    evidence: str
    explanation: str
    recommendation: str


RULES = [
    Rule("SS001", "Debug mode enabled", "Information Disclosure", "High",
         re.compile(r"\bDEBUG\s*=\s*(True|1)\b|app\.run\([^\n]*debug\s*=\s*True", re.I),
         "Disable debug mode outside local development.",
         "Debug output can expose stack traces, configuration data, and application internals."),
    Rule("SS002", "Hard-coded secret", "Information Disclosure", "Critical",
         re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key|token)\b\s*=\s*['\"][^'\"\n]{6,}['\"]"),
         "Load secrets from an approved secret manager or protected environment variable.",
         "A credential stored in source code can leak through repository access or version history."),
    Rule("SS003", "Weak Flask session cookie setting", "Spoofing", "High",
         re.compile(r"SESSION_COOKIE_(SECURE|HTTPONLY)\s*=\s*False", re.I),
         "Enable Secure and HttpOnly session-cookie protections in production.",
         "Weak cookie settings can make session theft or impersonation easier."),
    Rule("SS004", "Insecure HTTP endpoint", "Information Disclosure", "Medium",
         re.compile(r"['\"]http://(?!localhost|127\.0\.0\.1)[^'\"\s]+", re.I),
         "Use HTTPS and validate the remote certificate.",
         "Unencrypted transport can expose or alter data in transit."),
    Rule("SS005", "Shell execution enabled", "Elevation of Privilege", "High",
         re.compile(r"subprocess\.(run|call|Popen)\([^\n]*shell\s*=\s*True", re.I),
         "Avoid shell=True and pass a validated argument list to subprocess.",
         "Shell interpretation can enable command injection when input is attacker controlled."),
    Rule("SS006", "Unsafe dynamic code execution", "Tampering", "Critical",
         re.compile(r"\b(eval|exec)\s*\("),
         "Replace dynamic execution with explicit parsing and an allowlist of permitted operations.",
         "Dynamic execution may allow an attacker to alter program behavior."),
    Rule("SS007", "Broad cross-origin access", "Spoofing", "Medium",
         re.compile(r"CORS\([^\n]*(origins\s*=\s*['\"]?\*|resources\s*=\s*\{?['\"]?/\*)", re.I),
         "Restrict cross-origin requests to trusted origins and required routes.",
         "Broad cross-origin permissions may allow untrusted sites to make requests in a user's context."),
    Rule("SS008", "Unbounded request body read", "Denial of Service", "Medium",
         re.compile(r"request\.(get_data|data)\b", re.I),
         "Set request-size limits and reject oversized payloads before processing.",
         "Reading an unrestricted request body can consume excessive memory or processing time."),
]

TEXT_EXTENSIONS = {".py", ".txt", ".ini", ".cfg", ".toml", ".yaml", ".yml", ".json", ".env"}
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build"}


def scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in TEXT_EXTENSIONS and path.name not in {"Dockerfile", "requirements.txt"}:
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for line_no, line in enumerate(lines, start=1):
            for rule in RULES:
                match = rule.pattern.search(line)
                if match:
                    excerpt = line.strip()
                    if rule.rule_id == "SS002":
                        excerpt = re.sub(r"(['\"])[^'\"]+\1", r"\1[REDACTED]\1", excerpt)
                    findings.append(Finding(
                        rule.rule_id, rule.title, rule.stride, rule.severity,
                        str(path.relative_to(root)), line_no, excerpt[:180],
                        rule.explanation, rule.recommendation,
                    ))
    return findings


def summary(findings: list[Finding]) -> dict:
    severities = {level: 0 for level in ["Critical", "High", "Medium", "Low"]}
    stride = {}
    for finding in findings:
        severities[finding.severity] = severities.get(finding.severity, 0) + 1
        stride[finding.stride] = stride.get(finding.stride, 0) + 1
    return {"total_findings": len(findings), "by_severity": severities, "by_stride": stride}


def write_json(output: Path, target: Path, findings: list[Finding]) -> None:
    payload = {"tool": "SecureScope", "target": str(target), "summary": summary(findings),
               "findings": [asdict(f) for f in findings]}
    output.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_html(output: Path, target: Path, findings: list[Finding]) -> None:
    counts = summary(findings)
    rows = "".join(
        f"<tr><td>{html.escape(f.severity)}</td><td>{html.escape(f.stride)}</td>"
        f"<td>{html.escape(f.title)}</td><td>{html.escape(f.file)}:{f.line}</td>"
        f"<td><code>{html.escape(f.evidence)}</code></td><td>{html.escape(f.recommendation)}</td></tr>"
        for f in findings
    )
    document = f"""<!doctype html><html><head><meta charset='utf-8'><title>SecureScope Report</title>
<style>body{{font:16px Arial,sans-serif;max-width:1180px;margin:40px auto;color:#172033}}h1{{color:#163a63}}
table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #d6dce5;padding:10px;text-align:left;vertical-align:top}}
th{{background:#163a63;color:white}}tr:nth-child(even){{background:#f4f7fa}}code{{font-size:13px;word-break:break-word}}</style></head>
<body><h1>SecureScope STRIDE Report</h1><p><strong>Target:</strong> {html.escape(str(target))}</p>
<p><strong>Total findings:</strong> {counts['total_findings']} &nbsp; <strong>Critical:</strong> {counts['by_severity']['Critical']}
&nbsp; <strong>High:</strong> {counts['by_severity']['High']} &nbsp; <strong>Medium:</strong> {counts['by_severity']['Medium']}</p>
<table><thead><tr><th>Severity</th><th>STRIDE</th><th>Finding</th><th>Location</th><th>Evidence</th><th>Recommendation</th></tr></thead>
<tbody>{rows}</tbody></table><p><em>Prototype output requires human review and does not prove that an application is secure.</em></p></body></html>"""
    output.write_text(document, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan a Python web application for STRIDE-related security indicators.")
    parser.add_argument("target", type=Path, help="Project directory to scan")
    parser.add_argument("--json", type=Path, default=Path("securescope-report.json"))
    parser.add_argument("--html", type=Path, default=Path("securescope-report.html"))
    args = parser.parse_args()
    if not args.target.is_dir():
        parser.error("target must be an existing directory")
    findings = scan(args.target.resolve())
    write_json(args.json, args.target, findings)
    write_html(args.html, args.target, findings)
    print(f"SecureScope found {len(findings)} potential issues.")
    print(f"JSON report: {args.json}\nHTML report: {args.html}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
