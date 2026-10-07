#!/usr/bin/env python3
"""SecureScope: a transparent STRIDE-oriented scanner for Python web apps."""

from __future__ import annotations

import argparse
import ast
import csv
from urllib.parse import urlsplit
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


VERSION = "0.2.0"


def _name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _name(node.value) + "." + node.attr
    return ""


def _setting(node):
    if isinstance(node, ast.Subscript) and _name(node.value).endswith(".config"):
        if isinstance(node.slice, ast.Constant):
            return str(node.slice.value)
    return _name(node).split(".")[-1]


def _literal(node):
    return node.value if isinstance(node, ast.Constant) else None


def _secret_key(key):
    return bool(re.search(r"(?:^|_)(password|passwd|secret|secret_key|api_key|token|access_token)(?:$|_)", key, re.I))


def _python_hits(source):
    tree = ast.parse(source)
    hits = set()
    def setting(key, value, line):
        v = _literal(value)
        if key.upper() == "DEBUG" and v in (True, 1):
            hits.add(("SS001", line))
        if _secret_key(key) and isinstance(v, str) and v.strip():
            hits.add(("SS002", line))
        if key.upper() in {"SESSION_COOKIE_SECURE", "SESSION_COOKIE_HTTPONLY"} and v in (False, 0):
            hits.add(("SS003", line))
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                setting(_setting(target), node.value, node.lineno)
        elif isinstance(node, ast.AnnAssign) and node.value:
            setting(_setting(node.target), node.value, node.lineno)
        elif isinstance(node, ast.Call):
            name = _name(node.func)
            kw = {k.arg: k.value for k in node.keywords if k.arg}
            if name.endswith(".config.update"):
                for key, value in kw.items():
                    setting(key, value, value.lineno)
                for arg in node.args:
                    if isinstance(arg, ast.Dict):
                        for k, v in zip(arg.keys, arg.values):
                            if isinstance(k, ast.Constant):
                                setting(str(k.value), v, v.lineno)
            if name.endswith(".run") and _literal(kw.get("debug")) is True:
                hits.add(("SS001", node.lineno))
            if name in {"subprocess.run", "subprocess.call", "subprocess.Popen"} and _literal(kw.get("shell")) is True:
                hits.add(("SS005", node.lineno))
            if name in {"eval", "exec", "builtins.eval", "builtins.exec"}:
                hits.add(("SS006", node.lineno))
            if name in {"CORS", "flask_cors.CORS", "cross_origin"}:
                # A wildcard route alone does not imply wildcard origins.
                origins = kw.get("origins")
                wildcard = _literal(origins) == "*"
                if isinstance(origins, (ast.List, ast.Tuple)):
                    wildcard = any(_literal(v) == "*" for v in origins.elts)
                resources = kw.get("resources")
                if isinstance(resources, ast.Dict):
                    for settings in resources.values:
                        if isinstance(settings, ast.Dict):
                            for k, v in zip(settings.keys, settings.values):
                                if _literal(k) == "origins" and _literal(v) == "*":
                                    wildcard = True
                if wildcard:
                    hits.add(("SS007", node.lineno))
        if isinstance(node, ast.Attribute) and _name(node) in {"request.data", "request.get_data"}:
            hits.add(("SS008", node.lineno))
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.startswith("http://"):
            host = urlsplit(node.value).hostname
            if host and host not in {"localhost", "127.0.0.1", "::1"}:
                hits.add(("SS004", node.lineno))
    return sorted(hits, key=lambda h: (h[1], h[0]))


def scan(root: Path) -> list[Finding]:
    """Read source only. Never import or execute the application being scanned."""
    findings = []
    rules = {rule.rule_id: rule for rule in RULES}
    root = root.resolve()
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        relative = path.relative_to(root)
        if any(part in SKIP_DIRS for part in relative.parts):
            continue
        if path.suffix.lower() not in TEXT_EXTENSIONS and path.name not in {".env", "Dockerfile", "requirements.txt"}:
            continue
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        lines = source.splitlines()
        if path.suffix.lower() == ".py":
            try:
                hits = _python_hits(source)
            except SyntaxError as exc:
                raise ValueError(f"Cannot parse {relative}:{exc.lineno}; scan stopped to avoid an incomplete report") from exc
        else:
            hits = []
            for line_no, line in enumerate(lines, 1):
                if line.lstrip().startswith(("#", ";", "//")):
                    continue
                for rule in RULES:
                    if rule.pattern.search(line):
                        hits.append((rule.rule_id, line_no))
        for rule_id, line_no in hits:
            rule = rules[rule_id]
            # Do not copy raw source into any report: credentials may share a line
            # with a different finding or appear inside URL user information.
            excerpt = f"{rule.title} detected; source content withheld. Review the source at this location."
            findings.append(Finding(rule.rule_id, rule.title, rule.stride, rule.severity,
                str(relative), line_no, excerpt, rule.explanation, rule.recommendation))
    return findings


def write_csv(output: Path, target: Path, findings: list[Finding]) -> None:
    with output.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(Finding.__dataclass_fields__))
        writer.writeheader()
        for finding in findings:
            # Neutralize spreadsheet formula prefixes in untrusted filenames.
            row = asdict(finding)
            writer.writerow({k: "'" + v if isinstance(v, str) and v.startswith(("=", "+", "-", "@")) else v for k, v in row.items()})


def summary(findings: list[Finding]) -> dict:
    severities = {level: 0 for level in ["Critical", "High", "Medium", "Low"]}
    stride = {}
    for finding in findings:
        severities[finding.severity] = severities.get(finding.severity, 0) + 1
        stride[finding.stride] = stride.get(finding.stride, 0) + 1
    return {"total_findings": len(findings), "by_severity": severities, "by_stride": stride}


def write_json(output: Path, target: Path, findings: list[Finding]) -> None:
    payload = {"tool": "SecureScope", "version": VERSION, "limitations": "Static indicators require human review. No dataflow or complete STRIDE coverage. Raw source is withheld to protect secrets.", "target": str(target), "summary": summary(findings),
               "findings": [asdict(f) for f in findings]}
    output.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_html(output: Path, target: Path, findings: list[Finding]) -> None:
    counts = summary(findings)
    rows = "".join(
        f"<tr><td>{html.escape(f.severity)}</td><td>{html.escape(f.stride)}</td>"
        f"<td><strong>{html.escape(f.rule_id)}: {html.escape(f.title)}</strong><p>{html.escape(f.explanation)}</p></td><td>{html.escape(f.file)}:{f.line}</td>"
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
<tbody>{rows or "<tr><td colspan='6'>No supported indicators found. This does not prove the application is secure.</td></tr>"}</tbody></table><p><em>Prototype output requires human review and does not prove that an application is secure.</em></p></body></html>"""
    output.write_text(document, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan a Python web application for STRIDE-related security indicators.")
    parser.add_argument("--version", action="version", version="SecureScope " + VERSION)
    parser.add_argument("--csv", type=Path, help="Optional CSV report")
    parser.add_argument("target", type=Path, help="Project directory to scan")
    parser.add_argument("--json", type=Path, default=Path("securescope-report.json"))
    parser.add_argument("--html", type=Path, default=Path("securescope-report.html"))
    args = parser.parse_args()
    if not args.target.is_dir():
        parser.error("target must be an existing directory")
    try:
        findings = scan(args.target.resolve())
    except ValueError as exc:
        parser.error(str(exc))
    outputs = [args.json, args.html] + ([args.csv] if args.csv else [])
    if len({p.resolve() for p in outputs}) != len(outputs):
        parser.error("report output paths must be distinct")
    for output in outputs:
        if output.resolve().is_relative_to(args.target.resolve()):
            parser.error("save reports outside the scanned directory")
        output.parent.mkdir(parents=True, exist_ok=True)
    write_json(args.json, args.target, findings)
    write_html(args.html, args.target, findings)
    if args.csv:
        write_csv(args.csv, args.target, findings)
        print(f"CSV report: {args.csv}")
    print(f"SecureScope found {len(findings)} potential issues.")
    print(f"JSON report: {args.json}\nHTML report: {args.html}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
