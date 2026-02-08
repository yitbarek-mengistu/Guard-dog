"""
Guard-dog
Simple Python CLI orchestrator that runs Semgrep and pip-audit (if installed),
collects JSON outputs and writes a combined report.

Usage:
  python scan.py [--min-severity {LOW,MEDIUM,HIGH,CRITICAL}] [--output report.json]

This is an MVP intended for local use and CI. It favors calling installed CLIs
(`semgrep` and `pip-audit`) and parsing their JSON outputs. It does not install
those tools for you.
"""

TOOL_NAME = "Guard-dog"

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime

SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def which(cmd):
    return shutil.which(cmd)


def run_cmd(cmd, capture_output=True):
    try:
        res = subprocess.run(cmd, shell=True, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return res.returncode, res.stdout, res.stderr
    except Exception as e:
        return 1, "", str(e)


def run_semgrep(output_path):
    if not which("semgrep"):
        return {"ok": False, "error": "semgrep not found"}
    cmd = f"semgrep --config auto --json --output {output_path}"
    code, out, err = run_cmd(cmd)
    return {"ok": code == 0, "code": code, "stdout": out, "stderr": err}


def run_pip_audit(output_path):
    if not which("pip-audit"):
        return {"ok": False, "error": "pip-audit not found"}
    cmd = f"pip-audit -f json > {output_path}"
    code, out, err = run_cmd(cmd)
    return {"ok": code == 0, "code": code, "stdout": out, "stderr": err}


def normalize_semgrep(semgrep_json):
    findings = []
    try:
        data = json.loads(semgrep_json)
    except Exception:
        return findings
    for res in data.get("results", []):
        findings.append({
            "tool": "semgrep",
            "rule_id": res.get("check_id"),
            "message": res.get("extra", {}).get("message"),
            "path": res.get("path"),
            "start": res.get("start", {}),
            "end": res.get("end", {}),
            "severity": res.get("extra", {}).get("severity", "LOW").upper(),
        })
    return findings


def normalize_pip_audit(pip_json):
    findings = []
    try:
        data = json.loads(pip_json)
    except Exception:
        return findings
    for pkg in data:
        vuln = pkg.get("vulns")
        if not vuln:
            continue
        for v in vuln:
            findings.append({
                "tool": "pip-audit",
                "package": pkg.get("name"),
                "installed_version": pkg.get("version"),
                "vuln_id": v.get("id") or v.get("aliases", [None])[0],
                "description": v.get("details"),
                "severity": (v.get("severity") or "LOW").upper(),
            })
    return findings


def severity_at_least(s, threshold):
    try:
        return SEVERITY_ORDER.index(s) >= SEVERITY_ORDER.index(threshold)
    except ValueError:
        return False


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--min-severity", choices=SEVERITY_ORDER, default="LOW")
    p.add_argument("--output", default="vuln-report.json")
    args = p.parse_args()

    timestamp = datetime.utcnow().isoformat() + "Z"
    out_dir = os.path.dirname(os.path.abspath(args.output)) or "."
    os.makedirs(out_dir, exist_ok=True)

    semgrep_out = os.path.join(out_dir, "semgrep.json")
    pip_out = os.path.join(out_dir, "pip-audit.json")

    results = {"metadata": {"timestamp": timestamp, "tool": TOOL_NAME}, "findings": []}

    sg = run_semgrep(semgrep_out)
    if sg.get("ok"):
        with open(semgrep_out, "r", encoding="utf-8") as f:
            semg = f.read()
        results["findings"].extend(normalize_semgrep(semg))
    else:
        results.setdefault("errors", []).append({"tool": "semgrep", "detail": sg})

    pa = run_pip_audit(pip_out)
    if pa.get("ok"):
        with open(pip_out, "r", encoding="utf-8") as f:
            pjs = f.read()
        results["findings"].extend(normalize_pip_audit(pjs))
    else:
        results.setdefault("errors", []).append({"tool": "pip-audit", "detail": pa})

    # Filter by severity
    filtered = [f for f in results["findings"] if severity_at_least(f.get("severity", "LOW"), args.min_severity)]
    results["filtered_findings"] = filtered
    results["counts"] = {"total": len(results["findings"]), "filtered": len(filtered)}

    with open(args.output, "w", encoding="utf-8") as outf:
        json.dump(results, outf, indent=2)

    # Exit non-zero if high severity findings exist
    for f in filtered:
        if severity_at_least(f.get("severity", "LOW"), "HIGH"):
            print(f"{TOOL_NAME}: High/critical issue found. See {args.output}")
            sys.exit(2)

    print(f"{TOOL_NAME}: Scan complete. Report: {args.output}")
    sys.exit(0)
