
# Vulnerability Scanner (MVP)

This repository contains a minimal Python CLI that orchestrates Semgrep and pip-audit to scan Python source code and dependencies.

Files:
- `vulnscan/scan.py` - CLI orchestrator
- `vulnscan/requirements.txt` - Python packages expected (semgrep, pip-audit)
- `.github/workflows/scan.yml` - GitHub Actions workflow (created next)

Usage (local):
1. Create a virtual environment and install requirements
   python -m venv .venv; .\.venv\Scripts\Activate; pip install -r vulnscan/requirements.txt
2. Run the scanner
   python vulnscan/scan.py --min-severity MEDIUM --output report.json

CI: A GitHub Actions workflow runs the scanner on push and pull_request and uploads the report as an artifact.
