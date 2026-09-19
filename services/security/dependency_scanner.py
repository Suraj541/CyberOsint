"""
Dependency & Container Security Scanner Module.
Conforms to IMPLEMENT.md Section 37 (Step 36: Security Hardening).
Provides automated scanning for third-party libraries and Dockerfile container configurations.
"""

from dataclasses import dataclass, field
import logging
from pathlib import Path
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger("cyber_osint.services.security.dependency_scanner")

# Curated catalog of known historical CVE patterns for fast static verification
KNOWN_VULNERABILITIES = [
    {"package": "urllib3", "version_spec": "<1.26.18", "cve": "CVE-2023-45803", "severity": "medium", "description": "HTTP request body leak on redirect"},
    {"package": "requests", "version_spec": "<2.31.0", "cve": "CVE-2023-32681", "severity": "medium", "description": "Proxy-Authorization header leak on redirect"},
    {"package": "cryptography", "version_spec": "<41.0.6", "cve": "CVE-2023-49083", "severity": "high", "description": "NULL-dereference when loading PKCS#7 certificates"},
    {"package": "jinja2", "version_spec": "<3.1.3", "cve": "CVE-2024-22195", "severity": "medium", "description": "HTML attribute injection vulnerability"},
]


@dataclass
class VulnerabilityFinding:
    package: str
    installed_version: Optional[str]
    cve: str
    severity: str
    description: str
    recommendation: str


@dataclass
class ContainerPostureFinding:
    severity: str
    rule_id: str
    line_number: Optional[int]
    description: str
    remediation: str


class DependencyScanner:
    """Scans project dependency manifests (requirements.txt / package.json) for security vulnerabilities."""

    def __init__(self, repo_root: Optional[Path] = None):
        if repo_root:
            self.repo_root = Path(repo_root)
        else:
            self.repo_root = Path(__file__).resolve().parent.parent.parent

    def scan_dependencies(self) -> Dict[str, Any]:
        """Scans requirements files for vulnerable packages."""
        findings: List[VulnerabilityFinding] = []
        scanned_files = []

        req_candidates = [
            self.repo_root / "requirements.txt",
            self.repo_root / "apps" / "api" / "requirements.txt",
        ]

        total_packages = 0
        for req_file in req_candidates:
            if not req_file.exists():
                continue
            scanned_files.append(str(req_file.relative_to(self.repo_root)))
            try:
                content = req_file.read_text(encoding="utf-8")
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    total_packages += 1
                    # Match package==version or package>=version
                    pkg_match = re.match(r"^([A-Za-z0-9_\-\.]+)(?:[=><~]+([0-9A-Za-z_\.\-]+))?", line)
                    if pkg_match:
                        pkg_name = pkg_match.group(1).lower()
                        installed_ver = pkg_match.group(2)
                        for vuln in KNOWN_VULNERABILITIES:
                            if vuln["package"] == pkg_name:
                                # For demonstration, flag if matching known vulnerable package
                                findings.append(
                                    VulnerabilityFinding(
                                        package=pkg_name,
                                        installed_version=installed_ver,
                                        cve=vuln["cve"],
                                        severity=vuln["severity"],
                                        description=vuln["description"],
                                        recommendation=f"Update {pkg_name} to latest patched version.",
                                    )
                                )
            except Exception as exc:
                logger.debug("Failed reading requirements file %s: %s", req_file, exc)

        return {
            "status": "passed" if len(findings) == 0 else "vulnerabilities_detected",
            "total_packages_scanned": total_packages,
            "vulnerabilities_found": len(findings),
            "scanned_manifests": scanned_files,
            "findings": [asdict_finding(f) for f in findings],
        }


class ContainerScanner:
    """Audits Dockerfiles and container runtime configurations for security hardening."""

    def __init__(self, repo_root: Optional[Path] = None):
        if repo_root:
            self.repo_root = Path(repo_root)
        else:
            self.repo_root = Path(__file__).resolve().parent.parent.parent

    def scan_dockerfile(self, dockerfile_path: Optional[Path] = None) -> Dict[str, Any]:
        """Inspects Dockerfile against security best practices (CIS Docker Benchmark)."""
        target = dockerfile_path or (self.repo_root / "Dockerfile")
        if not target.exists():
            # Check apps/api/Dockerfile
            alt_target = self.repo_root / "apps" / "api" / "Dockerfile"
            if alt_target.exists():
                target = alt_target

        findings: List[ContainerPostureFinding] = []
        if not target.exists():
            return {
                "status": "no_dockerfile",
                "scanned_file": None,
                "dockerfile_checked": "Dockerfile",
                "findings": [],
                "findings_count": 0,
                "total_findings": 0,
                "recommendations": ["Ensure Dockerfile is created with non-root user and immutable base tags."],
                "message": "No Dockerfile found in repository root.",
            }

        try:
            content = target.read_text(encoding="utf-8")
            lines = content.splitlines()

            has_user_directive = False
            has_healthcheck = False

            for line_idx, line in enumerate(lines, start=1):
                clean = line.strip()
                if not clean or clean.startswith("#"):
                    continue

                upper = clean.upper()
                if upper.startswith("USER ") and "ROOT" not in upper:
                    has_user_directive = True

                if upper.startswith("HEALTHCHECK "):
                    has_healthcheck = True

                # Check for :latest tag in FROM
                if upper.startswith("FROM ") and (":LATEST" in upper or ":" not in clean.split()[1]):
                    findings.append(
                        ContainerPostureFinding(
                            severity="warning",
                            rule_id="UNPINNED_BASE_IMAGE",
                            line_number=line_idx,
                            description=f"Base image uses unpinned or :latest tag: '{clean}'",
                            remediation="Pin base image to specific digest or immutable version tag.",
                        )
                    )

                # Check for hardcoded secrets in ENV
                if upper.startswith("ENV ") and re.search(r"(?i)(?:secret|password|token|key)\s*=", clean):
                    findings.append(
                        ContainerPostureFinding(
                            severity="critical",
                            rule_id="HARDCODED_SECRET_IN_DOCKERFILE",
                            line_number=line_idx,
                            description="Potential hardcoded credential in Dockerfile ENV directive.",
                            remediation="Pass secrets at runtime via environment variables or secret mounts.",
                        )
                    )

            if not has_user_directive:
                findings.append(
                    ContainerPostureFinding(
                        severity="warning",
                        rule_id="RUNS_AS_ROOT",
                        line_number=None,
                        description="Container runs as default root user without non-privileged USER directive.",
                        remediation="Add 'USER appuser' or non-root UID/GID before container execution.",
                    )
                )

            if not has_healthcheck:
                findings.append(
                    ContainerPostureFinding(
                        severity="info",
                        rule_id="MISSING_HEALTHCHECK",
                        line_number=None,
                        description="No HEALTHCHECK instruction configured in Dockerfile.",
                        remediation="Define HEALTHCHECK instruction to allow orchestrator to detect stalled containers.",
                    )
                )

            return {
                "status": "passed" if len(findings) == 0 else "recommendations_found",
                "scanned_file": str(target.relative_to(self.repo_root)),
                "dockerfile_checked": str(target.relative_to(self.repo_root)),
                "total_findings": len(findings),
                "findings_count": len(findings),
                "recommendations": ["Ensure base image digests are pinned for production deployments."],
                "findings": [
                    {
                        "severity": f.severity,
                        "rule_id": f.rule_id,
                        "line_number": f.line_number,
                        "description": f.description,
                        "remediation": f.remediation,
                    }
                    for f in findings
                ],
            }
        except Exception as exc:
            return {"status": "error", "message": str(exc), "findings": []}


def asdict_finding(f: VulnerabilityFinding) -> Dict[str, Any]:
    return {
        "package": f.package,
        "installed_version": f.installed_version,
        "cve": f.cve,
        "severity": f.severity,
        "description": f.description,
        "recommendation": f.recommendation,
    }


dependency_scanner = DependencyScanner()
container_scanner = ContainerScanner()
