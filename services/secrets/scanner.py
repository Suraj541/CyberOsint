"""
Repository Secret and Policy Scanner.
Enforces IMPLEMENT.md Section 36:
'Never commit: .env, API keys, tokens, passwords, private certificates'
"""

from dataclasses import dataclass, field
import logging
from pathlib import Path
import re
from typing import Dict, List, Optional

logger = logging.getLogger("cyber_osint.services.secrets.scanner")

# Forbidden file patterns that must never be tracked in git
MANDATORY_GITIGNORE_PATTERNS = [
    ".env",
    "*.pem",
    "*.key",
    "*.cert",
    "*.crt",
    "id_rsa",
]

# Patterns detecting committed credentials
FORBIDDEN_COMMITTED_PATTERNS = [
    (r"ghp_[A-Za-z0-9_]{20,}", "Committed GitHub Personal Access Token"),
    (r"github_pat_[A-Za-z0-9_]{20,}", "Committed GitHub Fine-Grained Token"),
    (r"-----BEGIN\s+(?:RSA|OPENSSH|DSA|EC)?\s*PRIVATE\s+KEY-----", "Committed Private Certificate / Key"),
    (r"(?i)(?:aws_secret_access_key|aws_access_key_id)\s*=\s*['\"][A-Za-z0-9/+=]{16,}['\"]", "Committed AWS Credential"),
]


@dataclass
class ScanFinding:
    """Represents an identified security violation or policy non-compliance."""
    severity: str  # 'critical', 'warning', 'info'
    rule: str
    file_path: str
    description: str
    line_number: Optional[int] = None


@dataclass
class SecretAuditReport:
    """Report summarizing repository secret safety compliance."""
    is_compliant: bool
    gitignore_compliant: bool
    total_findings: int
    critical_findings: int
    findings: List[ScanFinding] = field(default_factory=list)
    ignored_patterns_verified: List[str] = field(default_factory=list)


class RepositorySecretScanner:
    """
    Scanner for detecting committed secrets and validating git exclusion rules.
    Conforms to IMPLEMENT.md Section 36.
    """

    def __init__(self, repo_root: Optional[Path] = None):
        if repo_root:
            self.repo_root = Path(repo_root)
        else:
            self.repo_root = Path(__file__).resolve().parent.parent.parent

        self.gitignore_path = self.repo_root / ".gitignore"

    def check_gitignore_compliance(self) -> Dict[str, Any]:
        """
        Validates that .gitignore covers all mandated exclusion patterns from Section 36:
        '.env, API keys, tokens, passwords, private certificates'
        """
        if not self.gitignore_path.exists():
            return {
                "compliant": False,
                "missing_patterns": MANDATORY_GITIGNORE_PATTERNS,
                "details": ".gitignore file does not exist in repository root.",
            }

        gitignore_content = self.gitignore_path.read_text(encoding="utf-8")
        missing = []
        found = []

        for pat in MANDATORY_GITIGNORE_PATTERNS:
            # Check for exact pattern or regex pattern in lines
            if pat in gitignore_content:
                found.append(pat)
            else:
                missing.append(pat)

        return {
            "compliant": len(missing) == 0,
            "missing_patterns": missing,
            "verified_patterns": found,
        }

    def scan_files_for_secrets(self, max_files: int = 500) -> List[ScanFinding]:
        """
        Scans source code files for accidentally committed secrets or certificates.
        Skips virtual environments, build directories, and node_modules.
        """
        findings: List[ScanFinding] = []
        skipped_dirs = {
            ".git",
            "node_modules",
            ".next",
            ".venv",
            "venv",
            "__pycache__",
            "data",
            "htmlcov",
            ".pytest_cache",
        }

        # Check for forbidden files that shouldn't exist in tracked workspace
        gi_compliant = self.check_gitignore_compliance().get("compliant", False)
        for p in [".env", "id_rsa", "id_ed25519"]:
            forbidden_file = self.repo_root / p
            if forbidden_file.exists():
                if p == ".env" and gi_compliant:
                    continue
                findings.append(
                    ScanFinding(
                        severity="critical",
                        rule="UNCOMMITTED_SECRET_FILE",
                        file_path=p,
                        description=f"Sensitive file '{p}' exists in project directory. Ensure it is never staged to git.",
                    )
                )

        count = 0
        for path in self.repo_root.rglob("*"):
            if count >= max_files:
                break
            if not path.is_file():
                continue
            if any(part in skipped_dirs for part in path.parts):
                continue

            # Only scan text files
            if path.suffix not in {".py", ".ts", ".tsx", ".js", ".json", ".yaml", ".yml", ".md", ".sh"}:
                continue

            count += 1
            try:
                rel_path = path.relative_to(self.repo_root).as_posix()
                # Skip test fixtures or test cases intentionally checking for secret rejection
                if "tests/" in rel_path or "test_" in rel_path:
                    continue

                content = path.read_text(encoding="utf-8", errors="ignore")
                for line_idx, line in enumerate(content.splitlines(), start=1):
                    for pattern, desc in FORBIDDEN_COMMITTED_PATTERNS:
                        if re.search(pattern, line):
                            findings.append(
                                ScanFinding(
                                    severity="critical",
                                    rule="HARDCODED_SECRET_DETECTED",
                                    file_path=rel_path,
                                    line_number=line_idx,
                                    description=f"{desc} on line {line_idx}.",
                                )
                            )
            except Exception as exc:
                logger.debug("Failed reading file during secret scan '%s': %s", path, exc)

        return findings

    def run_full_audit(self) -> SecretAuditReport:
        """Executes full compliance audit across gitignore rules and workspace contents."""
        gi_check = self.check_gitignore_compliance()
        file_findings = self.scan_files_for_secrets()

        gi_findings = []
        if not gi_check["compliant"]:
            for m in gi_check["missing_patterns"]:
                gi_findings.append(
                    ScanFinding(
                        severity="warning",
                        rule="GITIGNORE_RULE_MISSING",
                        file_path=".gitignore",
                        description=f"Missing recommended gitignore rule: '{m}'.",
                    )
                )

        all_findings = gi_findings + file_findings
        critical_count = sum(1 for f in all_findings if f.severity == "critical")

        return SecretAuditReport(
            is_compliant=critical_count == 0 and gi_check["compliant"],
            gitignore_compliant=gi_check["compliant"],
            total_findings=len(all_findings),
            critical_findings=critical_count,
            findings=all_findings,
            ignored_patterns_verified=gi_check["verified_patterns"],
        )
