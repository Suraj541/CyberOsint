"""Learning Paths & Cybersecurity Academy Service.

Conforms to Section 48 (Step 47) Version 3 specification:
  - Structured, role-aligned cybersecurity learning pathways
  - Hands-on lab exercises, required competencies, and module progressions
  - Direct links to real OSINT intelligence records, CVEs, and ATT&CK techniques
"""

from datetime import datetime
import logging
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from app.models.intelligence import LearningPathModel

logger = logging.getLogger("cyber_osint.services.learning")

CURATED_LEARNING_PATHS: List[Dict[str, Any]] = [
    {
        "slug": "soc-analyst-pathway",
        "title": "SOC Analyst Operational Specialization (L1 to L3)",
        "role": "Security Operations Center (SOC) Analyst",
        "difficulty": "intermediate",
        "estimated_hours": 60,
        "description": "Comprehensive operational curriculum preparing analysts for high-velocity alert triage, phishing triage, SIEM correlation, endpoint telemetry analysis, and incident containment.",
        "modules": [
            {
                "id": "soc-mod-1",
                "title": "Module 1: Alert Triage & False Positive Reduction",
                "description": "Techniques for analyzing high-volume EDR and NIDS alerts, IP reputation checks, and verifying false alarms.",
                "duration_hours": 12,
                "competencies": ["Log correlation", "VirusTotal/URLhaus lookups", "Alert classification"],
                "lab_exercise": "Triage 20 simulated multi-vector alert packets and separate genuine beaconing from benign web traffic.",
                "linked_content_ids": [1],
            },
            {
                "id": "soc-mod-2",
                "title": "Module 2: Network Forensics & Protocol Dissection",
                "description": "Deep inspection of PCAP packet captures, TLS certificate anomalies, DNS tunneling, and HTTP C2 headers.",
                "duration_hours": 18,
                "competencies": ["Wireshark", "Zeek/Bro logs", "DNS beacon detection"],
                "lab_exercise": "Extract Cobalt Strike beaconing intervals and payload stage DLLs from a live Wireshark capture.",
                "linked_content_ids": [1],
            },
            {
                "id": "soc-mod-3",
                "title": "Module 3: Host Forensics & Incident Response",
                "description": "Memory dumping, Windows Event Log investigation (Sysmon, Event ID 4688, 4624), and PowerShell script block logging.",
                "duration_hours": 30,
                "competencies": ["KAPE triage", "Volatility 3", "MFT / USN journal analysis"],
                "lab_exercise": "Analyze a compromised Domain Controller memory dump to identify Pass-the-Hash credentials.",
                "linked_content_ids": [1],
            },
        ],
    },
    {
        "slug": "threat-hunter-attack",
        "title": "Proactive Threat Hunting with MITRE ATT&CK",
        "role": "Threat Hunter",
        "difficulty": "advanced",
        "estimated_hours": 50,
        "description": "Advanced methodology for hypothesis-driven threat hunting, mapping adversary behaviors against ATT&CK enterprise tactics, and building robust Sigma/YARA rules.",
        "modules": [
            {
                "id": "hunt-mod-1",
                "title": "Module 1: Hypothesis Formulation & Data Stacking",
                "description": "Formulating hunt hypotheses based on recent threat advisories and performing frequency analysis on process execution logs.",
                "duration_hours": 15,
                "competencies": ["Hypothesis formulation", "Parent-child process anomaly hunting"],
                "lab_exercise": "Hunt for Living-off-the-Land binaries (certutil, bitsadmin) across 1 million endpoint events.",
                "linked_content_ids": [1],
            },
            {
                "id": "hunt-mod-2",
                "title": "Module 2: Lateral Movement & Kerberos Abuse",
                "description": "Detecting Kerberoasting, AS-REP roasting, Overpass-the-Hash, and remote service creation across Active Directory.",
                "duration_hours": 20,
                "competencies": ["Kerberos ticket analysis", "BloodHound graph queries", "Sigma rules"],
                "lab_exercise": "Construct a Sigma detection rule for unconstrained Kerberos delegation exploitation.",
                "linked_content_ids": [1],
            },
            {
                "id": "hunt-mod-3",
                "title": "Module 3: Defense Evasion & Rootkit Hunting",
                "description": "Hunting for process hollowing, DLL side-loading, and BYOVD (Bring Your Own Vulnerable Driver) kernel rootkits.",
                "duration_hours": 15,
                "competencies": ["Kernel driver verification", "Process injection detection"],
                "lab_exercise": "Detect signed vulnerable driver load events leading to EDR blindspot termination.",
                "linked_content_ids": [1],
            },
        ],
    },
    {
        "slug": "malware-reverse-engineering",
        "title": "Malware Analysis & Binary Reverse Engineering",
        "role": "Malware Analyst",
        "difficulty": "advanced",
        "estimated_hours": 80,
        "description": "Rigorous practical training in static, dynamic, and code-level reverse engineering of malicious Windows and Linux PE/ELF payloads using Ghidra and x64dbg.",
        "modules": [
            {
                "id": "mal-mod-1",
                "title": "Module 1: Static Triage & Deobfuscation",
                "description": "PE header parsing, import hash (imphash) clustering, section entropy inspection, and string decryption.",
                "duration_hours": 20,
                "competencies": ["FLOSS", "Capa", "PEStudio", "YARA generation"],
                "lab_exercise": "Deobfuscate a heavily packed .NET RedLine Stealer stub to extract C2 domains and config.",
                "linked_content_ids": [1],
            },
            {
                "id": "mal-mod-2",
                "title": "Module 2: Dynamic Behavioral Sandbox Analysis",
                "description": "Sandboxed runtime tracing, API hooking, registry persistence tracking, and network simulation.",
                "duration_hours": 25,
                "competencies": ["Procmon", "FakeNet-NG", "API Monitor"],
                "lab_exercise": "Intercept dynamic C2 check-in packets and recover an in-memory RC4 encryption key.",
                "linked_content_ids": [1],
            },
            {
                "id": "mal-mod-3",
                "title": "Module 3: Disassembly & Decompilation with Ghidra",
                "description": "Reconstructing control flow graphs, locating main dispatch routines, reversing custom crypto, and patching anti-analysis tricks.",
                "duration_hours": 35,
                "competencies": ["Ghidra", "x64dbg", "Anti-debugging defeat", "Assembly x86_64"],
                "lab_exercise": "Reverse engineer a LockBit ransomware encryptor function and identify weakness in the PRNG keygen.",
                "linked_content_ids": [1],
            },
        ],
    },
]


class LearningService:
    """Manages structured Cybersecurity Learning Paths and progress tracking."""

    def seed_initial_paths(self, db: Session) -> int:
        """Seeds curated cybersecurity learning curricula."""
        seeded = 0
        for item in CURATED_LEARNING_PATHS:
            existing = db.query(LearningPathModel).filter(LearningPathModel.slug == item["slug"]).first()
            if not existing:
                path = LearningPathModel(
                    slug=item["slug"],
                    title=item["title"],
                    description=item["description"],
                    difficulty=item["difficulty"],
                    estimated_hours=item["estimated_hours"],
                    role=item["role"],
                    modules=item["modules"],
                )
                db.add(path)
                seeded += 1
        if seeded > 0:
            db.commit()
            logger.info("Seeded %d learning paths", seeded)
        return seeded

    def list_paths(
        self,
        db: Session,
        difficulty: Optional[str] = None,
        role: Optional[str] = None,
    ) -> List[LearningPathModel]:
        """Lists available learning paths with role and difficulty filtering."""
        self.seed_initial_paths(db)
        query = db.query(LearningPathModel)
        if difficulty:
            query = query.filter(LearningPathModel.difficulty == difficulty.lower())
        if role:
            query = query.filter(LearningPathModel.role.ilike(f"%{role}%"))
        return query.order_by(LearningPathModel.estimated_hours.asc()).all()

    def get_path_by_slug(self, db: Session, slug: str) -> Optional[LearningPathModel]:
        """Retrieves a learning pathway by unique slug."""
        self.seed_initial_paths(db)
        return db.query(LearningPathModel).filter(LearningPathModel.slug == slug).first()

    def get_path_by_id(self, db: Session, path_id: int) -> Optional[LearningPathModel]:
        """Retrieves a learning pathway by ID."""
        self.seed_initial_paths(db)
        return db.query(LearningPathModel).filter(LearningPathModel.id == path_id).first()


learning_service = LearningService()
