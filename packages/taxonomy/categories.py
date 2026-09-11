"""
Cybersecurity Taxonomy Categories Definition
Defines the canonical 16 cybersecurity domains, stable category identifiers,
hierarchical subcategories, keywords, and canonical tags.
Conforms strictly to IMPLEMENT.md Section 14 specifications.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class CategoryId(str, Enum):
    """
    Stable snake_case category identifiers.
    Must never be changed once established to ensure backward and cross-system compatibility.
    """

    APPLICATION_SECURITY = "application_security"
    CLOUD_SECURITY = "cloud_security"
    NETWORK_SECURITY = "network_security"
    MALWARE = "malware"
    THREAT_INTELLIGENCE = "threat_intelligence"
    DIGITAL_FORENSICS = "digital_forensics"
    INCIDENT_RESPONSE = "incident_response"
    OSINT = "osint"
    CRYPTOGRAPHY = "cryptography"
    IDENTITY = "identity"
    MOBILE = "mobile"
    IOT = "iot"
    ICS = "ics"
    AI_SECURITY = "ai_security"
    DEVSECOPS = "devsecops"
    VULNERABILITY_MANAGEMENT = "vulnerability_management"


@dataclass
class Subcategory:
    """Hierarchical classification node beneath a primary category."""

    id: str
    name: str
    description: str
    keywords: List[str] = field(default_factory=list)


@dataclass
class Category:
    """Top-level cybersecurity domain definition."""

    id: str
    name: str
    description: str
    subcategories: List[Subcategory] = field(default_factory=list)
    keywords: List[str] = field(default_factory=list)
    canonical_tags: List[str] = field(default_factory=list)

    @property
    def subcategory_ids(self) -> List[str]:
        return [sub.id for sub in self.subcategories]

    def get_subcategory(self, sub_id: str) -> Optional[Subcategory]:
        for sub in self.subcategories:
            if sub.id == sub_id:
                return sub
        return None


# -------------------------------------------------------------
# Canonical Catalogue of all 16 Mandated Categories
# -------------------------------------------------------------
CATEGORIES_CATALOGUE: Dict[str, Category] = {
    CategoryId.APPLICATION_SECURITY.value: Category(
        id=CategoryId.APPLICATION_SECURITY.value,
        name="Application Security",
        description="Protection of software applications and APIs across their lifecycle from code execution, injection, and design flaws.",
        subcategories=[
            Subcategory("web_security", "Web Security", "Web application defenses, OWASP Top 10, SSRF, XSS, CSRF", ["owasp", "xss", "csrf", "ssrf", "clickjacking"]),
            Subcategory("api_security", "API Security", "REST, GraphQL, and gRPC security, BOLA, rate limiting, schema validation", ["bola", "graphql", "rest api", "jwt validation"]),
            Subcategory("injection_attacks", "Injection Attacks", "SQLi, command injection, LDAP injection, template injection", ["sqli", "sql injection", "rce", "command injection", "ssti"]),
            Subcategory("memory_safety", "Memory Safety", "Buffer overflows, use-after-free, memory corruption, ROP chains", ["buffer overflow", "use-after-free", "memory corruption", "heap spray"]),
            Subcategory("secure_coding", "Secure Coding", "Code review, sanitization, input validation, secure design patterns", ["secure coding", "input sanitization", "defensive programming"]),
        ],
        keywords=["appsec", "web application", "injection", "buffer overflow", "xss", "sqli", "owasp", "api security"],
        canonical_tags=["Application Security", "AppSec", "Web Security", "API Security", "OWASP"],
    ),
    CategoryId.CLOUD_SECURITY.value: Category(
        id=CategoryId.CLOUD_SECURITY.value,
        name="Cloud Security",
        description="Securing cloud infrastructure, services, workloads, and configurations in multi-cloud and hybrid environments.",
        subcategories=[
            Subcategory("aws_security", "AWS Security", "Amazon Web Services IAM, S3 bucket permissions, GuardDuty, CloudTrail", ["aws", "s3", "cloudtrail", "guardduty", "iam"]),
            Subcategory("azure_security", "Azure Security", "Microsoft Azure Sentinel, Entra ID, Defender for Cloud", ["azure", "entra id", "azure ad", "sentinel"]),
            Subcategory("gcp_security", "GCP Security", "Google Cloud Platform security command center, IAM, workload identity", ["gcp", "google cloud", "workload identity"]),
            Subcategory("kubernetes_security", "Kubernetes & Container Security", "K8s RBAC, pod security admission, container breakouts, image scanning", ["kubernetes", "k8s", "docker", "container breakout"]),
            Subcategory("cloud_misconfiguration", "Cloud Misconfiguration", "Exposed storage, overly permissive IAM, public metadata services", ["cloud misconfiguration", "leaked s3", "exposed bucket"]),
            Subcategory("serverless_security", "Serverless Security", "Lambda, Cloud Functions, and event-driven architecture security", ["serverless", "lambda security", "cloud functions"]),
        ],
        keywords=["cloud security", "aws", "azure", "gcp", "kubernetes", "k8s", "container", "docker", "s3 bucket"],
        canonical_tags=["Cloud Security", "AWS", "Azure", "GCP", "Kubernetes", "Containers"],
    ),
    CategoryId.NETWORK_SECURITY.value: Category(
        id=CategoryId.NETWORK_SECURITY.value,
        name="Network Security",
        description="Protection of network infrastructure, perimeter defenses, traffic isolation, and transport protocols.",
        subcategories=[
            Subcategory("firewalls_ids_ips", "Firewalls & NIDS/NIPS", "Stateful inspection, next-gen firewalls, Suricata, Snort, Zeek", ["firewall", "ids", "ips", "suricata", "snort", "zeek"]),
            Subcategory("dns_security", "DNS Security", "DNS spoofing, DNS tunneling, DNSSEC, sinkholing, DoH/DoT", ["dns", "dnssec", "dns tunneling", "sinkholing"]),
            Subcategory("vpn_zerotrust", "VPN & Zero Trust", "WireGuard, OpenVPN, ZTNA, micro-segmentation, perimeter-less defense", ["vpn", "zero trust", "ztna", "wireguard", "microsegmentation"]),
            Subcategory("ddos_protection", "DDoS Protection", "Distributed denial of service, volumetric attacks, amplification, mitigations", ["ddos", "dos", "amplification attack", "syn flood"]),
            Subcategory("wireless_security", "Wireless Security", "Wi-Fi WPA3, evil twin, Bluetooth, RFID, rogue AP detection", ["wpa3", "wi-fi", "bluetooth security", "evil twin"]),
        ],
        keywords=["network security", "firewall", "ids", "ips", "dns", "ddos", "vpn", "zero trust", "routing"],
        canonical_tags=["Network Security", "Firewall", "DNS", "DDoS", "Zero Trust", "VPN"],
    ),
    CategoryId.MALWARE.value: Category(
        id=CategoryId.MALWARE.value,
        name="Malware",
        description="Analysis, detection, reverse engineering, and tracking of malicious software and payload artifacts.",
        subcategories=[
            Subcategory("ransomware", "Ransomware", "File encryption, double extortion, ransomware-as-a-service (RaaS)", ["ransomware", "raas", "extortion", "encryptor"]),
            Subcategory("infostealers", "Infostealers", "Credential harvesting, cookie theft, RedLine, Lumma, Vidar", ["infostealer", "stealer", "redline", "lumma", "vidar"]),
            Subcategory("trojans", "Trojans & RATs", "Remote access trojans, backdoors, Cobalt Strike, Mythic, Sliver", ["rat", "trojan", "cobalt strike", "sliver", "backdoor"]),
            Subcategory("rootkits", "Rootkits & Bootkits", "Kernel-mode drivers, UEFI rootkits, persistence mechanisms", ["rootkit", "bootkit", "uefi", "kernel driver"]),
            Subcategory("botnets", "Botnets", "C2 coordination, Mirai, IoT infection, brute-force spreading", ["botnet", "mirai", "c2", "command and control"]),
            Subcategory("wiper_malware", "Wiper Malware", "Destructive malware, master boot record erasure, disk wiping", ["wiper", "hermeticwiper", "caddwiper", "destructive malware"]),
        ],
        keywords=["malware", "ransomware", "infostealer", "trojan", "rat", "rootkit", "botnet", "wiper", "payload"],
        canonical_tags=["Malware", "Ransomware", "Infostealer", "Trojan", "Botnet", "Rootkit"],
    ),
    CategoryId.THREAT_INTELLIGENCE.value: Category(
        id=CategoryId.THREAT_INTELLIGENCE.value,
        name="Threat Intelligence",
        description="Evidence-based knowledge about cyber threats, adversary capabilities, infrastructure, and campaigns.",
        subcategories=[
            Subcategory("apt_groups", "Advanced Persistent Threats (APTs)", "Nation-state groups, cyber espionage, state-sponsored campaigns", ["apt", "nation-state", "espionage", "sandworm", "lazarus"]),
            Subcategory("indicators_of_compromise", "Indicators of Compromise (IOCs)", "Hashes, malicious domains, C2 IPs, JA3/JA4 fingerprints", ["ioc", "file hash", "malicious ip", "ja3", "c2 domain"]),
            Subcategory("tactics_techniques_procedures", "TTPs & MITRE ATT&CK", "Attack mappings, behavioral matrix, persistence techniques", ["mitre att&ck", "ttp", "attack technique"]),
            Subcategory("darkweb_monitoring", "Darkweb & Threat Actors", "Underground forums, leak sites, illicit marketplaces, Telegram channels", ["darkweb", "leak site", "underground forum", "actor profile"]),
            Subcategory("detection_rules", "Detection Rules", "YARA, Sigma, Snort rules, behavioral hunting queries", ["yara", "sigma rule", "detection rule", "threat hunting"]),
        ],
        keywords=["threat intelligence", "cti", "apt", "ioc", "mitre", "att&ck", "darkweb", "threat actor"],
        canonical_tags=["Threat Intelligence", "CTI", "APT", "IOC", "MITRE ATT&CK", "Dark Web"],
    ),
    CategoryId.DIGITAL_FORENSICS.value: Category(
        id=CategoryId.DIGITAL_FORENSICS.value,
        name="Digital Forensics",
        description="Identification, preservation, extraction, and documentation of digital evidence for post-incident investigations.",
        subcategories=[
            Subcategory("memory_forensics", "Memory Forensics", "RAM capture analysis, Volatility, process hollowing, injected DLLs", ["volatility", "memory forensics", "ram dump", "process injection"]),
            Subcategory("disk_forensics", "Disk & File System Forensics", "NTFS artifact analysis, MFT, USN journal, shadow copies, carving", ["mft", "file carving", "disk image", "sleuthkit", "autopsy"]),
            Subcategory("network_forensics", "Network Forensics", "PCAP analysis, traffic flow analysis, Wireshark, Zeek logs", ["pcap", "wireshark", "packet capture", "network forensics"]),
            Subcategory("timeline_reconstruction", "Timeline & Artifact Analysis", "Prefetch, ShimCache, AmCache, Event Logs, LNK files", ["prefetch", "shimcache", "amcache", "event logs", "timeline"]),
            Subcategory("mobile_forensics", "Mobile Forensics", "iOS/Android forensic extraction, encrypted databases, Cellebrite", ["cellebrite", "mobile forensics", "sqlite carving"]),
        ],
        keywords=["digital forensics", "dfir", "memory forensics", "volatility", "pcap", "mft", "disk forensics"],
        canonical_tags=["Digital Forensics", "DFIR", "Memory Forensics", "Disk Forensics", "Wireshark"],
    ),
    CategoryId.INCIDENT_RESPONSE.value: Category(
        id=CategoryId.INCIDENT_RESPONSE.value,
        name="Incident Response",
        description="Structured operational containment, eradication, and recovery workflows during active security compromises.",
        subcategories=[
            Subcategory("containment_eradication", "Containment & Eradication", "Host isolation, credential revocation, malicious artifact removal", ["host isolation", "containment", "eradication"]),
            Subcategory("playbooks_runbooks", "Playbooks & Runbooks", "Standard operating procedures for ransomware, phishing, account takeover", ["incident playbook", "soar", "runbook"]),
            Subcategory("threat_hunting", "Threat Hunting", "Proactive hypothesis-driven hunting, living-off-the-land detection", ["threat hunting", "hypothesis hunting", "lolbas"]),
            Subcategory("breach_investigation", "Breach Investigation", "Root cause analysis, data exposure estimation, forensic reporting", ["breach investigation", "root cause analysis", "compromise assessment"]),
            Subcategory("post_incident_review", "Post-Incident & Lessons Learned", "Corrective action planning, control gap identification", ["lessons learned", "post-mortem", "incident report"]),
        ],
        keywords=["incident response", "ir", "containment", "playbook", "threat hunting", "breach response", "csirt"],
        canonical_tags=["Incident Response", "IR", "Threat Hunting", "Playbook", "CSIRT", "Containment"],
    ),
    CategoryId.OSINT.value: Category(
        id=CategoryId.OSINT.value,
        name="OSINT",
        description="Collection, correlation, and analysis of publicly accessible information for defense, research, and adversary reconnaissance.",
        subcategories=[
            Subcategory("domain_recon", "Domain & Infrastructure Recon", "DNS history, WHOIS, certificates, ASN routing, Shodan, Censys", ["whois", "shodan", "censys", "subdomain enumeration", "crt.sh"]),
            Subcategory("threat_actor_profiling", "Threat Actor Profiling", "Aliases, public communication channels, historical attribution", ["threat actor profiling", "attribution", "handle tracking"]),
            Subcategory("data_leaks_dumps", "Data Leaks & Exposure", "Breached database monitoring, Pastebin scrapers, public GitHub leaks", ["data leak", "breach compilation", "public leak", "exposed secret"]),
            Subcategory("social_media_intel", "SOCMINT & Human Intel", "Public profile mapping, social graph analysis, forum presence", ["socmint", "social media intel", "public profile"]),
            Subcategory("satellite_geo_intel", "GEOINT & Geospatial", "Geographic correlation, physical infrastructure geolocation", ["geoint", "geolocation", "ip geolocation"]),
        ],
        keywords=["osint", "reconnaissance", "shodan", "censys", "whois", "subdomain", "data leak", "socmint"],
        canonical_tags=["OSINT", "Reconnaissance", "Shodan", "WHOIS", "Data Leaks", "SOCMINT"],
    ),
    CategoryId.CRYPTOGRAPHY.value: Category(
        id=CategoryId.CRYPTOGRAPHY.value,
        name="Cryptography",
        description="Mathematical principles, cipher suites, key exchange, encryption implementations, and cryptographic attacks.",
        subcategories=[
            Subcategory("post_quantum", "Post-Quantum Cryptography (PQC)", "Lattice-based cryptography, NIST PQC standards, ML-KEM, Dilithium", ["pqc", "post-quantum", "kyber", "dilithium", "ml-kem"]),
            Subcategory("pki_certificates", "Public Key Infrastructure (PKI)", "X.509 certificates, TLS/SSL handshake, certificate revocation, CA trust", ["pki", "tls", "ssl", "x509", "certificate"]),
            Subcategory("encryption_algorithms", "Ciphers & Hashes", "AES, ChaCha20, RSA, ECC, SHA-256, Argon2 password hashing", ["aes", "rsa", "ecc", "chacha20", "sha256", "argon2"]),
            Subcategory("zero_knowledge", "Zero-Knowledge & Privacy Tech", "ZK-SNARKs, homomorphic encryption, secure multiparty computation", ["zero knowledge", "zkp", "homomorphic encryption", "smpc"]),
            Subcategory("crypto_flaws", "Cryptographic Flaws & Attacks", "Padding oracles, side-channel attacks, nonce reuse, weak PRNG", ["padding oracle", "side channel", "weak key", "nonce reuse"]),
        ],
        keywords=["cryptography", "encryption", "tls", "pki", "post-quantum", "cipher", "hashing", "zero knowledge"],
        canonical_tags=["Cryptography", "Encryption", "TLS", "PKI", "Post-Quantum", "Ciphers"],
    ),
    CategoryId.IDENTITY.value: Category(
        id=CategoryId.IDENTITY.value,
        name="Identity",
        description="Identity and access management (IAM), authentication, directory services, and credential security.",
        subcategories=[
            Subcategory("authentication_mfa", "Authentication & MFA", "Passkeys, FIDO2, WebAuthn, MFA bypass, SIM swapping", ["mfa", "fido2", "passkey", "webauthn", "mfa fatigue"]),
            Subcategory("active_directory", "Active Directory & Kerberos", "Kerberoasting, DCSync, AS-REP roasting, BloodHound, Golden Ticket", ["active directory", "kerberoasting", "dcsync", "bloodhound"]),
            Subcategory("sso_federation", "SSO & Identity Federation", "SAML, OAuth 2.0, OpenID Connect, token forging, redirect hijacking", ["sso", "saml", "oauth", "oidc", "token theft"]),
            Subcategory("privileged_access", "Privileged Access Management (PAM)", "Just-in-time access, vaulting, session recording, least privilege", ["pam", "privileged access", "least privilege"]),
            Subcategory("credential_theft", "Credential Theft & Brute Force", "Credential stuffing, password spraying, password dumps, keylogging", ["credential stuffing", "password spraying", "brute force"]),
        ],
        keywords=["identity", "iam", "authentication", "active directory", "mfa", "sso", "oauth", "kerberos", "pam"],
        canonical_tags=["Identity", "IAM", "Authentication", "Active Directory", "MFA", "OAuth", "SSO"],
    ),
    CategoryId.MOBILE.value: Category(
        id=CategoryId.MOBILE.value,
        name="Mobile",
        description="Mobile operating system security, smartphone applications, hardware isolation, and cellular telemetry.",
        subcategories=[
            Subcategory("android_security", "Android Security", "Android APK analysis, intents, IPC, root detection, safety net", ["android", "apk", "frida", "intent filter"]),
            Subcategory("ios_security", "iOS Security", "iOS jailbreaking, Secure Enclave, sandbox escape, IPA inspection", ["ios", "secure enclave", "jailbreak", "ipa"]),
            Subcategory("mobile_malware", "Mobile Malware", "Bankers, spyware, Pegasus, Predator, commercial surveillanceware", ["mobile malware", "pegasus", "predator", "spyware"]),
            Subcategory("baseband_cellular", "Cellular & Baseband", "5G/LTE security, IMSI catchers, baseband RCE, SIM security", ["5g", "lte", "imsi catcher", "baseband"]),
        ],
        keywords=["mobile security", "android", "ios", "apk", "smartphone", "baseband", "cellular", "jailbreak"],
        canonical_tags=["Mobile Security", "Android", "iOS", "Mobile Malware", "Baseband"],
    ),
    CategoryId.IOT.value: Category(
        id=CategoryId.IOT.value,
        name="IoT",
        description="Internet of Things device security, smart appliances, connected cameras, and consumer hardware firmware.",
        subcategories=[
            Subcategory("embedded_firmware", "Firmware Analysis", "Firmware extraction, squashfs, Binwalk, Ghidra reverse engineering", ["firmware", "binwalk", "firmware extraction", "uboot"]),
            Subcategory("hardware_hacking", "Hardware Hacking", "UART, JTAG, SPI, glitching, side-channel analysis", ["uart", "jtag", "hardware hacking", "spi flash"]),
            Subcategory("smart_home", "Smart Home & Connected Devices", "Zigbee, Z-Wave, Matter, smart bulbs, IP cameras", ["smart home", "zigbee", "z-wave", "matter", "ip camera"]),
            Subcategory("iot_botnets", "IoT Botnets & Worms", "Default credentials, Telnet scanning, automated firmware exploitation", ["iot botnet", "default credential", "telnet"]),
        ],
        keywords=["iot", "firmware", "hardware hacking", "uart", "jtag", "smart home", "connected devices"],
        canonical_tags=["IoT", "Firmware", "Hardware Hacking", "Smart Home", "Embedded"],
    ),
    CategoryId.ICS.value: Category(
        id=CategoryId.ICS.value,
        name="ICS",
        description="Industrial Control Systems, Operational Technology (OT), SCADA networks, and critical national infrastructure.",
        subcategories=[
            Subcategory("scada_plc", "SCADA & PLCs", "Programmable logic controllers, HMIs, ladder logic, firmware tampering", ["plc", "scada", "hmi", "modbus", "dnp3"]),
            Subcategory("ot_network_protocols", "OT Protocols", "Modbus, DNP3, PROFINET, EtherNet/IP, IEC 60870-5-104", ["profinet", "ethernet/ip", "iec 104", "industrial protocol"]),
            Subcategory("critical_infrastructure", "Critical Infrastructure", "Power grid, water treatment, nuclear facilities, pipeline security", ["critical infrastructure", "smart grid", "substation", "pipeline"]),
            Subcategory("safety_systems", "Safety Instrumented Systems (SIS)", "TRITON/Trisis malware, safety override, emergency shutdown", ["triton", "trisis", "safety instrumented system"]),
        ],
        keywords=["ics", "scada", "plc", "operational technology", "ot security", "critical infrastructure", "modbus"],
        canonical_tags=["ICS", "SCADA", "Operational Technology", "OT", "PLC", "Critical Infrastructure"],
    ),
    CategoryId.AI_SECURITY.value: Category(
        id=CategoryId.AI_SECURITY.value,
        name="AI Security",
        description="Security of artificial intelligence, foundation models, machine learning pipelines, and autonomous agent safety.",
        subcategories=[
            Subcategory("llm_jailbreaks", "LLM Jailbreaks & Prompt Injection", "Direct/indirect prompt injection, guardrail evasion, system prompt leaks", ["prompt injection", "jailbreak", "system prompt", "llm exploit"]),
            Subcategory("adversarial_ml", "Adversarial Machine Learning", "Evasion attacks, adversarial perturbation, model inversion", ["adversarial ml", "evasion attack", "perturbation"]),
            Subcategory("training_poisoning", "Training Data Poisoning", "Data contamination, backdoor insertion, dataset supply chain flaws", ["data poisoning", "backdoor attack", "training data"]),
            Subcategory("ai_agent_security", "AI Agent Security", "Autonomous tool misuse, sandbox breakouts, agent hijacking", ["ai agent", "mcp security", "agent hijacking", "tool abuse"]),
            Subcategory("deepfakes", "Deepfakes & Synthetic Media", "Voice cloning, synthetic identity, video impersonation", ["deepfake", "synthetic media", "voice clone"]),
        ],
        keywords=["ai security", "llm", "prompt injection", "jailbreak", "adversarial ml", "data poisoning", "deepfake"],
        canonical_tags=["AI Security", "LLM", "Prompt Injection", "Adversarial ML", "GenAI", "Deepfakes"],
    ),
    CategoryId.DEVSECOPS.value: Category(
        id=CategoryId.DEVSECOPS.value,
        name="DevSecOps",
        description="Integrating security practices, automated code analysis, supply chain hygiene, and compliance into CI/CD pipelines.",
        subcategories=[
            Subcategory("ci_cd_security", "CI/CD Pipeline Security", "GitHub Actions workflows, build runners, secret leakage, poisoned pipeline", ["ci/cd", "github actions", "pipeline security", "build runner"]),
            Subcategory("code_analysis", "SAST / DAST / IAST", "Static code analysis, dynamic testing, interactive analysis, Semgrep", ["sast", "dast", "semgrep", "sonar", "static analysis"]),
            Subcategory("supply_chain", "Software Supply Chain & SBOM", "Dependency confusion, typosquatting, malicious packages, SPDX, CycloneDX", ["supply chain", "sbom", "cyclonedx", "dependency confusion"]),
            Subcategory("infrastructure_as_code", "IaC Security", "Terraform, CloudFormation, Ansible, drift detection, misconfigured policy", ["iac", "terraform", "cloudformation", "checkov"]),
            Subcategory("secrets_management", "Secrets Management", "Vault, hardcoded token scanning, TruffleHog, GitGuardian", ["secrets detection", "vault", "hardcoded credentials", "trufflehog"]),
        ],
        keywords=["devsecops", "ci/cd", "sast", "dast", "supply chain", "sbom", "iac", "terraform", "pipeline security"],
        canonical_tags=["DevSecOps", "CI/CD", "SAST", "Supply Chain", "SBOM", "IaC", "Secrets Management"],
    ),
    CategoryId.VULNERABILITY_MANAGEMENT.value: Category(
        id=CategoryId.VULNERABILITY_MANAGEMENT.value,
        name="Vulnerability Management",
        description="Lifecycle of identifying, categorizing, prioritizing, and remediating software and system vulnerabilities.",
        subcategories=[
            Subcategory("cve_intelligence", "CVE & Vulnerability Intelligence", "CVE tracking, NVD advisories, CISA KEV catalog, patch releases", ["cve", "nvd", "cisa kev", "vulnerability advisory"]),
            Subcategory("scoring_prioritization", "Prioritization & Scoring", "CVSS v3/v4, EPSS exploit prediction, SSVC decision trees", ["cvss", "epss", "ssvc", "risk scoring"]),
            Subcategory("zero_day_research", "Zero-Day Research", "Unpatched vulnerabilities, 0-day brokerages, exploit development", ["zero-day", "0-day", "exploit research", "unpatched"]),
            Subcategory("patch_management", "Patch Management", "Patch deployment, regression testing, hotpatching, vendor updates", ["patching", "patch management", "hotpatch", "security update"]),
            Subcategory("vulnerability_scanning", "Vulnerability Scanning", "Nessus, Qualys, OpenVAS, Nuclei template execution", ["vulnerability scanner", "nuclei", "nessus", "openvas"]),
        ],
        keywords=["vulnerability management", "cve", "cvss", "epss", "zero-day", "patching", "vulnerability scanning"],
        canonical_tags=["Vulnerability Management", "CVE", "CVSS", "EPSS", "Zero-Day", "Patching"],
    ),
}
