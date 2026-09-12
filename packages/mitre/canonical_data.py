"""
Canonical MITRE ATT&CK Enterprise Matrix Data
Provides curated, authoritative baseline dataset for MITRE ATT&CK Enterprise v14/v15:
- 14 Tactical Phases (TA0043 to TA0040)
- Enterprise Techniques & Sub-techniques
- Active Threat Actor Groups (APT29, APT28, Lazarus, Volt Typhoon, LockBit, Akira)
- Malware & Tools (Cobalt Strike, Mimikatz, Akira, BlackCat, TrickBot)
- Mitigations & Telemetry Data Sources
- Complete directional relationships graph.
Conforms strictly to IMPLEMENT.md Section 26.
"""

from typing import Dict, List
from packages.mitre.models import (
    AttackDataSource,
    AttackGroup,
    AttackMitigation,
    AttackRelationship,
    AttackSoftware,
    AttackTactic,
    AttackTechnique,
)

# --------------------------------------------------------------------------
# 1. 14 Enterprise Tactics (Kill Chain Order)
# --------------------------------------------------------------------------
CANONICAL_TACTICS: List[AttackTactic] = [
    AttackTactic(
        id="TA0043",
        name="Reconnaissance",
        description="The adversary is trying to gather information they can use to plan future operations.",
        order=1,
        url="https://attack.mitre.org/tactics/TA0043/",
    ),
    AttackTactic(
        id="TA0042",
        name="Resource Development",
        description="The adversary is trying to establish resources they can use to support operations.",
        order=2,
        url="https://attack.mitre.org/tactics/TA0042/",
    ),
    AttackTactic(
        id="TA0001",
        name="Initial Access",
        description="The adversary is trying to get into your network through targeted vectors.",
        order=3,
        url="https://attack.mitre.org/tactics/TA0001/",
    ),
    AttackTactic(
        id="TA0002",
        name="Execution",
        description="The adversary is trying to run malicious code on local or remote endpoints.",
        order=4,
        url="https://attack.mitre.org/tactics/TA0002/",
    ),
    AttackTactic(
        id="TA0003",
        name="Persistence",
        description="The adversary is trying to maintain their foothold across reboots or credential changes.",
        order=5,
        url="https://attack.mitre.org/tactics/TA0003/",
    ),
    AttackTactic(
        id="TA0004",
        name="Privilege Escalation",
        description="The adversary is trying to gain higher-level permissions (SYSTEM/root/Domain Admin).",
        order=6,
        url="https://attack.mitre.org/tactics/TA0004/",
    ),
    AttackTactic(
        id="TA0005",
        name="Defense Evasion",
        description="The adversary is trying to avoid being detected by security solutions and analysts.",
        order=7,
        url="https://attack.mitre.org/tactics/TA0005/",
    ),
    AttackTactic(
        id="TA0006",
        name="Credential Access",
        description="The adversary is trying to steal account names, hashes, and passwords.",
        order=8,
        url="https://attack.mitre.org/tactics/TA0006/",
    ),
    AttackTactic(
        id="TA0007",
        name="Discovery",
        description="The adversary is trying to observe and explore your environment, network, and systems.",
        order=9,
        url="https://attack.mitre.org/tactics/TA0007/",
    ),
    AttackTactic(
        id="TA0008",
        name="Lateral Movement",
        description="The adversary is trying to pivot through your environment to reach high-value assets.",
        order=10,
        url="https://attack.mitre.org/tactics/TA0008/",
    ),
    AttackTactic(
        id="TA0009",
        name="Collection",
        description="The adversary is trying to gather data of interest to their operational goal.",
        order=11,
        url="https://attack.mitre.org/tactics/TA0009/",
    ),
    AttackTactic(
        id="TA0011",
        name="Command and Control",
        description="The adversary is trying to communicate with compromised systems to control them.",
        order=12,
        url="https://attack.mitre.org/tactics/TA0011/",
    ),
    AttackTactic(
        id="TA0010",
        name="Exfiltration",
        description="The adversary is trying to steal and transmit sensitive data out of your environment.",
        order=13,
        url="https://attack.mitre.org/tactics/TA0010/",
    ),
    AttackTactic(
        id="TA0040",
        name="Impact",
        description="The adversary is trying to manipulate, interrupt, or destroy your systems and data.",
        order=14,
        url="https://attack.mitre.org/tactics/TA0040/",
    ),
]

# --------------------------------------------------------------------------
# 2. Enterprise Techniques & Sub-techniques
# --------------------------------------------------------------------------
CANONICAL_TECHNIQUES: List[AttackTechnique] = [
    # Reconnaissance
    AttackTechnique(
        id="T1589",
        name="Gather Victim Identity Information",
        description="Adversaries may gather identity information about the victim organization such as employee names and email addresses.",
        tactic_id="TA0043",
        tactic_name="Reconnaissance",
        platforms=["PRE"],
        data_sources=["DS0028"],
        url="https://attack.mitre.org/techniques/T1589/",
    ),
    # Resource Development
    AttackTechnique(
        id="T1588",
        name="Obtain Capabilities",
        description="Adversaries may buy and/or steal capabilities (malware, exploits, digital certificates) that can be used during targeting.",
        tactic_id="TA0042",
        tactic_name="Resource Development",
        platforms=["PRE"],
        data_sources=["DS0028"],
        url="https://attack.mitre.org/techniques/T1588/",
    ),
    # Initial Access
    AttackTechnique(
        id="T1190",
        name="Exploit Public-Facing Application",
        description="Adversaries may attempt to exploit vulnerabilities in Internet-facing software (e.g. CVE-2024-3400, CVE-2023-46805).",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        platforms=["Linux", "Windows", "Containers"],
        data_sources=["DS0028", "DS0015"],
        detection_methods="Monitor external application logs for unexpected input parameters, anomalous payload characters, and crash events.",
        url="https://attack.mitre.org/techniques/T1190/",
    ),
    AttackTechnique(
        id="T1566",
        name="Phishing",
        description="Adversaries may send phishing messages with malicious attachments or links to gain initial access.",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        platforms=["Linux", "macOS", "Windows", "SaaS"],
        data_sources=["DS0028", "DS0015"],
        detection_methods="Inspect email security gateways and analyze outbound clicks to newly registered domains.",
        url="https://attack.mitre.org/techniques/T1566/",
    ),
    AttackTechnique(
        id="T1566.001",
        name="Spearphishing Attachment",
        description="Adversaries may send spearphishing emails with malicious file attachments (e.g. macro-enabled docs, ISO, LNK).",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        parent_technique_id="T1566",
        is_subtechnique=True,
        platforms=["Linux", "macOS", "Windows"],
        data_sources=["DS0028", "DS0024"],
        url="https://attack.mitre.org/techniques/T1566/001/",
    ),
    AttackTechnique(
        id="T1566.002",
        name="Spearphishing Link",
        description="Adversaries may send spearphishing emails with hyperlinks directing victims to credential harvesting or exploit sites.",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        parent_technique_id="T1566",
        is_subtechnique=True,
        platforms=["Linux", "macOS", "Windows", "SaaS"],
        data_sources=["DS0028"],
        url="https://attack.mitre.org/techniques/T1566/002/",
    ),
    AttackTechnique(
        id="T1078",
        name="Valid Accounts",
        description="Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, or Privilege Escalation.",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        platforms=["Linux", "macOS", "Windows", "Cloud", "Identity"],
        data_sources=["DS0012", "DS0029"],
        detection_methods="Monitor for unusual geolocations, impossible travel alerts, and concurrent interactive sessions.",
        url="https://attack.mitre.org/techniques/T1078/",
    ),
    AttackTechnique(
        id="T1078.004",
        name="Cloud Accounts",
        description="Adversaries may obtain credentials for cloud management consoles or identity providers (Azure AD, AWS IAM, GCP).",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        parent_technique_id="T1078",
        is_subtechnique=True,
        platforms=["Cloud", "Identity"],
        data_sources=["DS0029"],
        url="https://attack.mitre.org/techniques/T1078/004/",
    ),
    # Execution
    AttackTechnique(
        id="T1059",
        name="Command and Scripting Interpreter",
        description="Adversaries may abuse command and script interpreters to execute commands, scripts, or malicious binaries.",
        tactic_id="TA0002",
        tactic_name="Execution",
        platforms=["Linux", "macOS", "Windows"],
        data_sources=["DS0015", "DS0017"],
        detection_methods="Monitor process invocation of cmd.exe, powershell.exe, bash, and python with suspicious flags (-enc, -nop, curl | sh).",
        url="https://attack.mitre.org/techniques/T1059/",
    ),
    AttackTechnique(
        id="T1059.001",
        name="PowerShell",
        description="Adversaries may abuse PowerShell commands and scripts for code execution and memory-only staging.",
        tactic_id="TA0002",
        tactic_name="Execution",
        parent_technique_id="T1059",
        is_subtechnique=True,
        platforms=["Windows"],
        data_sources=["DS0015", "DS0017"],
        url="https://attack.mitre.org/techniques/T1059/001/",
    ),
    AttackTechnique(
        id="T1059.003",
        name="Windows Command Shell",
        description="Adversaries may abuse cmd.exe for command execution, batch file execution, and environment configuration.",
        tactic_id="TA0002",
        tactic_name="Execution",
        parent_technique_id="T1059",
        is_subtechnique=True,
        platforms=["Windows"],
        data_sources=["DS0015", "DS0017"],
        url="https://attack.mitre.org/techniques/T1059/003/",
    ),
    # Persistence
    AttackTechnique(
        id="T1053",
        name="Scheduled Task/Job",
        description="Adversaries may abuse task scheduling functionality to facilitate initial or recurring code execution.",
        tactic_id="TA0003",
        tactic_name="Persistence",
        platforms=["Linux", "macOS", "Windows"],
        data_sources=["DS0015", "DS0017"],
        url="https://attack.mitre.org/techniques/T1053/",
    ),
    # Privilege Escalation
    AttackTechnique(
        id="T1068",
        name="Exploitation for Privilege Escalation",
        description="Adversaries may exploit software vulnerabilities in elevated services or the OS kernel to elevate privileges.",
        tactic_id="TA0004",
        tactic_name="Privilege Escalation",
        platforms=["Linux", "macOS", "Windows"],
        data_sources=["DS0015"],
        url="https://attack.mitre.org/techniques/T1068/",
    ),
    # Defense Evasion
    AttackTechnique(
        id="T1055",
        name="Process Injection",
        description="Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges.",
        tactic_id="TA0005",
        tactic_name="Defense Evasion",
        platforms=["Linux", "macOS", "Windows"],
        data_sources=["DS0017"],
        url="https://attack.mitre.org/techniques/T1055/",
    ),
    AttackTechnique(
        id="T1027",
        name="Obfuscated Files or Information",
        description="Adversaries may attempt to make an executable or script difficult to discover or analyze (base64, XOR, packing).",
        tactic_id="TA0005",
        tactic_name="Defense Evasion",
        platforms=["Linux", "macOS", "Windows"],
        data_sources=["DS0024"],
        url="https://attack.mitre.org/techniques/T1027/",
    ),
    # Credential Access
    AttackTechnique(
        id="T1003",
        name="OS Credential Dumping",
        description="Adversaries may dump credentials from the operating system to obtain account login and credential material.",
        tactic_id="TA0006",
        tactic_name="Credential Access",
        platforms=["Linux", "macOS", "Windows"],
        data_sources=["DS0017", "DS0015"],
        url="https://attack.mitre.org/techniques/T1003/",
    ),
    AttackTechnique(
        id="T1003.001",
        name="LSASS Memory",
        description="Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS).",
        tactic_id="TA0006",
        tactic_name="Credential Access",
        parent_technique_id="T1003",
        is_subtechnique=True,
        platforms=["Windows"],
        data_sources=["DS0017"],
        url="https://attack.mitre.org/techniques/T1003/001/",
    ),
    # Discovery
    AttackTechnique(
        id="T1046",
        name="Network Service Discovery",
        description="Adversaries may attempt to get a listing of services running on hosts in a network (port scanning, nmap, masscan).",
        tactic_id="TA0007",
        tactic_name="Discovery",
        platforms=["Linux", "macOS", "Windows", "Cloud"],
        data_sources=["DS0028"],
        url="https://attack.mitre.org/techniques/T1046/",
    ),
    # Lateral Movement
    AttackTechnique(
        id="T1021",
        name="Remote Services",
        description="Adversaries may use valid accounts to log into a service specifically designed to accept remote connections (RDP, SSH, SMB).",
        tactic_id="TA0008",
        tactic_name="Lateral Movement",
        platforms=["Linux", "macOS", "Windows"],
        data_sources=["DS0012", "DS0028"],
        url="https://attack.mitre.org/techniques/T1021/",
    ),
    # Collection
    AttackTechnique(
        id="T1114",
        name="Email Collection",
        description="Adversaries may target user email to collect sensitive communications and attachments.",
        tactic_id="TA0009",
        tactic_name="Collection",
        platforms=["Linux", "macOS", "Windows", "SaaS"],
        data_sources=["DS0029"],
        url="https://attack.mitre.org/techniques/T1114/",
    ),
    # Command and Control
    AttackTechnique(
        id="T1071",
        name="Application Layer Protocol",
        description="Adversaries may communicate using application layer protocols (HTTP, HTTPS, DNS) to blend in with normal network traffic.",
        tactic_id="TA0011",
        tactic_name="Command and Control",
        platforms=["Linux", "macOS", "Windows", "Cloud"],
        data_sources=["DS0028"],
        url="https://attack.mitre.org/techniques/T1071/",
    ),
    # Exfiltration
    AttackTechnique(
        id="T1041",
        name="Exfiltration Over C2 Channel",
        description="Adversaries may steal data by exfiltrating it over an existing command and control channel.",
        tactic_id="TA0010",
        tactic_name="Exfiltration",
        platforms=["Linux", "macOS", "Windows"],
        data_sources=["DS0028"],
        url="https://attack.mitre.org/techniques/T1041/",
    ),
    # Impact
    AttackTechnique(
        id="T1486",
        name="Data Encrypted for Impact",
        description="Adversaries may encrypt data on target systems to interrupt availability to system and network resources (Ransomware).",
        tactic_id="TA0040",
        tactic_name="Impact",
        platforms=["Linux", "macOS", "Windows"],
        data_sources=["DS0024", "DS0015"],
        detection_methods="Monitor high rates of file modifications and creations with unusual extensions or ransom notes.",
        url="https://attack.mitre.org/techniques/T1486/",
    ),
]

# --------------------------------------------------------------------------
# 3. Active Threat Actor Groups
# --------------------------------------------------------------------------
CANONICAL_GROUPS: List[AttackGroup] = [
    AttackGroup(
        id="G0016",
        name="APT29",
        aliases=["Cozy Bear", "Nobelium", "Midnight Blizzard", "The Dukes"],
        description="Russian state-sponsored cyber espionage group attributed to the SVR. Known for SolarWinds supply chain breach, Microsoft Graph API abuse, and cloud identity credential attacks.",
        associated_techniques=["T1190", "T1566", "T1078.004", "T1059.001", "T1071"],
        associated_software=["S0154", "S0002"],
        url="https://attack.mitre.org/groups/G0016/",
    ),
    AttackGroup(
        id="G0007",
        name="APT28",
        aliases=["Fancy Bear", "Forest Blizzard", "Sednit", "Strontium", "Sofacy"],
        description="Russian military intelligence (GRU) cyber unit active since at least 2004. Known for zero-day exploitation, spearphishing, and credential harvesting targeting defense, government, and aerospace.",
        associated_techniques=["T1190", "T1566.001", "T1003", "T1059", "T1021"],
        associated_software=["S0154", "S0002"],
        url="https://attack.mitre.org/groups/G0007/",
    ),
    AttackGroup(
        id="G0096",
        name="Lazarus Group",
        aliases=["HIDDEN COBRA", "Zinc", "Guardians of Peace"],
        description="Democratic People's Republic of Korea (DPRK) state-sponsored cyber syndicate conducting espionage and financially motivated cryptocurrency thefts.",
        associated_techniques=["T1566.002", "T1059", "T1055", "T1027", "T1486"],
        associated_software=["S0154"],
        url="https://attack.mitre.org/groups/G0096/",
    ),
    AttackGroup(
        id="G0125",
        name="Volt Typhoon",
        aliases=["Bronze Silhouette", "Vanguard Panda", "Insidious Taurus"],
        description="People's Republic of China state-sponsored cyber actor focused on stealthy persistence within critical infrastructure sectors, leveraging living-off-the-land techniques and compromised SOHO routers.",
        associated_techniques=["T1190", "T1078", "T1059.003", "T1046", "T1021"],
        associated_software=[],
        url="https://attack.mitre.org/groups/G0125/",
    ),
    AttackGroup(
        id="G0140",
        name="Akira",
        aliases=["Punk Spider"],
        description="Ransomware-as-a-service group active since March 2023 targeting commercial enterprises globally, commonly weaponizing Cisco ASA/FTD VPN vulnerabilities.",
        associated_techniques=["T1190", "T1078", "T1059.001", "T1486", "T1041"],
        associated_software=["S0650", "S0002"],
        url="https://attack.mitre.org/groups/G0140/",
    ),
    AttackGroup(
        id="G0105",
        name="LockBit",
        aliases=["Bitwise Spider"],
        description="Prolific ransomware affiliate syndicate operating LockBit 2.0 and 3.0 (LockBit Black). Conducts double-extortion attacks against worldwide enterprise networks.",
        associated_techniques=["T1190", "T1566.001", "T1059.001", "T1055", "T1486", "T1041"],
        associated_software=["S0002", "S0154"],
        url="https://attack.mitre.org/groups/G0105/",
    ),
]

# --------------------------------------------------------------------------
# 4. Software (Malware & Tools)
# --------------------------------------------------------------------------
CANONICAL_SOFTWARE: List[AttackSoftware] = [
    AttackSoftware(
        id="S0154",
        name="Cobalt Strike",
        software_type="tool",
        aliases=["Beacon"],
        description="Commercial adversary simulation and penetration testing platform widely abused by threat actors for interactive post-exploitation, beaconing, and lateral movement.",
        associated_techniques=["T1059.001", "T1055", "T1071", "T1021"],
        url="https://attack.mitre.org/software/S0154/",
    ),
    AttackSoftware(
        id="S0002",
        name="Mimikatz",
        software_type="tool",
        aliases=[],
        description="Credential extraction tool capable of dumping plaintext passwords, Kerberos tickets, and NTLM hashes from Windows LSASS memory.",
        associated_techniques=["T1003", "T1003.001", "T1055"],
        url="https://attack.mitre.org/software/S0002/",
    ),
    AttackSoftware(
        id="S0650",
        name="Akira",
        software_type="malware",
        aliases=["Akira Ransomware"],
        description="Cross-platform ransomware (Windows and Linux ESXi) utilizing ChaCha20/RSA encryption and multi-threading for rapid file locking.",
        associated_techniques=["T1486", "T1059.001", "T1027"],
        url="https://attack.mitre.org/software/S0650/",
    ),
    AttackSoftware(
        id="S0446",
        name="BlackCat",
        software_type="malware",
        aliases=["ALPHV", "Noberus"],
        description="Rust-based ransomware family employing modern encryption primitives, command-line customizations, and evasion techniques.",
        associated_techniques=["T1486", "T1059", "T1055"],
        url="https://attack.mitre.org/software/S0446/",
    ),
    AttackSoftware(
        id="S0038",
        name="TrickBot",
        software_type="malware",
        aliases=["TheTrick"],
        description="Modular banking Trojan evolved into a multi-stage loader and reconnaissance platform frequently deploying secondary ransomware payloads.",
        associated_techniques=["T1566.001", "T1059.001", "T1055", "T1003"],
        url="https://attack.mitre.org/software/S0038/",
    ),
]

# --------------------------------------------------------------------------
# 5. Mitigations
# --------------------------------------------------------------------------
CANONICAL_MITIGATIONS: List[AttackMitigation] = [
    AttackMitigation(
        id="M1036",
        name="Multi-factor Authentication",
        description="Use two or more factors to authenticate users (something you know, have, or are) on Internet-accessible management consoles, VPNs, and email.",
        associated_techniques=["T1078", "T1078.004", "T1190"],
        url="https://attack.mitre.org/mitigations/M1036/",
    ),
    AttackMitigation(
        id="M1049",
        name="Antivirus/Antimalware",
        description="Use signatures, heuristics, and behavioral behavioral analysis to detect and quarantine known malicious software at host boundaries.",
        associated_techniques=["T1059", "T1055", "T1486"],
        url="https://attack.mitre.org/mitigations/M1049/",
    ),
    AttackMitigation(
        id="M1018",
        name="User Account Management",
        description="Manage the creation, modification, use, and permissions of user and administrator accounts according to least privilege.",
        associated_techniques=["T1078", "T1003"],
        url="https://attack.mitre.org/mitigations/M1018/",
    ),
    AttackMitigation(
        id="M1042",
        name="Disable or Remove Feature or Program",
        description="Remove or disable unneeded software, scripts, or network services to minimize attack surface.",
        associated_techniques=["T1059.001", "T1021"],
        url="https://attack.mitre.org/mitigations/M1042/",
    ),
    AttackMitigation(
        id="M1051",
        name="Update Software",
        description="Perform regular software updates and vulnerability patching to mitigate exploitable security flaws in public applications.",
        associated_techniques=["T1190", "T1068"],
        url="https://attack.mitre.org/mitigations/M1051/",
    ),
    AttackMitigation(
        id="M1053",
        name="Data Backup",
        description="Regularly perform and test data backups, ensuring isolated, immutable off-site or offline storage to withstand ransomware encryption.",
        associated_techniques=["T1486"],
        url="https://attack.mitre.org/mitigations/M1053/",
    ),
]

# --------------------------------------------------------------------------
# 6. Data Sources
# --------------------------------------------------------------------------
CANONICAL_DATA_SOURCES: List[AttackDataSource] = [
    AttackDataSource(
        id="DS0015",
        name="Command Execution",
        description="Command-line arguments and interpreter execution records collected from OS shell environments.",
        collection_layers=["Host"],
        associated_techniques=["T1059", "T1059.001", "T1059.003", "T1190"],
        url="https://attack.mitre.org/datasources/DS0015/",
    ),
    AttackDataSource(
        id="DS0017",
        name="Process Creation",
        description="Telemetry capturing OS process spawning events, process IDs, parent process lineage, and hashes.",
        collection_layers=["Host"],
        associated_techniques=["T1059", "T1055", "T1003", "T1003.001"],
        url="https://attack.mitre.org/datasources/DS0017/",
    ),
    AttackDataSource(
        id="DS0028",
        name="Network Traffic",
        description="Telemetry derived from network sessions, packet inspection, NetFlow, DNS, and HTTP metadata.",
        collection_layers=["Network"],
        associated_techniques=["T1190", "T1566", "T1071", "T1041", "T1046"],
        url="https://attack.mitre.org/datasources/DS0028/",
    ),
    AttackDataSource(
        id="DS0029",
        name="Cloud Service Logs",
        description="Audit logging produced by cloud service providers tracking identity authentications and API invocations.",
        collection_layers=["Cloud"],
        associated_techniques=["T1078.004", "T1114"],
        url="https://attack.mitre.org/datasources/DS0029/",
    ),
    AttackDataSource(
        id="DS0024",
        name="File Creation",
        description="File system monitoring events indicating new binaries, scripts, or encrypted extensions written to disk.",
        collection_layers=["Host"],
        associated_techniques=["T1566.001", "T1027", "T1486"],
        url="https://attack.mitre.org/datasources/DS0024/",
    ),
    AttackDataSource(
        id="DS0012",
        name="Logon Session",
        description="Operating system audit records tracking interactive, network, and remote desktop logon/logoff attempts.",
        collection_layers=["Host", "Identity"],
        associated_techniques=["T1078", "T1021"],
        url="https://attack.mitre.org/datasources/DS0012/",
    ),
]

# --------------------------------------------------------------------------
# 7. Directional Canonical Relationships
# --------------------------------------------------------------------------
def build_canonical_relationships() -> List[AttackRelationship]:
    """Construct complete directional relationships graph conforming to Section 26."""
    rel: List[AttackRelationship] = []

    # 1. Technique -> belongs_to -> Tactic
    for tech in CANONICAL_TECHNIQUES:
        rel.append(AttackRelationship(
            source_id=tech.id,
            source_type="technique",
            relationship="belongs_to",
            target_id=tech.tactic_id,
            target_type="tactic",
            description=f"Technique {tech.name} achieves tactical objective {tech.tactic_name}",
        ))

    # 2. Threat Actor -> uses -> Technique
    for grp in CANONICAL_GROUPS:
        for tid in grp.associated_techniques:
            rel.append(AttackRelationship(
                source_id=grp.id,
                source_type="group",
                relationship="uses",
                target_id=tid,
                target_type="technique",
                description=f"{grp.name} employs technique {tid}",
            ))

    # 3. Malware -> implements -> Technique
    for sw in CANONICAL_SOFTWARE:
        for tid in sw.associated_techniques:
            rel.append(AttackRelationship(
                source_id=sw.id,
                source_type="software",
                relationship="implements",
                target_id=tid,
                target_type="technique",
                description=f"{sw.name} implements technique {tid}",
            ))

    # 4. Technique -> detected_by -> Data Source
    for ds in CANONICAL_DATA_SOURCES:
        for tid in ds.associated_techniques:
            rel.append(AttackRelationship(
                source_id=tid,
                source_type="technique",
                relationship="detected_by",
                target_id=ds.id,
                target_type="data_source",
                description=f"Technique {tid} is detected via telemetry from {ds.name} ({ds.id})",
            ))

    # 5. Mitigation -> mitigates -> Technique
    for mit in CANONICAL_MITIGATIONS:
        for tid in mit.associated_techniques:
            rel.append(AttackRelationship(
                source_id=mit.id,
                source_type="mitigation",
                relationship="mitigates",
                target_id=tid,
                target_type="technique",
                description=f"Mitigation {mit.name} hardens defense against technique {tid}",
            ))

    return rel


CANONICAL_RELATIONSHIPS: List[AttackRelationship] = build_canonical_relationships()
