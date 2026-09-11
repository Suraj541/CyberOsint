"""
Cybersecurity Entity Gazetteers
Curated knowledge bases for deterministic extraction of malware strains,
threat actors, vendors, products, and core technologies.
Conforms strictly to IMPLEMENT.md Section 16 specifications.
"""

from typing import Dict, List, NamedTuple, Optional


class GazetteerEntry(NamedTuple):
    name: str
    normalized_name: str
    aliases: List[str]
    description: str
    category: str


# -------------------------------------------------------------
# 1. Malware Strains Gazetteer
# -------------------------------------------------------------
MALWARE_GAZETTEER: Dict[str, GazetteerEntry] = {
    "LockBit": GazetteerEntry("LockBit", "lockbit", ["LockBit 3.0", "LockBit Black", "LockBit Green"], "Ransomware-as-a-service group", "ransomware"),
    "BlackCat": GazetteerEntry("BlackCat", "blackcat", ["ALPHV", "Noberus"], "Rust-based ransomware family", "ransomware"),
    "Akira": GazetteerEntry("Akira", "akira", [], "Targeted enterprise ransomware family", "ransomware"),
    "Conti": GazetteerEntry("Conti", "conti", ["Wizard Spider"], "High-impact Russian ransomware strain", "ransomware"),
    "REvil": GazetteerEntry("REvil", "revil", ["Sodinokibi"], "Extortion-driven ransomware syndicate", "ransomware"),
    "Ryuk": GazetteerEntry("Ryuk", "ryuk", [], "Precursor enterprise ransomware family", "ransomware"),
    "DarkSide": GazetteerEntry("DarkSide", "darkside", ["BlackMatter"], "Colonial Pipeline ransomware actor", "ransomware"),
    "WannaCry": GazetteerEntry("WannaCry", "wannacry", ["WanaCrypt0r"], "Self-propagating EternalBlue ransomware", "ransomware"),
    "NotPetya": GazetteerEntry("NotPetya", "notpetya", ["Nyetya"], "Destructive wiper disguised as ransomware", "wiper"),
    "HermeticWiper": GazetteerEntry("HermeticWiper", "hermeticwiper", ["FoxBlade"], "Targeted disk wiper malware", "wiper"),
    "CaddyWiper": GazetteerEntry("CaddyWiper", "caddywiper", [], "Destructive partition wiper malware", "wiper"),
    "RedLine": GazetteerEntry("RedLine", "redline", ["RedLine Stealer"], "Widely distributed information stealer", "infostealer"),
    "Lumma": GazetteerEntry("Lumma", "lumma", ["Lumma Stealer", "LummaC2"], "C-based credential and crypto wallet stealer", "infostealer"),
    "Vidar": GazetteerEntry("Vidar", "vidar", ["Vidar Stealer"], "Information stealer variant of Arkei", "infostealer"),
    "Agent Tesla": GazetteerEntry("Agent Tesla", "agent tesla", [], "Advanced keylogger and spyware RAT", "infostealer"),
    "Emotet": GazetteerEntry("Emotet", "emotet", ["Geodo"], "Modular botnet loader and banking trojan", "trojan"),
    "TrickBot": GazetteerEntry("TrickBot", "trickbot", ["TheTrick"], "Banking trojan turned modular malware loader", "trojan"),
    "Qakbot": GazetteerEntry("Qakbot", "qakbot", ["QBot", "Pinkslipbot"], "Modular banking malware and initial access loader", "trojan"),
    "Cobalt Strike": GazetteerEntry("Cobalt Strike", "cobalt strike", ["Beacon"], "Adversary simulation software used by threat actors", "c2_framework"),
    "Mythic": GazetteerEntry("Mythic", "mythic", [], "Open-source post-exploitation C2 framework", "c2_framework"),
    "Sliver": GazetteerEntry("Sliver", "sliver", [], "Open-source cross-platform adversary emulation tool", "c2_framework"),
    "Mirai": GazetteerEntry("Mirai", "mirai", [], "Linux IoT botnet worm targeting default credentials", "botnet"),
    "Pegasus": GazetteerEntry("Pegasus", "pegasus", [], "NSO Group zero-click mobile surveillanceware", "spyware"),
    "Predator": GazetteerEntry("Predator", "predator", ["Cytrox"], "Commercial spyware targeting mobile operating systems", "spyware"),
    "Triton": GazetteerEntry("Triton", "triton", ["Trisis", "HatMan"], "ICS malware targeting safety instrumented systems (SIS)", "ics_malware"),
    "Industroyer": GazetteerEntry("Industroyer", "industroyer", ["CrashOverride"], "SCADA malware designed to disrupt electrical substations", "ics_malware"),
    "Mimikatz": GazetteerEntry("Mimikatz", "mimikatz", [], "Post-exploitation credential extraction tool", "hacktool"),
}

# -------------------------------------------------------------
# 2. Threat Actors & APTs Gazetteer
# -------------------------------------------------------------
THREAT_ACTOR_GAZETTEER: Dict[str, GazetteerEntry] = {
    "APT28": GazetteerEntry("APT28", "apt28", ["Fancy Bear", "Sofacy", "Sednit", "Strontium"], "Russian GRU 85th Main Special Service Center", "nation_state"),
    "APT29": GazetteerEntry("APT29", "apt29", ["Cozy Bear", "Nobelium", "Midnight Blizzard"], "Russian Foreign Intelligence Service (SVR)", "nation_state"),
    "Sandworm": GazetteerEntry("Sandworm", "sandworm", ["TeleBots", "Voodoo Bear", "Seashell Blizzard"], "Russian GRU Unit 74455 military intelligence", "nation_state"),
    "Lazarus Group": GazetteerEntry("Lazarus Group", "lazarus group", ["Hidden Cobra", "Zinc", "Labyrinth Chollima"], "North Korean Reconnaissance General Bureau", "nation_state"),
    "APT41": GazetteerEntry("APT41", "apt41", ["Double Dragon", "Barium", "Wicked Panda"], "Chinese Ministry of State Security contractor nexus", "nation_state"),
    "Volt Typhoon": GazetteerEntry("Volt Typhoon", "volt typhoon", ["Vanguard Panda", "Bronze Silhouette"], "Chinese state-sponsored critical infrastructure actor", "nation_state"),
    "Salt Typhoon": GazetteerEntry("Salt Typhoon", "salt typhoon", ["GhostEmperor", "FamousSparrow"], "Chinese cyber espionage group targeting telecommunications", "nation_state"),
    "Scattered Spider": GazetteerEntry("Scattered Spider", "scattered spider", ["Octo Tempest", "UNC3944"], "Financially motivated social engineering and SIM-swapping collective", "cybercrime"),
    "FIN7": GazetteerEntry("FIN7", "fin7", ["Carbanak", "Sangria Tempest"], "Russian-nexus cybercrime syndicate", "cybercrime"),
    "TA505": GazetteerEntry("TA505", "ta505", ["Hive0065"], "Prolific cybercrime actor distributing banking trojans and ransomware", "cybercrime"),
    "MuddyWater": GazetteerEntry("MuddyWater", "muddywater", ["Static Kitten", "Mercury"], "Iranian Ministry of Intelligence and Security (MOIS)", "nation_state"),
    "Turla": GazetteerEntry("Turla", "turla", ["Snake", "Venomous Bear", "Krypton"], "Russian FSB Center 16 cyber espionage actor", "nation_state"),
    "Kimsuky": GazetteerEntry("Kimsuky", "kimsuky", ["Thallium", "Velvet Chollima"], "North Korean military cyber espionage unit", "nation_state"),
}

# -------------------------------------------------------------
# 3. Vendors Gazetteer
# -------------------------------------------------------------
VENDOR_GAZETTEER: Dict[str, GazetteerEntry] = {
    "Microsoft": GazetteerEntry("Microsoft", "microsoft", ["MSFT"], "Global software and cloud platform vendor", "vendor"),
    "Cisco": GazetteerEntry("Cisco", "cisco", ["Cisco Systems"], "Enterprise networking and cybersecurity hardware vendor", "vendor"),
    "Palo Alto Networks": GazetteerEntry("Palo Alto Networks", "palo alto networks", ["PAN"], "Next-generation firewall and security platform vendor", "vendor"),
    "Fortinet": GazetteerEntry("Fortinet", "fortinet", [], "Cybersecurity and network appliance vendor", "vendor"),
    "Apple": GazetteerEntry("Apple", "apple", [], "Hardware and consumer operating system vendor", "vendor"),
    "Google": GazetteerEntry("Google", "google", ["Alphabet"], "Search, cloud infrastructure, and Android vendor", "vendor"),
    "VMware": GazetteerEntry("VMware", "vmware", ["Broadcom"], "Virtualization and cloud infrastructure software vendor", "vendor"),
    "Ivanti": GazetteerEntry("Ivanti", "ivanti", ["Pulse Secure"], "IT management and remote access security vendor", "vendor"),
    "Citrix": GazetteerEntry("Citrix", "citrix", ["Cloud Software Group"], "Application virtualization and remote access gateway vendor", "vendor"),
    "Check Point": GazetteerEntry("Check Point", "check point", ["Check Point Software"], "Perimeter and endpoint security vendor", "vendor"),
    "Juniper": GazetteerEntry("Juniper", "juniper", ["Juniper Networks"], "Enterprise routing and network security vendor", "vendor"),
    "Apache": GazetteerEntry("Apache", "apache", ["Apache Software Foundation"], "Open-source web and enterprise software foundation", "vendor"),
    "Oracle": GazetteerEntry("Oracle", "oracle", [], "Enterprise database and Java platform vendor", "vendor"),
    "F5 Networks": GazetteerEntry("F5 Networks", "f5 networks", ["F5"], "Application delivery controller and WAF vendor", "vendor"),
    "Linux": GazetteerEntry("Linux", "linux", ["Linux Foundation"], "Open-source kernel and operating systems ecosystem", "vendor"),
    "Atlassian": GazetteerEntry("Atlassian", "atlassian", [], "Enterprise collaboration and issue tracking software vendor", "vendor"),
    "CrowdStrike": GazetteerEntry("CrowdStrike", "crowdstrike", [], "Cloud-native endpoint detection and response vendor", "vendor"),
    "Splunk": GazetteerEntry("Splunk", "splunk", [], "SIEM and log analytics enterprise software vendor", "vendor"),
}

# -------------------------------------------------------------
# 4. Products Gazetteer
# -------------------------------------------------------------
PRODUCT_GAZETTEER: Dict[str, GazetteerEntry] = {
    "Windows Server": GazetteerEntry("Windows Server", "windows server", [], "Server operating system by Microsoft", "product"),
    "Windows 11": GazetteerEntry("Windows 11", "windows 11", [], "Client desktop operating system by Microsoft", "product"),
    "PAN-OS": GazetteerEntry("PAN-OS", "pan-os", [], "Operating system for Palo Alto Networks firewalls", "product"),
    "FortiOS": GazetteerEntry("FortiOS", "fortios", [], "Operating system for Fortinet FortiGate appliances", "product"),
    "IOS-XE": GazetteerEntry("IOS-XE", "ios-xe", ["Cisco IOS-XE"], "Network operating system for Cisco enterprise switches and routers", "product"),
    "Cisco ASA": GazetteerEntry("Cisco ASA", "cisco asa", ["Adaptive Security Appliance"], "Security appliance software from Cisco", "product"),
    "vCenter": GazetteerEntry("vCenter", "vcenter", ["vCenter Server"], "Centralized server management software from VMware", "product"),
    "Connect Secure": GazetteerEntry("Connect Secure", "connect secure", ["Pulse Connect Secure"], "SSL VPN and remote access appliance by Ivanti", "product"),
    "NetScaler": GazetteerEntry("NetScaler", "netscaler", ["Citrix ADC"], "Application delivery controller by Citrix", "product"),
    "Exchange Server": GazetteerEntry("Exchange Server", "exchange server", ["Microsoft Exchange"], "Email and calendaring server by Microsoft", "product"),
    "Active Directory": GazetteerEntry("Active Directory", "active directory", ["AD", "Entra ID"], "Directory service and identity infrastructure by Microsoft", "product"),
    "Confluence": GazetteerEntry("Confluence", "confluence", ["Atlassian Confluence"], "Enterprise collaboration workspace software", "product"),
    "Jira": GazetteerEntry("Jira", "jira", ["Atlassian Jira"], "Issue tracking and project management software", "product"),
    "OpenSSL": GazetteerEntry("OpenSSL", "openssl", [], "Cryptographic toolkit implementing TLS protocols", "product"),
    "Nginx": GazetteerEntry("Nginx", "nginx", [], "Web server, reverse proxy, and load balancer", "product"),
    "Apache HTTP Server": GazetteerEntry("Apache HTTP Server", "apache http server", ["httpd"], "Cross-platform open-source web server", "product"),
    "Kubernetes": GazetteerEntry("Kubernetes", "kubernetes", ["K8s"], "Container orchestration platform", "product"),
    "Docker": GazetteerEntry("Docker", "docker", ["Docker Engine"], "Containerization runtime environment", "product"),
    "Log4j": GazetteerEntry("Log4j", "log4j", ["Log4Shell"], "Java-based logging utility by Apache", "product"),
    "sudo": GazetteerEntry("sudo", "sudo", [], "Privilege escalation utility in Unix-like operating systems", "product"),
    "runc": GazetteerEntry("runc", "runc", [], "CLI tool for spawning and running containers per OCI spec", "product"),
    "Grafana": GazetteerEntry("Grafana", "grafana", [], "Open-source data visualization and monitoring dashboard", "product"),
    "WordPress": GazetteerEntry("WordPress", "wordpress", [], "Content management system powering web properties", "product"),
}

# -------------------------------------------------------------
# 5. Technologies Gazetteer
# -------------------------------------------------------------
TECHNOLOGY_GAZETTEER: Dict[str, GazetteerEntry] = {
    "HTTP/2": GazetteerEntry("HTTP/2", "http/2", ["h2"], "Binary transport revision of Hypertext Transfer Protocol", "technology"),
    "HTTP/3": GazetteerEntry("HTTP/3", "http/3", ["QUIC"], "Transport protocol based on UDP and QUIC", "technology"),
    "TLS 1.3": GazetteerEntry("TLS 1.3", "tls 1.3", [], "Current cryptographic protocol for secure communications", "technology"),
    "Kerberos": GazetteerEntry("Kerberos", "kerberos", [], "Network authentication protocol using ticket-based symmetric keys", "technology"),
    "OAuth 2.0": GazetteerEntry("OAuth 2.0", "oauth 2.0", ["OAuth"], "Open standard authorization framework and tokens", "technology"),
    "SAML 2.0": GazetteerEntry("SAML 2.0", "saml 2.0", ["SAML"], "XML-based standard for exchanging authentication and authorization", "technology"),
    "Modbus": GazetteerEntry("Modbus", "modbus", ["Modbus TCP"], "Industrial serial communications protocol in SCADA", "technology"),
    "DNP3": GazetteerEntry("DNP3", "dnp3", [], "Distributed Network Protocol for electric and water utilities", "technology"),
    "PROFINET": GazetteerEntry("PROFINET", "profinet", [], "Industrial technical standard for data communication over Industrial Ethernet", "technology"),
    "BGP": GazetteerEntry("BGP", "bgp", ["Border Gateway Protocol"], "Routing protocol of the global Internet backbone", "technology"),
    "DNSSEC": GazetteerEntry("DNSSEC", "dnssec", [], "Security extensions for the Domain Name System", "technology"),
    "GraphQL": GazetteerEntry("GraphQL", "graphql", [], "Query language for APIs and runtime for executing queries", "technology"),
    "gRPC": GazetteerEntry("gRPC", "grpc", [], "High-performance RPC framework using protocol buffers", "technology"),
    "WireGuard": GazetteerEntry("WireGuard", "wireguard", [], "Modern cryptographic communication protocol and VPN kernel module", "technology"),
    "WebSockets": GazetteerEntry("WebSockets", "websockets", [], "Full-duplex communication channels over a single TCP connection", "technology"),
    "eBPF": GazetteerEntry("eBPF", "ebpf", [], "Extended Berkeley Packet Filter for kernel tracing and observability", "technology"),
    "FIDO2": GazetteerEntry("FIDO2", "fido2", ["Passkeys", "WebAuthn"], "Passwordless authentication standards by FIDO Alliance", "technology"),
}
