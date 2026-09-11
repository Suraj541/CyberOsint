"""
Taxonomy Mappings
Provides lookup dictionaries mapping arbitrary tags, aliases, and CWE identifiers
to canonical category and subcategory IDs.
Conforms strictly to IMPLEMENT.md Section 14 specifications.
"""

from typing import Dict, Optional, Tuple

# -------------------------------------------------------------
# Common Tags to (Category ID, Subcategory ID) Mapping
# -------------------------------------------------------------
TAG_TO_CATEGORY: Dict[str, Tuple[str, Optional[str]]] = {
    # Application Security
    "appsec": ("application_security", None),
    "web-security": ("application_security", "web_security"),
    "owasp": ("application_security", "web_security"),
    "xss": ("application_security", "web_security"),
    "csrf": ("application_security", "web_security"),
    "sqli": ("application_security", "injection_attacks"),
    "sql-injection": ("application_security", "injection_attacks"),
    "rce": ("application_security", "injection_attacks"),
    "remote-code-execution": ("application_security", "injection_attacks"),
    "buffer-overflow": ("application_security", "memory_safety"),
    "use-after-free": ("application_security", "memory_safety"),
    "api-security": ("application_security", "api_security"),
    "ssrf": ("application_security", "web_security"),

    # Cloud Security
    "cloud": ("cloud_security", None),
    "aws": ("cloud_security", "aws_security"),
    "azure": ("cloud_security", "azure_security"),
    "gcp": ("cloud_security", "gcp_security"),
    "google-cloud": ("cloud_security", "gcp_security"),
    "kubernetes": ("cloud_security", "kubernetes_security"),
    "k8s": ("cloud_security", "kubernetes_security"),
    "docker": ("cloud_security", "kubernetes_security"),
    "container": ("cloud_security", "kubernetes_security"),
    "s3": ("cloud_security", "aws_security"),

    # Network Security
    "network": ("network_security", None),
    "firewall": ("network_security", "firewalls_ids_ips"),
    "ids": ("network_security", "firewalls_ids_ips"),
    "ips": ("network_security", "firewalls_ids_ips"),
    "dns": ("network_security", "dns_security"),
    "ddos": ("network_security", "ddos_protection"),
    "dos": ("network_security", "ddos_protection"),
    "vpn": ("network_security", "vpn_zerotrust"),
    "zero-trust": ("network_security", "vpn_zerotrust"),
    "ztna": ("network_security", "vpn_zerotrust"),
    "wifi": ("network_security", "wireless_security"),

    # Malware
    "malware": ("malware", None),
    "ransomware": ("malware", "ransomware"),
    "infostealer": ("malware", "infostealers"),
    "stealer": ("malware", "infostealers"),
    "trojan": ("malware", "trojans"),
    "rat": ("malware", "trojans"),
    "rootkit": ("malware", "rootkits"),
    "bootkit": ("malware", "rootkits"),
    "botnet": ("malware", "botnets"),
    "wiper": ("malware", "wiper_malware"),

    # Threat Intelligence
    "threat-intel": ("threat_intelligence", None),
    "cti": ("threat_intelligence", None),
    "apt": ("threat_intelligence", "apt_groups"),
    "nation-state": ("threat_intelligence", "apt_groups"),
    "ioc": ("threat_intelligence", "indicators_of_compromise"),
    "mitre": ("threat_intelligence", "tactics_techniques_procedures"),
    "att&ck": ("threat_intelligence", "tactics_techniques_procedures"),
    "darkweb": ("threat_intelligence", "darkweb_monitoring"),
    "yara": ("threat_intelligence", "detection_rules"),
    "sigma": ("threat_intelligence", "detection_rules"),

    # Digital Forensics
    "forensics": ("digital_forensics", None),
    "dfir": ("digital_forensics", None),
    "memory-forensics": ("digital_forensics", "memory_forensics"),
    "volatility": ("digital_forensics", "memory_forensics"),
    "pcap": ("digital_forensics", "network_forensics"),
    "wireshark": ("digital_forensics", "network_forensics"),
    "disk-forensics": ("digital_forensics", "disk_forensics"),

    # Incident Response
    "incident-response": ("incident_response", None),
    "ir": ("incident_response", None),
    "threat-hunting": ("incident_response", "threat_hunting"),
    "containment": ("incident_response", "containment_eradication"),
    "playbook": ("incident_response", "playbooks_runbooks"),
    "breach": ("incident_response", "breach_investigation"),

    # OSINT
    "osint": ("osint", None),
    "recon": ("osint", "domain_recon"),
    "shodan": ("osint", "domain_recon"),
    "censys": ("osint", "domain_recon"),
    "whois": ("osint", "domain_recon"),
    "socmint": ("osint", "social_media_intel"),
    "geoint": ("osint", "satellite_geo_intel"),
    "data-leak": ("osint", "data_leaks_dumps"),

    # Cryptography
    "crypto": ("cryptography", None),
    "cryptography": ("cryptography", None),
    "encryption": ("cryptography", "encryption_algorithms"),
    "post-quantum": ("cryptography", "post_quantum"),
    "pqc": ("cryptography", "post_quantum"),
    "tls": ("cryptography", "pki_certificates"),
    "ssl": ("cryptography", "pki_certificates"),
    "pki": ("cryptography", "pki_certificates"),
    "zero-knowledge": ("cryptography", "zero_knowledge"),

    # Identity
    "iam": ("identity", None),
    "identity": ("identity", None),
    "authentication": ("identity", "authentication_mfa"),
    "mfa": ("identity", "authentication_mfa"),
    "2fa": ("identity", "authentication_mfa"),
    "active-directory": ("identity", "active_directory"),
    "kerberos": ("identity", "active_directory"),
    "sso": ("identity", "sso_federation"),
    "saml": ("identity", "sso_federation"),
    "oauth": ("identity", "sso_federation"),
    "pam": ("identity", "privileged_access"),

    # Mobile
    "mobile": ("mobile", None),
    "android": ("mobile", "android_security"),
    "ios": ("mobile", "ios_security"),
    "apk": ("mobile", "android_security"),
    "pegasus": ("mobile", "mobile_malware"),
    "5g": ("mobile", "baseband_cellular"),

    # IoT
    "iot": ("iot", None),
    "firmware": ("iot", "embedded_firmware"),
    "hardware-hacking": ("iot", "hardware_hacking"),
    "embedded": ("iot", "embedded_firmware"),
    "smart-home": ("iot", "smart_home"),

    # ICS / OT
    "ics": ("ics", None),
    "scada": ("ics", "scada_plc"),
    "plc": ("ics", "scada_plc"),
    "ot": ("ics", None),
    "operational-technology": ("ics", None),
    "modbus": ("ics", "ot_network_protocols"),
    "critical-infrastructure": ("ics", "critical_infrastructure"),

    # AI Security
    "ai": ("ai_security", None),
    "ai-security": ("ai_security", None),
    "llm": ("ai_security", "llm_jailbreaks"),
    "prompt-injection": ("ai_security", "llm_jailbreaks"),
    "jailbreak": ("ai_security", "llm_jailbreaks"),
    "adversarial-ml": ("ai_security", "adversarial_ml"),
    "deepfake": ("ai_security", "deepfakes"),

    # DevSecOps
    "devsecops": ("devsecops", None),
    "ci-cd": ("devsecops", "ci_cd_security"),
    "sast": ("devsecops", "code_analysis"),
    "dast": ("devsecops", "code_analysis"),
    "supply-chain": ("devsecops", "supply_chain"),
    "sbom": ("devsecops", "supply_chain"),
    "iac": ("devsecops", "infrastructure_as_code"),
    "terraform": ("devsecops", "infrastructure_as_code"),

    # Vulnerability Management
    "cve": ("vulnerability_management", "cve_intelligence"),
    "vulnerability": ("vulnerability_management", "cve_intelligence"),
    "cvss": ("vulnerability_management", "scoring_prioritization"),
    "epss": ("vulnerability_management", "scoring_prioritization"),
    "zero-day": ("vulnerability_management", "zero_day_research"),
    "0-day": ("vulnerability_management", "zero_day_research"),
    "patch": ("vulnerability_management", "patch_management"),
}

# -------------------------------------------------------------
# CWE to Canonical Category Mapping
# -------------------------------------------------------------
CWE_TO_CATEGORY: Dict[str, Tuple[str, Optional[str]]] = {
    # Web & Injection
    "CWE-79": ("application_security", "web_security"),         # XSS
    "CWE-89": ("application_security", "injection_attacks"),    # SQLi
    "CWE-78": ("application_security", "injection_attacks"),    # OS Command Injection
    "CWE-77": ("application_security", "injection_attacks"),    # Command Injection
    "CWE-22": ("application_security", "web_security"),         # Path Traversal
    "CWE-352": ("application_security", "web_security"),        # CSRF
    "CWE-434": ("application_security", "web_security"),        # Unrestricted File Upload
    "CWE-502": ("application_security", "injection_attacks"),    # Deserialization of Untrusted Data
    "CWE-918": ("application_security", "web_security"),        # SSRF

    # Memory Safety
    "CWE-119": ("application_security", "memory_safety"),       # Memory Buffer Restrictions
    "CWE-120": ("application_security", "memory_safety"),       # Classic Buffer Overflow
    "CWE-121": ("application_security", "memory_safety"),       # Stack-based Buffer Overflow
    "CWE-122": ("application_security", "memory_safety"),       # Heap-based Buffer Overflow
    "CWE-125": ("application_security", "memory_safety"),       # Out-of-bounds Read
    "CWE-787": ("application_security", "memory_safety"),       # Out-of-bounds Write
    "CWE-416": ("application_security", "memory_safety"),       # Use After Free
    "CWE-476": ("application_security", "memory_safety"),       # NULL Pointer Dereference

    # Cryptography
    "CWE-327": ("cryptography", "crypto_flaws"),                 # Broken/Risky Cryptographic Algorithm
    "CWE-326": ("cryptography", "crypto_flaws"),                 # Inadequate Encryption Strength
    "CWE-330": ("cryptography", "crypto_flaws"),                 # Use of Insufficiently Random Values
    "CWE-338": ("cryptography", "crypto_flaws"),                 # Weak PRNG

    # Identity & Access
    "CWE-287": ("identity", "authentication_mfa"),               # Improper Authentication
    "CWE-306": ("identity", "authentication_mfa"),               # Missing Authentication for Critical Function
    "CWE-798": ("identity", "credential_theft"),                 # Use of Hard-coded Credentials
    "CWE-259": ("identity", "credential_theft"),                 # Hard-coded Password
    "CWE-269": ("identity", "privileged_access"),                # Improper Privilege Management
    "CWE-862": ("identity", "privileged_access"),                # Missing Authorization
    "CWE-863": ("identity", "privileged_access"),                # Incorrect Authorization

    # Network / Denial of Service
    "CWE-400": ("network_security", "ddos_protection"),          # Uncontrolled Resource Consumption
    "CWE-770": ("network_security", "ddos_protection"),          # Allocation of Resources Without Limits

    # Information Disclosure
    "CWE-200": ("osint", "data_leaks_dumps"),                    # Exposure of Sensitive Information
}
