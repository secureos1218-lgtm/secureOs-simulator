import os
import json
import time
from typing import List, Dict, Any, Optional

try:
    from google import genai
    from google.genai import types
    HAS_GENAI = True
except ImportError:
    HAS_GENAI = False

try:
    import chromadb
    HAS_CHROMA = True
except ImportError:
    HAS_CHROMA = False

DEFAULT_MODELS = [
    'gemini-2.5-flash',
    'gemini-2.5-pro',
]

CYBER_LIBRARY_SYSTEM_PROMPT = """You are the SecurOS AI Security Assistant — an authoritative, exhaustive Cybersecurity Knowledge Library and Academic Reference System.
Your exclusive purpose is to provide structured, deep, educational, and reference-grade cybersecurity knowledge.
Do NOT analyze scan telemetry or logs (that is handled by JARVIS). Instead, focus entirely on explaining:
- Security concepts, architectures, and theoretical foundations
- Standards & frameworks: OWASP Top 10, NIST SP 800-53/800-61, MITRE ATT&CK, PTES, ISO 27001, CIS Controls
- Enterprise identity: Active Directory, Kerberos mechanics, Tiered administration, PAM
- Network protocols: TCP/IP, OSI layers, DNS/DNSSEC, TLS 1.3, BGP, ARP, Firewalls, IDS/IPS
- Cryptography: Symmetric vs Asymmetric, AES-GCM, RSA, ECC, password hashing (Argon2id, bcrypt), PKI
- Defensive strategies: Blue teaming, Incident Response (PICERL), SIEM correlation, Threat Hunting
- Cloud & container security: AWS/Azure IAM, Docker isolation, Kubernetes RBAC, CI/CD supply chain

Formatting Guidelines:
1. Provide comprehensive, structured explanations with clear Markdown headers (`###`, `####`), bullet points, and tables.
2. Include both attack concepts (how the attack works fundamentally) and defense/hardening principles.
3. Cite authoritative standards (NIST, OWASP, RFC, MITRE) whenever applicable.
4. Keep the tone academic, authoritative, professional, and educational."""

# =====================================================================
# COMPREHENSIVE CYBERSECURITY LIBRARY REPOSITORY
# =====================================================================

COMPREHENSIVE_CYBER_LIBRARY = [
    # ── 1. WEB APPLICATION SECURITY & OWASP ─────────────────────────
    {
        "id": "kb_owasp_top10",
        "title": "OWASP Top 10 Comprehensive Control Reference",
        "category": "Web Application Security",
        "content": """### OWASP Top 10 Web Application Vulnerabilities & Mitigations
The Open Web Application Security Project (OWASP) Top 10 represents the most critical security risks facing web applications.

1. **A01:2021 - Broken Access Control**: Occurs when authorization checks are improperly enforced or absent, allowing attackers to access unauthorized resources (IDOR, privilege escalation, path traversal, metadata manipulation).
   - *Mitigation*: Enforce strict server-side authorization checks for every endpoint; adopt role-based access control (RBAC); deny by default; disable web server directory listing.

2. **A02:2021 - Cryptographic Failures**: Involves exposure of sensitive data due to weak or absent cryptography (plaintext transmission over HTTP, outdated algorithms like MD5/DES/RC4, hardcoded keys, missing salt in password hashes).
   - *Mitigation*: Mandate TLS 1.3 for all data in transit; enforce strong authenticated encryption (AES-256-GCM); use memory-hard password hashing (Argon2id, bcrypt, scrypt).

3. **A03:2021 - Injection**: SQL, OS command, NoSQL, and LDAP injection occur when untrusted user input is directly concatenated into structured interpreters.
   - *Mitigation*: Strictly utilize parameterized queries (Prepared Statements) or ORM abstractions; validate input against strict allowlists; enforce least privilege on database accounts.

4. **A04:2021 - Insecure Design**: Flaws in architectural design and lack of threat modeling (STRIDE/DREAD) that cannot be fixed by implementation controls alone.
   - *Mitigation*: Establish secure software development lifecycles (SSDLC); integrate automated threat modeling; validate trust boundaries.

5. **A05:2021 - Security Misconfiguration**: Default credentials, unhardened HTTP security headers, verbose error stack traces, unneeded enabled ports or services.
   - *Mitigation*: Implement hardened baseline templates (CIS Benchmarks); remove unused features; configure defense headers (X-Frame-Options, CSP, HSTS, X-Content-Type-Options).

6. **A06:2021 - Vulnerable and Outdated Components**: Using dependencies with known CVEs (libraries, frameworks, container images).
   - *Mitigation*: Maintain Software Bill of Materials (SBOM); run automated dependency scans (Dependabot, Snyk, OWASP Dependency-Check); patch proactively.

7. **A07:2021 - Identification & Authentication Failures**: Weak credential policies, lack of multi-factor authentication (MFA), vulnerability to credential stuffing and session fixation.
   - *Mitigation*: Enforce phishing-resistant MFA (FIDO2/WebAuthn); implement robust account lockout/rate limiting; rotate session IDs upon authentication.

8. **A08:2021 - Software and Data Integrity Failures**: Relying on software updates, plugins, or CI/CD pipelines without verifying cryptographic integrity or signatures.
   - *Mitigation*: Verify digital signatures on dependencies (Sigstore, Cosign); guard CI/CD build environments; restrict code execution permissions.

9. **A09:2021 - Security Logging & Monitoring Failures**: Inability to detect, alert on, or reconstruct security breaches due to insufficient logging.
   - *Mitigation*: Centralize logs into a SIEM; capture authentication events, privilege escalation, and high-frequency 404/403 requests; monitor with automated alerting.

10. **A10:2021 - Server-Side Request Forgery (SSRF)**: Web application fetches a remote resource without validating the user-supplied URL, allowing attackers to coerce the server into sending requests to internal systems (e.g., AWS/GCP cloud metadata services at `169.254.169.254`).
   - *Mitigation*: Enforce strict URL allowlists; disable HTTP redirection in server HTTP clients; isolate cloud metadata endpoints using IMDSv2."""
    },
    {
        "id": "kb_xss_csrf_cors",
        "title": "Client-Side Attacks: XSS, CSRF, and CORS In-Depth",
        "category": "Web Application Security",
        "content": """### Client-Side Security Architecture: XSS, CSRF, and CORS

#### Cross-Site Scripting (XSS)
XSS occurs when malicious JavaScript executes within the victim's browser context.
- **Stored XSS**: Payload is persistently saved in the database (e.g. comments, profiles) and served to subsequent visitors.
- **Reflected XSS**: Payload is immediately reflected in the server's HTTP response (e.g. search query parameters).
- **DOM-based XSS**: Vulnerability exists purely in client-side JavaScript when an untrusted source (e.g. `location.search`) is passed into a dangerous sink (`innerHTML`, `eval`, `document.write`).
- *Defense*: Context-aware output encoding (HTML, JavaScript, CSS); robust Content Security Policy (CSP); modern component frameworks (React/Angular) that escape variables by default; set `HttpOnly` flags on session cookies.

#### Cross-Site Request Forgery (CSRF)
CSRF tricks an authenticated user's browser into transmitting unauthorized HTTP requests to a target application where the victim is already logged in.
- *Mechanism*: The browser automatically includes session cookies with cross-origin requests unless restricted.
- *Defense*: Use `SameSite=Strict` or `SameSite=Lax` cookie attributes; implement unique cryptographically random Anti-CSRF tokens validated on the server for all state-changing requests (POST, PUT, DELETE).

#### Cross-Origin Resource Sharing (CORS) Misconfigurations
CORS allows browsers to relax the Same-Origin Policy (SOP).
- *Vulnerability*: Setting `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`, or blindly reflecting the incoming `Origin` header.
- *Defense*: Maintain an explicit allowlist of trusted domains; never reflect untrusted origins; do not trust `null` origins."""
    },

    # ── 2. ACTIVE DIRECTORY & ENTERPRISE IDENTITY ────────────────────
    {
        "id": "kb_active_directory_kerberos",
        "title": "Active Directory Kerberos Protocol & Roasting Attacks",
        "category": "Active Directory Security",
        "content": """### Active Directory Security: Kerberos Architecture & Attack Vectors

#### Kerberos Authentication Mechanics
Kerberos relies on a trusted Key Distribution Center (KDC) operating on Domain Controllers (TCP/UDP Port 88):
1. **AS-REQ / AS-REP**: Client requests a Ticket-Granting Ticket (TGT). User encrypts timestamp with their password hash. KDC validates and returns TGT encrypted with the domain KRBTGT secret.
2. **TGS-REQ / TGS-REP**: Client presents TGT to request a Ticket-Granting Service (TGS) ticket for a target Service Principal Name (SPN). KDC encrypts TGS ticket with the service account's password hash.
3. **AP-REQ / AP-REP**: Client submits TGS ticket to target service to authenticate.

#### Kerberoasting (MITRE ATT&CK T1558.003)
- *Mechanism*: Any authenticated domain user can request a TGS ticket for any registered Service Principal Name (SPN) in the domain. The ticket is encrypted with the SPN account's NTLM password hash. Attackers extract the ticket from memory and crack it offline using Hashcat (mode 13100).
- *Defense*: Migrate service accounts to Group Managed Service Accounts (gMSA) featuring automatic 128-character password rotation; enforce AES256 Kerberos encryption over legacy RC4-HMAC; enforce complex 25+ character passwords on service accounts.

#### AS-REP Roasting (MITRE ATT&CK T1558.004)
- *Mechanism*: Targets accounts where Kerberos pre-authentication is disabled (`DONT_REQ_PREAUTH`). An attacker queries the KDC without user credentials and receives an AS-REP response containing encrypted timestamp data that can be cracked offline.
- *Defense*: Audit Active Directory to ensure `Do not require Kerberos preauthentication` is unchecked on all accounts; enforce complex passwords.

#### DCSync (MITRE ATT&CK T1003.006)
- *Mechanism*: Exploits the Directory Replication Service Remote Protocol (MS-DRSR). An attacker possessing replication permissions impersonates a Domain Controller to pull password hashes (including KRBTGT) from Active Directory without executing code on the DC.
- *Defense*: Audit domain ACLs to ensure only legitimate Domain Controllers hold `Replicating Directory Changes` and `Replicating Directory Changes All` rights."""
    },
    {
        "id": "kb_ad_hardening_tiered",
        "title": "Active Directory Tiered Architecture & Privileged Access",
        "category": "Active Directory Security",
        "content": """### Active Directory Enterprise Hardening: Tiered Administration & PAM

#### Tiered Administrative Model
The Microsoft Tiered Administration Model separates identity planes to prevent credential theft and lateral movement:
- **Tier 0 (Control Plane)**: Domain Controllers, PKI/AD CS, Azure AD Connect, Tier 0 Group Policy Objects. Tier 0 credentials must NEVER be entered on any Tier 1 or Tier 2 system.
- **Tier 1 (Server Plane)**: Enterprise application servers, database servers, hypervisors, internal web applications.
- **Tier 2 (Workstation Plane)**: End-user workstations, laptops, mobile devices.

#### Credential Protection Technologies
1. **Windows Defender Credential Guard**: Uses Virtualization-Based Security (VBS) to isolate LSA secrets (Local Security Authority) in a protected virtual machine, preventing tools like Mimikatz from harvesting NTLM hashes or Kerberos tickets from `lsass.exe`.
2. **LSA Protection (RunAsPPL)**: Enforces Protected Process Light mode on `lsass.exe` to prevent unprivileged code injection.
3. **Privileged Access Workstations (PAWs)**: Dedicated hardened physical workstations restricted to administrative tasks only, with internet access and email blocked."""
    },

    # ── 3. NETWORK PROTOCOLS & PERIMETER DEFENSE ────────────────────
    {
        "id": "kb_tcp_ip_osi_model",
        "title": "TCP/IP Suite, OSI 7-Layer Architecture, and Transport Security",
        "category": "Network Security",
        "content": """### Network Protocol Architecture: OSI Model & TCP/IP Mechanics

#### OSI 7-Layer Model Reference
1. **Layer 1 - Physical**: Bits on wire (Ethernet cables, fiber optics, wireless RF).
2. **Layer 2 - Data Link**: Frames, MAC addressing, ARP, switches, VLANs (802.1Q). Attacks: MAC flooding, ARP poisoning. Defense: Dynamic ARP Inspection (DAI), Port Security.
3. **Layer 3 - Network**: Packets, IPv4/IPv6, routing protocols (BGP, OSPF), ICMP. Attacks: IP spoofing, Ping of Death. Defense: uRPF (Unicast Reverse Path Forwarding), packet filtering.
4. **Layer 4 - Transport**: Segments, TCP (connection-oriented, reliable, windowing) & UDP (connectionless). Attacks: SYN flood, port scanning. Defense: SYN cookies, stateful firewalls.
5. **Layer 5 - Session**: Inter-host session management (RPC, NetBIOS, SMB).
6. **Layer 6 - Presentation**: Data representation, encoding, TLS/SSL encryption.
7. **Layer 7 - Application**: Application payloads (HTTP, DNS, SSH, FTP, SMTP).

#### TCP 3-Way Handshake & Teardown
- **Establishment**:
  1. Client sends `SYN` (Synchronize) with Initial Sequence Number (ISN).
  2. Server responds with `SYN-ACK` (Synchronize-Acknowledge) with its own ISN and `Ack = Client ISN + 1`.
  3. Client responds with `ACK` (Acknowledge) with `Ack = Server ISN + 1`.
- **Termination**:
  - `FIN` (Graceful termination handshake) or `RST` (Abrupt reset due to closed port or error).
- **SYN Flood Attack**: Attacker floods server with `SYN` requests from spoofed IPs without completing the handshake, exhausting the server's connection backlog table. Defended via **SYN Cookies**."""
    },
    {
        "id": "kb_tls_cryptography",
        "title": "TLS 1.3 vs 1.2 Handshake, Cipher Suites, and PKI",
        "category": "Cryptography & PKI",
        "content": """### Cryptographic Protocols: TLS 1.3 vs TLS 1.2 & Public Key Infrastructure

#### TLS 1.3 Improvements Over TLS 1.2
1. **Reduced Handshake Latency (1-RTT & 0-RTT)**:
   - TLS 1.2 required 2 round trips (2-RTT) to complete the cryptographic negotiation.
   - TLS 1.3 combines key exchange and cipher negotiation into a single round trip (1-RTT). Supports 0-RTT session resumption for repeat connections.
2. **Removal of Insecure Cryptographic Primitives**:
   - Deprecated weak algorithms: RSA key transport, Static Diffie-Hellman, RC4, DES, 3DES, MD5, SHA-1, CBC mode ciphers (vulnerable to Padding Oracle / POODLE attacks).
   - Enforced **Ephemeral Diffie-Hellman (DHE / ECDHE)** for mandatory **Perfect Forward Secrecy (PFS)**. Compromise of server private key cannot decrypt historical captured traffic.
3. **Encrypted Handshake Extensions**:
   - TLS 1.3 encrypts certificate messages and handshake metadata, preventing passive network eavesdroppers from observing the server's certificate or identity.

#### Public Key Infrastructure (PKI)
- **Certificate Authority (CA)**: Trusted third party signing X.509 digital certificates.
- **Revocation**: CRL (Certificate Revocation Lists) vs OCSP (Online Certificate Status Protocol) and OCSP Stapling.
- **Certificate Transparency (CT)**: Public append-only cryptographic logs preventing rogue CA certificate issuance."""
    },

    # ── 4. PENETRATION TESTING & OFFENSIVE METHODOLOGIES ────────────
    {
        "id": "kb_ptes_methodology",
        "title": "PTES Penetration Testing Execution Standard Framework",
        "category": "Penetration Testing",
        "content": """### PTES Penetration Testing Execution Standard Methodology

The PTES standard provides an end-to-end framework for professional penetration testing engagements:

1. **Pre-engagement Interactions**: Defining rules of engagement (ROE), testing scope, communication channels, IP whitelists, emergency contacts, and compliance constraints.
2. **Intelligence Gathering (OSINT & Reconnaissance)**:
   - *Passive*: DNS records, WHOIS, Shodan, Certificate Transparency logs, employee social engineering surface.
   - *Active*: Port sweeps, banner grabbing, service enumeration (Nmap, Masscan).
3. **Threat Modeling**: Identifying assets, threat actors, attack surface exposure, and prioritized business logic risks.
4. **Vulnerability Analysis**: Evaluating discovered open ports and services for unpatched CVEs, configuration weaknesses, and exposed credentials using automated (DAST) and manual techniques.
5. **Exploitation**: Controlled, safe exploitation of validated vulnerabilities to bypass access barriers without causing service degradation.
6. **Post-Exploitation**: Assessing business impact through internal network enumeration, privilege escalation, credential extraction, and lateral movement analysis.
7. **Reporting & Debrief**: Delivering comprehensive Executive Summaries (risk ratings, financial impact) and Technical Remediation Directives (CVSS scoring, exact CLI configurations, patch priorities)."""
    },
    {
        "id": "kb_privilege_escalation",
        "title": "Privilege Escalation Mechanics: Linux and Windows",
        "category": "Penetration Testing",
        "content": """### Privilege Escalation Vectors: Linux and Windows Operating Systems

#### Linux Privilege Escalation
1. **SUID / SGID Binaries**: Executables with SetUID bit (`chmod u+s`) execute with file owner permissions (often root). Misconfigured binaries (GTFOBins: `nmap`, `find`, `vim`, `bash`) allow spawning elevated shells.
2. **Sudo Privileges**: Misconfigured `/etc/sudoers` entries allowing unprivileged users to execute commands with `sudo` without password (`NOPASSWD`).
3. **Kernel Exploits**: Dirty COW (CVE-2016-5195), PwnKit (CVE-2021-4034), Dirty Pipe (CVE-2022-0847) exploiting race conditions in kernel memory.
4. **Cron Job Vulnerabilities**: Scheduled jobs running as root executing writable scripts or referencing binaries with relative PATH entries.

#### Windows Privilege Escalation
1. **Token Impersonation (SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege)**: Service accounts running web servers or SQL can impersonate higher-privileged tokens via Named Pipe potato exploits (SweetPotato, PrintSpoofer).
2. **Unquoted Service Paths**: Services installed with unquoted paths containing spaces (`C:\\Program Files\\My Service\\svc.exe`) allow placing malicious executables (`C:\\Program.exe`) that execute upon service restart.
3. **Weak Service Permissions**: Services where authenticated users have `SERVICE_CHANGE_CONFIG` or `SERVICE_ALL_ACCESS` rights, allowing modification of `binPath` to run arbitrary commands as `NT AUTHORITY\\SYSTEM`.
4. **AlwaysInstallElevated**: Registry keys allowing standard users to execute MSI installers with elevated SYSTEM privileges."""
    },

    # ── 5. DEFENSIVE SECURITY, SOC & INCIDENT RESPONSE ───────────────
    {
        "id": "kb_incident_response_picerl",
        "title": "Incident Response Lifecycle: SANS PICERL & NIST SP 800-61",
        "category": "Incident Response",
        "content": """### Incident Response Frameworks: SANS PICERL & NIST SP 800-61

#### The SANS PICERL Lifecycle
1. **Preparation**: Establishing policies, incident response plans (IRP), forensic toolkits, playbooks, communication trees, and continuous log forwarding to SIEM.
2. **Identification (Detection)**: Detecting anomalous behavior, alerts from EDR/NIDS, correlating indicators of compromise (IOCs), and determining scope and severity.
3. **Containment**:
   - *Short-Term*: Isolating affected endpoints from network (firewall block rules, VLAN quarantine, disabling compromised accounts).
   - *Long-Term*: Applying interim patches, segmenting subnets, implementing enhanced monitoring.
4. **Eradication**: Removing malware binaries, rootkits, backdoors, scheduled tasks, and rogue persistence mechanisms; revoking compromised credentials and certificates.
5. **Recovery**: Restoring systems from clean, validated backups; verifying system integrity; monitoring traffic to confirm adversary has not regained access.
6. **Lessons Learned**: Conducting post-incident review within 14 days; documenting root cause, response timeline, gaps, and updating defensive controls."""
    },
    {
        "id": "kb_siem_event_ids",
        "title": "SOC Telemetry & Critical Windows Security Event IDs",
        "category": "SOC & Detection Engineering",
        "content": """### SOC Detection Engineering: Critical Windows Security Event IDs

Monitoring these essential Windows Security Log Event IDs enables early adversary detection:
- **Event ID 4624**: Successful Account Logon (Logon Type 2: Interactive, Type 3: Network/SMB, Type 10: RemoteDesktop RDP).
- **Event ID 4625**: Failed Account Logon (Critical for detecting brute-force and password spraying attacks).
- **Event ID 4672**: Special Privileges Assigned to New Logon (Indicates Administrator or SYSTEM logon).
- **Event ID 4688**: New Process Created (Enabling Command-Line Process Auditing reveals attacker CLI tools and arguments).
- **Event ID 7045 / 4697**: New Windows Service Installed (Common persistence and privilege escalation mechanism).
- **Event ID 4720**: New User Account Created (Often created by adversaries for backdoor persistence).
- **Event ID 4728 / 4732**: Member Added to Privileged Security Group (Domain Admins, Enterprise Admins).
- **Event ID 4104**: PowerShell Script Block Logging (Captures full decoded script content executed by PowerShell)."""
    },

    # ── 6. CRYPTOGRAPHY, FORENSICS & COMPLIANCE ─────────────────────
    {
        "id": "kb_cryptography_algorithms",
        "title": "Modern Cryptographic Standards: AES, RSA, ECC, and Hashes",
        "category": "Cryptography & PKI",
        "content": """### Cryptography Standards: Symmetric, Asymmetric, and Hashing Primitives

#### 1. Symmetric Encryption
Uses a single shared key for encryption and decryption. High throughput.
- **AES (Advanced Encryption Standard)**: 128, 192, or 256-bit key length.
  - *Modes*: Electronic Codebook (ECB) is INSECURE (leaks plaintext patterns). Cipher Block Chaining (CBC) is vulnerable to padding oracle attacks unless paired with MAC.
  - *Best Practice*: **AES-GCM (Galois/Counter Mode)** provides Authenticated Encryption with Associated Data (AEAD), guaranteeing confidentiality and integrity simultaneously.
- **ChaCha20-Poly1305**: High-speed AEAD stream cipher ideal for mobile and hardware lacking AES-NI acceleration.

#### 2. Asymmetric (Public Key) Encryption
Uses mathematically linked key pairs (public key for encryption/verification, private key for decryption/signing).
- **RSA**: Relies on prime factorization. Minimum recommended key size: 2048-bit (transitional) or 4096-bit (recommended).
- **Elliptic Curve Cryptography (ECC)**: Relies on elliptic curve discrete logarithm problem. Offers equivalent security to RSA with significantly smaller keys (e.g. 256-bit ECC ≈ 3072-bit RSA). Standards: ECDSA, Ed25519 (EdDSA).

#### 3. Cryptographic Hashes & Password Storage
- **Cryptographic Hashing (One-Way, Fixed Output)**: SHA-256, SHA-3, BLAKE3. (MD5 and SHA-1 are cryptographically broken).
- **Password Hashing (Memory-Hard & Computationally Intensive)**: Protects against GPU/ASIC brute forcing.
  - **Argon2id**: Winner of Password Hashing Competition. State-of-the-art protection against side-channel and GPU attacks.
  - **bcrypt**: Robust, time-tested Blowfish-based password hashing.
  - **PBKDF2**: NIST compliant with high iteration count (≥600,000 rounds for SHA-256)."""
    },
    {
        "id": "kb_zero_trust_architecture",
        "title": "Zero Trust Architecture Principles (NIST SP 800-207)",
        "category": "Defensive Architecture",
        "content": """### Zero Trust Architecture (NIST SP 800-207)

Zero Trust is an enterprise cybersecurity architecture based on the core tenet: **"Never Trust, Always Verify."** It assumes the perimeter has already been breached.

#### Core Principles
1. **All Data Sources and Computing Services Are Resources**: Every device, service, and API is treated as a protected asset.
2. **All Communication Is Secured Regardless of Network Location**: Internal corporate network traffic is considered as untrusted as public internet traffic. All communications must be encrypted in transit.
3. **Access to Individual Resources Is Granted on a Per-Session Basis**: Authentication and authorization are dynamic and evaluated per request.
4. **Access Is Determined by Dynamic Policy**: Policies incorporate user identity, device posture, location, time, behavioral telemetry, and threat context.
5. **Continuous Diagnostic Monitoring & Authentication**: Continuous verification replaces static perimeter-based VPN access."""
    }
]

class SecurityAssistant:
    """
    Dedicated Cybersecurity Knowledge Base Assistant.
    Maintains a persistent ChromaDB vector store and provides authoritative,
    reference-grade cybersecurity knowledge and education.
    """
    def __init__(self, db_path="./cyber_kb"):
        self.ai_client = None
        self._init_ai_client()

        self.chroma_client = None
        self.kb_collection = None

        if HAS_CHROMA:
            try:
                self.chroma_client = chromadb.PersistentClient(path=db_path)
                self.kb_collection = self.chroma_client.get_or_create_collection("cybersecurity_library")
                self._seed_library_if_needed()
                print("[+] Security Assistant Knowledge Library online.")
            except Exception as e:
                print(f"[!] ChromaDB Assistant Notice: {str(e)}")

    def _init_ai_client(self):
        api_key = os.getenv("GEMINI_API_KEY", "").strip().strip('"').strip("'")
        if api_key and HAS_GENAI:
            try:
                self.ai_client = genai.Client(api_key=api_key)
                print("[+] Security Assistant Generative Engine initialized.")
            except Exception as e:
                print(f"[!] Gemini Assistant Initialization Error: {str(e)}")
        elif HAS_GENAI:
            try:
                self.ai_client = genai.Client()
            except Exception:
                pass

    def _seed_library_if_needed(self):
        """Populates the ChromaDB knowledge collection with comprehensive library documents if empty."""
        if not self.kb_collection:
            return
        try:
            current_count = self.kb_collection.count()
            if current_count < len(COMPREHENSIVE_CYBER_LIBRARY):
                docs = [item["content"] for item in COMPREHENSIVE_CYBER_LIBRARY]
                metas = [{"title": item["title"], "category": item["category"]} for item in COMPREHENSIVE_CYBER_LIBRARY]
                ids = [item["id"] for item in COMPREHENSIVE_CYBER_LIBRARY]
                self.kb_collection.upsert(documents=docs, metadatas=metas, ids=ids)
                print(f"[+] Seeded {len(ids)} comprehensive cybersecurity library documents into ChromaDB.")
        except Exception as e:
            print(f"[!] Error seeding library: {str(e)}")

    def seed_knowledge_base(self, documents: list, metadatas: list, ids: list):
        """Allows external scripts to ingest additional knowledge documents."""
        if self.kb_collection:
            try:
                self.kb_collection.upsert(documents=documents, metadatas=metadatas, ids=ids)
                print(f"[+] Ingested {len(ids)} knowledge base items into ChromaDB.")
            except Exception as e:
                print(f"[!] Error ingesting into ChromaDB: {str(e)}")

    def _match_static_library(self, query: str) -> Optional[str]:
        """Provides instant, exhaustive technical answers from the built-in library."""
        q_lower = query.lower()

        # Keyword mapping to authoritative library documents
        if any(k in q_lower for k in ["owasp", "injection", "broken access", "ssrf", "xss", "csrf", "cors"]):
            return (
                f"{COMPREHENSIVE_CYBER_LIBRARY[0]['content']}\n\n---\n\n"
                f"{COMPREHENSIVE_CYBER_LIBRARY[1]['content']}"
            )
        elif any(k in q_lower for k in ["active directory", "kerberos", "kerberoast", "as-rep", "dcsync", "ticket", "tier"]):
            return (
                f"{COMPREHENSIVE_CYBER_LIBRARY[2]['content']}\n\n---\n\n"
                f"{COMPREHENSIVE_CYBER_LIBRARY[3]['content']}"
            )
        elif any(k in q_lower for k in ["tcp", "ip", "osi", "syn", "handshake", "layer", "packet"]):
            return COMPREHENSIVE_CYBER_LIBRARY[4]["content"]
        elif any(k in q_lower for k in ["tls", "ssl", "cipher", "crypto", "aes", "rsa", "hash", "argon2", "bcrypt"]):
            return (
                f"{COMPREHENSIVE_CYBER_LIBRARY[5]['content']}\n\n---\n\n"
                f"{COMPREHENSIVE_CYBER_LIBRARY[8]['content']}"
            )
        elif any(k in q_lower for k in ["ptes", "pentest", "penetration testing", "reconnaissance", "privilege escalation", "suid"]):
            return (
                f"{COMPREHENSIVE_CYBER_LIBRARY[6]['content']}\n\n---\n\n"
                f"{COMPREHENSIVE_CYBER_LIBRARY[7]['content']}"
            )
        elif any(k in q_lower for k in ["incident response", "picerl", "soc", "siem", "event id", "suricata", "snort"]):
            return (
                f"{COMPREHENSIVE_CYBER_LIBRARY[9]['content']}\n\n---\n\n"
                f"{COMPREHENSIVE_CYBER_LIBRARY[10]['content']}"
            )
        elif any(k in q_lower for k in ["zero trust", "ztna", "perimeter"]):
            return COMPREHENSIVE_CYBER_LIBRARY[11]["content"]

        return None

    def query_cyber_knowledge(self, user_query: str) -> str:
        """
        Queries the cybersecurity knowledge library using ChromaDB vector search
        augmented by generative AI or authoritative library synthesis.
        """
        user_query = user_query.strip()
        if not user_query:
            return "Please submit a cybersecurity knowledge query or topic."

        retrieved_docs = []
        retrieved_metas = []

        if self.kb_collection:
            try:
                results = self.kb_collection.query(
                    query_texts=[user_query],
                    n_results=3
                )
                if results and "documents" in results and results["documents"]:
                    retrieved_docs = results["documents"][0]
                    retrieved_metas = results["metadatas"][0] if "metadatas" in results else []
            except Exception as e:
                print(f"[!] Vector store query notice: {str(e)}")

        context_blocks = []
        for i, doc in enumerate(retrieved_docs):
            title = retrieved_metas[i].get("title", "Reference") if i < len(retrieved_metas) else "Reference"
            context_blocks.append(f"### [Reference Source: {title}]\n{doc}")

        context_str = "\n\n".join(context_blocks) if context_blocks else ""

        # Attempt generative synthesis via Gemini if available
        if not self.ai_client:
            self._init_ai_client()

        if self.ai_client:
            for model_id in DEFAULT_MODELS:
                try:
                    config = types.GenerateContentConfig(
                        system_instruction=CYBER_LIBRARY_SYSTEM_PROMPT,
                        temperature=0.2,
                        max_output_tokens=3500
                    )
                    prompt = (
                        f"GROUNDING CONTEXT FROM INTERNAL CYBERSECURITY LIBRARY:\n{context_str}\n\n"
                        f"USER INQUIRY: {user_query}\n\n"
                        "Provide a structured, authoritative, and educational response explaining the relevant principles, attack mechanisms, and defense standards."
                    )
                    response = self.ai_client.models.generate_content(
                        model=model_id,
                        contents=prompt,
                        config=config
                    )
                    if response and response.text:
                        return response.text
                except Exception:
                    continue

        # Offline / Fallback Knowledge Library Resolution
        static_match = self._match_static_library(user_query)
        if static_match:
            return static_match

        if context_str:
            return f"### SecurOS Cybersecurity Knowledge Reference\n\n{context_str}"

        # Default structured cybersecurity reference response
        return (
            f"### SecurOS Cybersecurity Library: {user_query}\n\n"
            "This concept is part of the core cybersecurity domain. Key pillars to investigate:\n"
            "- **Threat Modeling**: Review data flows, boundaries, and STRIDE categories.\n"
            "- **Defensive Controls**: Apply the Principle of Least Privilege, Zero Trust isolation, and multi-layered defense-in-depth.\n"
            "- **Standards Alignment**: Reference the corresponding NIST SP 800-53 controls or OWASP Top 10 guidelines.\n\n"
            "*Tip: Configure your `GEMINI_API_KEY` to unlock real-time generative research over thousands of academic papers, or choose from the curated library topics above.*"
        )

# Module-level instances for easy import
sec_assistant = SecurityAssistant()
assistant = sec_assistant
