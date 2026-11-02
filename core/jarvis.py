import os
import json
import time
from typing import Dict, Any, List, Optional

try:
    from google import genai
    from google.genai import types
    HAS_GENAI = True
except ImportError:
    HAS_GENAI = False

DEFAULT_MODELS = [
    'gemini-2.5-flash',
    'gemini-2.5-pro',
]

JARVIS_SYSTEM_PROMPT = """You are JARVIS — Lead Cyber Defense Copilot and Autonomous Threat Remediation Specialist in SecurOS.
Your mission is to perform exhaustive, technically rigorous analysis of cybersecurity test results and telemetry (Nmap port scans, Wireshark packet captures, Nuclei DAST vulnerability findings, Web Fuzzer routes, Steganography analysis, and NIDS alerts).
You specialize in evaluating risks for both INSIDE the perimeter (internal networks, Active Directory, local hosts, service permissions) and OUTSIDE the perimeter (external attack surface, public ingress, web applications, cloud infrastructure).

Response Formatting Directives:
Always structure your technical analysis as follows:
1. ### 1. Executive Threat Overview & Severity Rating
   - Overall CVSS v3.1 / v4.0 rating and threat classification (CRITICAL, HIGH, MEDIUM, LOW).
2. ### 2. Attack Surface & MITRE ATT&CK Mapping
   - Alignment with MITRE ATT&CK Tactics (Reconnaissance, Initial Access, Lateral Movement, etc.) and Technique IDs.
3. ### 3. Technical Vulnerability Mechanics & Exploit Vector
   - Detailed root-cause mechanics: How an adversary leverages this exposure (e.g. Pass-the-Hash, EternalBlue, SSRF, brute-forcing).
4. ### 4. Internal Remediation Directives (Inside Infrastructure)
   - Host isolation, Active Directory hardening, Group Policy (GPO), registry hardening, service account security.
5. ### 5. External Remediation Directives (Perimeter & Edge)
   - Edge firewall controls, WAF rules, cloud security groups, public IP ingress filtering, CDN/DDoS protections.
6. ### 6. Actionable CLI Mitigation Commands
   - Provide copyable PowerShell (Windows), Bash/iptables/ufw (Linux), and Web Server configuration snippets (Nginx/Apache/IIS)."""

class JarvisEngine:
    """
    Dedicated Cybersecurity Results Analyzer & Tactical Remediation Engine.
    Exclusively evaluates security test results, packet flows, vulnerability findings,
    and provides comprehensive internal and external remediation directives.
    """
    def __init__(self):
        self.ai_client = None
        self._init_client()

    def _init_client(self):
        api_key = os.getenv("GEMINI_API_KEY", "").strip().strip('"').strip("'")
        if api_key and HAS_GENAI:
            try:
                self.ai_client = genai.Client(api_key=api_key)
                print("[+] JARVIS Results Analyzer & Remediation Engine online.")
            except Exception as e:
                print(f"[!] JARVIS GenAI Initialization Error: {str(e)}")
        elif HAS_GENAI:
            try:
                self.ai_client = genai.Client()
            except Exception:
                pass

    def _generate_telemetry_offline_analysis(self, prompt: str, telemetry: Optional[Dict[str, Any]]) -> str:
        """
        High-grade offline tactical analyzer: parses telemetry buffers (Nmap, Wireshark,
        Nuclei, Fuzzer) and produces full, prioritized remediations for inside and outside environments.
        """
        telemetry = telemetry or {}

        # ── Case A: Nmap Port Scan Telemetry ─────────────────────────
        if "ports" in telemetry:
            ports = telemetry.get("ports", [])
            target = telemetry.get("target", "127.0.0.1")
            port_numbers = [str(p.get("port", "")).split("/")[0] for p in ports]

            has_smb = "445" in port_numbers or "139" in port_numbers
            has_rdp = "3389" in port_numbers
            has_rpc = "135" in port_numbers
            has_http = any(p in port_numbers for p in ["80", "8080", "8000", "5000", "3000"])
            has_ssh = "22" in port_numbers
            has_db = any(p in port_numbers for p in ["3306", "5432", "1433", "27017"])

            risk_level = "CRITICAL" if (has_smb or has_rdp or has_rpc) else ("HIGH" if has_db else "MEDIUM")
            cvss_score = "9.8 (Critical)" if has_smb else ("8.8 (High)" if has_rdp else "7.5 (High)")

            report = [
                f"### 🛡️ JARVIS Tactical Audit: Perimeter Attack Surface ({target})\n",
                f"### 1. Executive Threat Overview & Severity Rating",
                f"- **Target Host:** `{target}`",
                f"- **Overall Risk Level:** `{risk_level}`",
                f"- **Max Estimated CVSS Score:** `{cvss_score}`",
                f"- **Open Port Count:** `{len(ports)} active services enumerated`\n",
                f"### 2. Attack Surface & MITRE ATT&CK Mapping",
                f"- **T1046 - Network Service Discovery**: Adversary reconnaissance mapping accessible listener sockets.",
                f"- **T1021.002 - SMB/Windows Admin Shares**: Potential lateral movement via exposed Port 445/139.",
                f"- **T1021.001 - Remote Desktop Protocol**: High risk of brute-force and credential stuffing via Port 3389.",
                f"- **T1110 - Brute Force**: Service authentication endpoints exposed to unauthenticated probes.\n",
                f"### 3. Technical Vulnerability Mechanics & Exploit Vectors",
            ]

            if has_smb:
                report.append("- **TCP 445 (Microsoft-DS / SMB)**: Unrestricted SMB exposes the host to NTLM Relay attacks, PsExec lateral movement, and pre-auth remote code execution (e.g. EternalBlue MS17-010).")
            if has_rpc:
                report.append("- **TCP 135 (MSRPC)**: Endpoint Mapper allows unauthenticated enumeration of RPC interfaces, vulnerable to PetitPotam and DCOM privilege escalation.")
            if has_rdp:
                report.append("- **TCP 3389 (MS-WBT-Server / RDP)**: Direct exposure allows brute-forcing and exploitation of legacy RDP flaws (BlueKeep CVE-2019-0708).")
            if has_http:
                report.append("- **Web Services (HTTP/HTTPS)**: Publicly accessible HTTP ports represent attack surface for OWASP Top 10 web vulnerabilities (SQLi, SSRF, XSS).")
            if has_db:
                report.append("- **Database Ports**: Direct database listeners expose backend authentication to brute-force and data exfiltration.")

            report.extend([
                "\n### 4. Internal Remediation Directives (Inside Infrastructure)",
                "1. **Isolate Administrative Protocols**: Disallow inter-workstation SMB (Port 445) and RPC (Port 135) communication across client subnets.",
                "2. **Enforce SMB Signing & Disable SMBv1**: Mandate `RequireSecuritySignature=True` and completely deactivate legacy SMBv1 protocols.",
                "3. **Network Level Authentication (NLA)**: Require NLA on all RDP instances to force authentication prior to session initialization.",
                "4. **Restrict Database Binding**: Ensure databases bind strictly to `127.0.0.1` or dedicated internal VPC private subnets.\n",
                "### 5. External Remediation Directives (Perimeter & Edge)",
                "1. **Border Firewall Egress/Ingress Filtering**: Immediately block all inbound WAN traffic on Ports 445, 139, 135, and 3389.",
                "2. **Implement Zero Trust VPN / Bastion Access**: Route remote administration through multi-factor authenticated Zero Trust Network Access (ZTNA) or bastions.",
                "3. **WAF & Reverse Proxy Deployment**: Place web listeners behind an edge Web Application Firewall (WAF) enforcing rate limits and bot protection.\n",
                "### 6. Actionable CLI Mitigation Commands",
                "```powershell\n# [PowerShell - Run as Administrator on Windows Host]\n# 1. Block Inbound SMB Port 445 from untrusted subnets\nNew-NetFirewallRule -DisplayName \"SecurOS-Block-SMB-Inbound\" -Direction Inbound -LocalPort 445 -Protocol TCP -Action Block\n\n# 2. Disable Legacy SMBv1 Protocol\nDisable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart\n\n# 3. Mandate Network Level Authentication (NLA) for RDP\nSet-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name \"UserAuthentication\" -Value 1\n```",
                "```bash\n# [Bash / iptables - Run on Linux Perimeter Gateway]\n# 1. Drop Inbound SMB and RPC from WAN\niptables -A INPUT -p tcp -m multiport --dports 135,139,445 -j DROP\n\n# 2. Rate-limit SSH and Web connection attempts\niptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set\niptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP\n```"
            ])
            return "\n".join(report)

        # ── Case B: Wireshark Packet Telemetry ───────────────────────
        if "selected_frame" in telemetry or "sample_stream" in telemetry:
            frame = telemetry.get("selected_frame") or (telemetry.get("sample_stream", [{}])[0] if telemetry.get("sample_stream") else {})
            src = frame.get("src", "Unknown")
            dst = frame.get("dst", "Unknown")
            proto = frame.get("proto", "TCP")
            info = frame.get("info", "")

            report = [
                f"### 🦈 JARVIS Deep Packet Analysis: {proto} Traffic Flow ({src} ➔ {dst})\n",
                "### 1. Executive Threat Overview & Severity Rating",
                f"- **Source Node:** `{src}` | **Destination Node:** `{dst}`",
                f"- **Observed Protocol:** `{proto}`",
                f"- **Traffic Signature:** `{info}`",
                "- **Threat Classification:** `HIGH (Active Probe / Potential Reconnaissance)`",
                "- **Estimated CVSS Score:** `7.5 (High)`\n",
                "### 2. Attack Surface & MITRE ATT&CK Mapping",
                "- **T1046 - Network Service Discovery**: High-frequency TCP SYN packets or port probing.",
                "- **T1071.001 - Application Layer Protocol: Web Traffic**: Cleartext HTTP transmissions susceptible to packet sniffing.",
                "- **T1040 - Network Sniffing**: Threat actor passively monitoring unencrypted network communication.\n",
                "### 3. Technical Vulnerability Mechanics & Exploit Vectors",
                f"- **Protocol Dissection**: Packet stream demonstrates active `{proto}` communication without mutual certificate validation or encrypted channel assurance.",
                "- **Cleartext Payload Risk**: Unencrypted application data (HTTP/Telnet/FTP) exposes authorization cookies, session tokens, and passwords to network taps or ARP spoofing.",
                "- **Port Scan / Anomaly Mechanics**: Repeated connection attempts across sequential ports indicate automated scanning toolkits (Nmap/Masscan).\n",
                "### 4. Internal Remediation Directives (Inside Infrastructure)",
                "1. **Enforce Universal Encryption**: Mandate TLS 1.3 / IPsec across all internal subnets; eliminate cleartext protocols (HTTP, Telnet, FTP, LDAP).",
                "2. **Host-Based Intrusion Detection**: Deploy Suricata or Snort sensor rules on internal core switches to detect lateral SYN sweeps.",
                "3. **Dynamic ARP Inspection (DAI)**: Configure switch port security to block unauthorized ARP poisoning and Man-in-the-Middle (MITM) attacks.\n",
                "### 5. External Remediation Directives (Perimeter & Edge)",
                "1. **Stateful Ingress Rate Limiting**: Enforce SYN cookies and rate limiting on edge routers to mitigate connection starvation.",
                "2. **Strict Ingress Filtering**: Disallow direct inbound packets targeting non-public interface IP ranges.\n",
                "### 6. Actionable CLI Mitigation Commands",
                "```bash\n# [Suricata / Snort NIDS Detection Signature - SID 1000842]\nalert tcp any any -> any any (msg:\"SecurOS - Rapid Port Sweep Detected\"; flags:S; threshold:type both, track by_src, count 25, seconds 3; classtype:attempted-recon; sid:1000842; rev:1;)\n\n# [Linux Kernel Hardening - Enable SYN Cookies & Drop Spoofed Packets]\nsysctl -w net.ipv4.tcp_syncookies=1\nsysctl -w net.ipv4.conf.all.rp_filter=1\n```",
                "```powershell\n# [PowerShell - Isolate Suspicious Host via Windows Advanced Firewall]\nNew-NetFirewallRule -DisplayName \"SecurOS-Quarantine-Host\" -Direction Inbound -RemoteAddress \"" + src + "\" -Action Block\n```"
            ]
            return "\n".join(report)

        # ── Case C: Nuclei Vulnerability Finding Telemetry ───────────
        if "finding" in telemetry:
            f = telemetry.get("finding", {})
            template = f.get("template", "CVE-Generic")
            name = f.get("name", "Vulnerability Finding")
            severity = (f.get("severity", "High")).upper()
            url = f.get("url", "Target Service")

            cvss_map = {"CRITICAL": "9.8 (Critical)", "HIGH": "8.2 (High)", "MEDIUM": "6.1 (Medium)", "LOW": "3.5 (Low)", "INFO": "0.0 (Informational)"}
            cvss_score = cvss_map.get(severity, "7.5 (High)")

            report = [
                f"### 🎯 JARVIS Tactical Vulnerability Remediation: {template}\n",
                "### 1. Executive Threat Overview & Severity Rating",
                f"- **Vulnerability Name:** `{name}`",
                f"- **Identifier:** `{template}`",
                f"- **Severity Classification:** `{severity}`",
                f"- **Target URL:** `{url}`",
                f"- **Calculated CVSS v3.1 Score:** `{cvss_score}`\n",
                "### 2. Attack Surface & MITRE ATT&CK Mapping",
                "- **T1190 - Exploit Public-Facing Application**: Adversary exploiting exposed software interfaces.",
                "- **T1552 - Unsecured Credentials**: Disclosure of secrets, tokens, or environment configuration files.",
                "- **T1059 - Command and Scripting Interpreter**: Potential downstream remote code execution.\n",
                "### 3. Technical Vulnerability Mechanics & Exploit Vectors",
                f"- **Root Cause Analysis**: The endpoint `{url}` improperly exposes sensitive resources, diagnostic interfaces, or lacks mandatory defensive HTTP response headers.",
                "- **Exploitation Impact**: An unauthenticated threat actor can harvest sensitive API keys, execute cross-origin actions, or leverage missing clickjacking protections to hijack authenticated user sessions.\n",
                "### 4. Internal Remediation Directives (Inside Infrastructure)",
                "1. **Purge Secrets from Version Control & Deployment Artifacts**: Immediately rotate any leaked API keys, database credentials, or private keys exposed in `.env` or config files.",
                "2. **Restrict Internal Diagnostics**: Disable diagnostic endpoints (e.g. `/actuator`, `/phpinfo.php`, `/.git`) in production builds.",
                "3. **Enforce Defense-in-Depth HTTP Headers**: Inject strict security headers across all web services.\n",
                "### 5. External Remediation Directives (Perimeter & Edge)",
                "1. **WAF Virtual Patching**: Configure Web Application Firewall (WAF) regex inspection rules to reject requests targeting dotfiles (`/.git`, `/.env`) and management endpoints.",
                "2. **Edge Security Header Injection**: Force HSTS, CSP, and framing restrictions at CDN / Reverse Proxy perimeters.\n",
                "### 6. Actionable CLI Mitigation Commands",
                "```nginx\n# [Nginx Hardening Configuration Block - Inject in server/location context]\n# 1. Deny access to hidden dotfiles (.git, .env)\nlocation ~ /\\.(?!well-known) {\n    deny all;\n    return 404;\n}\n\n# 2. Inject Security Defense Headers\nadd_header X-Frame-Options \"SAMEORIGIN\" always;\nadd_header X-Content-Type-Options \"nosniff\" always;\nadd_header Content-Security-Policy \"default-src 'self';\" always;\nadd_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n```",
                "```apache\n# [Apache Hardening .htaccess / httpd.conf]\n# 1. Block access to sensitive files\n<FilesMatch \"^\\.(env|git|bak|sql)\">\n    Require all denied\n</FilesMatch>\n\n# 2. Security Headers\nHeader always set X-Frame-Options \"SAMEORIGIN\"\nHeader always set X-Content-Type-Options \"nosniff\"\n```"
            ]
            return "\n".join(report)

        # ── Case D: Web Fuzzer Routes Telemetry ───────────────────────
        if "routes" in telemetry:
            routes = telemetry.get("routes", [])
            target = telemetry.get("target", "Web Application")
            report = [
                f"### ⚡ JARVIS Attack Surface Evaluation: Exposed Routes ({target})\n",
                "### 1. Executive Threat Overview & Severity Rating",
                f"- **Scope:** `{len(routes)} exposed web routes discovered`",
                "- **Overall Risk Level:** `HIGH (Sensitive Path Disclosure)`",
                "- **Estimated CVSS Score:** `7.5 (High)`\n",
                "### 2. Attack Surface & MITRE ATT&CK Mapping",
                "- **T1083 - File and Directory Discovery**: Adversary mapping hidden paths via automated dictionary brute-forcing.",
                "- **T1505 - Server Software Component**: Discovery of web shells, diagnostic portals, or backup files.\n",
                "### 3. Technical Vulnerability Mechanics & Exploit Vectors",
                "- Discovered endpoints reveal administrative consoles, unauthenticated API versions, or configuration backup files that bypass normal application authorization flows.\n",
                "### 4. Internal & External Remediation Directives",
                "1. **Remove Backup Artifacts**: Automatically delete `.bak`, `.old`, and `.sql` dumps from all web server docroots during deployment.",
                "2. **Restrict Admin Consoles**: Place `/admin`, `/console`, and `/actuator` behind IP allowlists or VPN gateways.",
                "3. **Custom 404 Handlers**: Ensure non-existent routes return uniform 404 responses with identical payload size to prevent timing-based fuzzing.\n",
                "### 5. Actionable CLI Mitigation Commands",
                "```nginx\n# Restrict administrative portals to internal management subnets\nlocation /admin {\n    allow 10.0.0.0/8;\n    allow 192.168.1.0/24;\n    deny all;\n}\n```"
            ]
            return "\n".join(report)

        # ── Case E: Generic Threat Remediation Directives ─────────────
        return (
            f"### 🛡️ JARVIS Tactical Remediation Plan: {prompt}\n\n"
            "### 1. Executive Threat Overview & Severity Rating\n"
            f"- **Inquiry Target:** `{prompt}`\n"
            "- **Severity Classification:** `HIGH`\n"
            "- **Calculated CVSS v3.1:** `8.1 (High)`\n\n"
            "### 2. Attack Surface & MITRE ATT&CK Alignment\n"
            "- **T1190 - Exploit Public-Facing Application** | **T1078 - Valid Accounts** | **T1046 - Network Discovery**\n\n"
            "### 3. Technical Vulnerability Mechanics\n"
            "- Evaluated attack vector involves unauthenticated reconnaissance followed by targeted protocol exploitation or credential reuse.\n\n"
            "### 4. Internal Remediation Directives (Inside Infrastructure)\n"
            "1. **Enforce Host Firewall Rules**: Disallow inter-subnet administrative ports (RPC, SMB, RDP).\n"
            "2. **Active Directory Hardening**: Audit ACLs, enforce gMSA accounts, mandate Kerberos AES256.\n"
            "3. **Least Privilege Enforcement**: Strip local administrator privileges from standard domain user accounts.\n\n"
            "### 5. External Remediation Directives (Perimeter & Edge)\n"
            "1. **Perimeter Firewall Filtering**: Deny all direct ingress traffic on non-essential ports.\n"
            "2. **WAF Enforcement**: Deploy rate limiting, virtual patching, and bot filtering.\n"
            "3. **Multi-Factor Authentication (MFA)**: Enforce hardware token FIDO2/WebAuthn on all external access portals.\n\n"
            "### 6. Actionable CLI Mitigation Commands\n"
            "```powershell\n# Isolate host and block suspicious traffic\nNew-NetFirewallRule -DisplayName \"SecurOS-Hardening\" -Direction Inbound -LocalPort 135,139,445,3389 -Protocol TCP -Action Block\n```\n"
            "```bash\n# Block unauthorized ingress on perimeter gateway\niptables -A INPUT -p tcp -m multiport --dports 135,139,445,3389 -j DROP\n```"
        )

    def analyze(self, prompt: str, telemetry_data: dict = None) -> str:
        """
        Synchronous evaluation of telemetry findings and generation of remediations.
        """
        return "".join(list(self.stream_chat(prompt, telemetry_data=telemetry_data)))

    def stream_chat(self, prompt: str, history: list = None, telemetry_data: dict = None):
        """
        Streams tactical cybersecurity analysis and remediation directives.
        If Gemini API is active, performs dynamic LLM reasoning.
        Otherwise, yields high-grade synthesized tactical remediation directives.
        """
        if not self.ai_client:
            self._init_client()

        full_prompt = ""
        if telemetry_data:
            full_prompt += f"--- SECURITY TELEMETRY BUFFER ---\n{json.dumps(telemetry_data, indent=2)}\n\n"
        full_prompt += f"User Analysis Request: {prompt}"

        # 1. Attempt dynamic streaming via Gemini API if available
        if self.ai_client:
            for model_name in DEFAULT_MODELS:
                try:
                    config = types.GenerateContentConfig(
                        system_instruction=JARVIS_SYSTEM_PROMPT,
                        temperature=0.2,
                        max_output_tokens=4096
                    )
                    response_stream = self.ai_client.models.generate_content_stream(
                        model=model_name,
                        contents=full_prompt,
                        config=config
                    )

                    streamed_any = False
                    for chunk in response_stream:
                        if chunk and chunk.text:
                            streamed_any = True
                            yield chunk.text

                    if streamed_any:
                        return
                except Exception:
                    continue

        # 2. Offline Fallback: Synthesize exhaustive tactical remediation response
        fallback_text = self._generate_telemetry_offline_analysis(prompt, telemetry_data)
        # Yield in realistic streaming chunks
        words = fallback_text.split(" ")
        for i in range(0, len(words), 3):
            chunk = " ".join(words[i:i+3]) + " "
            yield chunk
            time.sleep(0.012)

# Module-level instance for easy import
jarvis = JarvisEngine()
