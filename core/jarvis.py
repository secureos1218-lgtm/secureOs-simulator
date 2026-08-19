import os
import json
import time

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

JARVIS_SYSTEM_PROMPT = """
You are JARVIS, an expert Cyber Security AI Threat Copilot built into SecurOS.
Your domain expertise includes:
- Penetration Testing, VAPT Methodology, and Active Directory Exploitation (Kerberoasting, AS-REP Roasting, DCSync)
- Incident Response, SOC Telemetry, and Threat Anomaly Detection
- Exploit Development, Source Code Auditing, and Network Packet Analysis (Wireshark, Scapy, Nmap)

Response Guidelines:
1. Provide authoritative, direct, and actionable security insights.
2. Outline vulnerabilities, severity (CVSS), and exact CLI remediation commands (firewall rules, patch scripts).
3. Use clean Markdown formatting (tables, bullet points, code blocks).
"""

DEFAULT_MODELS = [
    'gemini-2.5-flash',
    'gemini-2.5-pro',
]

FALLBACK_KNOWLEDGE_MAP = {
    "vapt": """### JARVIS Tactical Assessment: VAPT Methodology

**Vulnerability Assessment & Penetration Testing (VAPT)** is an offensive security validation framework.

**1. Automated Assessment (VA Phase)**
* **Network Discovery**: Port sweeps and banner grabbing via Nmap (`nmap -sV -sC -T4`).
* **DAST & Web Exposure**: Automated CVE and template scanning using Nuclei & Web Fuzzers (`ffuf -u http://TARGET/FUZZ -w wordlist.txt`).

**2. Manual Penetration Testing (PT Phase)**
* **Privilege Escalation**: Exploitation of service account vulnerabilities (e.g. Kerberoasting with `GetUserSPNs.py`).
* **Lateral Movement**: Pass-the-Hash / Overpass-the-Hash and AD replication abuse (DCSync).

**3. Remediation Directives**
* Implement host-based firewalls, restrict RPC/SMB perimeters (TCP 445, 139).
* Rotate high-privilege Kerberos ticket-granting service accounts (KRBTGT).""",

    "packet": """### Network Threat Evaluation
* **High-Rate SYN Packets**: Indicates internal port scanning (T1046). Apply Suricata SID 1000842 and host firewall rate limiting.
* **Plaintext Protocols**: Cleartext protocols (HTTP, Telnet, FTP) leak credentials in transit. Enforce TLS 1.3 encryption across all subnets.""",

    "cve": """### Prioritized Vulnerability Intelligence
* **CVE-2024-21413 (CVSS 9.8)**: Microsoft Outlook Moniker RCE / NTLM leak. Disable legacy NTLM hash outbound relay.
* **CVE-2023-44487 (CVSS 7.5)**: HTTP/2 Rapid Reset DoS. Enforce strict stream concurrency limits in web server configs."""
}

class JarvisEngine:
    def __init__(self, db_path="cyber_kb"):
        self.chroma_client = None
        self.collection = None
        self.ai_client = None

        if HAS_CHROMA:
            try:
                self.chroma_client = chromadb.PersistentClient(path=db_path)
                self.collection = self.chroma_client.get_or_create_collection(name="cybersecurity_docs")
                print("[+] JARVIS RAG Vector Store online.")
            except Exception as e:
                print(f"[!] JARVIS ChromaDB Notice: {str(e)}")

        self._init_client()

    def _init_client(self):
        api_key = os.getenv("GEMINI_API_KEY", "").strip().strip('"').strip("'")
        if api_key and HAS_GENAI:
            try:
                self.ai_client = genai.Client(api_key=api_key)
                print(f"[+] JARVIS Copilot Engine online.")
            except Exception as e:
                print(f"[!] JARVIS GenAI Initialization Error: {str(e)}")
        elif HAS_GENAI:
            try:
                self.ai_client = genai.Client()
            except Exception:
                pass

    def retrieve_context(self, query: str, top_k: int = 1) -> str:
        if not self.collection:
            return ""
        try:
            results = self.collection.query(query_texts=[query], n_results=top_k)
            docs = results.get("documents", [[]])[0]
            if docs:
                return docs[0]
        except Exception:
            pass
        return ""

    def stream_chat(self, prompt: str, history: list = None, telemetry_data: dict = None):
        if not self.ai_client:
            self._init_client()

        rag_doc = self.retrieve_context(prompt)
        
        full_prompt = ""
        if telemetry_data:
            full_prompt += f"--- ACTIVE TELEMETRY BUFFER ---\n{json.dumps(telemetry_data, indent=2)}\n\n"
        if rag_doc:
            full_prompt += f"--- GROUNDING CONTEXT ---\n{rag_doc}\n\n"
            
        full_prompt += f"User Query: {prompt}"

        if self.ai_client:
            for model_name in DEFAULT_MODELS:
                try:
                    config = types.GenerateContentConfig(
                        system_instruction=JARVIS_SYSTEM_PROMPT,
                        temperature=0.2,
                        max_output_tokens=2048
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

        # Offline Fallback Synthesis
        q_lower = prompt.lower()
        for key, text in FALLBACK_KNOWLEDGE_MAP.items():
            if key in q_lower:
                for word in text.split(" "):
                    yield word + " "
                    time.sleep(0.015)
                return

        if rag_doc:
            yield f"### JARVIS Analysis & Directives\n\n{rag_doc}\n\n**Remediation Recommendation:** Review local firewall rules and isolate suspicious subnet traffic."
        else:
            yield f"### JARVIS Copilot Online\n\nReceived query: **{prompt}**.\n\nTo enable unrestricted real-time LLM streaming, set your API key in PowerShell:\n`$env:GEMINI_API_KEY=\"AIzaSy...\"`"