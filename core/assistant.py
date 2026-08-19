import os
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

DEFAULT_MODELS = [
    'gemini-2.5-flash',
    'gemini-2.5-pro',
]

FALLBACK_KNOWLEDGE_MAP = {
    "vapt": """### Vulnerability Assessment & Penetration Testing (VAPT)

**VAPT** is an end-to-end security testing methodology that combines automated vulnerability identification with manual exploitation to determine the real-world risk to an organization's assets.

**Core Methodological Phases:**
* **1. Reconnaissance & Target Scoping**: Active and passive asset mapping, port scanning (Nmap), and service identification.
* **2. Vulnerability Assessment (VA)**: Automated vulnerability discovery (DAST/SAST via tools like Nuclei, Nessus) to detect misconfigurations, unpatched CVEs, and insecure endpoints.
* **3. Penetration Testing (PT)**: Safe, targeted exploitation to validate exposure, demonstrate lateral movement paths (e.g., AD Kerberoasting, DCSync), and assess data exposure impact.
* **4. Executive & Technical Reporting**: Risk ranking via CVSS v3/v4 scoring and structured remediation directives.

**Primary Objectives:**
* Validate defensive controls (Firewall, EDR, SIEM).
* Prevent unauthorized initial access and remote code execution.
* Ensure regulatory compliance with ISO 27001, PCI-DSS, and SOC 2.""",
    
    "owasp": """### OWASP Top 10 Core Security Controls
* **A01: Broken Access Control**: Enforce strict server-side authorization checks on every endpoint.
* **A02: Cryptographic Failures**: Mandate TLS 1.3 in transit and strong algorithms (Argon2id, AES-GCM) at rest.
* **A03: Injection (SQLi/XSS/Command)**: Utilize parameterized queries, ORM abstractions, and output encoding.
* **A04: Insecure Design**: Apply threat modeling and secure architecture frameworks before coding.
* **A05: Security Misconfiguration**: Disable default credentials, remove unused features, and harden headers.
* **A06: Vulnerable and Outdated Components**: Maintain continuous dependency scans (SBOM, Dependabot).
* **A07: Identification and Authentication Failures**: Enforce MFA and rate-limit authentication endpoints.
* **A08: Software and Data Integrity Failures**: Validate digital signatures on plugins and CI/CD pipelines.
* **A09: Security Logging and Monitoring Failures**: Centralize audit logs into a SIEM with alerting rules.
* **A10: Server-Side Request Forgery (SSRF)**: Enforce strict URL allowlists and isolate internal cloud metadata services.""",
    
    "active directory": """### Active Directory Hardening & Defense
* **Kerberoasting Defense**: Migrate service accounts to Group Managed Service Accounts (gMSA) with 128-bit AES keys.
* **DCSync Defense**: Audit AD ACLs to remove unneeded `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` rights.
* **Tiered Administration**: Enforce PAWs (Privileged Access Workstations) and eliminate domain administrator logins on member endpoints."""
}

class SecurityAssistant:
    def __init__(self, db_path="./cyber_kb"):
        self.ai_client = None
        self._init_ai_client()

        self.chroma_client = None
        self.kb_collection = None
        if HAS_CHROMA:
            try:
                self.chroma_client = chromadb.PersistentClient(path=db_path)
                self.kb_collection = self.chroma_client.get_or_create_collection("cybersecurity_docs")
                print("[+] Security Assistant RAG Vector Store online.")
            except Exception as e:
                print(f"[!] ChromaDB Assistant Notice: {str(e)}")

    def _init_ai_client(self):
        api_key = os.getenv("GEMINI_API_KEY", "").strip().strip('"').strip("'")
        if api_key and HAS_GENAI:
            try:
                self.ai_client = genai.Client(api_key=api_key)
                print(f"[+] Security Assistant AI Client initialized.")
            except Exception as e:
                print(f"[!] Gemini Assistant Initialization Error: {str(e)}")
        elif HAS_GENAI:
            try:
                self.ai_client = genai.Client()
            except Exception:
                pass

    def seed_knowledge_base(self, documents: list, metadatas: list, ids: list):
        """Indexes knowledge base documents into ChromaDB for RAG context retrieval."""
        if self.kb_collection:
            try:
                self.kb_collection.upsert(documents=documents, metadatas=metadatas, ids=ids)
                print(f"[+] Seeded {len(ids)} knowledge base items into ChromaDB.")
            except Exception as e:
                print(f"[!] Error seeding ChromaDB: {str(e)}")

    def _get_static_fallback(self, query: str, rag_context: str = "") -> str:
        q = query.lower()
        for key, val in FALLBACK_KNOWLEDGE_MAP.items():
            if key in q:
                return val
        if rag_context:
            return f"### Security Knowledge Reference\n\n{rag_context}"
        return (
            "### SecurOS Security Advisory\n\n"
            "Query processed. Configure your `GEMINI_API_KEY` to enable unrestricted generative responses, "
            "or choose from one of the quick security directives above (OWASP, Active Directory, Zero Trust)."
        )

    def _call_gemini_fast(self, prompt: str, system_prompt: str, user_query: str = "", local_fallback: str = "") -> str:
        if not self.ai_client:
            self._init_ai_client()

        if self.ai_client:
            for model_id in DEFAULT_MODELS:
                try:
                    config = types.GenerateContentConfig(
                        system_instruction=system_prompt,
                        temperature=0.2,
                        max_output_tokens=3000
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

        return self._get_static_fallback(user_query, local_fallback)

    def explain_scan_telemetry(self, tool_type: str, scan_data: dict) -> str:
        system_prompt = (
            "You are an expert SOC Analyst in SecurOS. "
            "Quickly summarize the vulnerability, CVSS score, and provide exact CLI remediation commands."
        )
        prompt = f"Tool: {tool_type}\nRaw Telemetry Data:\n{scan_data}\n\nProvide rapid threat breakdown and remediation."
        return self._call_gemini_fast(prompt, system_prompt, user_query=tool_type)

    def query_cyber_knowledge(self, user_query: str) -> str:
        retrieved_docs = []
        retrieved_metas = []

        if self.kb_collection:
            try:
                results = self.kb_collection.query(
                    query_texts=[user_query],
                    n_results=3
                )
                if results and 'documents' in results and results['documents']:
                    retrieved_docs = results['documents'][0]
                    retrieved_metas = results['metadatas'][0] if 'metadatas' in results else []
            except Exception as e:
                print(f"[!] Vector store query error: {str(e)}")

        context_blocks = []
        for i, doc in enumerate(retrieved_docs):
            meta_info = f" [Source: {retrieved_metas[i].get('book', 'Internal Docs')}]" if i < len(retrieved_metas) else ""
            context_blocks.append(f"- {doc}{meta_info}")

        context_str = "\n".join(context_blocks) if context_blocks else ""

        system_prompt = (
            "You are the SecurOS AI Security Assistant. Answer cybersecurity questions comprehensively, "
            "with precise technical depth, structured headers, and CLI/defensive controls. "
            "Use the provided internal knowledge context when relevant."
        )
        prompt = f"Context from Knowledge Base:\n{context_str}\n\nUser Question: {user_query}" if context_str else f"User Question: {user_query}"
        
        return self._call_gemini_fast(prompt, system_prompt, user_query=user_query, local_fallback=context_str)