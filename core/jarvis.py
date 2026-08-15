import os
import json
import time
from google import genai
from google.genai import types

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

# Fast, high-throughput free-tier models
FAST_FREE_MODELS = [
    'gemini-2.5-flash',
    'gemini-2.5-flash-lite',
    'gemini-flash-latest'
]

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
        if api_key:
            try:
                self.ai_client = genai.Client(api_key=api_key)
                print(f"[+] JARVIS High-Speed Copilot Engine configured (Primary: {FAST_FREE_MODELS[0]}).")
            except Exception as e:
                print(f"[!] JARVIS GenAI Initialization Error: {str(e)}")
        else:
            try:
                self.ai_client = genai.Client()
            except Exception:
                print("[!] Warning: GEMINI_API_KEY environment variable is not set for JARVIS.")

    def retrieve_context(self, query: str, top_k: int = 1) -> str:
        """Fast Top-1 Vector retrieval for minimal prompt latency."""
        if not self.collection:
            return ""
        try:
            results = self.collection.query(query_texts=[query], n_results=top_k)
            docs = results.get("documents", [[]])[0]
            if docs:
                return f"\n--- RELEVANT KNOWLEDGE (RAG) ---\n{docs[0]}\n--------------------------------\n"
        except Exception:
            pass
        return ""

    def stream_chat(self, prompt: str, history: list = None, telemetry_data: dict = None):
        """Zero-latency streaming generator with thinking_budget=0 for instant first-token output."""
        if not self.ai_client:
            self._init_client()
            if not self.ai_client:
                yield "JARVIS Engine Offline: `GEMINI_API_KEY` is missing. Set it in PowerShell with:\n`$env:GEMINI_API_KEY=\"AIzaSy...\"`"
                return

        rag_context = self.retrieve_context(prompt)
        
        full_prompt = ""
        if telemetry_data:
            full_prompt += f"--- ACTIVE PACKET TELEMETRY BUFFER ---\n{json.dumps(telemetry_data, indent=2)}\n\n"
        if rag_context:
            full_prompt += f"{rag_context}\n\n"
            
        full_prompt += f"User Query: {prompt}"

        # Disabling thinking_budget eliminates the preliminary thinking delay for instant responses
        fast_config = types.GenerateContentConfig(
            system_instruction=JARVIS_SYSTEM_PROMPT,
            temperature=0.2,
            max_output_tokens=2048,
            thinking_config=types.ThinkingConfig(thinking_budget=0)
        )

        generated_text = ""
        last_error = ""

        for model_name in FAST_FREE_MODELS:
            try:
                current_query = full_prompt
                if generated_text:
                    current_query += f"\n\n[SYSTEM NOTE: Seamlessly continue writing from where it stopped without repeating]:\n{generated_text[-400:]}"

                response_stream = self.ai_client.models.generate_content_stream(
                    model=model_name,
                    contents=current_query,
                    config=fast_config
                )

                streamed_any = False
                for chunk in response_stream:
                    if chunk and chunk.text:
                        streamed_any = True
                        generated_text += chunk.text
                        yield chunk.text  # Immediate yield with no sleep delay

                if streamed_any:
                    return

            except Exception as e:
                last_error = str(e)
                # Fallback config without thinking_budget if model does not accept it
                try:
                    fallback_config = types.GenerateContentConfig(
                        system_instruction=JARVIS_SYSTEM_PROMPT,
                        temperature=0.2
                    )
                    response_stream = self.ai_client.models.generate_content_stream(
                        model=model_name,
                        contents=full_prompt,
                        config=fallback_config
                    )
                    for chunk in response_stream:
                        if chunk and chunk.text:
                            generated_text += chunk.text
                            yield chunk.text
                    return
                except Exception:
                    continue

        if rag_context and not generated_text:
            yield f"[⚠️ Instant Local RAG Knowledge Output]:\n\n{rag_context}"
        elif not generated_text:
            yield f"[!] Cloud API Notice: {last_error}"