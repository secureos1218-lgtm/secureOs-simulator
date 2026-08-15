import os
import time
from google import genai
from google.genai import types

try:
    import chromadb
    HAS_CHROMA = True
except ImportError:
    HAS_CHROMA = False

FAST_FREE_MODELS = [
    'gemini-2.5-flash',
    'gemini-2.5-flash-lite',
    'gemini-flash-latest'
]

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
        if api_key:
            try:
                self.ai_client = genai.Client(api_key=api_key)
                print(f"[+] Security Assistant High-Speed Client initialized (Using: {FAST_FREE_MODELS[0]}).")
            except Exception as e:
                print(f"[!] Gemini Assistant Initialization Error: {str(e)}")
        else:
            try:
                self.ai_client = genai.Client()
            except Exception:
                print("[!] Warning: GEMINI_API_KEY environment variable is not set.")

    def seed_knowledge_base(self, documents: list, metadatas: list, ids: list):
        """Populates or updates local ChromaDB with domain knowledge from seed_kb.py."""
        if not self.kb_collection:
            return
        try:
            self.kb_collection.upsert(
                documents=documents,
                metadatas=metadatas,
                ids=ids
            )
            print(f"[+] Successfully seeded {len(ids)} documents into ChromaDB Vector Store.")
        except Exception as e:
            print(f"[!] Vector store seed error: {str(e)}")

    def _call_gemini_fast(self, prompt: str, system_prompt: str, local_fallback: str = "") -> str:
        if not self.ai_client:
            self._init_ai_client()
            if not self.ai_client:
                return local_fallback or "Gemini API client uninitialized. Configure your `GEMINI_API_KEY`."

        # Zero-latency configuration: disable thinking budget and limit token overhead
        fast_config = types.GenerateContentConfig(
            system_instruction=system_prompt,
            temperature=0.2,
            max_output_tokens=1500,
            thinking_config=types.ThinkingConfig(thinking_budget=0)
        )

        last_error = ""
        for model_id in FAST_FREE_MODELS:
            try:
                response = self.ai_client.models.generate_content(
                    model=model_id,
                    contents=prompt,
                    config=fast_config
                )
                if response and response.text:
                    return response.text
            except Exception as e:
                last_error = str(e)
                try:
                    # Fallback config without thinking_budget if not supported
                    response = self.ai_client.models.generate_content(
                        model=model_id,
                        contents=prompt,
                        config=types.GenerateContentConfig(system_instruction=system_prompt)
                    )
                    if response and response.text:
                        return response.text
                except Exception:
                    continue

        if local_fallback:
            return f"[⚠️ Fast Local RAG Output]:\n\n{local_fallback}"
        return f"Error processing query: {last_error}"

    def explain_scan_telemetry(self, tool_type: str, scan_data: dict) -> str:
        system_prompt = (
            "You are an expert SOC Analyst in SecurOS. "
            "Quickly summarize the vulnerability, CVSS score, and provide 1-2 exact CLI remediation commands."
        )
        prompt = f"Tool: {tool_type}\nRaw Telemetry Data:\n{scan_data}\n\nProvide rapid threat breakdown and remediation."
        return self._call_gemini_fast(prompt, system_prompt)

    def query_cyber_knowledge(self, user_query: str) -> str:
        retrieved_docs = []
        retrieved_metas = []

        if self.kb_collection:
            try:
                results = self.kb_collection.query(
                    query_texts=[user_query],
                    n_results=2
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

        context_str = "\n".join(context_blocks) if context_blocks else "No specific internal textbook knowledge found."

        system_prompt = (
            "You are the SecurOS AI Security Assistant. Answer cybersecurity questions concisely and clearly. "
            "Use the provided internal knowledge context when relevant to ground your answers."
        )
        prompt = f"Context from Knowledge Base:\n{context_str}\n\nUser Question: {user_query}"
        
        return self._call_gemini_fast(prompt, system_prompt, local_fallback=context_str)