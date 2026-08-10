import os
import chromadb
from google import genai

class SecurityAssistant:
    def __init__(self):
        # Initializes client using environment variable GEMINI_API_KEY if present,
        # or defaults gracefully if not initialized.
        self.ai_client = None
        try:
            self.ai_client = genai.Client()
        except Exception as e:
            print(f"[!] Warning: Gemini API Client not initialized ({str(e)}). Ensure GEMINI_API_KEY is set.")
        
        # Local persistent vector database
        self.chroma_client = chromadb.PersistentClient(path="./cyber_kb")
        self.kb_collection = self.chroma_client.get_or_create_collection("cybersecurity_docs")

    def seed_knowledge_base(self, documents: list, metadatas: list, ids: list):
        """Populates local ChromaDB with domain knowledge."""
        self.kb_collection.add(
            documents=documents,
            metadatas=metadatas,
            ids=ids
        )

    def explain_scan_telemetry(self, tool_type: str, scan_data: dict) -> str:
        """Analyzes scan outputs and generates structured threat explanations and mitigations."""
        if not self.ai_client:
            return "Gemini API client uninitialized. Please configure your GEMINI_API_KEY environment variable."

        system_prompt = (
            "You are an expert SOC Analyst and Cyber Assistant in SecurOS. "
            "Analyze raw scan outputs, assess threat levels, explain vulnerabilities, "
            "and provide exact CLI remediation commands (e.g., firewall rules, patch commands)."
        )
        
        prompt = f"Tool: {tool_type}\nRaw Telemetry Data:\n{scan_data}\n\nExplain findings and remediation steps."
        
        try:
            response = self.ai_client.models.generate_content(
                model='gemini-2.5-flash',
                contents=prompt,
                config={'system_instruction': system_prompt}
            )
            return response.text
        except Exception as e:
            return f"Error processing telemetry: {str(e)}"

    def query_cyber_knowledge(self, user_query: str) -> str:
        """Queries vector database (RAG) and combines context with LLM inference."""
        retrieved_docs = []
        try:
            results = self.kb_collection.query(
                query_texts=[user_query],
                n_results=2
            )
            if results and 'documents' in results and results['documents']:
                retrieved_docs = results['documents'][0]
        except Exception as e:
            print(f"[!] Vector store query error: {str(e)}")

        context_str = "\n---\n".join(retrieved_docs) if retrieved_docs else "No specific internal docs found."

        if not self.ai_client:
            if retrieved_docs:
                return f"[RAG Knowledge Base Context]:\n{context_str}\n\n(Note: Set GEMINI_API_KEY for full AI responses)."
            return "No information found in local KB. Set GEMINI_API_KEY for AI query processing."

        system_prompt = (
            "You are the SecurOS AI Security Assistant. Answer cybersecurity questions clearly. "
            "Use the provided internal knowledge context when relevant to ground your answers."
        )

        prompt = f"Context from Knowledge Base:\n{context_str}\n\nUser Question: {user_query}"

        try:
            response = self.ai_client.models.generate_content(
                model='gemini-2.5-flash',
                contents=prompt,
                config={'system_instruction': system_prompt}
            )
            return response.text
        except Exception as e:
            return f"Error processing query: {str(e)}"