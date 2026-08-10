from core.assistant import SecurityAssistant

assistant = SecurityAssistant()

book_knowledge = [
    # -------------------------------------------------------------
    # 1. PENETRATION TESTING (Georgia Weidman) - Methodology & VAPT
    # -------------------------------------------------------------
    {
        "id": "weidman_01",
        "book": "Penetration Testing - Georgia Weidman",
        "category": "VAPT Methodology",
        "doc": "PTES Penetration Testing Execution Standard Stages: 1. Pre-engagement Interactions 2. Intelligence Gathering 3. Threat Modeling 4. Vulnerability Analysis 5. Exploitation 6. Post-Exploitation 7. Reporting."
    },
    {
        "id": "weidman_02",
        "book": "Penetration Testing - Georgia Weidman",
        "category": "Reconnaissance",
        "doc": "Nmap Scanning Strategy: Perform host discovery (-sn) first to map live IPs. Follow with TCP SYN scan (-sS) and service version detection (-sV). Use -p- for full port coverage and default scripts (-sC) for vulnerability surface mapping."
    },

    # -------------------------------------------------------------
    # 2. BLACK HAT PYTHON 2nd Ed (Justin Seitz) - Tool Dev & Exploit Logic
    # -------------------------------------------------------------
    {
        "id": "seitz_01",
        "book": "Black Hat Python 2nd Ed - Justin Seitz",
        "category": "Tool Development",
        "doc": "Network Sniffing in Python: Using Scapy or raw sockets (socket.AF_INET, socket.SOCK_RAW) allows capturing raw IP and ICMP headers. Packet parsing parses byte streams to extract protocol headers (IP, TCP, UDP)."
    },
    {
        "id": "seitz_02",
        "book": "Black Hat Python 2nd Ed - Justin Seitz",
        "category": "Web Security",
        "doc": "Web Fuzzing & Directory Brute-Forcing: Issues HTTP GET/POST requests substituting keywords (FUZZ) with wordlist dictionaries. Filters 404 status codes to discover exposed endpoints (200 OK, 301 Redirect, 403 Forbidden)."
    },

    # -------------------------------------------------------------
    # 3. BLUE TEAM HANDBOOK (Don Murdoch) - SOC, SIEM & Mitigation
    # -------------------------------------------------------------
    {
        "id": "murdoch_01",
        "book": "Blue Team Handbook - Don Murdoch",
        "category": "Incident Response",
        "doc": "Incident Response Lifecycle (PICERL): Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned. Containment isolates affected systems (firewall block rules, network segmentation) to stop lateral movement."
    },
    {
        "id": "murdoch_02",
        "book": "Blue Team Handbook - Don Murdoch",
        "category": "SIEM & Log Analysis",
        "doc": "SIEM Correlation Rules: Monitor web server logs for high frequency 404 responses (indicates directory fuzzing/scanning) or 401/403 status codes (indicates brute-force authentication attacks)."
    }
]

documents = [item["doc"] for item in book_knowledge]
metadatas = [{"book": item["book"], "category": item["category"]} for item in book_knowledge]
ids = [item["id"] for item in book_knowledge]

print("[*] Seeding Knowledge Base with book concepts from Georgia Weidman, Justin Seitz, and Don Murdoch...")
assistant.seed_knowledge_base(documents=documents, metadatas=metadatas, ids=ids)
print("[+] Knowledge Base successfully seeded!")