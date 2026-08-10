import asyncio
import json
import os
import queue
import threading
import time
import subprocess
import io
from PIL import Image
from flask import Flask, jsonify, render_template, request, send_file, send_from_directory
from flask_sock import Sock
from simple_websocket import ConnectionClosed

# Firebase Admin SDK & Firestore Imports
import firebase_admin
from firebase_admin import credentials, firestore

# Native Module Imports matching workspace file layout
from core.wireshark import WiresharkEngine
from core.nmap import NmapEngine
from core.fuzzer import FfufEngine
from core.nuclei import NucleiEngine
from core.assistant import SecurityAssistant

app = Flask(__name__, template_folder="templates")
sock = Sock(app)

# Global tracking matrix to isolate running process thread handles
ACTIVE_SCANS = {}

# Initialize SecurOS AI Assistant Engine
sec_assistant = SecurityAssistant()

# ==========================================
# 0. SAFE FIREBASE FIRESTORE INITIALIZATION
# ==========================================

db = None
KEY_FILE = "firebase_key.json"

if os.path.exists(KEY_FILE):
    try:
        if not firebase_admin._apps:
            cred = credentials.Certificate(KEY_FILE)
            firebase_admin.initialize_app(cred)
        db = firestore.client()
        print("[+] Firebase Firestore successfully bound to application workspace.")
    except Exception as e:
        print(f"[!] Firebase Initialization Error: {str(e)}")
else:
    print(f"[!] Warning: '{KEY_FILE}' not found. Firestore cloud logging is disabled.")

def save_scan_to_firestore(target, profile, ports_data):
    """
    Asynchronously writes completed Nmap scan telemetry directly into the 
    Google Cloud Firestore 'scan_history' document collection.
    """
    if not db:
        print("[!] Skipping Firestore sync: Database client is uninitialized.")
        return

    try:
        doc_ref = db.collection("scan_history").document()
        doc_ref.set({
            "target": target,
            "profile": profile,
            "timestamp": firestore.SERVER_TIMESTAMP,
            "discovered_ports": ports_data,
            "status": "COMPLETED"
        })
        print(f"[+] Scan record successfully synced to Firestore cloud: {doc_ref.id}")
    except Exception as e:
        print(f"[!] Firestore cloud sync error: {str(e)}")


# ==========================================
# 1. FRONTEND WORKSPACE PAGE RENDERS
# ==========================================

@app.get("/")
def index():
    """Renders the central Nmap Network Scanner control hub view."""
    return render_template("components/nmap_ui.html")

@app.get("/wireshark")
def wireshark_ui_panel():
    """Renders the synchronized, high-fidelity Wireshark analysis panel."""
    return render_template("components/wireshark_ui.html")

@app.get("/dashboard")
def security_dashboard_view():
    """Renders the comprehensive SecurOS Telemetry Security Dashboard."""
    return render_template("dashboard_ui.html")

@app.get("/steg")
def steganography_ui_view():
    """Renders the Digital Steganography & Data Hiding Laboratory panel."""
    return render_template("components/steg_ui.html")

@app.get("/fuzzer")
def fuzzer_ui_view():
    """Renders the FFUF Web Fuzzer directory brute-forcing panel."""
    return render_template("components/fuzzer_ui.html")

@app.get("/nuclei")
def nuclei_ui_view():
    """Renders the Nuclei Vulnerability Scanner control panel."""
    return render_template("components/nuclei_ui.html")


# ==========================================
# 2. FIREBASE REST API ENDPOINTS
# ==========================================

@app.route("/api/history", methods=["GET"])
def get_firestore_history():
    """
    Fetches the top 20 most recent scan history documents from 
    Firebase Firestore ordered chronologically.
    """
    if not db:
        return jsonify({"status": "error", "message": "Firestore client not initialized."}), 500

    try:
        scans_ref = db.collection("scan_history").order_by("timestamp", direction=firestore.Query.DESCENDING).limit(20)
        docs = scans_ref.stream()
        
        history = []
        for doc in docs:
            data = doc.to_dict()
            if data.get("timestamp"):
                data["timestamp"] = data["timestamp"].isoformat() if hasattr(data["timestamp"], 'isoformat') else str(data["timestamp"])
            history.append(data)
            
        return jsonify({"status": "success", "history": history})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ==========================================
# 3. SECUROS AI ASSISTANT REST API ENDPOINTS
# ==========================================

@app.route("/api/assistant/explain-scan", methods=["POST"])
def explain_scan():
    """Receives active scan payloads and generates AI risk summaries and mitigation guides."""
    payload = request.get_json() or {}
    tool = payload.get("tool", "Nmap")
    data = payload.get("data", {})
    
    explanation = sec_assistant.explain_scan_telemetry(tool, data)
    return jsonify({"status": "success", "explanation": explanation})

@app.route("/api/assistant/chat", methods=["POST"])
def chat_assistant():
    """Processes user questions against ChromaDB RAG Vector Store and Gemini LLM."""
    payload = request.get_json() or {}
    query = payload.get("query", "")
    
    if not query:
        return jsonify({"status": "error", "message": "Query string required."}), 400
        
    answer = sec_assistant.query_cyber_knowledge(query)
    return jsonify({"status": "success", "answer": answer})


# ==========================================
# 4. DIGITAL STEGANOGRAPHY & FORENSICS API
# ==========================================

def text_to_bits(text):
    """Converts a string into binary bits with a null byte terminator."""
    bits = []
    for char in text + '\x00':
        bin_char = format(ord(char), '08b')
        bits.extend([int(b) for b in bin_char])
    return bits

@app.route("/api/steg/encode", methods=["POST"])
def encode_steganography():
    """LSB Steganography Encoder: Embeds hidden message inside pixel color channels."""
    if 'file' not in request.files or 'message' not in request.form:
        return jsonify({"status": "error", "message": "Missing file or message payload."}), 400
        
    file = request.files['file']
    message = request.form['message']
    
    try:
        img = Image.open(file.stream).convert('RGB')
        pixels = list(img.getdata())
        bits = text_to_bits(message)
        
        if len(bits) > len(pixels) * 3:
            return jsonify({"status": "error", "message": "Message exceeds total pixel capacity."}), 400
            
        new_pixels = []
        bit_index = 0
        
        for pixel in pixels:
            r, g, b = pixel
            if bit_index < len(bits):
                r = (r & ~1) | bits[bit_index]
                bit_index += 1
            if bit_index < len(bits):
                g = (g & ~1) | bits[bit_index]
                bit_index += 1
            if bit_index < len(bits):
                b = (b & ~1) | bits[bit_index]
                bit_index += 1
            new_pixels.append((r, g, b))
            
        out_img = Image.new(img.mode, img.size)
        out_img.putdata(new_pixels)
        
        img_io = io.BytesIO()
        out_img.save(img_io, 'PNG')
        img_io.seek(0)
        
        return send_file(img_io, mimetype='image/png', as_attachment=True, download_name='steg_carrier.png')
    except Exception as e:
        return jsonify({"status": "error", "message": f"Encoding failure: {str(e)}"}), 500

@app.route("/api/steg/decode", methods=["POST"])
def decode_steganography():
    """LSB Steganography Decoder: Carves hidden strings out of image pixels."""
    if 'file' not in request.files:
        return jsonify({"status": "error", "message": "No file detected."}), 400
        
    file = request.files['file']
    try:
        img = Image.open(file.stream).convert('RGB')
        pixels = list(img.getdata())
        
        extracted_bits = [str(color_channel & 1) for pixel in pixels for color_channel in pixel]
                
        chars = []
        for i in range(0, len(extracted_bits), 8):
            byte_str = "".join(extracted_bits[i:i+8])
            if len(byte_str) < 8: 
                break
            char_code = int(byte_str, 2)
            if char_code == 0: 
                break
            chars.append(chr(char_code))
            
        return jsonify({"status": "success", "message": "".join(chars)})
    except Exception as e:
        return jsonify({"status": "error", "message": f"Decoding failure: {str(e)}"}), 500

@app.route("/api/steg/analyze-plane", methods=["POST"])
def analyze_bit_plane():
    """Isolates the 0th bit-plane to visually map LSB distortion footprints."""
    if 'file' not in request.files:
        return jsonify({"status": "error", "message": "No file detected."}), 400
        
    file = request.files['file']
    try:
        img = Image.open(file.stream).convert('RGB')
        width, height = img.size
        
        analysis_canvas = Image.new("L", (width, height))
        pixels = img.load()
        canvas_pixels = analysis_canvas.load()
        
        for y in range(height):
            for x in range(width):
                r, g, b = pixels[x, y]
                canvas_pixels[x, y] = 255 if (r & 1) == 1 else 0
                
        img_io = io.BytesIO()
        analysis_canvas.save(img_io, 'PNG')
        img_io.seek(0)
        
        return send_file(img_io, mimetype='image/png')
    except Exception as e:
        return jsonify({"status": "error", "message": f"Analysis failed: {str(e)}"}), 500


# ==========================================
# 5. ASYNCHRONOUS NMAP ENGINE WEBSOCKET ROUTE
# ==========================================

@sock.route("/ws/nmap")
def websocket_nmap_endpoint(ws):
    session_id = str(id(ws))

    def run_async_scan_loop(target, profile, custom_ports):
        async def run_generator():
            try:
                async for event in NmapEngine.execute_scan_stream(target, profile, custom_ports):
                    ws.send(json.dumps(event))
                    
                    if event.get("type") == "SCAN_COMPLETE":
                        payload = event.get("payload", {})
                        if payload.get("status") == "success":
                            save_scan_to_firestore(
                                target=payload.get("target", target),
                                profile=profile,
                                ports_data=payload.get("ports", [])
                            )
            except Exception as e:
                try:
                    ws.send(json.dumps({
                        "type": "TERMINAL_LINE", 
                        "text": f"\n[!] Scan Finished with structural bounds: {str(e)}\n"
                    }))
                except Exception:
                    pass
            finally:
                try:
                    ws.send(json.dumps({
                        "type": "SCAN_COMPLETE", 
                        "payload": {"target": target, "status": "failed", "summary": "Scan cycle finalized.", "ports": []}
                    }))
                except Exception:
                    pass

        new_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(new_loop)
        try:
            new_loop.run_until_complete(run_generator())
            new_loop.run_until_complete(asyncio.sleep(0.1))
        finally:
            new_loop.run_until_complete(new_loop.shutdown_asyncgens())
            new_loop.close()
            if session_id in ACTIVE_SCANS:
                del ACTIVE_SCANS[session_id]

    while True:
        try:
            raw_data = ws.receive()
            if not raw_data:
                break
                
            payload = json.loads(raw_data)
            action = payload.get("action")
            
            if action == "RUN_NMAP":
                target = payload.get("target", "127.0.0.1").strip()
                profile = payload.get("profile", "QUICK_SCAN")
                custom_ports = payload.get("custom_ports") or payload.get("ports")
                
                scan_thread = threading.Thread(
                    target=run_async_scan_loop,
                    args=(target, profile, custom_ports),
                    daemon=True
                )
                ACTIVE_SCANS[session_id] = scan_thread
                scan_thread.start()
                
            elif action == "STOP_SCAN" or action == "CANCEL_SCAN":
                if os.name == 'nt':
                    subprocess.run(["taskkill", "/F", "/IM", "nmap.exe"], capture_output=True)
                ws.send(json.dumps({
                    "type": "TERMINAL_LINE", 
                    "text": "\n[!] Scan forcefully canceled. Pipeline process tree terminated.\n"
                }))
                ws.send(json.dumps({
                    "type": "SCAN_COMPLETE", 
                    "payload": {"target": "", "status": "failed", "summary": "Cancelled", "ports": []}
                }))
                
        except ConnectionClosed:
            if os.name == 'nt':
                subprocess.run(["taskkill", "/F", "/IM", "nmap.exe"], capture_output=True)
            break
        except Exception:
            break


# ==========================================
# 6. WIRESHARK REST API ENDPOINTS
# ==========================================

@app.get("/api/wireshark/interfaces")
def get_network_interfaces():
    return jsonify(WiresharkEngine.get_interfaces())


# ==========================================
# 7. LIVE WEBSOCKET PACKET CAPTURE STREAM
# ==========================================

@sock.route("/ws/wireshark")
def websocket_wireshark_endpoint(ws):
    packet_queue = queue.Queue(maxsize=20000)
    stop_event = threading.Event()
    stop_event.set()

    def socket_drain_loop():
        while not stop_event.is_set():
            try:
                packet_data = packet_queue.get(timeout=0.1)
                ws.send(json.dumps(packet_data))
            except queue.Empty:
                continue
            except Exception:
                break

    while True:
        try:
            raw_data = ws.receive()
            if not raw_data:
                break
                
            payload = json.loads(raw_data)
            action = payload.get("action")
            
            if action == "START_CAPTURE":
                interface = payload.get("interface", "any")
                display_filter = payload.get("filter", "").strip()
                
                if stop_event.is_set():
                    stop_event.clear()
                    packet_queue.queue.clear()
                    
                    sniffer_thread = threading.Thread(
                        target=WiresharkEngine.capture_packets_sync,
                        args=(interface, 0, packet_queue, stop_event, display_filter if display_filter else None),
                        daemon=True
                    )
                    sniffer_thread.start()
                    
                    sender_thread = threading.Thread(target=socket_drain_loop, daemon=True)
                    sender_thread.start()
                    
            elif action == "STOP_CAPTURE":
                stop_event.set()
                ws.send(json.dumps({"type": "CAPTURE_STOPPED"}))
                
        except ConnectionClosed:
            stop_event.set()
            break
        except Exception:
            stop_event.set()
            break


# ==========================================
# 8. WEBSOCKET ENDPOINTS FOR FFUF & NUCLEI
# ==========================================

@sock.route("/ws/fuzzer")
def websocket_fuzzer_endpoint(ws):
    while True:
        try:
            raw_data = ws.receive()
            if not raw_data:
                break
            payload = json.loads(raw_data)
            if payload.get("action") == "RUN_FUZZ":
                target = payload.get("target", "http://127.0.0.1:8000/FUZZ")
                wordlist = payload.get("wordlist")

                def run_fuzz_loop():
                    new_loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(new_loop)
                    async def run():
                        try:
                            async for event in FfufEngine.execute_fuzz_stream(target, wordlist):
                                ws.send(json.dumps(event))
                        except Exception as e:
                            ws.send(json.dumps({"type": "TERMINAL_LINE", "text": f"[!] Error: {str(e)}"}))
                            ws.send(json.dumps({"type": "FUZZ_COMPLETE", "payload": {"status": "error"}}))
                    new_loop.run_until_complete(run())
                    new_loop.close()

                threading.Thread(target=run_fuzz_loop, daemon=True).start()
        except ConnectionClosed:
            break
        except Exception:
            break

@sock.route("/ws/nuclei")
def websocket_nuclei_endpoint(ws):
    while True:
        try:
            raw_data = ws.receive()
            if not raw_data:
                break
            payload = json.loads(raw_data)
            if payload.get("action") == "RUN_NUCLEI":
                target = payload.get("target")
                severity = payload.get("severity")

                def run_nuclei_loop():
                    new_loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(new_loop)
                    async def run():
                        try:
                            async for event in NucleiEngine.execute_nuclei_stream(target, severity):
                                ws.send(json.dumps(event))
                        except Exception as e:
                            ws.send(json.dumps({"type": "TERMINAL_LINE", "text": f"[!] Error: {str(e)}"}))
                            ws.send(json.dumps({"type": "NUCLEI_COMPLETE", "payload": {"status": "error"}}))
                    new_loop.run_until_complete(run())
                    new_loop.close()

                threading.Thread(target=run_nuclei_loop, daemon=True).start()
        except ConnectionClosed:
            break
        except Exception:
            break

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=True, use_reloader=False)
