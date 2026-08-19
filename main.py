import asyncio
import json
import os
import queue
import threading
import time
import subprocess
import io
import socket
import psutil
from PIL import Image
from flask import Flask, jsonify, request, send_file, Response, stream_with_context
from flask_sock import Sock
from simple_websocket import ConnectionClosed

# Firebase Admin SDK & Firestore Imports
import firebase_admin
from firebase_admin import credentials, firestore

# Native Module Imports
from core.wireshark import WiresharkEngine
from core.nmap import NmapEngine
from core.fuzzer import FfufEngine
from core.nuclei import NucleiEngine
from core.assistant import SecurityAssistant
from core.jarvis import JarvisEngine
from core.reporter import ReportGenerator
from core.rules import default_rule_engine

app = Flask(__name__)
sock = Sock(app)

ACTIVE_SCANS = {}

sec_assistant = SecurityAssistant()
jarvis = JarvisEngine()

# ==========================================
# HTTP SECURITY HEADERS & CORS MIDDLEWARE
# ==========================================

@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        response = Response(status=200)
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS, PUT, DELETE"
        return response

@app.after_request
def set_security_headers(response):
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS, PUT, DELETE"
    return response

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
    if not db:
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
# 1. API STATUS / HEALTH ROUTE
# ==========================================

@app.get("/")
def index():
    return jsonify({
        "status": "online",
        "service": "SecurOS Threat Defense Suite Backend",
        "version": "2.0",
        "endpoints": {
            "websockets": ["/ws/nmap", "/ws/wireshark", "/ws/nuclei", "/ws/fuzzer"],
            "jarvis": "/api/jarvis/stream",
            "assistant": "/api/assistant/chat",
            "interfaces": "/api/wireshark/interfaces",
            "reports": "/api/reports/export-universal"
        }
    })

# ==========================================
# 2. ROBUST NETWORK INTERFACE DISCOVERY
# ==========================================

@app.get("/api/wireshark/interfaces")
def get_network_interfaces():
    adapters = []
    try:
        io_counters = psutil.net_io_counters(pernic=True) if hasattr(psutil, "net_io_counters") else {}
        addrs = psutil.net_if_addrs() if hasattr(psutil, "net_if_addrs") else {}
        stats = psutil.net_if_stats() if hasattr(psutil, "net_if_stats") else {}

        for nic_name, addr_list in addrs.items():
            ipv4 = "Unassigned"
            for a in addr_list:
                if getattr(a, "family", None) == socket.AF_INET:
                    ipv4 = a.address
                    break

            nic_stats = stats.get(nic_name)
            is_up = nic_stats.isup if nic_stats else True
            counters = io_counters.get(nic_name)
            bytes_sent = counters.bytes_sent if counters else 0
            bytes_recv = counters.bytes_recv if counters else 0

            is_live = is_up and (bytes_sent + bytes_recv > 0) and ipv4 not in ["Unassigned", "127.0.0.1"]

            adapters.append({
                "id": nic_name,
                "name": nic_name,
                "ip": ipv4,
                "is_up": is_up,
                "is_live": is_live,
                "bytes_recv": bytes_recv,
                "bytes_sent": bytes_sent
            })

        if not adapters:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            adapters = [
                {"id": "Default Adapter", "name": "Primary Adapter", "ip": local_ip, "is_up": True, "is_live": True, "bytes_recv": 1024, "bytes_sent": 1024},
                {"id": "Loopback", "name": "Loopback (127.0.0.1)", "ip": "127.0.0.1", "is_up": True, "is_live": False, "bytes_recv": 0, "bytes_sent": 0}
            ]

        adapters.sort(key=lambda x: (not x["is_live"], not x["is_up"], x["name"]))
        return jsonify({"status": "success", "interfaces": adapters})

    except Exception as e:
        hostname = socket.gethostname()
        try:
            local_ip = socket.gethostbyname(hostname)
        except Exception:
            local_ip = "127.0.0.1"

        return jsonify({
            "status": "success",
            "interfaces": [
                {"id": "Default Adapter", "name": "Default Network Adapter", "ip": local_ip, "is_up": True, "is_live": True, "bytes_recv": 100, "bytes_sent": 100},
                {"id": "127.0.0.1", "name": "Loopback", "ip": "127.0.0.1", "is_up": True, "is_live": False, "bytes_recv": 0, "bytes_sent": 0}
            ],
            "warning": str(e)
        })

# ==========================================
# 3. FIREBASE REST API ENDPOINTS
# ==========================================

@app.route("/api/history", methods=["GET"])
def get_firestore_history():
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
# 4. SECUROS & JARVIS AI DUAL REST API ENDPOINTS
# ==========================================

@app.route("/api/assistant/chat", methods=["POST", "OPTIONS"])
def assistant_chat_api():
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200

    payload = request.get_json() or {}
    query = payload.get("query", "").strip()
    if not query:
        return jsonify({"status": "error", "message": "Query string required."}), 400
    try:
        answer = sec_assistant.query_cyber_knowledge(query)
        return jsonify({"status": "success", "answer": answer})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/assistant/explain-scan", methods=["POST", "OPTIONS"])
def explain_scan():
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200

    payload = request.get_json() or {}
    tool = payload.get("tool", "Nmap")
    data = payload.get("data", {})
    explanation = sec_assistant.explain_scan_telemetry(tool, data)
    return jsonify({"status": "success", "explanation": explanation})

@app.route("/api/jarvis/stream", methods=["POST", "OPTIONS"])
def jarvis_stream_api():
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200

    data = request.get_json() or {}
    user_query = data.get("prompt") or data.get("query", "")
    history = data.get("history", [])
    telemetry = data.get("context") or data.get("telemetry", None)

    def generate():
        try:
            for token in jarvis.stream_chat(user_query, history, telemetry):
                yield token
        except Exception as e:
            yield f"[!] Stream error: {str(e)}"

    return Response(stream_with_context(generate()), mimetype="text/plain")

# ==========================================
# 5. DIGITAL STEGANOGRAPHY & FORENSICS API
# ==========================================

def text_to_bits(text):
    bits = []
    for char in text + '\x00':
        bin_char = format(ord(char), '08b')
        bits.extend([int(b) for b in bin_char])
    return bits

@app.route("/api/steg/encode", methods=["POST", "OPTIONS"])
def encode_steganography():
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200

    file = request.files.get('file') or request.files.get('image')
    message = request.form.get('message', '')

    if not file or not message:
        return jsonify({"status": "error", "message": "Missing image file or secret message payload."}), 400

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

        return send_file(img_io, mimetype='image/png', as_attachment=True, download_name='stego_carrier.png')
    except Exception as e:
        return jsonify({"status": "error", "message": f"Encoding failure: {str(e)}"}), 500

@app.route("/api/steg/decode", methods=["POST", "OPTIONS"])
def decode_steganography():
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200

    file = request.files.get('file') or request.files.get('image')
    if not file:
        return jsonify({"status": "error", "message": "No file uploaded."}), 400

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

        decoded_msg = "".join(chars)
        return jsonify({"status": "success", "message": decoded_msg if decoded_msg else "No secret message found in LSB."})
    except Exception as e:
        return jsonify({"status": "error", "message": f"Decoding failure: {str(e)}"}), 500

@app.route("/api/steg/analyze-plane", methods=["POST", "OPTIONS"])
def analyze_bit_plane():
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200

    file = request.files.get('file') or request.files.get('image')
    plane = int(request.form.get('plane', 0))
    if not file:
        return jsonify({"status": "error", "message": "No file uploaded."}), 400

    try:
        img = Image.open(file.stream).convert('RGB')
        width, height = img.size

        analysis_canvas = Image.new("L", (width, height))
        pixels = img.load()
        canvas_pixels = analysis_canvas.load()

        for y in range(height):
            for x in range(width):
                r, g, b = pixels[x, y]
                canvas_pixels[x, y] = 255 if ((r >> plane) & 1) == 1 else 0

        img_io = io.BytesIO()
        analysis_canvas.save(img_io, 'PNG')
        img_io.seek(0)

        return send_file(img_io, mimetype='image/png')
    except Exception as e:
        return jsonify({"status": "error", "message": f"Analysis failed: {str(e)}"}), 500

# ==========================================
# 6. ASYNCHRONOUS NMAP ENGINE WEBSOCKET ROUTE
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
                        "text": f"\n[!] Scan Finished with notice: {str(e)}\n"
                    }))
                    ws.send(json.dumps({
                        "type": "SCAN_COMPLETE",
                        "payload": {"target": target, "status": "failed", "summary": str(e), "ports": []}
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
            action = payload.get("action", "RUN_NMAP")

            if action == "RUN_NMAP" or ("target" in payload and action not in ["STOP_SCAN", "CANCEL_SCAN"]):
                target = payload.get("target", "127.0.0.1").strip()
                profile = payload.get("flags") or payload.get("profile", "-T4 -F")
                custom_ports = payload.get("custom_ports") or payload.get("ports", "1-1000")

                scan_thread = threading.Thread(
                    target=run_async_scan_loop,
                    args=(target, profile, custom_ports),
                    daemon=True
                )
                ACTIVE_SCANS[session_id] = scan_thread
                scan_thread.start()

            elif action in ["STOP_SCAN", "CANCEL_SCAN"]:
                if os.name == 'nt':
                    subprocess.run(["taskkill", "/F", "/IM", "nmap.exe"], capture_output=True)
                ws.send(json.dumps({
                    "type": "TERMINAL_LINE",
                    "text": "\n[!] Scan forcefully canceled.\n"
                }))
                ws.send(json.dumps({
                    "type": "SCAN_COMPLETE",
                    "payload": {"target": "", "status": "cancelled", "summary": "Cancelled", "ports": []}
                }))

        except ConnectionClosed:
            if os.name == 'nt':
                subprocess.run(["taskkill", "/F", "/IM", "nmap.exe"], capture_output=True)
            break
        except Exception:
            break

# ==========================================
# 7. WIRESHARK LIVE PACKET CAPTURE STREAM (NIDS INTEGRATED)
# ==========================================

@sock.route("/ws/wireshark")
def websocket_wireshark_endpoint(ws):
    packet_queue = queue.Queue(maxsize=20000)
    stop_event = threading.Event()
    stop_event.set()

    def socket_drain_loop():
        count = 0
        while not stop_event.is_set():
            try:
                raw_pkt = packet_queue.get(timeout=0.1)
                if isinstance(raw_pkt, dict):
                    inner = raw_pkt.get("packet") or raw_pkt.get("data") or raw_pkt.get("payload") or raw_pkt
                else:
                    inner = {}

                count += 1
                num = inner.get("num") or inner.get("number") or inner.get("no") or inner.get("id") or count
                pkt_time = inner.get("time") or inner.get("timestamp") or inner.get("ts") or time.strftime("%H:%M:%S")
                src = inner.get("src") or inner.get("source") or inner.get("src_ip") or inner.get("ip_src") or inner.get("source_ip") or "127.0.0.1"
                dst = inner.get("dst") or inner.get("destination") or inner.get("dst_ip") or inner.get("ip_dst") or inner.get("destination_ip") or "127.0.0.1"
                proto = inner.get("proto") or inner.get("protocol") or inner.get("layer") or "TCP"
                length = inner.get("len") or inner.get("length") or inner.get("size") or inner.get("bytes") or 64
                info = inner.get("info") or inner.get("summary") or inner.get("desc") or inner.get("description") or f"{proto} Packet {length} bytes"

                normalized = {
                    "num": int(num) if str(num).isdigit() else count,
                    "time": str(pkt_time),
                    "src": str(src),
                    "dst": str(dst),
                    "proto": str(proto).upper(),
                    "len": int(length) if str(length).isdigit() else 64,
                    "info": str(info)
                }

                # Evaluate live packet against Suricata/Snort Rules in rules.py
                nids_alerts = default_rule_engine.inspect_packet(normalized)
                if nids_alerts:
                    ws.send(json.dumps({"type": "NIDS_ALERT", "alerts": nids_alerts}))

                ws.send(json.dumps({"type": "PACKET", "packet": normalized}))
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
            action = payload.get("action", "START_CAPTURE")

            if action == "START_CAPTURE":
                interface = payload.get("interface")
                if not interface or interface in ["any", "All", "Default Adapter", "default"]:
                    interface = None
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

@app.route("/api/wireshark/export-pcap", methods=["GET"])
def export_captured_pcap():
    try:
        pcap_stream = WiresharkEngine.export_pcap_bytes()
        filename = f"secur_capture_{int(time.time())}.pcap"
        return send_file(
            pcap_stream,
            mimetype="application/vnd.tcpdump.pcap",
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        return jsonify({"status": "error", "message": f"PCAP Export Failed: {str(e)}"}), 500

# ==========================================
# 8. VAPT EXECUTIVE REPORT EXPORT ENDPOINTS
# ==========================================

@app.route("/api/reports/export-universal", methods=["POST", "OPTIONS"])
def export_universal_vapt_report():
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200

    data = request.get_json() or {}
    target = data.get("target", "127.0.0.1")
    tool = data.get("tool", "General")
    tool_data = data.get("data", [])
    output_format = data.get("format", "html")

    content = ReportGenerator.generate_unified_vapt_report(
        target=target,
        nmap_data=tool_data if tool == "Nmap" else {},
        nuclei_data=tool_data if tool == "Nuclei" else [],
        fuzz_data=tool_data if tool == "Fuzzer" else [],
        ai_analysis=data.get("ai_analysis", f"SecurOS Unified Report for {tool}"),
        output_format=output_format
    )

    mem_file = io.BytesIO(content.encode("utf-8"))
    ext = "html" if output_format == "html" else "md"
    mimetype = "text/html" if output_format == "html" else "text/markdown"
    filename = f"SecurOS_{tool}_Report_{int(time.time())}.{ext}"

    return send_file(
        mem_file,
        mimetype=mimetype,
        as_attachment=True,
        download_name=filename
    )

# ==========================================
# 9. WEBSOCKET ENDPOINTS FOR FFUF & NUCLEI
# ==========================================

@sock.route("/ws/fuzzer")
def websocket_fuzzer_endpoint(ws):
    while True:
        try:
            raw_data = ws.receive()
            if not raw_data:
                break
            payload = json.loads(raw_data)
            target = payload.get("url") or payload.get("target", "http://127.0.0.1:8000/FUZZ")
            wordlist = payload.get("wordlist")

            def run_fuzz_loop():
                new_loop = asyncio.new_event_loop()
                asyncio.set_event_loop(new_loop)
                async def run():
                    try:
                        async for event in FfufEngine.execute_fuzz_stream(target, wordlist):
                            if isinstance(event, dict):
                                r_data = event.get("data") or event.get("route") or event
                                normalized_route = {
                                    "url": r_data.get("url") or r_data.get("path") or target.replace("FUZZ", str(r_data.get("input", ""))),
                                    "status": r_data.get("status") or r_data.get("status_code") or r_data.get("code") or 200,
                                    "length": r_data.get("length") or r_data.get("size") or r_data.get("len") or 0
                                }
                                ws.send(json.dumps({"type": "ROUTE_DISCOVERED", "data": normalized_route}))
                            else:
                                ws.send(json.dumps(event))
                    except Exception as e:
                        ws.send(json.dumps({"type": "TERMINAL_LINE", "text": f"[!] Fuzzer Notice: {str(e)}"}))
                    finally:
                        ws.send(json.dumps({"type": "FUZZ_COMPLETE"}))
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
            target = payload.get("target", "http://127.0.0.1:8000")
            severity = payload.get("severity") or payload.get("templates", "cves,vulnerabilities")

            def run_nuclei_loop():
                new_loop = asyncio.new_event_loop()
                asyncio.set_event_loop(new_loop)
                async def run():
                    try:
                        async for event in NucleiEngine.execute_nuclei_stream(target, severity):
                            if isinstance(event, dict):
                                f_data = event.get("data") or event.get("finding") or event
                                normalized_finding = {
                                    "template": f_data.get("template") or f_data.get("template_id") or f_data.get("id") or f_data.get("name") or "CVE-Generic",
                                    "severity": (f_data.get("severity") or f_data.get("level") or "Medium").capitalize(),
                                    "url": f_data.get("url") or f_data.get("matched") or f_data.get("host") or target
                                }
                                ws.send(json.dumps({"type": "FINDING", "data": normalized_finding}))
                            else:
                                ws.send(json.dumps(event))
                    except Exception as e:
                        ws.send(json.dumps({"type": "TERMINAL_LINE", "text": f"[!] Nuclei Notice: {str(e)}"}))
                    finally:
                        ws.send(json.dumps({"type": "NUCLEI_COMPLETE"}))
                new_loop.run_until_complete(run())
                new_loop.close()

            threading.Thread(target=run_nuclei_loop, daemon=True).start()
        except ConnectionClosed:
            break
        except Exception:
            break

# ==========================================
# 10. PRODUCTION DYNAMIC ENTRY POINT
# ==========================================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("HOST", "0.0.0.0")
    print(f"[*] SecurOS Engine Booting on {host}:{port}...")
    app.run(host=host, port=port, debug=False, use_reloader=False)