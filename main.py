import asyncio
import json
import os
import queue
import threading
import time
import subprocess
from flask import Flask, jsonify, render_template, request, send_from_directory
from flask_sock import Sock
from simple_websocket import ConnectionClosed

# Native Module Imports matching your exact workspace file layout
from core.wireshark import WiresharkEngine
from core.nmap import NmapEngine

app = Flask(__name__, template_folder="templates")
sock = Sock(app)

# Global tracking matrix to isolate running process thread handles
ACTIVE_SCANS = {}

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
    return render_template("dashboard.html")


# ==========================================
# 2. ASYNCHRONOUS NMAP ENGINE WEBSOCKET ROUTE
# ==========================================

@sock.route("/ws/nmap")
def websocket_nmap_endpoint(ws):
    """
    Handles live duplex Nmap visualization streams. Runs the core asynchronous
    generator loop inside an isolated background event matrix thread context.
    """
    session_id = str(id(ws))

    def run_async_scan_loop(target, profile, custom_ports):
        async def run_generator():
            try:
                # Intercepts streaming yields directly from your core/nmap.py script
                async for event in NmapEngine.execute_scan_stream(target, profile, custom_ports):
                    ws.send(json.dumps(event))
            except Exception as e:
                try:
                    ws.send(json.dumps({
                        "type": "TERMINAL_LINE", 
                        "text": f"\n[!] Scan Finished with structural bounds: {str(e)}\n"
                    }))
                except Exception:
                    pass
            finally:
                # GUARANTEED EXIT SIGNAL: Forces the frontend out of a looping state no matter what
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
                    # FIXED: Added taskkill target for nuclei.exe to clear both pipelines completely
                    subprocess.run(["taskkill", "/F", "/IM", "nmap.exe"], capture_output=True)
                    subprocess.run(["taskkill", "/F", "/IM", "nuclei.exe"], capture_output=True)
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
                subprocess.run(["taskkill", "/F", "/IM", "nuclei.exe"], capture_output=True)
            break
        except Exception:
            break


# ==========================================
# 3. INTERFACE DISCOVERY API ENDPOINT
# ==========================================

@app.get("/api/wireshark/interfaces")
def get_network_interfaces():
    """Natively queries active driver objects discovered by Scapy layers."""
    return jsonify(WiresharkEngine.get_interfaces())


# ==========================================
# 4. LIVE WEBSOCKET PACKET CAPTURE STREAM
# ==========================================

@sock.route("/ws/wireshark")
def websocket_wireshark_endpoint(ws):
    """Handles duplex packet transactions between Scapy and the UI layer."""
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

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=True, use_reloader=False)
