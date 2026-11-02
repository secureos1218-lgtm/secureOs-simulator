import asyncio
import json
import os
import re
import shutil
import socket
import tempfile
import time
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

class NmapEngine:
    TARGET_VALIDATION_REGEX = r"^[a-zA-Z0-9\.\:\-\/\s\,]+$"

    COMMON_NMAP_PATHS = [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
        r"C:\Nmap\nmap.exe",
        "/usr/bin/nmap",
        "/usr/local/bin/nmap",
    ]

    COMMON_PORT_SERVICES = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 110: "pop3", 135: "msrpc", 139: "netbios-ssn",
        143: "imap", 443: "https", 445: "microsoft-ds", 993: "imaps",
        995: "pop3s", 1433: "ms-sql-s", 1521: "oracle", 3000: "http",
        3306: "mysql", 3389: "ms-wbt-server", 5000: "http", 5432: "postgresql",
        5900: "vnc", 6379: "redis", 8000: "http", 8080: "http-proxy",
        8443: "https-alt", 8888: "http", 9000: "http", 9200: "elasticsearch",
        27017: "mongodb"
    }

    @classmethod
    def find_nmap_binary(cls) -> str:
        found = shutil.which("nmap")
        if found:
            return found
        for p in cls.COMMON_NMAP_PATHS:
            if os.path.isfile(p):
                return p
        return None

    @staticmethod
    def _get_source_ip() -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return "127.0.0.1"

    @classmethod
    def clean_target(cls, target: str) -> str:
        raw = target.strip()
        if "://" in raw:
            try:
                parsed = urlparse(raw)
                host = parsed.hostname or parsed.netloc or raw
                return host
            except Exception:
                pass
        # Handle host:port syntax (except IPv6)
        if ":" in raw and not raw.startswith("fe80") and not raw.startswith("::"):
            parts = raw.split(":")
            if len(parts) == 2 and parts[1].isdigit():
                return parts[0]
        return raw

    @classmethod
    def sanitize_input(cls, target: str) -> bool:
        if not target or not re.match(cls.TARGET_VALIDATION_REGEX, target.strip()):
            return False
        danger_chars = [';', '&&', '||', '|', '`', '$', '>', '<', '\n', '\r', '"', "'"]
        return not any(char in target for char in danger_chars)

    @classmethod
    async def execute_scan_stream(cls, target: str, scan_profile: str, custom_ports: str = None):
        target = cls.clean_target(target)
        source_ip = cls._get_source_ip()

        if not cls.sanitize_input(target):
            yield {"type": "TERMINAL_LINE", "text": "[!] Input Validation Error: Invalid characters detected in target specification.\n"}
            yield {"type": "SCAN_COMPLETE", "payload": {"target": target, "status": "error", "summary": "Input Validation Error", "ports": []}}
            return

        nmap_bin = cls.find_nmap_binary()

        # If Nmap is not installed on the system, gracefully fall back to native asynchronous port scanner
        if not nmap_bin:
            yield {"type": "TERMINAL_LINE", "text": "[*] Notice: Nmap binary not detected in PATH. Initializing SecurOS Native Async Engine...\n"}
            async for evt in cls._execute_native_scan_stream(target, scan_profile, custom_ports, source_ip):
                yield evt
            return

        # Build Nmap command arguments
        profile_str = (scan_profile or "").upper()
        base_args = ["--stats-every", "1s"]
        is_ping_sweep = False

        if "PING" in profile_str or "-SN" in profile_str:
            base_args.extend(["-sn", "-PS80,443,22,21,3389"])
            is_ping_sweep = True
        elif "VULN" in profile_str or "--SCRIPT" in profile_str:
            base_args.extend([
                "-sV",
                "--script=vuln",
                "--script-timeout", "30s",
                "--host-timeout", "3m",
                "--max-retries", "2",
                "-T4"
            ])
            if custom_ports and "-P-" not in profile_str:
                clean_ports = re.sub(r"[^0-9\,\-]", "", custom_ports)
                if clean_ports:
                    base_args.extend(["-p", clean_ports])
        elif "-P-" in profile_str or "FULL" in profile_str:
            base_args.extend(["-sV", "-p-", "-T4"])
        elif "INTENSE" in profile_str:
            base_args.extend(["-sV", "-sC", "-T4", "--host-timeout", "3m"])
            if custom_ports:
                clean_ports = re.sub(r"[^0-9\,\-]", "", custom_ports)
                if clean_ports:
                    base_args.extend(["-p", clean_ports])
        elif "QUICK" in profile_str or "-F" in profile_str:
            base_args.extend(["-sV", "-F", "-T4"])
            if custom_ports:
                clean_ports = re.sub(r"[^0-9\,\-]", "", custom_ports)
                if clean_ports:
                    base_args.extend(["-p", clean_ports])
        else:
            base_args.extend(["-sV", "-T4"])
            if custom_ports:
                clean_ports = re.sub(r"[^0-9\,\-]", "", custom_ports)
                if clean_ports:
                    base_args.extend(["-p", clean_ports])
            else:
                base_args.append("-F")

        # Use TCP Connect Scan (-sT) on Windows to ensure unprivileged execution
        if not is_ping_sweep and "-sT" not in base_args and "-sS" not in base_args:
            base_args.append("-sT")

        timestamp = int(time.time() * 1000)
        temp_dir = tempfile.gettempdir()
        xml_file = os.path.join(temp_dir, f"securos_nmap_{timestamp}.xml")
        command_arguments = base_args + ["-oX", xml_file] + target.split()

        cmd_display = f"nmap {' '.join(base_args)} {target}"
        yield {"type": "TERMINAL_LINE", "text": f"[*] Initializing Security Infrastructure Scan against: {target}\n"}
        yield {"type": "TERMINAL_LINE", "text": f"[*] Executing binary [{nmap_bin}]: {cmd_display}\n\n"}

        discovered_live_ports = []

        try:
            process = await asyncio.create_subprocess_exec(
                nmap_bin, *command_arguments,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            # Regex for real-time stdout port extraction
            port_line_regex = re.compile(r"^(\d+/(?:tcp|udp))\s+(\w+)\s+([^\s]+)(?:\s+(.*))?", re.IGNORECASE)
            discovered_port_regex = re.compile(r"Discovered open port (\d+)/(tcp|udp) on ([\d\.]+)", re.IGNORECASE)

            while True:
                line_bytes = await process.stdout.readline()
                if not line_bytes:
                    break
                line = line_bytes.decode('utf-8', errors='ignore')
                yield {"type": "TERMINAL_LINE", "text": line}

                # Progress percentage extraction
                progress_match = re.search(r"About\s+([\d\.]+)\%\s+done", line)
                if progress_match:
                    percent = float(progress_match.group(1))
                    yield {"type": "PROGRESS_UPDATE", "percent": percent, "label": f"Scanning ({int(percent)}%)"}

                # Real-time port discovery extraction
                disc_match = discovered_port_regex.search(line)
                if disc_match:
                    port_id, proto, host_ip = disc_match.groups()
                    port_key = f"{port_id}/{proto}"
                    service = cls.COMMON_PORT_SERVICES.get(int(port_id), "unknown")
                    port_obj = {
                        "source_ip": source_ip,
                        "dest_ip": host_ip,
                        "port": port_key,
                        "state": "OPEN",
                        "service": service,
                        "version": "Detecting..."
                    }
                    if port_key not in [p["port"] for p in discovered_live_ports]:
                        discovered_live_ports.append(port_obj)
                        yield {"type": "PORT_DISCOVERED", "port_data": port_obj, "data": port_obj}

                port_match = port_line_regex.match(line.strip())
                if port_match and not line.strip().startswith("PORT"):
                    port_proto, state, svc, ver = port_match.groups()
                    if state.upper() in ["OPEN", "FILTERED", "OPEN|FILTERED"]:
                        port_obj = {
                            "source_ip": source_ip,
                            "dest_ip": target,
                            "port": port_proto,
                            "state": state.upper(),
                            "service": svc or "unknown",
                            "version": (ver or "No Banner").strip()
                        }
                        if port_proto not in [p["port"] for p in discovered_live_ports]:
                            discovered_live_ports.append(port_obj)
                            yield {"type": "PORT_DISCOVERED", "port_data": port_obj, "data": port_obj}

            await process.wait()

            xml_data = ""
            try:
                if os.path.exists(xml_file):
                    with open(xml_file, "r", encoding="utf-8", errors="ignore") as f:
                        xml_data = f.read()
                    os.remove(xml_file)
            except Exception as e:
                yield {"type": "TERMINAL_LINE", "text": f"[!] XML read note: {str(e)}\n"}

            parsed_results = cls._parse_xml_results(xml_data, source_ip, target, scan_profile)

            # Merge any live-discovered ports if XML was empty or truncated
            final_ports = parsed_results.get("ports", [])
            for live_p in discovered_live_ports:
                if not any(fp.get("port") == live_p.get("port") for fp in final_ports):
                    final_ports.append(live_p)
            parsed_results["ports"] = final_ports

            # Stream complete event
            yield {"type": "SCAN_COMPLETE", "payload": parsed_results}

        except Exception as e:
            yield {"type": "TERMINAL_LINE", "text": f"\n[!] Nmap Execution Error: {str(e)}\n"}
            yield {"type": "SCAN_COMPLETE", "payload": {"target": target, "status": "error", "summary": f"Nmap execution error: {str(e)}", "ports": discovered_live_ports}}
        finally:
            if os.path.exists(xml_file):
                try:
                    os.remove(xml_file)
                except Exception:
                    pass

    @classmethod
    async def _execute_native_scan_stream(cls, target: str, scan_profile: str, custom_ports: str, source_ip: str):
        """Asynchronous fallback TCP connect scanner when Nmap is unavailable."""
        yield {"type": "TERMINAL_LINE", "text": f"[*] SecurOS Native Scanner active: probing {target}...\n"}

        # Resolve ports list
        ports_to_scan = [80, 443, 22, 21, 25, 53, 135, 139, 445, 1433, 3000, 3306, 3389, 5000, 5432, 8000, 8080, 8443]
        if custom_ports:
            clean = re.sub(r"[^0-9\,\-]", "", custom_ports)
            if "-" in clean and len(clean.split("-")) == 2:
                try:
                    start_p, end_p = map(int, clean.split("-"))
                    ports_to_scan = list(range(max(1, start_p), min(65535, end_p) + 1))[:200]
                except Exception:
                    pass
            elif clean:
                try:
                    ports_to_scan = [int(p) for p in clean.split(",") if p.isdigit()]
                except Exception:
                    pass

        total_ports = len(ports_to_scan)
        found_ports = []

        semaphore = asyncio.Semaphore(50)

        async def probe_port(port: int, idx: int):
            async with semaphore:
                try:
                    conn = asyncio.open_connection(target, port)
                    reader, writer = await asyncio.wait_for(conn, timeout=1.2)
                    service = cls.COMMON_PORT_SERVICES.get(port, "unknown")
                    banner = "Service Active"

                    # Quick banner grab
                    try:
                        if port in [80, 8080, 3000, 5000, 8000]:
                            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                            await writer.drain()
                        data = await asyncio.wait_for(reader.read(256), timeout=0.8)
                        if data:
                            banner_text = data.decode("latin-1", errors="ignore").splitlines()[0][:60]
                            banner = banner_text or banner
                    except Exception:
                        pass
                    finally:
                        writer.close()
                        try:
                            await writer.wait_closed()
                        except Exception:
                            pass

                    port_obj = {
                        "source_ip": source_ip,
                        "dest_ip": target,
                        "port": f"{port}/tcp",
                        "state": "OPEN",
                        "service": service,
                        "version": banner
                    }
                    return port_obj
                except Exception:
                    return None

        tasks = [asyncio.create_task(probe_port(p, i)) for i, p in enumerate(ports_to_scan)]

        completed = 0
        for task in asyncio.as_completed(tasks):
            res = await task
            completed += 1
            if completed % 10 == 0 or completed == total_ports:
                percent = round((completed / total_ports) * 100, 1)
                yield {"type": "PROGRESS_UPDATE", "percent": percent, "label": f"Scanning ({int(percent)}%)"}

            if res:
                found_ports.append(res)
                yield {"type": "TERMINAL_LINE", "text": f"[+] Discovered open port {res['port']} on {target} ({res['service']})\n"}
                yield {"type": "PORT_DISCOVERED", "port_data": res, "data": res}

        summary = f"Scan completed. Host is UP. {len(found_ports)} open port(s) discovered."
        yield {"type": "TERMINAL_LINE", "text": f"[*] {summary}\n"}
        yield {"type": "SCAN_COMPLETE", "payload": {"target": target, "status": "success", "summary": summary, "ports": found_ports}}

    @classmethod
    def _parse_xml_results(cls, xml_string: str, source_ip: str, default_target: str, scan_profile: str) -> dict:
        if not xml_string or not xml_string.strip():
            return {"target": default_target, "status": "success", "summary": "Audit completed. No open ports reported.", "ports": []}

        try:
            root = ET.fromstring(xml_string)
            discovered_ports = []
            host_status = "DOWN"

            for host in root.findall('host'):
                status_element = host.find('status')
                if status_element is not None:
                    host_status = status_element.get('state', 'DOWN').upper()

                addr_element = host.find('address')
                resolved_target = addr_element.get('addr', default_target) if addr_element is not None else default_target

                ports_element = host.find('ports')
                if ports_element is not None:
                    for port in ports_element.findall('port'):
                        port_id = port.get('portid')
                        protocol = port.get('protocol')
                        state = port.find('state').get('state', 'UNKNOWN').upper() if port.find('state') is not None else "UNKNOWN"

                        service_element = port.find('service')
                        service_name = cls.COMMON_PORT_SERVICES.get(int(port_id), "unknown") if port_id and port_id.isdigit() else "unknown"
                        version_banner = "No Banner"

                        if service_element is not None:
                            service_name = service_element.get('name', service_name)
                            product = service_element.get('product', '')
                            version = service_element.get('version', '')
                            combined_version = f"{product} {version}".strip()
                            if combined_version:
                                version_banner = combined_version

                        script_elements = port.findall('script')
                        vuln_logs = []
                        for script in script_elements:
                            sid = script.get('id', '')
                            if "vuln" in sid:
                                output = script.get('output', '').strip().replace('\n', ' | ')
                                if output:
                                    vuln_logs.append(f"[{sid}]: {output}")

                        if vuln_logs:
                            version_banner = f"⚠️ VULNERABLE: " + " | ".join(vuln_logs)

                        discovered_ports.append({
                            "source_ip": source_ip,
                            "dest_ip": resolved_target,
                            "port": f"{port_id}/{protocol}",
                            "state": state,
                            "service": service_name,
                            "version": version_banner
                        })

            summary = f"Discovery Sweeps Completed: Target is {host_status}." if "PING" in (scan_profile or "").upper() else f"Scan fully finalized. Host Status: {host_status}. Found {len(discovered_ports)} port(s)."
            return {"target": default_target, "status": "success", "summary": summary, "ports": discovered_ports}
        except Exception as e:
            return {"target": default_target, "status": "error", "summary": f"XML parse notice: {str(e)}", "ports": []}
