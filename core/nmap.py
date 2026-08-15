import asyncio
import json
import os
import re
import shutil
import socket
import time
import xml.etree.ElementTree as ET

class NmapEngine:
    TARGET_VALIDATION_REGEX = r"^[a-zA-Z0-9\.\:\-\/\s\,]+$"

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
    def sanitize_input(cls, target: str) -> bool:
        if not target or not re.match(cls.TARGET_VALIDATION_REGEX, target.strip()):
            return False
        danger_chars = [';', '&&', '||', '|', '`', '$', '>', '<', '\n', '\r']
        return not any(char in target for char in danger_chars)

    @classmethod
    async def execute_scan_stream(cls, target: str, scan_profile: str, custom_ports: str = None):
        target = target.strip()
        source_ip = cls._get_source_ip()

        if not cls.sanitize_input(target):
            yield {"type": "TERMINAL_LINE", "text": "[!] Input Validation Error: Malicious characters detected.\n"}
            yield {"type": "SCAN_COMPLETE", "payload": {"target": target, "status": "error", "summary": "Input Validation Error", "ports": []}}
            return

        if not shutil.which("nmap"):
            yield {"type": "TERMINAL_LINE", "text": "[!] Environment Error: Nmap binary not found on PATH.\n"}
            yield {"type": "SCAN_COMPLETE", "payload": {"target": target, "status": "error", "summary": "Nmap environment missing.", "ports": []}}
            return

        base_args = ["--stats-every", "1s"]
        
        if scan_profile == "PING_SWEEP":
            base_args.append("-sn")
        elif scan_profile == "QUICK_SCAN":
            base_args.extend(["-F", "-T4"])
        elif scan_profile == "INTENSE_SCAN":
            base_args.extend(["-sV", "-sC", "-T4", "--host-timeout", "3m"])
        elif scan_profile == "VULN_AUDIT":
            base_args.extend([
                "-sV", 
                "--script=vuln", 
                "--script-timeout", "30s",
                "--host-timeout", "3m",
                "--max-retries", "2",
                "-T4"
            ])
        elif scan_profile == "CUSTOM":
            if custom_ports:
                clean_ports = re.sub(r"[^0-9\,\-]", "", custom_ports)
                base_args.extend(["-p", clean_ports])
        else:
            base_args.extend(["-sV", "-F", "-T4"])

        if "-sn" not in base_args:
            base_args.append("-sT")
        else:
            base_args = ["--stats-every", "1s", "-sn", "-PS80,443,22,21,3389"]

        timestamp = int(time.time() * 1000)
        xml_file = f"temp_scan_{timestamp}.xml"
        command_arguments = base_args + ["-oX", xml_file] + target.split()

        yield {"type": "TERMINAL_LINE", "text": f"[*] Initializing Security Infrastructure Scan against: {target}\n"}
        yield {"type": "TERMINAL_LINE", "text": f"[*] Executing command: nmap {' '.join(base_args)} {target}\n\n"}

        try:
            process = await asyncio.create_subprocess_exec(
                "nmap", *command_arguments,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            while True:
                line_bytes = await process.stdout.readline()
                if not line_bytes:
                    break
                line = line_bytes.decode('utf-8', errors='ignore')
                yield {"type": "TERMINAL_LINE", "text": line}

                progress_match = re.search(r"About\s+([\d\.]+)\%\s+done", line)
                if progress_match:
                    percent = float(progress_match.group(1))
                    yield {"type": "PROGRESS_UPDATE", "percent": percent, "label": f"Scanning ({int(percent)}%)"}

            await process.wait()

            xml_data = ""
            try:
                if os.path.exists(xml_file):
                    with open(xml_file, "r", encoding="utf-8", errors="ignore") as f:
                        xml_data = f.read()
                    os.remove(xml_file)
                
                parsed_results = cls._parse_xml_results(xml_data, source_ip, target, scan_profile)
                
                discovered_ports = parsed_results.get("ports", [])
                web_targets = []
                
                for item in discovered_ports:
                    port_str = str(item.get("port", ""))
                    if "80" in port_str or "443" in port_str or "8080" in port_str or "http" in item.get("service", "").lower():
                        clean_port = port_str.split('/')[0]
                        protocol = "https" if "443" in port_str or "ssl" in item.get("service", "").lower() else "http"
                        web_targets.append(f"{protocol}://{item.get('dest_ip', target)}:{clean_port}")

                nuclei_bin = ".\\nuclei.exe" if os.path.exists(".\\nuclei.exe") else shutil.which("nuclei")

                if web_targets and scan_profile in ["VULN_AUDIT", "INTENSE_SCAN"] and nuclei_bin:
                    yield {"type": "TERMINAL_LINE", "text": f"\n[*] Launching Nuclei Automated Threat Hunting Pipeline against {len(web_targets)} target(s)...\n"}
                    
                    target_file = f"nuclei_targets_{timestamp}.txt"
                    with open(target_file, "w") as tf:
                        tf.write("\n".join(web_targets))
                    
                    try:
                        nuclei_process = await asyncio.create_subprocess_exec(
                            nuclei_bin, "-list", target_file, "-jsonl", "-silent",
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE
                        )
                        
                        while True:
                            line_bytes = await nuclei_process.stdout.readline()
                            if not line_bytes:
                                break
                            line = line_bytes.decode('utf-8', errors='ignore').strip()
                            
                            try:
                                vuln_data = json.loads(line)
                                vuln_id = vuln_data.get("template-id", "CVE-UNKNOWN")
                                info = vuln_data.get("info", {})
                                severity = info.get("severity", "info").upper()
                                name = info.get("name", "Vulnerability detected")
                                matcher = vuln_data.get("matched-at", target)
                                
                                yield {"type": "TERMINAL_LINE", "text": f"[Nuclei ⚠️ {severity}] {matcher} -> {name} ({vuln_id})\n"}
                                
                                parsed_results["ports"].append({
                                    "source_ip": source_ip,
                                    "dest_ip": matcher,
                                    "port": "VULN",
                                    "state": severity,
                                    "service": vuln_id,
                                    "version": f"⚠️ VULNERABLE: {name}"
                                })
                            except Exception:
                                if line:
                                    yield {"type": "TERMINAL_LINE", "text": f"{line}\n"}
                                
                        await nuclei_process.wait()
                    finally:
                        if os.path.exists(target_file):
                            os.remove(target_file)
                
                yield {"type": "SCAN_COMPLETE", "payload": parsed_results}
            except Exception as e:
                yield {"type": "SCAN_COMPLETE", "payload": {"target": target, "status": "error", "summary": f"Scan finalized but parsing failed: {str(e)}", "ports": []}}

        except Exception as e:
            yield {"type": "SCAN_COMPLETE", "payload": {"target": target, "status": "error", "summary": f"Core Exception Error: {str(e)}", "ports": []}}

    @classmethod
    def _parse_xml_results(cls, xml_string: str, source_ip: str, default_target: str, scan_profile: str) -> dict:
        if not xml_string.strip():
            return {"target": default_target, "status": "error", "summary": "No XML telemetry generated by Nmap.", "ports": []}

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
                        service_name = "unknown"
                        version_banner = "No Banner"
                        
                        if service_element is not None:
                            service_name = service_element.get('name', 'unknown')
                            product = service_element.get('product', '')
                            version = service_element.get('version', '')
                            combined_version = f"{product} {version}".strip()
                            if combined_version:
                                version_banner = combined_version

                        script_elements = port.findall('script')
                        vuln_logs = []
                        for script in script_elements:
                            if "vuln" in script.get('id', ''):
                                output = script.get('output', '').strip().replace('\n', ' | ')
                                if output:
                                    vuln_logs.append(f"[{script.get('id')}]: {output}")
                        
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

            summary = f"Discovery Sweeps Completed: Target is {host_status}." if scan_profile == "PING_SWEEP" else f"Scan fully finalized. Status Host: {host_status}."
            return {"target": default_target, "status": "success", "summary": summary, "ports": discovered_ports}
        except Exception as e:
            return {"target": default_target, "status": "error", "summary": f"Error mapping output payload tree: {str(e)}", "ports": []}