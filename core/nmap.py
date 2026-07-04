import asyncio
import json
import os
import re
import shutil
import socket
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
        """
        Executes Nmap asynchronously, yielding live terminal output and progress stats 
        line-by-line before running an inline automated Nuclei pipeline check and yielding results.
        """
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

        # Core arguments. --stats-every 1s forces real-time status output tracking metrics
        base_args = ["--stats-every", "1s"]
        
        # Profile Router including Update 3 (VULN_AUDIT)
        if scan_profile == "PING_SWEEP":
            base_args.append("-sn")
        elif scan_profile == "QUICK_SCAN":
            base_args.append("-F")
        elif scan_profile == "INTENSE_SCAN":
            base_args.extend(["-sV", "-sC"])  # Avoid raw packet -O if unprivileged fallback triggers
        elif scan_profile == "VULN_AUDIT":
            base_args.extend(["-sV", "--script=vuln"])
        elif scan_profile == "CUSTOM":
            if custom_ports:
                clean_ports = re.sub(r"[^0-9\,\-]", "", custom_ports)
                base_args.extend(["-p", clean_ports])
        else:
            base_args.extend(["-sV", "-F"])

        # Unprivileged safe default mode override: Force standard TCP Connect Mode (-sT) to ensure seamless execution
        if "-sn" not in base_args:
            base_args.append("-sT")
        else:
            # Swap unprivileged Ping Sweep to TCP handshake probe vector
            base_args = ["--stats-every", "1s", "-sn", "-PS80,443,22,21,3389"]

        # Final argument array request. Explicitly tracking output layout via an intermediate temp file for structural XML stability
        xml_file = f"temp_scan_{int(asyncio.get_event_loop().time())}.xml"
        command_arguments = base_args + ["-oX", xml_file] + target.split()

        yield {"type": "TERMINAL_LINE", "text": f"[*] Initializing Security Infrastructure Scan against: {target}\n"}
        yield {"type": "TERMINAL_LINE", "text": f"[*] Executing command: nmap {' '.join(command_arguments[:-target.split().__len__()])} [targets]\n\n"}

        try:
            process = await asyncio.create_subprocess_exec(
                "nmap", *command_arguments,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            # Asynchronous Line-by-Line Stdout Telemetry Reader
            while True:
                line_bytes = await process.stdout.readline()
                if not line_bytes:
                    break
                line = line_bytes.decode('utf-8', errors='ignore')
                
                # Yield live text straight out to the frontend console
                yield {"type": "TERMINAL_LINE", "text": line}

                # Update 2: Match completion percentages (e.g., Stats: About 42.50% done)
                progress_match = re.search(r"About\s+([\d\.]+)\%\s+done", line)
                if progress_match:
                    percent = float(progress_match.group(1))
                    yield {"type": "PROGRESS_UPDATE", "percent": percent, "label": f"Scanning ({int(percent)}%)"}

            await process.wait()

            # Read back and parse compiled XML output matrices
            try:
                if os.path.exists(xml_file):
                    with open(xml_file, "r", encoding="utf-8", errors="ignore") as f:
                        xml_data = f.read()
                    os.remove(xml_file)
                else:
                    xml_data = ""
                
                parsed_results = cls._parse_xml_results(xml_data, source_ip, target, scan_profile)
                
                # =================================================================
                # EXTENDED NUCLEI DAST PIPELINE RUNNER
                # =================================================================
                discovered_ports = parsed_results.get("ports", [])
                web_targets = []
                
                for item in discovered_ports:
                    port_str = str(item.get("port", ""))
                    # Isolate active web service signatures
                    if "80" in port_str or "443" in port_str or "8080" in port_str or "http" in item.get("service", "").lower():
                        clean_port = port_str.split('/')[0]
                        protocol = "https" if "443" in port_str or "ssl" in item.get("service", "").lower() else "http"
                        web_targets.append(f"{protocol}://{item.get('dest_ip', target)}:{clean_port}")

                # If web targets are discovered during specific profiles, execute Nuclei automated testing
                if web_targets and scan_profile in ["VULN_AUDIT", "INTENSE_SCAN"]:
                    yield {"type": "TERMINAL_LINE", "text": f"\n[*] Launching Nuclei Automated Threat Hunting Pipeline against {len(web_targets)} target(s)...\n"}
                    
                    target_file = f"nuclei_targets_{int(asyncio.get_event_loop().time())}.txt"
                    with open(target_file, "w") as tf:
                        tf.write("\n".join(web_targets))
                    
                    # Run local nuclei engine binary using JSONL streaming output layout
                    nuclei_process = await asyncio.create_subprocess_exec(
                        ".\\nuclei.exe", "-list", target_file, "-jsonl", "-silent",
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
                            
                            # Standardize output mappings cleanly into your active frontend UI components table array
                            parsed_results["ports"].append({
                                "source_ip": source_ip,
                                "dest_ip": matcher,
                                "port": "VULN",
                                "state": severity,  # This maps back onto our CSS color design classes
                                "service": vuln_id,
                                "version": f"⚠️ VULNERABLE: {name}"
                            })
                        except Exception:
                            if line:
                                yield {"type": "TERMINAL_LINE", "text": f"{line}\n"}
                            
                    await nuclei_process.wait()
                    if os.path.exists(target_file):
                        os.remove(target_file)
                # =================================================================
                
                yield {"type": "SCAN_COMPLETE", "payload": parsed_results}
            except Exception as e:
                yield {"type": "SCAN_COMPLETE", "payload": {"target": target, "status": "error", "summary": f"Scan finalized but parsing failed: {str(e)}", "ports": []}}

        except Exception as e:
            yield {"type": "SCAN_COMPLETE", "payload": {"target": target, "status": "error", "summary": f"Core Exception Error: {str(e)}", "ports": []}}

    @classmethod
    def _parse_xml_results(cls, xml_string: str, source_ip: str, default_target: str, scan_profile: str) -> dict:
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

                        # Update 3: Extract NSE Vulnerability script logs and inject them directly into versions columns
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
        except Exception:
            return {"target": default_target, "status": "error", "summary": "Error mapping output payload tree.", "ports": []}