import datetime
import html

class ReportGenerator:
    @staticmethod
    def generate_unified_vapt_report(
        target: str,
        nmap_data: dict = None,
        nuclei_data: list = None,
        fuzz_data: list = None,
        ai_analysis: str = "",
        output_format: str = "html"
    ) -> str:
        """
        Generates a consolidated VAPT report aggregating Nmap, Nuclei, 
        FFUF, and JARVIS AI Threat Intelligence.
        """
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        nmap_ports = (nmap_data or {}).get("ports", [])
        nuclei_findings = nuclei_data or []
        fuzz_findings = fuzz_data or []

        if output_format == "markdown":
            return ReportGenerator._build_unified_markdown(
                target, timestamp, nmap_ports, nuclei_findings, fuzz_findings, ai_analysis
            )
        else:
            return ReportGenerator._build_unified_html(
                target, timestamp, nmap_ports, nuclei_findings, fuzz_findings, ai_analysis
            )

    @staticmethod
    def generate_vapt_markdown(target: str, scan_data: dict, ai_analysis: str = "") -> str:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        ports = (scan_data or {}).get("ports", [])
        return ReportGenerator._build_unified_markdown(target, timestamp, ports, [], [], ai_analysis)

    @staticmethod
    def generate_vapt_html(target: str, scan_data: dict, ai_analysis: str = "") -> str:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        ports = (scan_data or {}).get("ports", [])
        return ReportGenerator._build_unified_html(target, timestamp, ports, [], [], ai_analysis)

    @staticmethod
    def _build_unified_markdown(target, timestamp, ports, nuclei, fuzz, ai_analysis):
        lines = [
            f"# SecurOS // Comprehensive VAPT Engagement Report",
            f"**Target Host / Domain:** `{target}`  ",
            f"**Execution Timestamp:** `{timestamp}`  ",
            f"**Classification:** `CONFIDENTIAL // TLP:AMBER`  ",
            f"**Lead AI Threat Engine:** `SecurOS Autonomous Auditor (JARVIS)`",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            f"An automated Vulnerability Assessment and Penetration Testing (VAPT) evaluation was conducted against `{target}`. "
            f"The scope included network service mapping ({len(ports)} services), automated vulnerability templates ({len(nuclei)} findings), "
            f"and web endpoint discovery ({len(fuzz)} routes).",
            "",
            "---",
            "",
            "## 2. Perimeter Attack Surface (Nmap)",
            "",
            "| Port / Proto | State | Service | Version Fingerprint |",
            "| :--- | :--- | :--- | :--- |"
        ]

        if not ports:
            lines.append("| *None* | *Closed/Filtered* | *N/A* | *No active ports detected* |")
        else:
            for p in ports:
                lines.append(f"| `{p.get('port', '?')}/{p.get('proto', 'tcp')}` | `{(p.get('state', 'open')).upper()}` | `{p.get('service', 'unknown')}` | `{p.get('version', 'N/A') or 'N/A'}` |")

        lines.extend([
            "",
            "---",
            "",
            "## 3. Vulnerability Findings (Nuclei)",
            "",
            "| Template / CVE ID | Severity | Matched URL / Endpoint | Details |",
            "| :--- | :--- | :--- | :--- |"
        ])

        if not nuclei:
            lines.append("| *None* | *Clean* | *N/A* | *No automated vulnerabilities identified* |")
        else:
            for v in nuclei:
                lines.append(f"| `{v.get('template_id', v.get('id', 'N/A'))}` | **{(v.get('severity') or 'info').upper()}** | `{v.get('matched_at', target)}` | {v.get('name', 'Identified via template')} |")

        lines.extend([
            "",
            "---",
            "",
            "## 4. Exposed Web Routes & Endpoints (FFUF)",
            "",
            "| Status Code | Route / URL | Response Size | Words |",
            "| :--- | :--- | :--- | :--- |"
        ])

        if not fuzz:
            lines.append("| *None* | *N/A* | *N/A* | *No hidden endpoints indexed* |")
        else:
            for f in fuzz:
                lines.append(f"| `{f.get('status', '200')}` | `{f.get('url', f.get('path', ''))}` | `{f.get('length', 'N/A')} bytes` | `{f.get('words', '-')}` |")

        lines.extend([
            "",
            "---",
            "",
            "## 5. JARVIS Threat Intelligence & Remediation Directives",
            "",
            ai_analysis if ai_analysis else "Standard perimeter hardening recommended: Restrict unused ports, apply critical patches, and enforce WAF inspection.",
            "",
            "---",
            "",
            "## 6. Engagement Sign-Off",
            "- **Testing Standard:** PTES, OWASP Top 10, MITRE ATT&CK Framework",
            f"- **Report Generated:** {timestamp}"
        ])

        return "\n".join(lines)

    @staticmethod
    def _build_unified_html(target, timestamp, ports, nuclei, fuzz, ai_analysis):
        port_rows = ""
        for p in ports:
            port_rows += f"<tr><td><code>{p.get('port', '?')}/{p.get('proto', 'tcp')}</code></td><td><span class='badge open'>{(p.get('state', 'open')).upper()}</span></td><td>{p.get('service', 'unknown')}</td><td>{p.get('version', 'N/A') or 'N/A'}</td></tr>"
        if not port_rows:
            port_rows = "<tr><td colspan='4' style='text-align:center;'>No open ports identified.</td></tr>"

        nuclei_rows = ""
        for v in nuclei:
            sev = (v.get('severity') or 'info').lower()
            badge_class = 'critical' if sev in ['critical', 'high'] else ('medium' if sev == 'medium' else 'open')
            nuclei_rows += f"<tr><td><code>{v.get('template_id', v.get('id', 'N/A'))}</code></td><td><span class='badge {badge_class}'>{sev.upper()}</span></td><td><code>{v.get('matched_at', target)}</code></td></tr>"
        if not nuclei_rows:
            nuclei_rows = "<tr><td colspan='3' style='text-align:center;'>No vulnerabilities flagged.</td></tr>"

        fuzz_rows = ""
        for f in fuzz:
            fuzz_rows += f"<tr><td><code>{f.get('status', '200')}</code></td><td><code>{f.get('url', f.get('path', ''))}</code></td><td>{f.get('length', 'N/A')} B</td></tr>"
        if not fuzz_rows:
            fuzz_rows = "<tr><td colspan='3' style='text-align:center;'>No hidden endpoints discovered.</td></tr>"

        escaped_ai = html.escape(ai_analysis) if ai_analysis else "Perimeter evaluation complete. Isolate exposed services and patch CVEs."

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Unified VAPT Engagement Audit - {html.escape(target)}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; line-height: 1.6; color: #1e293b; background: #f8fafc; padding: 40px; margin: 0; }}
    .container {{ max-width: 960px; margin: auto; background: #ffffff; padding: 40px; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.06); }}
    .header {{ border-bottom: 2px solid #e2e8f0; padding-bottom: 20px; margin-bottom: 24px; }}
    .header h1 {{ margin: 0 0 8px 0; color: #0f172a; font-size: 24px; }}
    .meta {{ font-size: 13px; color: #64748b; }}
    h2 {{ color: #0f172a; font-size: 18px; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; margin-top: 30px; }}
    table {{ width: 100%; border-collapse: collapse; margin: 16px 0; font-size: 13px; }}
    th, td {{ padding: 10px 14px; text-align: left; border-bottom: 1px solid #e2e8f0; }}
    th {{ background: #f1f5f9; color: #475569; font-weight: 600; }}
    code {{ background: #f1f5f9; padding: 2px 6px; border-radius: 4px; font-family: Consolas, monospace; font-size: 12px; }}
    .badge {{ padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; text-transform: uppercase; }}
    .badge.open {{ background: #e0f2fe; color: #0369a1; }}
    .badge.medium {{ background: #fef3c7; color: #b45309; }}
    .badge.critical {{ background: #fee2e2; color: #b91c1c; }}
    .ai-box {{ background: #0f172a; color: #e2e8f0; padding: 20px; border-radius: 6px; font-size: 13px; line-height: 1.7; white-space: pre-wrap; margin-top: 14px; }}
    @media print {{ body {{ padding: 0; background: #fff; }} .container {{ box-shadow: none; padding: 0; }} }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🛡️ SecurOS // Unified VAPT Engagement Audit Report</h1>
      <div class="meta">Target: <strong>{html.escape(target)}</strong> | Generated: {timestamp} | Classification: Confidential (TLP:AMBER)</div>
    </div>
    
    <h2>1. Executive Summary</h2>
    <p>Comprehensive security posture audit combining port enumeration, web directory discovery, and vulnerability templates.</p>

    <h2>2. Discovered Network Services (Nmap)</h2>
    <table>
      <thead><tr><th>Port / Protocol</th><th>State</th><th>Service</th><th>Version Fingerprint</th></tr></thead>
      <tbody>{port_rows}</tbody>
    </table>

    <h2>3. Vulnerability Findings (Nuclei)</h2>
    <table>
      <thead><tr><th>Template / CVE ID</th><th>Severity</th><th>Matched Endpoint</th></tr></thead>
      <tbody>{nuclei_rows}</tbody>
    </table>

    <h2>4. Web Directory Discovery (FFUF)</h2>
    <table>
      <thead><tr><th>Status Code</th><th>Discovered URL</th><th>Payload Size</th></tr></thead>
      <tbody>{fuzz_rows}</tbody>
    </table>

    <h2>5. JARVIS AI Threat Analysis & Prioritized Remediation</h2>
    <div class="ai-box">{escaped_ai}</div>
  </div>
</body>
</html>"""