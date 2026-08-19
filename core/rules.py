import re
import time
from collections import defaultdict
from typing import Dict, List, Any, Optional

# =====================================================================
# 1. BUILT-IN NIDS RULES (Suricata / Snort Compatible Signatures)
# =====================================================================

DEFAULT_NIDS_RULES = [
    # Custom User Rule: Rapid Internal TCP SYN Port Scan
    'alert tcp $HOME_NET any -> $HOME_NET any (msg:"SEC_SOC - Rapid Internal TCP SYN Port Scan Detected"; flags:S,12; threshold:type both, track by_src, count 25, seconds 3; classtype:attempted-recon; sid:1000842; rev:1;)',
    
    # Pre-auth / Remote Code Execution Signatures
    'alert tcp any any -> $HOME_NET 445 (msg:"SEC_SOC - SMBv1 EternalBlue MS17-010 Exploit Probe"; content:"|ff|SMB|32|"; classtype:attempted-admin; sid:1000101; rev:1;)',
    'alert tcp any any -> $HOME_NET 443 (msg:"SEC_SOC - Microsoft Exchange CVE-2024-21413 SSRF Token Attempt"; content:"/owa/auth.owa"; http_uri; classtype:web-application-attack; sid:1000201; rev:1;)',
    'alert tcp any any -> $HOME_NET 80 (msg:"SEC_SOC - Generic SQL Injection Union Select Attack"; content:"UNION"; nocase; content:"SELECT"; nocase; classtype:web-application-attack; sid:1000301; rev:1;)',
    'alert tcp any any -> $HOME_NET 80 (msg:"SEC_SOC - Web Directory Traversal /etc/passwd Extraction"; content:"../etc/passwd"; classtype:attempted-recon; sid:1000401; rev:1;)',
    
    # Active Directory Attack Vectors
    'alert tcp any any -> $HOME_NET 88 (msg:"SEC_SOC - Active Directory AS-REP Roasting / Kerberoasting Probe"; content:"|05|"; classtype:credential-theft; sid:1000501; rev:1;)'
]


# =====================================================================
# 2. PARSED RULE DATA STRUCTURE & PARSER
# =====================================================================

class NidsRule:
    """Represents a structured Suricata/Snort detection signature."""
    def __init__(self, raw_rule: str):
        self.raw_rule = raw_rule.strip()
        self.action = "alert"
        self.protocol = "TCP"
        self.src_net = "$HOME_NET"
        self.src_port = "any"
        self.dst_net = "$HOME_NET"
        self.dst_port = "any"
        self.msg = "Unknown Signature"
        self.sid = 0
        self.rev = 1
        self.classtype = "misc-activity"
        self.flags = ""
        self.content = []
        self.threshold_count = 0
        self.threshold_seconds = 0
        
        self._parse()

    def _parse(self):
        # Extract rule header
        header_pattern = r'^(alert|drop|pass)\s+(\w+)\s+(\S+)\s+(\S+)\s+->\s+(\S+)\s+(\S+)\s*\((.*)\)$'
        match = re.match(header_pattern, self.raw_rule, re.IGNORECASE)
        if not match:
            return

        self.action = match.group(1).lower()
        self.protocol = match.group(2).upper()
        self.src_net = match.group(3)
        self.src_port = match.group(4)
        self.dst_net = match.group(5)
        self.dst_port = match.group(6)
        options_str = match.group(7)

        # Parse options
        for opt in options_str.split(';'):
            opt = opt.strip()
            if not opt:
                continue
            if opt.startswith('msg:'):
                self.msg = opt.split(':', 1)[1].strip('"').strip("'")
            elif opt.startswith('sid:'):
                try:
                    self.sid = int(opt.split(':', 1)[1].strip())
                except ValueError:
                    pass
            elif opt.startswith('rev:'):
                try:
                    self.rev = int(opt.split(':', 1)[1].strip())
                except ValueError:
                    pass
            elif opt.startswith('classtype:'):
                self.classtype = opt.split(':', 1)[1].strip()
            elif opt.startswith('flags:'):
                self.flags = opt.split(':', 1)[1].strip()
            elif opt.startswith('content:'):
                self.content.append(opt.split(':', 1)[1].strip('"'))
            elif 'threshold:' in opt:
                count_m = re.search(r'count\s+(\d+)', opt)
                sec_m = re.search(r'seconds\s+(\d+)', opt)
                if count_m:
                    self.threshold_count = int(count_m.group(1))
                if sec_m:
                    self.threshold_seconds = int(sec_m.group(1))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sid": self.sid,
            "msg": self.msg,
            "protocol": self.protocol,
            "classtype": self.classtype,
            "raw": self.raw_rule,
            "threshold_count": self.threshold_count,
            "threshold_seconds": self.threshold_seconds
        }


# =====================================================================
# 3. RULE ENGINE & LIVE STATEFUL DETECTOR
# =====================================================================

class RuleEngine:
    """Manages signatures, parses NIDS rules, and inspects live packet streams."""
    
    def __init__(self, custom_rule_strings: Optional[List[str]] = None):
        self.rules: List[NidsRule] = []
        raw_list = custom_rule_strings if custom_rule_strings else DEFAULT_NIDS_RULES
        for r_str in raw_list:
            self.load_rule(r_str)
            
        # Stateful buffers for threshold tracking (e.g. sid:1000842 SYN scans)
        self.ip_syn_history: Dict[str, List[float]] = defaultdict(list)
        self.alert_history: List[Dict[str, Any]] = []

    def load_rule(self, rule_str: str) -> None:
        """Parses and adds a single rule to the active inspection matrix."""
        parsed = NidsRule(rule_str)
        if parsed.sid != 0:
            self.rules.append(parsed)

    def load_rules_from_file(self, filepath: str) -> int:
        """Loads rules line-by-line from a .rules configuration file."""
        loaded = 0
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.load_rule(line)
                        loaded += 1
        except Exception as e:
            print(f"[!] Rule file load warning: {str(e)}")
        return loaded

    def inspect_packet(self, packet: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Evaluates an individual packet dictionary against all active NIDS rules.
        Expected format: {'src': str, 'dst': str, 'proto': str, 'info': str, 'len': int}
        """
        alerts = []
        now = time.time()
        src_ip = packet.get("src", "0.0.0.0")
        dst_ip = packet.get("dst", "0.0.0.0")
        proto = packet.get("proto", "TCP").upper()
        info = packet.get("info", "")

        for rule in self.rules:
            # 1. Protocol check
            if rule.protocol != "ANY" and rule.protocol != proto:
                continue

            # 2. SYN Port Scan Threshold Evaluation (Rule SID 1000842)
            if rule.sid == 1000842:
                # Track TCP SYN flags or connection attempts
                if proto == "TCP" and ("SYN" in info.upper() or "SEQ=" in info.upper()):
                    # Purge records older than threshold window
                    cutoff = now - (rule.threshold_seconds or 3)
                    self.ip_syn_history[src_ip] = [t for t in self.ip_syn_history[src_ip] if t > cutoff]
                    self.ip_syn_history[src_ip].append(now)

                    if len(self.ip_syn_history[src_ip]) >= (rule.threshold_count or 25):
                        alert_event = {
                            "timestamp": time.strftime("%H:%M:%S"),
                            "sid": rule.sid,
                            "severity": "High",
                            "msg": rule.msg,
                            "classtype": rule.classtype,
                            "src": src_ip,
                            "dst": dst_ip,
                            "count": len(self.ip_syn_history[src_ip]),
                            "mitigation": "Enforce firewall rate limiting or isolate host via PowerShell/iptables."
                        }
                        alerts.append(alert_event)
                        self.alert_history.append(alert_event)
                        # Reset buffer after firing alert to prevent duplicate flooding
                        self.ip_syn_history[src_ip] = []

            # 3. Content matching check
            if rule.content:
                matched_all_contents = True
                for c in rule.content:
                    if c.lower() not in info.lower():
                        matched_all_contents = False
                        break
                        
                if matched_all_contents:
                    alert_event = {
                        "timestamp": time.strftime("%H:%M:%S"),
                        "sid": rule.sid,
                        "severity": "Critical" if "Exploit" in rule.msg or "SSRF" in rule.msg else "Medium",
                        "msg": rule.msg,
                        "classtype": rule.classtype,
                        "src": src_ip,
                        "dst": dst_ip,
                        "details": f"Signature match on content payload: '{rule.content[0]}'"
                    }
                    alerts.append(alert_event)
                    self.alert_history.append(alert_event)

        return alerts

    def get_all_rules_summary(self) -> List[Dict[str, Any]]:
        """Returns a list of all loaded rules for frontend inspection & RAG storage."""
        return [r.to_dict() for r in self.rules]


# =====================================================================
# 4. SINGLETON INSTANCE EXPORT
# =====================================================================

# Global engine instance initialized with default Suricata/Snort signatures
default_rule_engine = RuleEngine()