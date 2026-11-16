"""
Advanced Translator: Wireshark-style display filter strings -> Scapy BPF expressions.

Supports rich Wireshark display filter syntax:
  tcp.port == 80          -> "port 80"
  tcp.port != 80          -> "not port 80"
  udp.port == 53          -> "port 53"
  ip.addr == 10.0.0.5     -> "host 10.0.0.5"
  ip.addr != 10.0.0.5     -> "not host 10.0.0.5"
  ip.src == 10.0.0.5      -> "src host 10.0.0.5"
  ip.dst == 10.0.0.5      -> "dst host 10.0.0.5"
  http                    -> "(tcp port 80 or tcp port 8080)"
  https / tls             -> "tcp port 443"
  dns                     -> "port 53"
  ssh                     -> "tcp port 22"
  smb                     -> "tcp port 445"
  rdp                     -> "tcp port 3389"
  ftp                     -> "tcp port 21"
  icmp                    -> "icmp"
  arp                     -> "arp"
  && / || / !             -> "and" / "or" / "not"
"""
import re

_TOKEN_PATTERNS = [
    # Boolean logic translations
    (re.compile(r"&&"), " and "),
    (re.compile(r"\|\|"), " or "),
    (re.compile(r"!(?!=)"), " not "),

    # Negative equalities
    (re.compile(r"tcp\.port\s*!=\s*(\d+)", re.I), r"not port \1"),
    (re.compile(r"udp\.port\s*!=\s*(\d+)", re.I), r"not port \1"),
    (re.compile(r"ip\.addr\s*!=\s*([\d\.]+)", re.I), r"not host \1"),
    (re.compile(r"ip\.src\s*!=\s*([\d\.]+)", re.I), r"not src host \1"),
    (re.compile(r"ip\.dst\s*!=\s*([\d\.]+)", re.I), r"not dst host \1"),

    # Positive port specifications
    (re.compile(r"tcp\.port\s*==\s*(\d+)", re.I), r"port \1"),
    (re.compile(r"udp\.port\s*==\s*(\d+)", re.I), r"port \1"),
    (re.compile(r"tcp\.srcport\s*==\s*(\d+)", re.I), r"src port \1"),
    (re.compile(r"tcp\.dstport\s*==\s*(\d+)", re.I), r"dst port \1"),
    (re.compile(r"udp\.srcport\s*==\s*(\d+)", re.I), r"src port \1"),
    (re.compile(r"udp\.dstport\s*==\s*(\d+)", re.I), r"dst port \1"),
    (re.compile(r"\bport\s*==\s*(\d+)", re.I), r"port \1"),

    # Host specifications
    (re.compile(r"ip\.addr\s*==\s*([\d\.]+)", re.I), r"host \1"),
    (re.compile(r"ip\.src\s*==\s*([\d\.]+)", re.I), r"src host \1"),
    (re.compile(r"ip\.dst\s*==\s*([\d\.]+)", re.I), r"dst host \1"),
    (re.compile(r"ip\.host\s*==\s*([\d\.]+)", re.I), r"host \1"),

    # Protocol shortcuts
    (re.compile(r"\bdns\b", re.I), "port 53"),
    (re.compile(r"\bhttps\b", re.I), "tcp port 443"),
    (re.compile(r"\btls\b", re.I), "tcp port 443"),
    (re.compile(r"\bhttp\b", re.I), "(tcp port 80 or tcp port 8080)"),
    (re.compile(r"\bssh\b", re.I), "tcp port 22"),
    (re.compile(r"\bsmb\b", re.I), "tcp port 445"),
    (re.compile(r"\brdp\b", re.I), "tcp port 3389"),
    (re.compile(r"\bftp\b", re.I), "tcp port 21"),
    (re.compile(r"\bicmp\b", re.I), "icmp"),
    (re.compile(r"\barp\b", re.I), "arp"),
]


def translate_display_filter(expr: str) -> str:
    """
    Converts a Wireshark-style display filter string into a BPF string.
    Returns an empty string (== "no filter") if expr is blank.
    """
    if not expr or not expr.strip():
        return ""

    out = expr.strip()
    for pattern, replacement in _TOKEN_PATTERNS:
        out = pattern.sub(replacement, out)

    # Clean up redundant spaces
    out = re.sub(r"\s+", " ", out).strip()
    return out
