"""
Lightweight translator: Wireshark-style display filter strings -> BPF expressions.

Supports the common subset people actually type day to day:
  tcp.port==80          -> "port 80"
  tcp.port == 80         -> "port 80"
  udp.port==53           -> "port 53"
  ip.addr==10.0.0.5      -> "host 10.0.0.5"
  ip.src==10.0.0.5       -> "src host 10.0.0.5"
  ip.dst==10.0.0.5       -> "dst host 10.0.0.5"
  tcp                     -> "tcp"
  udp                     -> "udp"
  icmp                    -> "icmp"
  arp                     -> "arp"
  dns                     -> "port 53"
  http                    -> "tcp port 80 or tcp port 8080"
  and / or                -> passed through (BPF supports the same keywords)

Anything that doesn't match a known pattern is left as-is and handed to BPF
verbatim, so raw BPF expressions ("host 1.2.3.4 and port 443") still work
unchanged. If the resulting expression is invalid BPF, scapy's sniff() will
raise -- the caller should catch that and surface it to the UI rather than
silently dropping the filter.
"""
import re

_TOKEN_PATTERNS = [
    (re.compile(r"tcp\.port\s*==\s*(\d+)", re.I), r"port \1"),
    (re.compile(r"udp\.port\s*==\s*(\d+)", re.I), r"port \1"),
    (re.compile(r"tcp\.srcport\s*==\s*(\d+)", re.I), r"src port \1"),
    (re.compile(r"tcp\.dstport\s*==\s*(\d+)", re.I), r"dst port \1"),
    (re.compile(r"udp\.srcport\s*==\s*(\d+)", re.I), r"src port \1"),
    (re.compile(r"udp\.dstport\s*==\s*(\d+)", re.I), r"dst port \1"),
    (re.compile(r"ip\.addr\s*==\s*([\d.]+)", re.I), r"host \1"),
    (re.compile(r"ip\.src\s*==\s*([\d.]+)", re.I), r"src host \1"),
    (re.compile(r"ip\.dst\s*==\s*([\d.]+)", re.I), r"dst host \1"),
    (re.compile(r"\bdns\b", re.I), "port 53"),
    (re.compile(r"\bhttp\b", re.I), "(tcp port 80 or tcp port 8080)"),
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

    # Wireshark uses "and"/"or"/"not" already, which BPF also understands,
    # so no further token rewriting is needed for boolean logic.
    return out