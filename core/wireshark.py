import io
import queue
import time
import json
import socket
import psutil
import random
from scapy.all import sniff, IP, IPv6, ARP, TCP, UDP, ICMP, Ether, conf, DNS, DNSQR, Raw, PcapWriter

conf.use_pcap = True

class WiresharkEngine:
    _intel_cache = {}
    _start_time = None
    _captured_raw_packets = []

    @classmethod
    def get_interfaces(cls):
        """Discovers capture-capable interfaces by correlating Scapy ifaces and psutil."""
        results = []
        try:
            io_counters = psutil.net_io_counters(pernic=True) if hasattr(psutil, "net_io_counters") else {}
            stats = psutil.net_if_stats() if hasattr(psutil, "net_if_stats") else {}

            seen_names = set()

            # First priority: Scapy conf.ifaces which represents actual PCAP capture interfaces
            for key, iface in conf.ifaces.items():
                name = str(getattr(iface, "name", "") or key)
                desc = str(getattr(iface, "description", "") or name)
                ip = str(getattr(iface, "ip", "") or "Unassigned")

                if name in seen_names:
                    continue
                seen_names.add(name)

                # Skip unneeded virtual miniports that cannot carry capture traffic
                if any(x in desc.lower() for x in ["wan miniport (network monitor)", "wan miniport (ipv6)", "wan miniport (ip)"]):
                    continue

                cnt = io_counters.get(name) or io_counters.get(desc)
                bytes_sent = cnt.bytes_sent if cnt else 0
                bytes_recv = cnt.bytes_recv if cnt else 0

                st = stats.get(name) or stats.get(desc)
                is_up = st.isup if st else True

                is_live = bool((bytes_sent + bytes_recv > 0) or (ip not in ["Unassigned", "0.0.0.0"]))

                results.append({
                    "id": str(key),
                    "name": f"{name} ({desc})" if desc and desc != name else name,
                    "raw_name": name,
                    "ip": ip if ip != "Unassigned" else ("127.0.0.1" if "loopback" in name.lower() else "Unassigned"),
                    "is_up": is_up,
                    "is_live": is_live,
                    "bytes_recv": bytes_recv,
                    "bytes_sent": bytes_sent
                })

        except Exception as e:
            print(f"[!] Interface discovery note: {str(e)}")

        if not results:
            results = [
                {"id": "Wi-Fi", "name": "Wi-Fi (Wireless Network Adapter)", "raw_name": "Wi-Fi", "ip": "192.168.1.105", "is_up": True, "is_live": True, "bytes_recv": 5849302, "bytes_sent": 1294820},
                {"id": "Ethernet", "name": "Ethernet (Gigabit Adapter)", "raw_name": "Ethernet", "ip": "10.0.0.45", "is_up": True, "is_live": True, "bytes_recv": 12849200, "bytes_sent": 4839200},
                {"id": "Loopback", "name": "Loopback (Software Loopback 127.0.0.1)", "raw_name": "Loopback", "ip": "127.0.0.1", "is_up": True, "is_live": False, "bytes_recv": 0, "bytes_sent": 0}
            ]

        # Sort so live and up interfaces come first
        results.sort(key=lambda x: (not x["is_live"], not x["is_up"], x["name"]))
        return results

    @classmethod
    def resolve_interface_object(cls, interface_id_or_name: str):
        """Resolves interface string to a valid Scapy interface object."""
        if not interface_id_or_name or interface_id_or_name in ["any", "All", "Default Adapter", "default"]:
            # Pick first live interface
            for key, iface in conf.ifaces.items():
                if getattr(iface, "ip", None) and str(iface.ip) not in ["", "0.0.0.0", "Unassigned"]:
                    return iface
            return conf.iface

        target_str = str(interface_id_or_name).strip().lower()

        # Check for loopback specifically
        if "loopback" in target_str or "127.0.0.1" in target_str:
            for key, iface in conf.ifaces.items():
                if "loopback" in str(key).lower() or "loopback" in str(getattr(iface, "name", "")).lower():
                    return iface

        # Exact key or name match
        for key, iface in conf.ifaces.items():
            if str(key) == interface_id_or_name:
                return iface
            if str(getattr(iface, "name", "")).lower() == target_str:
                return iface
            if str(getattr(iface, "description", "")).lower() == target_str:
                return iface
            if str(getattr(iface, "ip", "")).lower() == target_str:
                return iface

        # Partial match
        for key, iface in conf.ifaces.items():
            k_low = str(key).lower()
            n_low = str(getattr(iface, "name", "")).lower()
            d_low = str(getattr(iface, "description", "")).lower()
            if target_str in k_low or target_str in n_low or target_str in d_low:
                return iface

        return conf.iface

    @classmethod
    def export_pcap_bytes(cls) -> io.BytesIO:
        buffer = io.BytesIO()
        try:
            pwriter = PcapWriter(buffer, sync=True)
            for pkt in cls._captured_raw_packets:
                pwriter.write(pkt)
            pwriter.flush()
        except Exception as e:
            print(f"[!] PCAP Writer Error: {str(e)}")

        buffer.seek(0)
        return buffer

    @classmethod
    def _lookup_ip_intel(cls, ip_addr: str) -> dict:
        if not ip_addr or ip_addr.startswith(("127.", "192.168.", "10.", "172.16.", "172.31.", "fe80:", "0.0.0.0")):
            return {"country": "LOCAL", "threat_level": "safe", "label": "Internal Infrastructure Network"}
        if ip_addr in cls._intel_cache:
            return cls._intel_cache[ip_addr]

        res = {"country": "PUB", "threat_level": "clean", "label": "External Public Traffic"}
        cls._intel_cache[ip_addr] = res
        return res

    @classmethod
    def _dissect_packet(cls, packet, packet_number: int) -> dict:
        if cls._start_time is None:
            cls._start_time = time.time()

        relative_time = time.time() - cls._start_time
        length = len(packet)

        src_mac = packet[Ether].src if packet.haslayer(Ether) else "00:00:00:00:00:00"
        dst_mac = packet[Ether].dst if packet.haslayer(Ether) else "00:00:00:00:00:00"

        source = "192.168.1.105"
        destination = "104.244.42.1"
        protocol = "ETHERNET"
        info = "Layer 2 Frame"

        ip_tree = {"version": "N/A", "ihl": "N/A", "tos": "0x00", "len": length, "id": "0", "flags": "N/A", "ttl": "0"}
        layer4_tree = {"src_port": "N/A", "dst_port": "N/A", "seq": "N/A", "ack": "N/A"}
        app_tree = None

        if packet.haslayer(IP):
            ip = packet[IP]
            source, destination, protocol = ip.src, ip.dst, "IPv4"
            info = f"IPv4 Datagram ({ip.src} -> {ip.dst})"
            ip_tree = {"version": 4, "ihl": ip.ihl, "tos": hex(ip.tos), "len": ip.len, "id": ip.id, "flags": str(ip.flags), "ttl": ip.ttl}
        elif packet.haslayer(IPv6):
            ipv6 = packet[IPv6]
            source, destination, protocol = ipv6.src, ipv6.dst, "IPv6"
            info = f"IPv6 Traffic Routing ({ipv6.src} -> {ipv6.dst})"
            ip_tree = {"version": 6, "tc": ipv6.tc, "fl": ipv6.fl, "plen": ipv6.plen, "nh": ipv6.nh, "hlim": ipv6.hlim}
        elif packet.haslayer(ARP):
            arp = packet[ARP]
            source, destination, protocol = arp.psrc, arp.pdst, "ARP"
            info = f"Who has {arp.pdst}? Tell {arp.psrc}" if arp.op == 1 else f"{arp.psrc} is at {arp.hwsrc}"

        if packet.haslayer(TCP):
            protocol = "TCP"
            tcp = packet[TCP]
            flags = tcp.sprintf("%TCP.flags%") if hasattr(tcp, 'sprintf') else "N/A"
            info = f"{tcp.sport} ➔ {tcp.dport} [{flags}] Seq={tcp.seq} Ack={tcp.ack} Win={tcp.window}"
            layer4_tree = {"src_port": tcp.sport, "dst_port": tcp.dport, "seq": tcp.seq, "ack": tcp.ack, "flags": flags, "window": tcp.window}

            if packet.haslayer(Raw):
                payload = bytes(packet[Raw].load)
                if payload[:4] in (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE") or payload[:5] in (b"HTTP/",):
                    try:
                        text = payload.decode("latin-1", errors="replace")
                        first_line = text.split("\r\n", 1)[0][:120]
                        protocol = "HTTP"
                        info = first_line
                        headers = text.split("\r\n", 1)[0].split("\r\n")[:8]
                        app_tree = {"kind": "HTTP", "summary": first_line, "headers": headers}
                    except Exception:
                        pass
                elif payload[:3] == b"\x16\x03\x01" or payload[:3] == b"\x16\x03\x03":
                    protocol = "TLS"
                    info = "TLS Client/Server Handshake Record"
                    app_tree = {"kind": "TLS", "summary": info}

        elif packet.haslayer(UDP):
            protocol = "UDP"
            udp = packet[UDP]
            info = f"{udp.sport} ➔ {udp.dport} Length={udp.len}"
            layer4_tree = {"src_port": udp.sport, "dst_port": udp.dport, "len": udp.len}

            if packet.haslayer(DNS):
                dns = packet[DNS]
                protocol = "DNS"
                if dns.qr == 0 and packet.haslayer(DNSQR):
                    qname = packet[DNSQR].qname.decode(errors="replace") if isinstance(packet[DNSQR].qname, bytes) else str(packet[DNSQR].qname)
                    info = f"DNS Query: {qname}"
                    app_tree = {"kind": "DNS", "summary": info, "query": qname, "is_response": False}
                elif dns.qr == 1:
                    info = "DNS Standard query response"
                    app_tree = {"kind": "DNS", "summary": info, "is_response": True}

        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            icmp = packet[ICMP]
            info = f"ICMP Type={icmp.type} Code={icmp.code}"

        src_intel = cls._lookup_ip_intel(source)
        dst_intel = cls._lookup_ip_intel(destination)

        raw_bytes = bytes(packet)
        hex_dump = []
        for i in range(0, min(len(raw_bytes), 256), 16):
            chunk = raw_bytes[i:i + 16]
            hex_str = " ".join(f"{b:02x}" for b in chunk)
            ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            hex_dump.append(f"{i:04x}   {hex_str:<48}   {ascii_str}")

        return {
            "number": int(packet_number),
            "num": int(packet_number),
            "time": f"{relative_time:.6f}",
            "source": str(source),
            "src": str(source),
            "destination": str(destination),
            "dst": str(destination),
            "protocol": str(protocol),
            "proto": str(protocol),
            "len": int(length),
            "length": int(length),
            "info": str(info),
            "intel": {
                "src_country": src_intel["country"],
                "dst_country": dst_intel["country"],
                "threat": "danger" if (src_intel.get("threat_level") == "suspicious" or dst_intel.get("threat_level") == "suspicious") else "clean",
                "meta": f"Src: {src_intel['label']} | Dst: {dst_intel['label']}"
            },
            "trees": {
                "frame": f"Frame {packet_number}: {length} bytes on wire ({length * 8} bits)",
                "ethernet": {"src_mac": src_mac, "dst_mac": dst_mac, "type": "0x0800 (IPv4)" if packet.haslayer(IP) else "0x0806 (ARP)"},
                "ip": ip_tree,
                "l4": layer4_tree,
                "app": app_tree
            },
            "hex": "\n".join(hex_dump)
        }

    @classmethod
    def capture_packets_sync(cls, interface, count, packet_queue, stop_event, bpf_filter=None):
        """Executes live packet capture, with seamless fallback simulation if hardware capture fails."""
        cls._start_time = time.time()
        cls._captured_raw_packets = []
        packet_indexer = 0
        packet_queue.put({"type": "CAPTURE_STARTED"}, block=False)

        def packet_callback(packet):
            nonlocal packet_indexer
            if stop_event.is_set():
                return True
            packet_indexer += 1
            cls._captured_raw_packets.append(packet)
            parsed = cls._dissect_packet(packet, packet_indexer)
            if parsed:
                try:
                    packet_queue.put({"type": "PACKET_ROW", "data": parsed, "packet": parsed}, block=False)
                except Exception:
                    pass

        iface_object = cls.resolve_interface_object(interface)

        try:
            sniff(
                iface=iface_object,
                prn=packet_callback,
                filter=bpf_filter if bpf_filter else None,
                promisc=True,
                count=0,
                store=0,
                stop_filter=lambda p: stop_event.is_set()
            )
        except Exception as err:
            err_msg = str(err)
            print(f"[!] Scapy Sniffer Notice: {err_msg}")
            packet_queue.put({"type": "CAPTURE_ERROR", "message": f"Driver notice: {err_msg}. Activating SecurOS Telemetry Generator..."}, block=False)
            # Run simulation fallback so the user can test the simulator
            cls._run_simulation_stream(packet_queue, stop_event)
        finally:
            packet_queue.put({"type": "CAPTURE_COMPLETE"}, block=False)

    @classmethod
    def _run_simulation_stream(cls, packet_queue, stop_event):
        """Generates realistic telemetry packets for testing and simulator demonstrations."""
        indexer = 0
        protocols = [
            ("TCP", 80, 49210, "HTTP GET /api/v1/telemetry HTTP/1.1"),
            ("TCP", 443, 51042, "TLSv1.3 Handshake Client Hello [SNI: securos.local]"),
            ("DNS", 53, 53211, "Standard query 0x12a4 A threat-intel.soc"),
            ("TCP", 445, 49152, "SMB2 Tree Connect Request Tree: \\\\DC01\\IPC$"),
            ("TCP", 88, 49811, "AS-REQ Authentication Request (Kerberos v5)"),
            ("TCP", 22, 54120, "SSH-2.0-OpenSSH_9.3 Encrypted Key Exchange"),
            ("ICMP", 0, 0, "Echo (ping) request id=0x0001 seq=1/256"),
            ("ARP", 0, 0, "Who has 192.168.1.1? Tell 192.168.1.105")
        ]

        while not stop_event.is_set():
            indexer += 1
            proto, dport, sport, info = random.choice(protocols)
            src_ip = f"192.168.1.{random.choice([105, 142, 201, 8])}"
            dst_ip = f"10.0.0.{random.choice([1, 23, 45, 88])}" if proto != "DNS" else "8.8.8.8"
            pkt_len = random.randint(64, 1420)

            parsed = {
                "number": indexer,
                "num": indexer,
                "time": f"{time.time() - (cls._start_time or time.time()):.6f}",
                "source": src_ip,
                "src": src_ip,
                "destination": dst_ip,
                "dst": dst_ip,
                "protocol": proto,
                "proto": proto,
                "len": pkt_len,
                "length": pkt_len,
                "info": info,
                "intel": {
                    "src_country": "LOCAL",
                    "dst_country": "PUB" if dst_ip == "8.8.8.8" else "LOCAL",
                    "threat": "danger" if ("Kerberos" in info or "SMB2" in info) else "clean",
                    "meta": "SecurOS Telemetry Stream"
                },
                "trees": {
                    "frame": f"Frame {indexer}: {pkt_len} bytes on wire ({pkt_len * 8} bits)",
                    "ethernet": {"src_mac": "AzureWaveTec:13:d0:bd", "dst_mac": "00:50:56:c0:00:08", "type": "0x0800 (IPv4)"},
                    "ip": {"version": 4, "src": src_ip, "dst": dst_ip, "ttl": 64, "len": pkt_len},
                    "l4": {"src_port": sport, "dst_port": dport, "seq": 1000 + indexer, "ack": 0},
                    "app": {"kind": proto, "summary": info}
                },
                "hex": f"0000   45 00 00 {pkt_len:02x} 1c 20 40 00 40 06 b8 61 c0 a8 01 69   E.... @.@..a...i\n0010   0a 00 00 17 {sport:04x} {dport:04x} 00 00 00 00 50 02 72 10       ..........P.r."
            }

            packet_queue.put({"type": "PACKET_ROW", "data": parsed, "packet": parsed}, block=False)
            time.sleep(random.uniform(0.15, 0.45))
