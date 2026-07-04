import queue
import time
import urllib.request
import json
from scapy.all import sniff, IP, IPv6, ARP, TCP, UDP, ICMP, Ether, conf, DNS, DNSQR, Raw

class WiresharkEngine:
    _intel_cache = {}
    _start_time = None

    @staticmethod
    def get_interfaces():
        results = []
        try:
            for iface_id, iface in conf.ifaces.items():
                friendly_name = getattr(iface, "description", "") or str(iface.name)
                name_lower = friendly_name.lower()
                
                if any(x in name_lower for x in ["wfp", "filter", "scheduler", "miniport", "virtualbox", "loopback"]):
                    continue
                    
                results.append({
                    "id": str(iface.name), 
                    "name": f"{friendly_name}"
                })
        except Exception:
            pass
            
        if not results:
            try:
                results.append({"id": str(conf.iface.name), "name": getattr(conf.iface, "description", "Default Adapter")})
            except Exception:
                results.append({"id": "any", "name": "All Active Interfaces (Promiscuous Mode)"})
            
        results.sort(key=lambda x: ("wi-fi" in x["name"].lower() or "ethernet" in x["name"].lower()), reverse=True)
        return results

    @classmethod
    def _lookup_ip_intel(cls, ip_addr: str) -> dict:
        if ip_addr.startswith(("127.", "192.168.", "10.", "172.16.", "172.31.", "fe80:")):
            return {"country": "LOCAL", "threat_level": "safe", "label": "Internal Infrastructure Network"}
        if ip_addr in cls._intel_cache:
            return cls._intel_cache[ip_addr]
        try:
            url = f"https://ipapi.co/{ip_addr}/json/"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=1.0) as response:
                data = json.loads(response.read().decode())
                cls._intel_cache[ip_addr] = {
                    "country": data.get("country_code", "UNK"),
                    "threat_level": "clean",
                    "label": data.get("org", "Public IP Node")
                }
                return cls._intel_cache[ip_addr]
        except Exception:
            return {"country": "PUB", "threat_level": "clean", "label": "External Public Traffic"}

    @classmethod
    def _dissect_packet(cls, packet, packet_number: int) -> dict:
        """
        Guarantees that every root key match (number, time, source, destination, 
        protocol, length, info) is present to completely prevent frontend 'undefined' prints.
        """
        if cls._start_time is None:
            cls._start_time = time.time()

        relative_time = time.time() - cls._start_time
        length = len(packet)

        src_mac = packet[Ether].src if packet.haslayer(Ether) else "00:00:00:00:00:00"
        dst_mac = packet[Ether].dst if packet.haslayer(Ether) else "00:00:00:00:00:00"

        # Safe baseline root variables - strictly matching your JS variable keys
        source = "0.0.0.0"
        destination = "0.0.0.0"
        protocol = "RAW"
        info = "Layer 2 Link Frame"
        
        ip_tree = {"version": "N/A", "ihl": "N/A", "tos": "0x00", "len": length, "id": "0", "flags": "N/A", "ttl": "0"}
        layer4_tree = {"src_port": "N/A", "dst_port": "N/A", "seq": "N/A", "ack": "N/A"}
        app_tree = None

        if packet.haslayer(IP):
            ip = packet[IP]
            source, destination, protocol = ip.src, ip.dst, "IPv4"
            info = "IPv4 Traffic Routing"
            ip_tree = {"version": 4, "ihl": ip.ihl, "tos": hex(ip.tos), "len": ip.len, "id": ip.id, "flags": str(ip.flags), "ttl": ip.ttl}
        elif packet.haslayer(IPv6):
            source, destination, protocol, info = packet[IPv6].src, packet[IPv6].dst, "IPv6", "IPv6 Routing Segment"
        elif packet.haslayer(ARP):
            source, destination, protocol, info = packet[ARP].psrc, packet[ARP].pdst, "ARP", f"Who has {packet[ARP].pdst}? Tell {packet[ARP].psrc}"

        if packet.haslayer(TCP):
            protocol = "TCP"
            tcp = packet[TCP]
            flags = tcp.sprintf("%TCP.flags%") if hasattr(tcp, 'sprintf') else "N/A"
            info = f"{tcp.sport} ➔ {tcp.dport} [{flags}] Seq={tcp.seq} Ack={tcp.ack}"
            layer4_tree = {"src_port": tcp.sport, "dst_port": tcp.dport, "seq": tcp.seq, "ack": tcp.ack}

            if packet.haslayer(Raw):
                payload = bytes(packet[Raw].load)
                if payload[:4] in (b"GET ", b"POST", b"PUT ", b"HEAD") or payload[:5] in (b"HTTP/",):
                    try:
                        text = payload.decode("latin-1", errors="replace")
                        first_line = text.split("\r\n", 1)[0][:120]
                        protocol = "HTTP"
                        info = first_line
                        headers = text.split("\r\n", 1)[0].split("\r\n")[:8]
                        app_tree = {"kind": "HTTP", "summary": first_line, "headers": headers}
                    except Exception:
                        pass

        elif packet.haslayer(UDP):
            protocol = "UDP"
            udp = packet[UDP]
            info = f"{udp.sport} ➔ {udp.dport} Length={udp.len}"
            layer4_tree = {"src_port": udp.sport, "dst_port": udp.dport}

            if packet.haslayer(DNS):
                dns = packet[DNS]
                protocol = "DNS"
                if dns.qr == 0 and packet.haslayer(DNSQR):
                    qname = packet[DNSQR].qname.decode(errors="replace") if isinstance(packet[DNSQR].qname, bytes) else str(packet[DNSQR].qname)
                    info = f"Standard query {qname}"
                    app_tree = {"kind": "DNS", "summary": info, "query": qname, "is_response": False}

        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            info = f"ICMP type {packet[ICMP].type}"

        # Geolocation fields
        src_intel = cls._lookup_ip_intel(source)
        dst_intel = cls._lookup_ip_intel(destination)

        # Build raw hex layouts
        raw_bytes = bytes(packet)
        hex_dump = []
        for i in range(0, len(raw_bytes), 16):
            chunk = raw_bytes[i:i + 16]
            hex_str = " ".join(f"{b:02x}" for b in chunk)
            ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            hex_dump.append(f"{i:04x}  {hex_str:<48}  {ascii_str}")

        # ROOT VARIABLES ARE NAMED EXACTLY WHAT THE JAVASCRIPT CORRESPONDING ARRAYS DEMAND
        return {
            "number": int(packet_number), 
            "time": f"{relative_time:.6f}",
            "source": str(source), 
            "destination": str(destination), 
            "protocol": str(protocol), 
            "length": int(length), 
            "info": str(info),
            "intel": {
                "src_country": src_intel["country"],
                "dst_country": dst_intel["country"],
                "threat": "danger" if (src_intel["threat_level"] == "suspicious" or dst_intel["threat_level"] == "suspicious") else "clean",
                "meta": f"Src: {src_intel['label']} | Dst: {dst_intel['label']}"
            },
            "trees": {
                "frame": f"Frame {packet_number}: {length} bytes on wire.",
                "ethernet": {"src_mac": src_mac, "dst_mac": dst_mac, "type": "0x800"},
                "ip": ip_tree, "l4": layer4_tree, "app": app_tree
            },
            "hex": "\n".join(hex_dump)
        }

    @classmethod
    def capture_packets_sync(cls, interface, count, packet_queue, stop_event, bpf_filter=None):
        cls._start_time = time.time()
        packet_indexer = 0
        packet_queue.put({"type": "CAPTURE_STARTED"}, block=False)

        def packet_callback(packet):
            nonlocal packet_indexer
            if stop_event.is_set():
                return True
            packet_indexer += 1
            parsed = cls._dissect_packet(packet, packet_indexer)
            if parsed:
                try:
                    packet_queue.put({"type": "PACKET_ROW", "data": parsed}, block=False)
                except Exception:
                    pass

        # Match interface parameter strings back to explicit Scapy physical drivers
        iface_object = None
        if interface and interface != "any":
            for name, iface_obj in conf.ifaces.items():
                if str(name) == str(interface) or str(iface_obj.name) == str(interface):
                    iface_object = iface_obj
                    break

        try:
            sniff(
                iface=iface_object, 
                prn=packet_callback,
                filter=bpf_filter if bpf_filter else None,
                promisc=True,
                count=0,
                store=0
            )
        except Exception as err:
            packet_queue.put({"type": "CAPTURE_ERROR", "message": str(err)}, block=False)
        finally:
            packet_queue.put({"type": "CAPTURE_COMPLETE"}, block=False)