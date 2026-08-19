import { useState, useEffect, useRef } from "react";
import {
  AreaChart, Area, PieChart, Pie, Cell, RadarChart, Radar,
  PolarGrid, PolarAngleAxis, PolarRadiusAxis,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from "recharts";
import {
  Shield, Activity, Target, Zap, Bot,
  Download, Play, Square, Search, Upload, Terminal,
  AlertTriangle, Send, RefreshCw, Globe, Filter,
  FileText, Copy, Network, Server, Database,
  BarChart2, FileDown, Check, BookOpen, Radio, ChevronRight
} from "lucide-react";
import { exportReport, streamJarvis, WS_BASE } from "../services/api";

// ─── Shared UI Helpers ────────────────────────────────────────────────────────

function GlassCard({ children, className = "", style = {} }: {
  children: React.ReactNode;
  className?: string;
  style?: React.CSSProperties;
}) {
  return (
    <div
      className={`rounded-lg border backdrop-blur-md ${className}`}
      style={{
        background: "rgba(10, 18, 32, 0.75)",
        borderColor: "rgba(0, 212, 255, 0.13)",
        ...style,
      }}
    >
      {children}
    </div>
  );
}

function SeverityBadge({ level }: { level: string }) {
  const map: Record<string, string> = {
    Critical: "bg-red-500/20 text-red-400 border-red-500/30",
    High: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    Medium: "bg-amber-500/20 text-amber-400 border-amber-500/30",
    Low: "bg-green-500/20 text-green-400 border-green-500/30",
    Info: "bg-blue-500/20 text-blue-400 border-blue-500/30",
    Open: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
    Filtered: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  };
  return (
    <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${map[level] ?? map.Info}`}>
      {level}
    </span>
  );
}

function StatusBadge({ code }: { code: number }) {
  let cls = "bg-green-500/20 text-green-400 border-green-500/30";
  if (code >= 300 && code < 400) cls = "bg-blue-500/20 text-blue-400 border-blue-500/30";
  if (code === 403 || code === 401) cls = "bg-orange-500/20 text-orange-400 border-orange-500/30";
  if (code >= 500) cls = "bg-red-500/20 text-red-400 border-red-500/30";
  return <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${cls}`}>{code}</span>;
}

function PulseDot({ color = "bg-green-400" }: { color?: string }) {
  return (
    <span className="relative flex h-2.5 w-2.5">
      <span className={`animate-ping absolute inline-flex h-full w-full rounded-full ${color} opacity-75`} />
      <span className={`relative inline-flex rounded-full h-2.5 w-2.5 ${color}`} />
    </span>
  );
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <span className="text-[10px] font-mono text-cyan-400 uppercase tracking-widest font-semibold">▸ {children}</span>
  );
}

// ─── Screen 1: SOC Dashboard ───────────────────────────────────────────────────

function SOCDashboard() {
  const [history, setHistory] = useState<any[]>([]);

  useEffect(() => {
    fetch("/api/history")
      .then(res => res.json())
      .then(data => {
        if (data.history) setHistory(data.history);
      })
      .catch(() => {});
  }, []);

  const timelineData = [
    { time: "00:00", probes: 12, cveAlerts: 2 },
    { time: "03:00", probes: 28, cveAlerts: 4 },
    { time: "06:00", probes: 45, cveAlerts: 7 },
    { time: "09:00", probes: 134, cveAlerts: 18 },
    { time: "12:00", probes: 189, cveAlerts: 29 },
    { time: "15:00", probes: 212, cveAlerts: 34 },
    { time: "18:00", probes: 178, cveAlerts: 26 },
    { time: "21:00", probes: 143, cveAlerts: 21 },
    { time: "23:59", probes: 98, cveAlerts: 15 },
  ];

  const severityData = [
    { name: "Critical", value: 8, color: "#ef4444" },
    { name: "High", value: 23, color: "#f97316" },
    { name: "Medium", value: 45, color: "#f59e0b" },
    { name: "Low", value: 67, color: "#22c55e" },
  ];

  const mitreData = [
    { subject: "Discovery", A: 85 },
    { subject: "Cred. Access", A: 62 },
    { subject: "Lateral Mvmt", A: 45 },
    { subject: "Execution", A: 78 },
    { subject: "Persistence", A: 53 },
    { subject: "Exfiltration", A: 37 },
  ];

  const threatTable = [
    { target: "192.168.1.105:445", cve: "CVE-2024-21413", tactic: "Initial Access", severity: "Critical", mitigation: "Apply MS Exchange patch KB5034768; disable legacy auth" },
    { target: "10.0.0.23:80", cve: "CVE-2023-44487", tactic: "Impact", severity: "High", mitigation: "Enable HTTP/2 reset limits; update nginx ≥1.25.3" },
    { target: "172.16.0.45:22", cve: "CVE-2023-38408", tactic: "Credential Access", severity: "Critical", mitigation: "Patch OpenSSH to 9.3p2; disable agent forwarding" },
  ];

  const kpis = [
    { label: "Monitored Endpoints", value: "247/256", sub: "Live subnet monitored", icon: <Server size={16} className="text-cyan-400" />, color: "#00d4ff", glow: "rgba(0,212,255,0.12)" },
    { label: "Active Open Ports", value: "1,842", sub: "Attack surface active", icon: <Network size={16} className="text-orange-400" />, color: "#f97316", glow: "rgba(249,115,22,0.12)" },
    { label: "Max Risk CVSS", value: "9.8", sub: "CVE-2024-21413 · Critical", icon: <AlertTriangle size={16} className="text-red-400" />, color: "#ef4444", glow: "rgba(239,68,68,0.12)" },
    { label: "AI Threat Engine", value: "SYNCED", sub: "JARVIS RAG Synchronized", icon: <Bot size={16} className="text-violet-400" />, color: "#8b5cf6", glow: "rgba(139,92,246,0.12)" },
  ];

  return (
    <div className="w-full space-y-5">
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {kpis.map((k, i) => (
          <GlassCard key={i} className="p-4" style={{ boxShadow: `0 0 24px ${k.glow}` }}>
            <div className="flex items-start justify-between mb-2">
              <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">{k.label}</span>
              {k.icon}
            </div>
            <div className="text-2xl font-bold font-mono mb-1" style={{ color: k.color }}>{k.value}</div>
            <div className="text-[10px] font-mono text-slate-500">{k.sub}</div>
          </GlassCard>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <GlassCard className="lg:col-span-2 p-5 flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <SectionLabel>Attack Surface Exposure Timeline</SectionLabel>
          </div>
          <div className="w-full h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timelineData}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
                <XAxis dataKey="time" stroke="#1e2a40" tick={{ fontSize: 10, fill: "#4a5568" }} />
                <YAxis stroke="#1e2a40" tick={{ fontSize: 10, fill: "#4a5568" }} />
                <Tooltip contentStyle={{ background: "rgba(6,9,14,0.95)", border: "1px solid rgba(0,212,255,0.18)", borderRadius: 8, fontSize: 11 }} />
                <Area type="monotone" dataKey="probes" stroke="#00d4ff" fill="#00d4ff" fillOpacity={0.2} dot={false} />
                <Area type="monotone" dataKey="cveAlerts" stroke="#8b5cf6" fill="#8b5cf6" fillOpacity={0.2} dot={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </GlassCard>

        <GlassCard className="p-5 flex flex-col">
          <SectionLabel>Vulnerability Severity</SectionLabel>
          <div className="w-full h-52 mt-2">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={severityData} cx="50%" cy="50%" innerRadius={48} outerRadius={75} paddingAngle={3} dataKey="value">
                  {severityData.map((e, i) => <Cell key={i} fill={e.color} />)}
                </Pie>
                <Tooltip contentStyle={{ background: "rgba(6,9,14,0.95)", border: "1px solid rgba(0,212,255,0.18)", borderRadius: 8, fontSize: 11 }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="grid grid-cols-2 gap-2 mt-2">
            {severityData.map(s => (
              <div key={s.name} className="flex items-center gap-1.5 text-[11px] font-mono text-slate-400">
                <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: s.color }} />
                {s.name} ({s.value})
              </div>
            ))}
          </div>
        </GlassCard>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <GlassCard className="p-5 flex flex-col">
          <SectionLabel>MITRE ATT&CK Distribution</SectionLabel>
          <div className="w-full h-64 mt-2">
            <ResponsiveContainer width="100%" height="100%">
              <RadarChart data={mitreData}>
                <PolarGrid stroke="rgba(255,255,255,0.05)" />
                <PolarAngleAxis dataKey="subject" tick={{ fontSize: 10, fill: "#8b5cf6" }} />
                <PolarRadiusAxis angle={30} domain={[0, 100]} tick={false} axisLine={false} />
                <Radar dataKey="A" stroke="#8b5cf6" fill="#8b5cf6" fillOpacity={0.25} strokeWidth={2} />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </GlassCard>

        <GlassCard className="lg:col-span-2 p-5 flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <SectionLabel>Prioritized Threat Intelligence</SectionLabel>
          </div>
          <div className="overflow-x-auto w-full flex-1">
            <table className="w-full text-[11px] font-mono">
              <thead>
                <tr className="border-b border-white/10">
                  {["Target", "CVE / Vector", "Tactic", "Severity", "Mitigation Directive"].map(h => (
                    <th key={h} className="text-left text-slate-500 pb-2 pr-4 font-normal">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {threatTable.map((row, i) => (
                  <tr key={i} className="border-b border-white/5 hover:bg-white/[0.03]">
                    <td className="py-2.5 pr-4 text-cyan-400">{row.target}</td>
                    <td className="py-2.5 pr-4 text-amber-400">{row.cve}</td>
                    <td className="py-2.5 pr-4 text-slate-300">{row.tactic}</td>
                    <td className="py-2.5 pr-4"><SeverityBadge level={row.severity} /></td>
                    <td className="py-2.5 text-slate-400">{row.mitigation}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </GlassCard>
      </div>
    </div>
  );
}

// ─── Screen 2: Live Nmap Scanner ───────────────────────────────────────────────

function NmapScanner() {
  const [target, setTarget] = useState("127.0.0.1");
  const [profile, setProfile] = useState("-T4 -F");
  const [portRange, setPortRange] = useState("1-1000");
  const [scanning, setScanning] = useState(false);
  const [lines, setLines] = useState<string[]>([]);
  const [ports, setPorts] = useState<any[]>([]);
  const [jarvisResponse, setJarvisResponse] = useState("");
  const wsRef = useRef<WebSocket | null>(null);
  const termRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    termRef.current?.scrollTo({ top: termRef.current.scrollHeight, behavior: "smooth" });
  }, [lines]);

  function handleStartScan() {
    setScanning(true);
    setLines(["[+] Initiating Nmap socket stream..."]);
    setPorts([]);
    setJarvisResponse("");

    const ws = new WebSocket(`${WS_BASE}/ws/nmap`);
    wsRef.current = ws;

    ws.onopen = () => {
      ws.send(JSON.stringify({
        action: "RUN_NMAP",
        target,
        profile,
        custom_ports: portRange,
        flags: profile,
      }));
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === "TERMINAL_LINE" || data.type === "output") {
          setLines(prev => [...prev, data.text || data.data]);
        } else if (data.type === "PORT_DISCOVERED" || data.type === "port") {
          const p = data.port_data || data.data;
          setPorts(prev => [...prev, p]);
        } else if (data.type === "SCAN_COMPLETE") {
          setScanning(false);
          const found = data.payload?.ports || [];
          if (found.length > 0) setPorts(found);
          setLines(prev => [...prev, `[✔] Scan Complete: ${data.payload?.summary || "Audit finished."}`]);
        }
      } catch (e) {
        setLines(prev => [...prev, event.data]);
      }
    };

    ws.onerror = () => setScanning(false);
    ws.onclose = () => setScanning(false);
  }

  function handleStopScan() {
    if (wsRef.current) {
      wsRef.current.send(JSON.stringify({ action: "STOP_SCAN" }));
      wsRef.current.close();
    }
    setScanning(false);
  }

  function handleAnalyze() {
    setJarvisResponse("");
    streamJarvis("Analyze these open ports and attack vectors:", { ports, target }, (chunk) => {
      setJarvisResponse(prev => prev + chunk);
    });
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 w-full h-full min-h-[calc(100vh-100px)]">
      <GlassCard className="lg:col-span-3 p-4 flex flex-col gap-4">
        <SectionLabel>Scan Configuration</SectionLabel>
        <div>
          <label className="block text-[11px] font-mono text-slate-400 mb-1">Target Host / Subnet</label>
          <input
            value={target}
            onChange={e => setTarget(e.target.value)}
            className="w-full rounded px-3 py-2 text-xs font-mono text-cyan-300 bg-black/40 border border-cyan-400/20 outline-none focus:border-cyan-400/60"
          />
        </div>
        <div>
          <label className="block text-[11px] font-mono text-slate-400 mb-1">Scan Profile</label>
          <select
            value={profile}
            onChange={e => setProfile(e.target.value)}
            className="w-full rounded px-3 py-2 text-xs font-mono text-cyan-300 bg-[#06090e] border border-cyan-400/20 outline-none"
          >
            <option value="-T4 -F">Quick Fast Scan (-T4 -F)</option>
            <option value="-sV --script vuln">Service & Vulnerability (-sV --script vuln)</option>
            <option value="-p-">Full Port Range (-p-)</option>
          </select>
        </div>
        <div>
          <label className="block text-[11px] font-mono text-slate-400 mb-1">Port Range</label>
          <input
            value={portRange}
            onChange={e => setPortRange(e.target.value)}
            className="w-full rounded px-3 py-2 text-xs font-mono text-cyan-300 bg-black/40 border border-cyan-400/20 outline-none"
          />
        </div>
        <div className="flex flex-col gap-2 mt-2">
          <button
            onClick={handleStartScan}
            disabled={scanning}
            className="flex items-center justify-center gap-2 w-full py-2.5 rounded text-xs font-mono font-semibold"
            style={{ background: "rgba(0,212,255,0.15)", border: "1px solid rgba(0,212,255,0.4)", color: "#00d4ff" }}
          >
            {scanning ? <><RefreshCw size={13} className="animate-spin" /> Scanning Host…</> : <><Play size={13} /> Launch Nmap Audit</>}
          </button>
          <button
            onClick={handleStopScan}
            disabled={!scanning}
            className="flex items-center justify-center gap-2 w-full py-2.5 rounded text-xs font-mono border border-red-500/40 text-red-400 hover:bg-red-500/10"
          >
            <Square size={13} /> Abort
          </button>
        </div>
      </GlassCard>

      <GlassCard className="lg:col-span-4 flex flex-col overflow-hidden h-[500px] lg:h-full">
        <div className="flex items-center gap-2 px-4 py-3 border-b border-cyan-400/15">
          <Terminal size={14} className="text-cyan-400" />
          <SectionLabel>Live Telemetry Console</SectionLabel>
        </div>
        <div ref={termRef} className="flex-1 overflow-y-auto p-4 space-y-1 text-[11px] font-mono bg-black/50">
          {lines.length === 0 ? (
            <span className="text-slate-600">$ Ready — launch an audit to stream live telemetry...</span>
          ) : (
            lines.map((l, i) => <div key={i} className="text-[#98c379]">{l}</div>)
          )}
        </div>
      </GlassCard>

      <GlassCard className="lg:col-span-5 flex flex-col overflow-hidden h-[500px] lg:h-full">
        <div className="flex items-center gap-2 px-4 py-3 border-b border-cyan-400/15">
          <BarChart2 size={14} className="text-cyan-400" />
          <SectionLabel>Discovered Ports & Matrix</SectionLabel>
        </div>
        <div className="flex-1 overflow-y-auto w-full">
          <table className="w-full text-[11px] font-mono">
            <thead className="sticky top-0 bg-[#0a1220] border-b border-white/10">
              <tr>
                {["Port", "Service", "Version", "State"].map(h => (
                  <th key={h} className="text-left text-slate-400 py-2 px-3 font-normal">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {ports.map((p, i) => (
                <tr key={i} className="border-b border-white/5">
                  <td className="py-2 px-3 text-cyan-400">{p.port || p.portid}</td>
                  <td className="py-2 px-3 text-slate-300">{p.service || p.name}</td>
                  <td className="py-2 px-3 text-slate-400">{p.version || p.product || "open"}</td>
                  <td className="py-2 px-3"><SeverityBadge level={p.state || "Open"} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="border-t border-violet-500/20 p-4 bg-violet-950/20">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] font-mono text-violet-400 uppercase tracking-wider font-semibold">JARVIS Intelligence</span>
            <button onClick={handleAnalyze} className="text-[11px] font-mono border border-violet-500/40 text-violet-300 px-3 py-1 rounded hover:bg-violet-500/10">
              <Zap size={11} className="inline mr-1" /> Analyze
            </button>
          </div>
          {jarvisResponse && (
            <div className="text-[11px] font-mono text-slate-300 whitespace-pre-wrap max-h-36 overflow-y-auto">
              {jarvisResponse}
            </div>
          )}
        </div>
      </GlassCard>
    </div>
  );
}

// ─── Screen 3: Live Wireshark Sniffer (With JARVIS Packet Inspection) ──────────

interface NetworkAdapter {
  id: string;
  name: string;
  ip: string;
  is_up: boolean;
  is_live: boolean;
  bytes_recv: number;
}

function WiresharkSniffer() {
  const [capturing, setCapturing] = useState(false);
  const [packetList, setPacketList] = useState<any[]>([]);
  const [selected, setSelected] = useState<any>(null);
  const [bpf, setBpf] = useState("");
  const [interfaces, setInterfaces] = useState<NetworkAdapter[]>([]);
  const [selectedIface, setSelectedIface] = useState("");
  const [packetCount, setPacketCount] = useState(0);
  const [jarvisAnalysis, setJarvisAnalysis] = useState("");
  const [analyzing, setAnalyzing] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    fetch("/api/wireshark/interfaces")
      .then((res) => res.json())
      .then((data) => {
        if (data && Array.isArray(data.interfaces) && data.interfaces.length > 0) {
          setInterfaces(data.interfaces);
          const live = data.interfaces.find((i: NetworkAdapter) => i.is_live);
          setSelectedIface(live ? live.id : data.interfaces[0].id);
        } else {
          const fallback = [{ id: "default", name: "Default Adapter", ip: "127.0.0.1", is_up: true, is_live: true, bytes_recv: 0 }];
          setInterfaces(fallback);
          setSelectedIface("default");
        }
      })
      .catch(() => {
        const fallback = [{ id: "default", name: "Local Network", ip: "127.0.0.1", is_up: true, is_live: true, bytes_recv: 0 }];
        setInterfaces(fallback);
        setSelectedIface("default");
      });
  }, []);

  function toggleCapture() {
    if (capturing) {
      if (wsRef.current) {
        wsRef.current.send(JSON.stringify({ action: "STOP_CAPTURE" }));
        wsRef.current.close();
      }
      setCapturing(false);
    } else {
      setCapturing(true);
      setPacketList([]);
      setPacketCount(0);
      setJarvisAnalysis("");
      const ws = new WebSocket(`${WS_BASE}/ws/wireshark`);
      wsRef.current = ws;

      ws.onopen = () => {
        ws.send(JSON.stringify({
          action: "START_CAPTURE",
          interface: selectedIface,
          filter: bpf,
        }));
      };

      ws.onmessage = (event) => {
        try {
          const raw = JSON.parse(event.data);
          const p = raw.packet || raw.data || raw.payload || raw;
          
          if (p && (p.src || p.source || p.src_ip || p.proto || p.protocol || raw.type === "PACKET")) {
            const normalizedPacket = {
              num: p.num ?? p.number ?? p.no ?? packetList.length + 1,
              time: p.time || p.timestamp || new Date().toLocaleTimeString(),
              src: p.src || p.source || p.src_ip || p.ip_src || "127.0.0.1",
              dst: p.dst || p.destination || p.dst_ip || p.ip_dst || "127.0.0.1",
              proto: (p.proto || p.protocol || "TCP").toUpperCase(),
              len: p.len ?? p.length ?? p.size ?? 64,
              info: p.info || p.summary || p.description || "Ethernet / IP Frame"
            };

            setPacketCount((c) => c + 1);
            setPacketList((prev) => [normalizedPacket, ...prev.slice(0, 199)]);
          }
        } catch (e) {}
      };

      ws.onerror = () => setCapturing(false);
      ws.onclose = () => setCapturing(false);
    }
  }

  function analyzeWithJarvis() {
    if (!packetList.length && !selected) return;
    setAnalyzing(true);
    setJarvisAnalysis("");
    const contextData = {
      selected_frame: selected,
      sample_stream: packetList.slice(0, 15)
    };
    streamJarvis("Analyze these network packets for suspicious protocol traffic, brute force, or anomalies:", contextData, (chunk) => {
      setJarvisAnalysis(prev => prev + chunk);
    }, () => setAnalyzing(false));
  }

  const activeAdapterObj = interfaces.find(i => i.id === selectedIface);

  return (
    <div className="flex flex-col gap-4 w-full h-full min-h-[calc(100vh-100px)]">
      <GlassCard className="p-4 flex items-center gap-3 flex-wrap">
        <div className="flex flex-col">
          <label className="text-[10px] font-mono text-slate-400 mb-1">Network Interface</label>
          <select
            value={selectedIface}
            onChange={e => setSelectedIface(e.target.value)}
            className="rounded px-3 py-2 text-xs font-mono text-cyan-300 bg-[#06090e] border border-cyan-400/20 outline-none min-w-[240px]"
          >
            {interfaces.map((iface) => (
              <option key={iface.id} value={iface.id}>
                {iface.is_live ? "● [LIVE] " : "○ "}
                {iface.name} ({iface.ip})
              </option>
            ))}
          </select>
        </div>

        <div className="flex items-center gap-2 px-3 py-2 rounded bg-black/40 border border-white/10 mt-4">
          <Radio size={13} className={activeAdapterObj?.is_live ? "text-green-400 animate-pulse" : "text-slate-500"} />
          <span className="text-xs font-mono text-slate-300">
            {activeAdapterObj?.is_live ? "TRAFFIC ACTIVE" : "IDLE / STANDBY"}
          </span>
          <span className="text-[11px] font-mono text-cyan-400">({activeAdapterObj?.ip || "0.0.0.0"})</span>
        </div>

        <div className="flex-1 flex flex-col min-w-[200px]">
          <label className="text-[10px] font-mono text-slate-400 mb-1">Berkeley Packet Filter (BPF)</label>
          <input
            value={bpf}
            onChange={e => setBpf(e.target.value)}
            placeholder="tcp or udp or port 80 or host 192.168.1.1"
            className="rounded px-3 py-2 text-xs font-mono text-cyan-300 bg-black/40 border border-cyan-400/20 outline-none"
          />
        </div>

        <div className="flex gap-2 mt-4">
          <button
            onClick={toggleCapture}
            className="flex items-center gap-2 px-4 py-2 rounded text-xs font-mono font-semibold"
            style={{
              background: capturing ? "rgba(239,68,68,0.15)" : "rgba(34,197,94,0.15)",
              border: capturing ? "1px solid rgba(239,68,68,0.4)" : "1px solid rgba(34,197,94,0.4)",
              color: capturing ? "#ef4444" : "#22c55e",
            }}
          >
            {capturing ? <><Square size={13} /> Stop Sniffer</> : <><Play size={13} /> Start Sniffer</>}
          </button>
          <button
            onClick={analyzeWithJarvis}
            className="flex items-center gap-1.5 px-4 py-2 rounded text-xs font-mono bg-violet-500/20 border border-violet-500/40 text-violet-300 hover:bg-violet-500/30"
          >
            <Zap size={13} /> {analyzing ? "Analyzing…" : "Analyze with JARVIS"}
          </button>
        </div>
      </GlassCard>

      <div className="flex items-center justify-between px-2 text-xs font-mono text-slate-400">
        <div className="flex items-center gap-2">
          {capturing && <PulseDot color="bg-green-400" />}
          <span>Status: {capturing ? "Streaming live adapter packets..." : "Capture Idle"}</span>
        </div>
        <div>Captured Packets: <span className="text-cyan-400 font-bold">{packetCount}</span></div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 flex-1 min-h-[350px]">
        <GlassCard className="lg:col-span-8 overflow-hidden">
          <div className="overflow-y-auto h-full w-full max-h-[450px]">
            <table className="w-full text-[11px] font-mono">
              <thead className="sticky top-0 bg-[#0a1220] border-b border-white/10">
                <tr>
                  {["#", "Timestamp", "Source IP", "Destination IP", "Protocol", "Length", "Packet Information"].map(h => (
                    <th key={h} className="text-left text-slate-400 py-2.5 px-3 font-normal">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {packetList.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="py-12 text-center text-slate-600">
                      {capturing ? "Listening for network frames..." : "No packets captured. Select an active network adapter and start sniffer."}
                    </td>
                  </tr>
                ) : (
                  packetList.map((p, i) => (
                    <tr
                      key={i}
                      onClick={() => setSelected(p)}
                      className={`border-b border-white/5 cursor-pointer ${selected === p ? "bg-cyan-400/15 text-cyan-200" : "hover:bg-white/[0.03]"}`}
                    >
                      <td className="py-2 px-3 text-slate-500">{p.num || i + 1}</td>
                      <td className="py-2 px-3 text-slate-400">{p.time}</td>
                      <td className="py-2 px-3 text-cyan-400">{p.src}</td>
                      <td className="py-2 px-3 text-violet-400">{p.dst}</td>
                      <td className="py-2 px-3">
                        <span className="px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-400/20 text-[10px]">
                          {p.proto}
                        </span>
                      </td>
                      <td className="py-2 px-3 text-slate-400">{p.len} B</td>
                      <td className="py-2 px-3 text-slate-300 truncate max-w-[240px]">{p.info}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </GlassCard>

        <GlassCard className="lg:col-span-4 p-4 flex flex-col border-violet-500/20 bg-violet-950/20">
          <SectionLabel>JARVIS Traffic Intelligence</SectionLabel>
          <div className="flex-1 overflow-y-auto mt-2 text-xs font-mono text-slate-300 whitespace-pre-wrap leading-relaxed">
            {jarvisAnalysis ? (
              jarvisAnalysis
            ) : (
              <span className="text-slate-500">
                Click <strong>"Analyze with JARVIS"</strong> to run real-time threat analysis over captured frames and inspect for port scanning, cleartext credential leaks, or unusual TCP flags.
              </span>
            )}
          </div>
        </GlassCard>
      </div>
    </div>
  );
}

// ─── Screen 4: Live Nuclei DAST (With JARVIS CVE Exploit Analysis) ─────────────

function NucleiDASTScanner() {
  const [targetUrl, setTargetUrl] = useState("http://127.0.0.1:8000");
  const [running, setRunning] = useState(false);
  const [vulns, setVulns] = useState<any[]>([]);
  const [selected, setSelected] = useState<any>(null);
  const [jarvisExploitGuide, setJarvisExploitGuide] = useState("");
  const [analyzing, setAnalyzing] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  function handleRunNuclei() {
    setRunning(true);
    setVulns([]);
    setJarvisExploitGuide("");
    const ws = new WebSocket(`${WS_BASE}/ws/nuclei`);
    wsRef.current = ws;

    ws.onopen = () => {
      ws.send(JSON.stringify({
        action: "RUN_NUCLEI",
        target: targetUrl,
        severity: "cves,vulnerabilities",
      }));
    };

    ws.onmessage = (event) => {
      try {
        const raw = JSON.parse(event.data);
        if (raw.type === "FINDING" || raw.finding || raw.template || raw.data) {
          const item = raw.data || raw.finding || raw;
          const normalized = {
            template: item.template || item.template_id || item.id || item.name || "CVE-Finding",
            severity: (item.severity || item.level || "Medium").toUpperCase(),
            url: item.url || item.matched || item.host || targetUrl
          };
          setVulns(prev => [...prev, normalized]);
        } else if (raw.type === "NUCLEI_COMPLETE") {
          setRunning(false);
          ws.close();
        }
      } catch (e) {}
    };

    ws.onerror = () => setRunning(false);
    ws.onclose = () => setRunning(false);
  }

  function analyzeFindingWithJarvis(finding: any) {
    setSelected(finding);
    setAnalyzing(true);
    setJarvisExploitGuide("");
    streamJarvis(`Analyze this vulnerability finding: ${finding.template} at ${finding.url}. Detail CVSS scoring, attack mechanics, and provide copyable CLI remediation commands.`, { finding }, (chunk) => {
      setJarvisExploitGuide(prev => prev + chunk);
    }, () => setAnalyzing(false));
  }

  return (
    <div className="flex flex-col gap-4 w-full h-full min-h-[calc(100vh-100px)]">
      <GlassCard className="p-3 flex items-center gap-3 flex-wrap">
        <input
          value={targetUrl}
          onChange={e => setTargetUrl(e.target.value)}
          className="flex-1 rounded px-3 py-2 text-xs font-mono text-cyan-300 bg-black/40 border border-cyan-400/20 outline-none"
        />
        <button
          onClick={handleRunNuclei}
          disabled={running}
          className="flex items-center gap-2 px-4 py-2 rounded text-xs font-mono font-semibold"
          style={{ background: "rgba(0,212,255,0.15)", border: "1px solid rgba(0,212,255,0.4)", color: "#00d4ff" }}
        >
          {running ? <><RefreshCw size={13} className="animate-spin" /> Scanning Target…</> : <><Target size={13} /> Run Nuclei Scan</>}
        </button>
        <button
          onClick={() => exportReport("Nuclei", vulns, "html")}
          className="flex items-center gap-2 px-3 py-2 rounded text-xs font-mono border border-slate-700 text-slate-300 hover:bg-white/5"
        >
          <Download size={13} /> Export
        </button>
      </GlassCard>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 flex-1 min-h-[400px]">
        <GlassCard className="lg:col-span-7 overflow-hidden">
          <div className="overflow-y-auto h-full w-full max-h-[450px]">
            <table className="w-full text-[11px] font-mono">
              <thead className="sticky top-0 bg-[#0a1220] border-b border-white/10">
                <tr>
                  {["Template / CVE", "Severity", "Matched URL", "Action"].map(h => (
                    <th key={h} className="text-left text-slate-400 py-2.5 px-3 font-normal">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {vulns.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="py-12 text-center text-slate-500">
                      {running ? "Scanning target for known vulnerabilities..." : "No findings discovered yet. Run a scan to discover CVEs."}
                    </td>
                  </tr>
                ) : (
                  vulns.map((v, i) => (
                    <tr key={i} className={`border-b border-white/5 ${selected === v ? "bg-violet-500/15" : "hover:bg-white/[0.03]"}`}>
                      <td className="py-2 px-3 text-amber-400">{v.template}</td>
                      <td className="py-2 px-3"><SeverityBadge level={v.severity} /></td>
                      <td className="py-2 px-3 text-slate-300 truncate max-w-[200px]">{v.url}</td>
                      <td className="py-2 px-3">
                        <button
                          onClick={() => analyzeFindingWithJarvis(v)}
                          className="px-2 py-1 bg-violet-500/20 text-violet-300 border border-violet-500/30 rounded text-[10px] hover:bg-violet-500/30 flex items-center gap-1"
                        >
                          <Zap size={10} /> Analyze
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </GlassCard>

        <GlassCard className="lg:col-span-5 p-4 flex flex-col border-violet-500/20 bg-violet-950/20">
          <SectionLabel>JARVIS Tactical CVE Remediation Engine</SectionLabel>
          <div className="flex-1 overflow-y-auto mt-2 text-xs font-mono text-slate-300 whitespace-pre-wrap leading-relaxed max-h-[400px]">
            {jarvisExploitGuide ? (
              jarvisExploitGuide
            ) : (
              <span className="text-slate-500">
                Click <strong>"Analyze"</strong> on any discovered CVE finding to generate technical remediation steps, patch guidance, and threat mechanics.
              </span>
            )}
          </div>
        </GlassCard>
      </div>
    </div>
  );
}

// ─── Screen 5: Live Web Fuzzer (With JARVIS Exposure Analysis) ────────────────

function WebFuzzer() {
  const [targetUrl, setTargetUrl] = useState("http://127.0.0.1:8000/FUZZ");
  const [fuzzing, setFuzzing] = useState(false);
  const [routes, setRoutes] = useState<any[]>([]);
  const [fuzzAnalysis, setFuzzAnalysis] = useState("");
  const [analyzing, setAnalyzing] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  function handleStartFuzz() {
    setFuzzing(true);
    setRoutes([]);
    setFuzzAnalysis("");
    const ws = new WebSocket(`${WS_BASE}/ws/fuzzer`);
    wsRef.current = ws;

    ws.onopen = () => {
      ws.send(JSON.stringify({
        action: "RUN_FUZZ",
        url: targetUrl,
      }));
    };

    ws.onmessage = (event) => {
      try {
        const raw = JSON.parse(event.data);
        if (raw.type === "ROUTE_DISCOVERED" || raw.route || raw.data || raw.status_code) {
          const item = raw.data || raw.route || raw;
          const normalized = {
            url: item.url || item.path || targetUrl.replace("FUZZ", String(item.input || "")),
            status: Number(item.status || item.status_code || item.code || 200),
            length: Number(item.length || item.size || item.len || 0)
          };
          setRoutes(prev => [...prev, normalized]);
        } else if (raw.type === "FUZZ_COMPLETE") {
          setFuzzing(false);
          ws.close();
        }
      } catch (e) {}
    };

    ws.onerror = () => setFuzzing(false);
    ws.onclose = () => setFuzzing(false);
  }

  function analyzeAttackSurfaceWithJarvis() {
    if (!routes.length) return;
    setAnalyzing(true);
    setFuzzAnalysis("");
    streamJarvis("Analyze these exposed web routes for critical information disclosure, backup exposures, and sensitive admin endpoints:", { routes, target: targetUrl }, (chunk) => {
      setFuzzAnalysis(prev => prev + chunk);
    }, () => setAnalyzing(false));
  }

  return (
    <div className="flex flex-col gap-4 w-full h-full min-h-[calc(100vh-100px)]">
      <GlassCard className="p-3 flex items-center gap-3 flex-wrap">
        <input
          value={targetUrl}
          onChange={e => setTargetUrl(e.target.value)}
          placeholder="http://127.0.0.1:8000/FUZZ"
          className="flex-1 rounded px-3 py-2 text-xs font-mono text-cyan-300 bg-black/40 border border-cyan-400/20 outline-none"
        />
        <button
          onClick={handleStartFuzz}
          disabled={fuzzing}
          className="flex items-center gap-2 px-4 py-2 rounded text-xs font-mono font-semibold"
          style={{ background: "rgba(0,212,255,0.15)", border: "1px solid rgba(0,212,255,0.4)", color: "#00d4ff" }}
        >
          {fuzzing ? <><RefreshCw size={13} className="animate-spin" /> Fuzzing Routes…</> : <><Zap size={13} /> Start Fuzzing</>}
        </button>
        <button
          onClick={analyzeAttackSurfaceWithJarvis}
          className="flex items-center gap-1.5 px-4 py-2 rounded text-xs font-mono bg-violet-500/20 border border-violet-500/40 text-violet-300 hover:bg-violet-500/30"
        >
          <Bot size={13} /> {analyzing ? "Evaluating…" : "Analyze Attack Surface"}
        </button>
        <button
          onClick={() => exportReport("Fuzzer", routes, "html")}
          className="flex items-center gap-2 px-3 py-2 rounded text-xs font-mono border border-slate-700 text-slate-300 hover:bg-white/5"
        >
          <Download size={13} /> Export
        </button>
      </GlassCard>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 flex-1 min-h-[400px]">
        <GlassCard className="lg:col-span-7 overflow-hidden">
          <div className="overflow-y-auto h-full w-full max-h-[450px]">
            <table className="w-full text-[11px] font-mono">
              <thead className="sticky top-0 bg-[#0a1220] border-b border-white/10">
                <tr>
                  {["Discovered URL", "Status", "Size"].map(h => (
                    <th key={h} className="text-left text-slate-400 py-2.5 px-4 font-normal">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {routes.length === 0 ? (
                  <tr>
                    <td colSpan={3} className="py-12 text-center text-slate-500">
                      {fuzzing ? "Fuzzing endpoints..." : "No routes discovered yet. Click Start Fuzzing to begin discovery."}
                    </td>
                  </tr>
                ) : (
                  routes.map((r, i) => (
                    <tr key={i} className="border-b border-white/5">
                      <td className="py-2 px-4 text-cyan-300">{r.url}</td>
                      <td className="py-2 px-4"><StatusBadge code={r.status} /></td>
                      <td className="py-2 px-4 text-slate-400">{r.length} B</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </GlassCard>

        <GlassCard className="lg:col-span-5 p-4 flex flex-col border-violet-500/20 bg-violet-950/20">
          <SectionLabel>JARVIS Attack Surface Evaluation</SectionLabel>
          <div className="flex-1 overflow-y-auto mt-2 text-xs font-mono text-slate-300 whitespace-pre-wrap leading-relaxed max-h-[400px]">
            {fuzzAnalysis ? (
              fuzzAnalysis
            ) : (
              <span className="text-slate-500">
                Click <strong>"Analyze Attack Surface"</strong> after fuzzing to identify exposed `.env`, backup archives, secret keys, and admin consoles.
              </span>
            )}
          </div>
        </GlassCard>
      </div>
    </div>
  );
}

// ─── Screen 6: Steganography Analyzer ──────────────────────────────────────────

function SteganographyAnalyzer() {
  const [tab, setTab] = useState<"encode" | "decode">("encode");
  const [message, setMessage] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [result, setResult] = useState<string>("");
  const [processing, setProcessing] = useState(false);
  const [planeImg, setPlaneImg] = useState<string>("");

  async function handleProcess() {
    if (!file) {
      alert("Please select an image file first.");
      return;
    }
    setProcessing(true);
    setResult("");
    const formData = new FormData();
    formData.append("file", file);
    if (tab === "encode") formData.append("message", message);

    const endpoint = tab === "encode" ? "/api/steg/encode" : "/api/steg/decode";
    try {
      const res = await fetch(endpoint, { method: "POST", body: formData });
      if (res.ok) {
        if (tab === "encode") {
          const blob = await res.blob();
          const url = window.URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = url;
          a.download = "stego_carrier.png";
          document.body.appendChild(a);
          a.click();
          a.remove();
          setResult("Secret payload successfully encoded into carrier image!");
        } else {
          const data = await res.json();
          setResult(data.message || "Decoded string is empty.");
        }
      } else {
        const err = await res.json();
        setResult(`[!] Error: ${err.message || "Failed to process image."}`);
      }
    } catch (e: any) {
      setResult(`[!] Request error: ${e.message}`);
    } finally {
      setProcessing(false);
    }
  }

  async function inspectBitPlane(planeIndex: number) {
    if (!file) return;
    const formData = new FormData();
    formData.append("file", file);
    formData.append("plane", planeIndex.toString());
    const res = await fetch("/api/steg/analyze-plane", { method: "POST", body: formData });
    if (res.ok) {
      const blob = await res.blob();
      setPlaneImg(window.URL.createObjectURL(blob));
    }
  }

  return (
    <div className="flex flex-col gap-4 w-full">
      <div className="flex gap-2">
        <button
          onClick={() => setTab("encode")}
          className={`px-4 py-2 rounded text-xs font-mono ${tab === "encode" ? "bg-cyan-500/20 text-cyan-400 border border-cyan-400/40" : "text-slate-500 border border-transparent"}`}
        >
          🔒 LSB Encode
        </button>
        <button
          onClick={() => setTab("decode")}
          className={`px-4 py-2 rounded text-xs font-mono ${tab === "decode" ? "bg-cyan-500/20 text-cyan-400 border border-cyan-400/40" : "text-slate-500 border border-transparent"}`}
        >
          🔓 LSB Decode
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <GlassCard className="p-5 flex flex-col gap-4">
          <SectionLabel>{tab === "encode" ? "Select Carrier Image (PNG)" : "Select Stego Image"}</SectionLabel>
          <input
            type="file"
            accept="image/*"
            onChange={e => {
              const f = e.target.files?.[0] || null;
              setFile(f);
              if (f) inspectBitPlane(0);
            }}
            className="text-xs text-slate-300 file:mr-3 file:py-1.5 file:px-3 file:rounded file:border-0 file:text-xs file:font-mono file:bg-cyan-500/20 file:text-cyan-300"
          />
          {tab === "encode" && (
            <textarea
              value={message}
              onChange={e => setMessage(e.target.value)}
              rows={5}
              placeholder="Enter secret message to hide..."
              className="w-full p-2.5 bg-black/40 border border-cyan-400/20 rounded text-xs text-cyan-300 font-mono outline-none"
            />
          )}
          <button
            onClick={handleProcess}
            disabled={processing}
            className="px-4 py-2.5 bg-cyan-500/20 border border-cyan-400/40 text-cyan-400 rounded text-xs font-mono font-semibold hover:bg-cyan-500/30"
          >
            {processing ? "Processing…" : tab === "encode" ? "Encode & Download Stego Image" : "Extract Hidden Secret"}
          </button>
          {result && (
            <div className="p-3 bg-black/60 border border-cyan-400/30 rounded text-xs font-mono text-green-300 whitespace-pre-wrap">
              {result}
            </div>
          )}
        </GlassCard>

        <GlassCard className="p-5 flex flex-col gap-4">
          <SectionLabel>Bit-Plane Inspection Canvas</SectionLabel>
          <div className="flex gap-1.5 flex-wrap">
            {Array.from({ length: 8 }, (_, i) => (
              <button
                key={i}
                onClick={() => inspectBitPlane(i)}
                className="px-2.5 py-1 text-[10px] font-mono bg-black/40 border border-white/10 rounded hover:border-cyan-400 text-slate-300"
              >
                Plane {i}
              </button>
            ))}
          </div>
          {planeImg ? (
            <img src={planeImg} alt="Bit Plane" className="w-full h-48 object-contain rounded bg-black/40 border border-white/5" />
          ) : (
            <div className="w-full h-48 flex items-center justify-center text-xs font-mono text-slate-600 bg-black/40 rounded border border-white/5">
              Upload an image to inspect bit-plane patterns
            </div>
          )}
        </GlassCard>
      </div>
    </div>
  );
}

// ─── Screen 7: DUAL WORKBENCH (JARVIS Tactical AI & Security Assistant Side-by-Side) ─

const KNOWLEDGE_TOPICS = [
  { title: "OWASP Top 10", prompt: "Explain the OWASP Top 10 vulnerabilities and standard remediation controls." },
  { title: "Active Directory Hardening", prompt: "What are the key defenses against Kerberoasting and DCSync in Active Directory?" },
  { title: "Zero Trust Architecture", prompt: "Explain the implementation principles of Zero Trust Architecture." },
  { title: "TLS 1.3 vs 1.2 Handshake", prompt: "Detail the cryptographic improvements of TLS 1.3 over TLS 1.2." },
];

function JarvisAndAssistantDualWorkbench() {
  const [jarvisMsgs, setJarvisMsgs] = useState<{ role: string; content: string; time: string }[]>([
    { role: "assistant", content: "JARVIS Threat Copilot online. Telemetry ingestion ready.", time: new Date().toLocaleTimeString() }
  ]);
  const [jarvisInput, setJarvisInput] = useState("");
  const [jarvisLoading, setJarvisLoading] = useState(false);

  const [assistantMsgs, setAssistantMsgs] = useState<{ role: string; content: string; time: string }[]>([
    { role: "assistant", content: "Security Assistant Desk active. Ask any cybersecurity question or click a topic below.", time: new Date().toLocaleTimeString() }
  ]);
  const [assistantInput, setAssistantInput] = useState("");
  const [assistantLoading, setAssistantLoading] = useState(false);

  function handleSendJarvis() {
    if (!jarvisInput.trim()) return;
    const now = new Date().toLocaleTimeString();
    const userMsg = { role: "user", content: jarvisInput, time: now };
    setJarvisMsgs(prev => [...prev, userMsg]);
    setJarvisInput("");
    setJarvisLoading(true);

    let assistantMsg = { role: "assistant", content: "", time: now };
    setJarvisMsgs(prev => [...prev, assistantMsg]);

    streamJarvis(userMsg.content, {}, (token) => {
      setJarvisMsgs(prev => {
        const next = [...prev];
        next[next.length - 1].content += token;
        return next;
      });
    }, () => setJarvisLoading(false));
  }

  async function handleSendAssistant(text?: string) {
    const query = text || assistantInput;
    if (!query.trim()) return;
    const now = new Date().toLocaleTimeString();
    setAssistantMsgs(prev => [...prev, { role: "user", content: query, time: now }]);
    if (!text) setAssistantInput("");
    setAssistantLoading(true);

    try {
      const res = await fetch("/api/assistant/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query }),
      });
      const data = await res.json();
      setAssistantMsgs(prev => [...prev, {
        role: "assistant",
        content: data.answer || "No response received.",
        time: new Date().toLocaleTimeString()
      }]);
    } catch (e: any) {
      setAssistantMsgs(prev => [...prev, {
        role: "assistant",
        content: `[!] Connection error: ${e.message}`,
        time: new Date().toLocaleTimeString()
      }]);
    } finally {
      setAssistantLoading(false);
    }
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 w-full h-full min-h-[calc(100vh-100px)]">
      {/* LEFT PANEL: JARVIS Tactical AI */}
      <GlassCard className="flex flex-col overflow-hidden h-[600px] lg:h-full border-violet-500/20">
        <div className="px-4 py-3 border-b border-violet-500/20 bg-violet-950/30 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Bot size={15} className="text-violet-400" />
            <span className="text-xs font-mono font-semibold text-violet-300 uppercase tracking-wider">JARVIS Tactical Copilot</span>
          </div>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-violet-500/20 text-violet-300 border border-violet-500/30">
            Realtime Stream
          </span>
        </div>

        <div className="flex-1 overflow-y-auto p-4 space-y-3 font-mono text-xs">
          {jarvisMsgs.map((m, i) => (
            <div key={i} className={`p-3 rounded ${m.role === "user" ? "bg-cyan-950/40 border border-cyan-400/20 ml-6 text-cyan-300" : "bg-violet-950/30 border border-violet-500/20 mr-6 text-slate-200"}`}>
              <div className="text-[9px] text-slate-500 mb-1">{m.role.toUpperCase()} · {m.time}</div>
              <div className="whitespace-pre-wrap leading-relaxed">{m.content}</div>
            </div>
          ))}
          {jarvisLoading && <div className="text-xs font-mono text-violet-400 animate-pulse">JARVIS streaming response…</div>}
        </div>

        <div className="p-3 border-t border-violet-500/20 bg-black/40 flex gap-2">
          <input
            value={jarvisInput}
            onChange={e => setJarvisInput(e.target.value)}
            onKeyDown={e => e.key === "Enter" && handleSendJarvis()}
            placeholder="Ask JARVIS regarding live telemetry, CVEs, or attack tactics..."
            className="flex-1 bg-black/50 border border-violet-500/30 rounded px-3 py-2 text-xs font-mono text-slate-200 outline-none focus:border-violet-400"
          />
          <button
            onClick={handleSendJarvis}
            className="px-4 py-2 bg-violet-500/20 border border-violet-500/40 text-violet-300 rounded text-xs font-mono hover:bg-violet-500/30"
          >
            <Send size={13} />
          </button>
        </div>
      </GlassCard>

      {/* RIGHT PANEL: Security Assistant Knowledge Desk */}
      <GlassCard className="flex flex-col overflow-hidden h-[600px] lg:h-full border-cyan-400/20">
        <div className="px-4 py-3 border-b border-cyan-400/15 bg-cyan-950/20 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <BookOpen size={15} className="text-cyan-400" />
            <span className="text-xs font-mono font-semibold text-cyan-300 uppercase tracking-wider">Security Assistant Desk</span>
          </div>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-400/30">
            Knowledge Engine
          </span>
        </div>

        <div className="p-2 border-b border-white/5 bg-black/20 flex gap-1.5 overflow-x-auto">
          {KNOWLEDGE_TOPICS.map((topic, i) => (
            <button
              key={i}
              onClick={() => handleSendAssistant(topic.prompt)}
              className="text-[10px] font-mono px-2.5 py-1 rounded bg-cyan-500/10 border border-cyan-400/20 text-cyan-300 hover:bg-cyan-500/20 whitespace-nowrap"
            >
              {topic.title}
            </button>
          ))}
        </div>

        <div className="flex-1 overflow-y-auto p-4 space-y-3 font-mono text-xs">
          {assistantMsgs.map((m, i) => (
            <div key={i} className={`p-3 rounded ${m.role === "user" ? "bg-slate-900 border border-slate-700 ml-6 text-slate-200" : "bg-cyan-950/30 border border-cyan-400/20 mr-6 text-cyan-100"}`}>
              <div className="text-[9px] text-slate-500 mb-1">{m.role.toUpperCase()} · {m.time}</div>
              <div className="whitespace-pre-wrap leading-relaxed">{m.content}</div>
            </div>
          ))}
          {assistantLoading && <div className="text-xs font-mono text-cyan-400 animate-pulse">Security Assistant researching knowledge base…</div>}
        </div>

        <div className="p-3 border-t border-cyan-400/20 bg-black/40 flex gap-2">
          <input
            value={assistantInput}
            onChange={e => setAssistantInput(e.target.value)}
            onKeyDown={e => e.key === "Enter" && handleSendAssistant()}
            placeholder="Ask Security Assistant (e.g. How to mitigate XSS in React?)..."
            className="flex-1 bg-black/50 border border-cyan-400/30 rounded px-3 py-2 text-xs font-mono text-slate-200 outline-none focus:border-cyan-400"
          />
          <button
            onClick={() => handleSendAssistant()}
            className="px-4 py-2 bg-cyan-500/20 border border-cyan-400/40 text-cyan-300 rounded text-xs font-mono hover:bg-cyan-500/30"
          >
            <Send size={13} />
          </button>
        </div>
      </GlassCard>
    </div>
  );
}

// ─── Main Navigation & Wrapper ─────────────────────────────────────────────────

interface TabItem {
  id: "dashboard" | "nmap" | "wireshark" | "nuclei" | "fuzzer" | "steg" | "ai_desk";
  emoji: string;
  label: string;
  violet?: boolean;
}

const TABS: TabItem[] = [
  { id: "dashboard", emoji: "📊", label: "SOC Dashboard" },
  { id: "nmap", emoji: "🛡️", label: "Nmap Scanner" },
  { id: "wireshark", emoji: "🦈", label: "Wireshark Sniffer" },
  { id: "nuclei", emoji: "🎯", label: "Nuclei DAST" },
  { id: "fuzzer", emoji: "⚡", label: "Web Fuzzer" },
  { id: "steg", emoji: "🧩", label: "Steganography" },
  { id: "ai_desk", emoji: "🤖", label: "JARVIS & Assistant", violet: true },
];

type TabId = TabItem["id"];

export default function App() {
  const [active, setActive] = useState<TabId>("dashboard");

  return (
    <div className="min-h-screen w-full bg-[#06090e] text-[#c9d4e8] flex flex-col font-sans">
      <nav className="sticky top-0 z-50 flex items-center justify-between px-4 h-16 w-full border-b border-[#00d4ff]/15 bg-[#06090e]/95 backdrop-blur-md">
        <div className="flex items-center gap-2.5 mr-4 flex-shrink-0">
          <div className="w-8 h-8 rounded-lg flex items-center justify-center bg-cyan-500/20 border border-cyan-400/40">
            <Shield size={16} className="text-cyan-400" />
          </div>
          <div className="text-sm font-semibold text-white font-mono">SecurOS</div>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-500/10 border border-cyan-400/20 text-cyan-400">
            SOC Suite
          </span>
        </div>

        <div className="flex items-center gap-1 overflow-x-auto flex-1 max-w-4xl">
          {TABS.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActive(tab.id)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-mono whitespace-nowrap transition-all ${
                active === tab.id
                  ? tab.violet
                    ? "bg-violet-500/20 text-violet-300 border border-violet-500/40"
                    : "bg-cyan-500/10 text-cyan-400 border border-cyan-400/30"
                  : "text-slate-400 border border-transparent hover:text-slate-200"
              }`}
            >
              <span>{tab.emoji}</span>
              <span>{tab.label}</span>
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2 ml-3 flex-shrink-0">
          <PulseDot />
          <span className="text-xs font-mono text-green-400">DEFCON 4</span>
        </div>
      </nav>

      <main className="flex-1 w-full max-w-[1680px] mx-auto p-4 md:p-6">
        {active === "dashboard" && <SOCDashboard />}
        {active === "nmap" && <NmapScanner />}
        {active === "wireshark" && <WiresharkSniffer />}
        {active === "nuclei" && <NucleiDASTScanner />}
        {active === "fuzzer" && <WebFuzzer />}
        {active === "steg" && <SteganographyAnalyzer />}
        {active === "ai_desk" && <JarvisAndAssistantDualWorkbench />}
      </main>
    </div>
  );
}