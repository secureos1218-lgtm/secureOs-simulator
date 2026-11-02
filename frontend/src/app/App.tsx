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
  BarChart2, FileDown, Check, BookOpen, Radio, ChevronRight,
  Layers, Code, Eye
} from "lucide-react";
import { exportReport, streamJarvis, queryAssistant, triggerFileDownload, API_BASE, WS_BASE } from "../services/api";

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
    CRITICAL: "bg-red-500/20 text-red-400 border-red-500/30",
    High: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    HIGH: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    Medium: "bg-amber-500/20 text-amber-400 border-amber-500/30",
    MEDIUM: "bg-amber-500/20 text-amber-400 border-amber-500/30",
    Low: "bg-green-500/20 text-green-400 border-green-500/30",
    LOW: "bg-green-500/20 text-green-400 border-green-500/30",
    Info: "bg-blue-500/20 text-blue-400 border-blue-500/30",
    INFO: "bg-blue-500/20 text-blue-400 border-blue-500/30",
    Open: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
    OPEN: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
    Filtered: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    FILTERED: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
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
    fetch(`${API_BASE}/api/history`)
      .then(res => res.json())
      .then(data => {
        if (data && data.history) setHistory(data.history);
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
  const [progress, setProgress] = useState(0);
  const [lines, setLines] = useState<string[]>([]);
  const [ports, setPorts] = useState<any[]>([]);
  const [selectedPort, setSelectedPort] = useState<any>(null);
  const [jarvisResponse, setJarvisResponse] = useState("");
  const wsRef = useRef<WebSocket | null>(null);
  const termRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    termRef.current?.scrollTo({ top: termRef.current.scrollHeight, behavior: "smooth" });
  }, [lines]);

  function handleStartScan() {
    setScanning(true);
    setProgress(5);
    setLines(["[+] Initiating Nmap socket stream..."]);
    setPorts([]);
    setSelectedPort(null);
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
        } else if (data.type === "PROGRESS_UPDATE") {
          setProgress(data.percent || 10);
        } else if (data.type === "PORT_DISCOVERED" || data.type === "port") {
          const p = data.port_data || data.data;
          if (p) {
            setPorts(prev => {
              const portKey = p.port || p.portid;
              if (prev.some(item => (item.port || item.portid) === portKey)) return prev;
              return [...prev, p];
            });
          }
        } else if (data.type === "SCAN_COMPLETE") {
          setScanning(false);
          setProgress(100);
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

  function handleAnalyze(portItem?: any) {
    const targetPorts = portItem ? [portItem] : ports;
    setJarvisResponse("");
    streamJarvis("Analyze these open ports and evaluate attack vectors, service exposures, and exploit potential:", { ports: targetPorts, target }, (chunk) => {
      setJarvisResponse(prev => prev + chunk);
    });
  }

  function downloadTerminalLogs() {
    triggerFileDownload(lines.join("\n"), `nmap_scan_${target.replace(/[^a-zA-Z0-9]/g, "_")}_${Date.now()}.log`);
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
            placeholder="127.0.0.1 or scanme.nmap.org"
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
            <option value="-sn">Ping Sweep Host Discovery (-sn)</option>
            <option value="-sV -sC -T4">Intense Script Audit (-sV -sC -T4)</option>
          </select>
        </div>
        <div>
          <label className="block text-[11px] font-mono text-slate-400 mb-1">Port Range</label>
          <input
            value={portRange}
            onChange={e => setPortRange(e.target.value)}
            placeholder="1-1000 or 80,443,8080"
            className="w-full rounded px-3 py-2 text-xs font-mono text-cyan-300 bg-black/40 border border-cyan-400/20 outline-none"
          />
        </div>

        {scanning && (
          <div className="space-y-1">
            <div className="flex justify-between text-[10px] font-mono text-cyan-400">
              <span>Scanning Progress</span>
              <span>{Math.round(progress)}%</span>
            </div>
            <div className="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
              <div
                className="bg-cyan-400 h-1.5 transition-all duration-300 rounded-full"
                style={{ width: `${progress}%` }}
              />
            </div>
          </div>
        )}

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
            className="flex items-center justify-center gap-2 w-full py-2.5 rounded text-xs font-mono border border-red-500/40 text-red-400 hover:bg-red-500/10 disabled:opacity-50"
          >
            <Square size={13} /> Abort
          </button>
          <div className="flex gap-2 mt-2">
            <button
              onClick={() => exportReport("Nmap", { ports, target }, "html")}
              className="flex-1 flex items-center justify-center gap-1.5 py-2 rounded text-[11px] font-mono border border-slate-700 text-slate-300 hover:bg-white/5"
            >
              <FileDown size={12} /> HTML
            </button>
            <button
              onClick={downloadTerminalLogs}
              className="flex-1 flex items-center justify-center gap-1.5 py-2 rounded text-[11px] font-mono border border-slate-700 text-slate-300 hover:bg-white/5"
            >
              <Download size={12} /> Logs
            </button>
          </div>
        </div>
      </GlassCard>

      <GlassCard className="lg:col-span-4 flex flex-col overflow-hidden h-[500px] lg:h-full">
        <div className="flex items-center justify-between px-4 py-3 border-b border-cyan-400/15">
          <div className="flex items-center gap-2">
            <Terminal size={14} className="text-cyan-400" />
            <SectionLabel>Live Telemetry Console</SectionLabel>
          </div>
          {scanning && <span className="text-[10px] font-mono text-cyan-400 animate-pulse">STREAM ACTIVE</span>}
        </div>
        <div ref={termRef} className="flex-1 overflow-y-auto p-4 space-y-1 text-[11px] font-mono bg-black/50">
          {lines.length === 0 ? (
            <span className="text-slate-600">$ Ready — launch an audit to stream live telemetry...</span>
          ) : (
            lines.map((l, i) => (
              <div
                key={i}
                className={l.includes("[!]") ? "text-red-400" : l.includes("[+]") ? "text-green-300 font-bold" : "text-[#98c379]"}
              >
                {l}
              </div>
            ))
          )}
        </div>
      </GlassCard>

      <GlassCard className="lg:col-span-5 flex flex-col overflow-hidden h-[500px] lg:h-full">
        <div className="flex items-center justify-between px-4 py-3 border-b border-cyan-400/15">
          <div className="flex items-center gap-2">
            <BarChart2 size={14} className="text-cyan-400" />
            <SectionLabel>Discovered Ports & Matrix</SectionLabel>
          </div>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-400/20">
            {ports.length} Open Ports
          </span>
        </div>
        <div className="flex-1 overflow-y-auto w-full max-h-[300px]">
          <table className="w-full text-[11px] font-mono">
            <thead className="sticky top-0 bg-[#0a1220] border-b border-white/10">
              <tr>
                {["Port", "Service", "Version", "State", "Action"].map(h => (
                  <th key={h} className="text-left text-slate-400 py-2 px-3 font-normal">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {ports.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-12 text-center text-slate-600">
                    {scanning ? "Scanning host for open ports..." : "No open ports discovered yet. Launch audit to begin."}
                  </td>
                </tr>
              ) : (
                ports.map((p, i) => (
                  <tr
                    key={i}
                    onClick={() => setSelectedPort(p)}
                    className={`border-b border-white/5 cursor-pointer ${selectedPort === p ? "bg-cyan-500/15" : "hover:bg-white/[0.03]"}`}
                  >
                    <td className="py-2 px-3 text-cyan-400 font-bold">{p.port || p.portid}</td>
                    <td className="py-2 px-3 text-slate-300">{p.service || p.name}</td>
                    <td className="py-2 px-3 text-slate-400 truncate max-w-[140px]">{p.version || p.product || "open"}</td>
                    <td className="py-2 px-3"><SeverityBadge level={p.state || "Open"} /></td>
                    <td className="py-2 px-3">
                      <button
                        onClick={(e) => { e.stopPropagation(); handleAnalyze(p); }}
                        className="text-[10px] px-2 py-0.5 rounded bg-violet-500/20 text-violet-300 border border-violet-500/30 hover:bg-violet-500/40"
                      >
                        Analyze
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
        <div className="border-t border-violet-500/20 p-4 bg-violet-950/20 flex-1 flex flex-col min-h-[160px]">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] font-mono text-violet-400 uppercase tracking-wider font-semibold">
              JARVIS Port Threat Assessment {selectedPort ? `(${selectedPort.port})` : ""}
            </span>
            <button onClick={() => handleAnalyze()} className="text-[11px] font-mono border border-violet-500/40 text-violet-300 px-3 py-1 rounded hover:bg-violet-500/10">
              <Zap size={11} className="inline mr-1" /> Analyze All
            </button>
          </div>
          <div className="text-[11px] font-mono text-slate-300 whitespace-pre-wrap flex-1 overflow-y-auto max-h-40 leading-relaxed">
            {jarvisResponse ? (
              jarvisResponse
            ) : (
              <span className="text-slate-500">
                Click <strong>"Analyze All"</strong> or click on any discovered port row to generate tactical attack surface intelligence and mitigation directives.
              </span>
            )}
          </div>
        </div>
      </GlassCard>
    </div>
  );
}

// ─── Screen 3: Live Wireshark Sniffer ──────────────────────────────────────────

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
  const [inspectorTab, setInspectorTab] = useState<"tree" | "jarvis">("tree");
  const [bpf, setBpf] = useState("");
  const [interfaces, setInterfaces] = useState<NetworkAdapter[]>([]);
  const [selectedIface, setSelectedIface] = useState("");
  const [packetCount, setPacketCount] = useState(0);
  const [captureNotice, setCaptureNotice] = useState("");
  const [jarvisAnalysis, setJarvisAnalysis] = useState("");
  const [analyzing, setAnalyzing] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    fetch(`${API_BASE}/api/wireshark/interfaces`)
      .then((res) => res.json())
      .then((data) => {
        if (data && Array.isArray(data.interfaces) && data.interfaces.length > 0) {
          setInterfaces(data.interfaces);
          const live = data.interfaces.find((i: NetworkAdapter) => i.is_live);
          setSelectedIface(live ? live.id : data.interfaces[0].id);
        } else {
          setFallbackAdapters();
        }
      })
      .catch(() => {
        setFallbackAdapters();
      });
  }, []);

  function setFallbackAdapters() {
    const realisticFallback: NetworkAdapter[] = [
      { id: "Wi-Fi", name: "Wi-Fi (Wireless Network Adapter)", ip: "192.168.1.105", is_up: true, is_live: true, bytes_recv: 5849302 },
      { id: "Ethernet 2", name: "Ethernet 2 (Intel I219-V Gigabit)", ip: "10.0.0.45", is_up: true, is_live: true, bytes_recv: 12849200 },
      { id: "Loopback", name: "Loopback (Software Loopback 127.0.0.1)", ip: "127.0.0.1", is_up: true, is_live: false, bytes_recv: 0 }
    ];
    setInterfaces(realisticFallback);
    setSelectedIface("Wi-Fi");
  }

  function toggleCapture() {
    if (capturing) {
      if (wsRef.current) {
        wsRef.current.send(JSON.stringify({ action: "STOP_CAPTURE" }));
        wsRef.current.close();
      }
      setCapturing(false);
      setCaptureNotice("Capture stopped by user.");
    } else {
      setCapturing(true);
      setPacketList([]);
      setPacketCount(0);
      setSelected(null);
      setJarvisAnalysis("");
      setCaptureNotice("Initializing capture socket...");

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
          if (raw.type === "CAPTURE_STARTED") {
            setCaptureNotice("Capture active. Listening for live network frames...");
            return;
          }
          if (raw.type === "CAPTURE_ERROR") {
            setCaptureNotice(`Notice: ${raw.message}`);
            return;
          }
          if (raw.type === "CAPTURE_STOPPED" || raw.type === "CAPTURE_COMPLETE") {
            setCapturing(false);
            setCaptureNotice("Capture finalized.");
            return;
          }
          const p = raw.packet || raw.data || raw.payload;
          if (p && (p.src || p.source || p.proto || p.protocol || raw.type === "PACKET")) {
            const normalizedPacket = {
              num: p.num ?? p.number ?? p.no ?? (packetList.length + 1),
              time: p.time || p.timestamp || new Date().toLocaleTimeString(),
              src: p.src || p.source || p.src_ip || "192.168.1.105",
              dst: p.dst || p.destination || p.dst_ip || "104.244.42.1",
              proto: (p.proto || p.protocol || "TCP").toUpperCase(),
              len: p.len ?? p.length ?? p.size ?? 64,
              info: p.info || p.summary || p.description || "Ethernet / IP Frame",
              trees: p.trees,
              hex: p.hex,
              intel: p.intel,
            };

            setPacketCount((c) => c + 1);
            setPacketList((prev) => [normalizedPacket, ...prev.slice(0, 199)]);
          }
        } catch (e) {}
      };

      ws.onerror = () => {
        setCapturing(false);
        setCaptureNotice("WebSocket connection error.");
      };
      ws.onclose = () => setCapturing(false);
    }
  }

  function analyzeWithJarvis() {
    if (!packetList.length && !selected) return;
    setAnalyzing(true);
    setJarvisAnalysis("");
    setInspectorTab("jarvis");
    const contextData = {
      selected_frame: selected,
      sample_stream: packetList.slice(0, 15)
    };
    streamJarvis("Analyze these network packets for suspicious protocol traffic, brute force, port scans, or plaintext credential leaks:", contextData, (chunk) => {
      setJarvisAnalysis(prev => prev + chunk);
    }, () => setAnalyzing(false));
  }

  function handleExportPcap() {
    window.open(`${API_BASE}/api/wireshark/export-pcap`, "_blank");
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
            className="rounded px-3 py-2 text-xs font-mono text-cyan-300 bg-[#06090e] border border-cyan-400/20 outline-none min-w-[260px]"
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
            {activeAdapterObj?.is_live ? "TRAFFIC ACTIVE" : "STANDBY"}
          </span>
          <span className="text-[11px] font-mono text-cyan-400">({activeAdapterObj?.ip || "127.0.0.1"})</span>
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
            onClick={handleExportPcap}
            className="flex items-center gap-1.5 px-3 py-2 rounded text-xs font-mono border border-cyan-400/40 text-cyan-300 hover:bg-cyan-500/10"
          >
            <Download size={13} /> Export .PCAP
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
          <span>{captureNotice || (capturing ? "Streaming live adapter packets..." : "Capture Idle")}</span>
        </div>
        <div>Captured Packets: <span className="text-cyan-400 font-bold">{packetCount}</span></div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 flex-1 min-h-[420px]">
        {/* Packet Stream Table */}
        <GlassCard className="lg:col-span-7 overflow-hidden flex flex-col">
          <div className="overflow-y-auto flex-1 w-full max-h-[500px]">
            <table className="w-full text-[11px] font-mono">
              <thead className="sticky top-0 bg-[#0a1220] border-b border-white/10 z-10">
                <tr>
                  {["#", "Timestamp", "Source IP", "Destination IP", "Protocol", "Length", "Packet Information"].map(h => (
                    <th key={h} className="text-left text-slate-400 py-2.5 px-3 font-normal">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {packetList.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="py-16 text-center text-slate-600">
                      {capturing ? "Listening for network frames..." : "No packets captured. Select an active network adapter and click 'Start Sniffer'."}
                    </td>
                  </tr>
                ) : (
                  packetList.map((p, i) => (
                    <tr
                      key={i}
                      onClick={() => setSelected(p)}
                      className={`border-b border-white/5 cursor-pointer ${selected === p ? "bg-cyan-400/20 text-cyan-200 font-semibold" : "hover:bg-white/[0.04]"}`}
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
                      <td className="py-2 px-3 text-slate-300 truncate max-w-[200px]">{p.info}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </GlassCard>

        {/* Packet Inspector & JARVIS Panel */}
        <GlassCard className="lg:col-span-5 p-4 flex flex-col border-violet-500/20 bg-violet-950/20">
          <div className="flex items-center justify-between border-b border-white/10 pb-3 mb-3">
            <div className="flex gap-2">
              <button
                onClick={() => setInspectorTab("tree")}
                className={`flex items-center gap-1.5 px-3 py-1 rounded text-xs font-mono ${inspectorTab === "tree" ? "bg-cyan-500/20 text-cyan-300 border border-cyan-400/40" : "text-slate-400 hover:text-slate-200"}`}
              >
                <Layers size={12} /> Packet Details
              </button>
              <button
                onClick={() => setInspectorTab("jarvis")}
                className={`flex items-center gap-1.5 px-3 py-1 rounded text-xs font-mono ${inspectorTab === "jarvis" ? "bg-violet-500/20 text-violet-300 border border-violet-500/40" : "text-slate-400 hover:text-slate-200"}`}
              >
                <Bot size={12} /> JARVIS Intelligence
              </button>
            </div>
            {selected && (
              <span className="text-[10px] font-mono text-cyan-400">Frame #{selected.num}</span>
            )}
          </div>

          <div className="flex-1 overflow-y-auto max-h-[440px] text-xs font-mono space-y-3">
            {inspectorTab === "tree" ? (
              selected ? (
                <div className="space-y-3 text-slate-300">
                  {/* Frame */}
                  <div className="p-2 rounded bg-black/40 border border-white/5">
                    <div className="font-semibold text-cyan-400 mb-1">▸ Frame Header</div>
                    <div className="text-[11px] text-slate-300">
                      {selected.trees?.frame || `Frame ${selected.num}: ${selected.len} bytes on wire`}
                    </div>
                  </div>

                  {/* Ethernet */}
                  {selected.trees?.ethernet && (
                    <div className="p-2 rounded bg-black/40 border border-white/5">
                      <div className="font-semibold text-cyan-400 mb-1">▸ Ethernet II</div>
                      <div className="text-[11px] text-slate-300 space-y-0.5">
                        <div>Source MAC: <span className="text-slate-400">{selected.trees.ethernet.src_mac}</span></div>
                        <div>Destination MAC: <span className="text-slate-400">{selected.trees.ethernet.dst_mac}</span></div>
                        <div>Type: <span className="text-slate-400">{selected.trees.ethernet.type}</span></div>
                      </div>
                    </div>
                  )}

                  {/* IP Layer */}
                  {selected.trees?.ip && (
                    <div className="p-2 rounded bg-black/40 border border-white/5">
                      <div className="font-semibold text-cyan-400 mb-1">▸ Internet Protocol ({selected.src} ➔ {selected.dst})</div>
                      <div className="text-[11px] text-slate-300 space-y-0.5">
                        <div>Source: <span className="text-cyan-400">{selected.src}</span></div>
                        <div>Destination: <span className="text-violet-400">{selected.dst}</span></div>
                        {selected.trees.ip.ttl && <div>Time to Live (TTL): {selected.trees.ip.ttl}</div>}
                        {selected.trees.ip.flags && <div>Flags: {selected.trees.ip.flags}</div>}
                      </div>
                    </div>
                  )}

                  {/* L4 Layer */}
                  {selected.trees?.l4 && (
                    <div className="p-2 rounded bg-black/40 border border-white/5">
                      <div className="font-semibold text-cyan-400 mb-1">▸ {selected.proto} Transport Layer</div>
                      <div className="text-[11px] text-slate-300 space-y-0.5">
                        <div>Source Port: {selected.trees.l4.src_port}</div>
                        <div>Destination Port: {selected.trees.l4.dst_port}</div>
                        {selected.trees.l4.flags && <div>Flags: [{selected.trees.l4.flags}]</div>}
                        {selected.trees.l4.seq && <div>Seq: {selected.trees.l4.seq}</div>}
                      </div>
                    </div>
                  )}

                  {/* Raw Hex Dump */}
                  {selected.hex && (
                    <div className="p-2 rounded bg-black/60 border border-white/10">
                      <div className="font-semibold text-amber-400 mb-1 flex items-center gap-1">
                        <Code size={12} /> Packet Byte Hex Dump
                      </div>
                      <pre className="text-[10px] text-slate-300 overflow-x-auto leading-tight font-mono">{selected.hex}</pre>
                    </div>
                  )}
                </div>
              ) : (
                <div className="py-20 text-center text-slate-500">
                  Select a packet row from the left table to inspect protocol trees and hex payload.
                </div>
              )
            ) : (
              <div className="whitespace-pre-wrap leading-relaxed text-slate-300">
                {jarvisAnalysis ? (
                  jarvisAnalysis
                ) : (
                  <span className="text-slate-500">
                    Click <strong>"Analyze with JARVIS"</strong> to run automated threat inspection across captured packets. JARVIS correlates traffic against MITRE ATT&CK, detects port scans, and identifies plaintext credentials.
                  </span>
                )}
              </div>
            )}
          </div>
        </GlassCard>
      </div>
    </div>
  );
}

// ─── Screen 4: Live Nuclei DAST ───────────────────────────────────────────────

function NucleiDASTScanner() {
  const [targetUrl, setTargetUrl] = useState("http://127.0.0.1:8000");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [running, setRunning] = useState(false);
  const [vulns, setVulns] = useState<any[]>([]);
  const [terminalLines, setTerminalLines] = useState<string[]>([]);
  const [showConsole, setShowConsole] = useState(false);
  const [selected, setSelected] = useState<any>(null);
  const [jarvisExploitGuide, setJarvisExploitGuide] = useState("");
  const [analyzing, setAnalyzing] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  function handleRunNuclei() {
    setRunning(true);
    setVulns([]);
    setTerminalLines(["[*] Initializing Nuclei DAST Vulnerability Pipeline..."]);
    setJarvisExploitGuide("");
    setSelected(null);

    const ws = new WebSocket(`${WS_BASE}/ws/nuclei`);
    wsRef.current = ws;

    ws.onopen = () => {
      ws.send(JSON.stringify({
        action: "RUN_NUCLEI",
        target: targetUrl,
        severity: severityFilter,
      }));
    };

    ws.onmessage = (event) => {
      try {
        const raw = JSON.parse(event.data);
        if (raw.type === "TERMINAL_LINE") {
          setTerminalLines(prev => [...prev, raw.text]);
        } else if (raw.type === "FINDING" || raw.finding) {
          const item = raw.data || raw.finding || raw;
          const normalized = {
            template: item.template || item.template_id || item.id || item.name || "CVE-Finding",
            name: item.name || "Identified Vulnerability",
            severity: (item.severity || item.level || "Medium").toUpperCase(),
            url: item.url || item.matched || item.host || targetUrl,
            description: item.description || ""
          };
          setVulns(prev => [...prev, normalized]);
        } else if (raw.type === "NUCLEI_COMPLETE") {
          setRunning(false);
          setTerminalLines(prev => [...prev, "[✔] Nuclei Vulnerability Audit Complete."]);
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
    streamJarvis(`Analyze this vulnerability finding: ${finding.template} (${finding.name}) at ${finding.url}. Detail CVSS scoring, attack mechanics, and provide copyable CLI remediation commands.`, { finding }, (chunk) => {
      setJarvisExploitGuide(prev => prev + chunk);
    }, () => setAnalyzing(false));
  }

  return (
    <div className="flex flex-col gap-4 w-full h-full min-h-[calc(100vh-100px)]">
      <GlassCard className="p-3 flex items-center gap-3 flex-wrap">
        <div className="flex-1 min-w-[260px]">
          <input
            value={targetUrl}
            onChange={e => setTargetUrl(e.target.value)}
            placeholder="http://127.0.0.1:8000"
            className="w-full rounded px-3 py-2 text-xs font-mono text-cyan-300 bg-black/40 border border-cyan-400/20 outline-none focus:border-cyan-400/60"
          />
        </div>

        <select
          value={severityFilter}
          onChange={e => setSeverityFilter(e.target.value)}
          className="rounded px-3 py-2 text-xs font-mono text-cyan-300 bg-[#06090e] border border-cyan-400/20 outline-none"
        >
          <option value="all">All Severities (Critical to Info)</option>
          <option value="critical">Critical Only</option>
          <option value="high,critical">High & Critical</option>
          <option value="medium,high,critical">Medium and Above</option>
          <option value="low,medium,high,critical">Low, Medium & High</option>
        </select>

        <button
          onClick={handleRunNuclei}
          disabled={running}
          className="flex items-center gap-2 px-4 py-2 rounded text-xs font-mono font-semibold"
          style={{ background: "rgba(0,212,255,0.15)", border: "1px solid rgba(0,212,255,0.4)", color: "#00d4ff" }}
        >
          {running ? <><RefreshCw size={13} className="animate-spin" /> Scanning Target…</> : <><Target size={13} /> Run Nuclei Scan</>}
        </button>

        <button
          onClick={() => setShowConsole(!showConsole)}
          className={`flex items-center gap-1.5 px-3 py-2 rounded text-xs font-mono border ${showConsole ? "border-cyan-400 text-cyan-300 bg-cyan-500/10" : "border-slate-700 text-slate-300 hover:bg-white/5"}`}
        >
          <Terminal size={13} /> Console
        </button>

        <button
          onClick={() => exportReport("Nuclei", vulns, "html")}
          className="flex items-center gap-2 px-3 py-2 rounded text-xs font-mono border border-slate-700 text-slate-300 hover:bg-white/5"
        >
          <Download size={13} /> Export HTML
        </button>
      </GlassCard>

      {showConsole && (
        <GlassCard className="p-3 max-h-48 overflow-y-auto font-mono text-[11px] bg-black/70 border-cyan-500/30">
          <div className="flex items-center justify-between pb-1 border-b border-white/10 mb-2">
            <span className="text-cyan-400 text-[10px] uppercase font-bold">Nuclei Live Console Stream</span>
            <button onClick={() => setTerminalLines([])} className="text-slate-400 hover:text-slate-200 text-[10px]">Clear</button>
          </div>
          {terminalLines.map((line, i) => (
            <div key={i} className={line.includes("CRITICAL") ? "text-red-400 font-bold" : line.includes("HIGH") ? "text-orange-400" : "text-[#98c379]"}>
              {line}
            </div>
          ))}
        </GlassCard>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 flex-1 min-h-[420px]">
        <GlassCard className="lg:col-span-7 overflow-hidden flex flex-col">
          <div className="px-4 py-3 border-b border-cyan-400/15 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Shield size={14} className="text-cyan-400" />
              <SectionLabel>Discovered Vulnerability Findings</SectionLabel>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-400/20">
              {vulns.length} Findings
            </span>
          </div>

          <div className="overflow-y-auto flex-1 w-full max-h-[450px]">
            <table className="w-full text-[11px] font-mono">
              <thead className="sticky top-0 bg-[#0a1220] border-b border-white/10 z-10">
                <tr>
                  {["Template / CVE", "Severity", "Matched URL / Path", "Action"].map(h => (
                    <th key={h} className="text-left text-slate-400 py-2.5 px-3 font-normal">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {vulns.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="py-16 text-center text-slate-500">
                      {running ? "Executing parallel DAST security checks across endpoints and headers..." : "No findings discovered yet. Enter target and click 'Run Nuclei Scan'."}
                    </td>
                  </tr>
                ) : (
                  vulns.map((v, i) => (
                    <tr key={i} className={`border-b border-white/5 ${selected === v ? "bg-violet-500/15" : "hover:bg-white/[0.03]"}`}>
                      <td className="py-2.5 px-3 text-amber-400 font-bold">
                        <div>{v.template}</div>
                        {v.name && v.name !== v.template && <div className="text-[10px] text-slate-400 font-normal">{v.name}</div>}
                      </td>
                      <td className="py-2.5 px-3"><SeverityBadge level={v.severity} /></td>
                      <td className="py-2.5 px-3 text-slate-300 truncate max-w-[240px]">{v.url}</td>
                      <td className="py-2.5 px-3">
                        <button
                          onClick={() => analyzeFindingWithJarvis(v)}
                          className="px-2.5 py-1 bg-violet-500/20 text-violet-300 border border-violet-500/30 rounded text-[10px] hover:bg-violet-500/40 flex items-center gap-1"
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
          <div className="flex items-center justify-between pb-2 border-b border-violet-500/20 mb-2">
            <SectionLabel>JARVIS Tactical CVE Remediation Engine</SectionLabel>
            {selected && <span className="text-[10px] font-mono text-violet-300">{selected.template}</span>}
          </div>

          <div className="flex-1 overflow-y-auto mt-2 text-xs font-mono text-slate-300 whitespace-pre-wrap leading-relaxed max-h-[420px]">
            {analyzing ? (
              <div className="py-8 text-center text-violet-400 animate-pulse">
                JARVIS synthesizing threat mechanics, CVSS scoring, and CLI remediation...
              </div>
            ) : jarvisExploitGuide ? (
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

// ─── Screen 5: Live Web Fuzzer ────────────────────────────────────────────────

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
        if (raw.type === "ROUTE_DISCOVERED" || raw.route) {
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

    const endpoint = tab === "encode" ? `${API_BASE}/api/steg/encode` : `${API_BASE}/api/steg/decode`;
    try {
      const res = await fetch(endpoint, { method: "POST", body: formData });
      if (res.ok) {
        if (tab === "encode") {
          const blob = await res.blob();
          triggerFileDownload(blob, "stego_carrier.png", "image/png");
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
    const res = await fetch(`${API_BASE}/api/steg/analyze-plane`, { method: "POST", body: formData });
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

// ─── Screen 7: DUAL WORKBENCH (JARVIS AI & Assistant with Export Actions) ───────

const JARVIS_SCENARIOS = [
  { 
    title: "SMB & RDP Exposure", 
    prompt: "Perform a technical risk assessment on exposed Ports 445 (SMB) and 3389 (RDP). Provide MITRE ATT&CK mapping and complete internal host hardening directives plus perimeter firewall rules." 
  },
  { 
    title: "SQL Injection Incident", 
    prompt: "Analyze a critical SQL Injection alert on an authentication endpoint. Detail the exploit mechanics, internal source code remediation, and edge WAF virtual patching rules." 
  },
  { 
    title: "External Attack Surface", 
    prompt: "Analyze an external perimeter port scan revealing open database listeners (3306, 5432) and RPC (135). Formulate comprehensive internal network isolation and perimeter edge access controls." 
  },
  { 
    title: "ARP Spoofing Detection", 
    prompt: "Analyze Wireshark telemetry exhibiting high-volume duplicate ARP replies and MAC spoofing. Detail man-in-the-middle attack vectors and network switch Dynamic ARP Inspection (DAI) remediations." 
  },
];

const KNOWLEDGE_TOPICS = [
  { 
    title: "OWASP Top 10", 
    prompt: "Provide an exhaustive breakdown of the OWASP Top 10 vulnerabilities with attack mechanisms and defensive controls." 
  },
  { 
    title: "Active Directory & Kerberos", 
    prompt: "Explain Active Directory security architecture, Kerberos authentication protocol, Kerberoasting, and Tiered Administration defense." 
  },
  { 
    title: "Network Protocols & OSI", 
    prompt: "Detail the OSI and TCP/IP protocol stack security, including TCP handshake mechanics, DNSSEC, and TLS 1.3 cryptographic improvements." 
  },
  { 
    title: "Zero Trust Architecture", 
    prompt: "Explain NIST SP 800-207 Zero Trust Architecture principles, micro-segmentation, and continuous adaptive trust verification." 
  },
  { 
    title: "PTES PenTesting Standard", 
    prompt: "Provide a comprehensive breakdown of the Penetration Testing Execution Standard (PTES) 7 core phases and methodology." 
  },
  { 
    title: "Incident Response (PICERL)", 
    prompt: "Detail the NIST and SANS Incident Response lifecycle phases (Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned)." 
  },
  { 
    title: "Cryptography & PKI", 
    prompt: "Explain modern cryptographic algorithms, asymmetric key exchange (ECDHE, RSA), symmetric ciphers (AES-GCM), and PKI certificate validation." 
  },
];

function JarvisAndAssistantDualWorkbench() {
  const [jarvisMsgs, setJarvisMsgs] = useState<{ role: string; content: string; time: string }[]>([
    { 
      role: "assistant", 
      content: "JARVIS Cyber Defense Copilot online. Ready to evaluate security test results (Nmap, Wireshark, Nuclei, Fuzzer) and formulate inside/outside tactical remediations.", 
      time: new Date().toLocaleTimeString() 
    }
  ]);
  const [jarvisInput, setJarvisInput] = useState("");
  const [jarvisLoading, setJarvisLoading] = useState(false);

  const [assistantMsgs, setAssistantMsgs] = useState<{ role: string; content: string; time: string }[]>([
    { 
      role: "assistant", 
      content: "SecurOS Cybersecurity Knowledge Library online. ChromaDB vector database synchronized with MITRE ATT&CK, OWASP, NIST standards, and reference texts. Ask any cybersecurity question or choose a reference topic below.", 
      time: new Date().toLocaleTimeString() 
    }
  ]);
  const [assistantInput, setAssistantInput] = useState("");
  const [assistantLoading, setAssistantLoading] = useState(false);

  function handleSendJarvis(text?: string) {
    const promptToSend = text || jarvisInput;
    if (!promptToSend.trim()) return;
    const now = new Date().toLocaleTimeString();
    const userMsg = { role: "user", content: promptToSend, time: now };
    setJarvisMsgs(prev => [...prev, userMsg]);
    if (!text) setJarvisInput("");
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
      const answer = await queryAssistant(query);
      setAssistantMsgs(prev => [...prev, {
        role: "assistant",
        content: answer,
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

  function downloadChatTranscript(title: string, messages: Array<{ role: string; content: string; time: string }>) {
    let md = `# SecurOS ${title} Report\nGenerated on: ${new Date().toLocaleString()}\n\n---\n\n`;
    messages.forEach((m) => {
      md += `### [${m.role.toUpperCase()}] · ${m.time}\n${m.content}\n\n`;
    });
    triggerFileDownload(md, `${title.replace(/\s+/g, "_")}_Transcript_${Date.now()}.md`, "text/markdown");
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 w-full h-full min-h-[calc(100vh-100px)]">
      {/* LEFT PANEL: JARVIS Security Results & Threat Remediation Copilot */}
      <GlassCard className="flex flex-col overflow-hidden h-[600px] lg:h-full border-violet-500/20">
        <div className="px-4 py-3 border-b border-violet-500/20 bg-violet-950/30 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Bot size={15} className="text-violet-400" />
            <div>
              <span className="text-xs font-mono font-semibold text-violet-300 uppercase tracking-wider block leading-tight">JARVIS Threat Remediation Copilot</span>
              <span className="text-[9px] font-mono text-slate-400 block">Results & Telemetry Analyzer · Inside & Outside Remediation</span>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => downloadChatTranscript("JARVIS_Copilot", jarvisMsgs)}
              className="text-[10px] font-mono px-2 py-0.5 rounded border border-violet-500/40 text-violet-300 hover:bg-violet-500/20 flex items-center gap-1"
            >
              <Download size={10} /> Export .MD
            </button>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-violet-500/20 text-violet-300 border border-violet-500/30">
              Results Analyzer
            </span>
          </div>
        </div>

        {/* Quick Tactical Scenarios */}
        <div className="p-2 border-b border-violet-500/10 bg-violet-950/10 flex gap-1.5 overflow-x-auto">
          {JARVIS_SCENARIOS.map((scen, i) => (
            <button
              key={i}
              onClick={() => handleSendJarvis(scen.prompt)}
              className="text-[10px] font-mono px-2.5 py-1 rounded bg-violet-500/10 border border-violet-500/20 text-violet-300 hover:bg-violet-500/20 whitespace-nowrap"
            >
              {scen.title}
            </button>
          ))}
        </div>

        <div className="flex-1 overflow-y-auto p-4 space-y-3 font-mono text-xs">
          {jarvisMsgs.map((m, i) => (
            <div key={i} className={`p-3 rounded ${m.role === "user" ? "bg-cyan-950/40 border border-cyan-400/20 ml-6 text-cyan-300" : "bg-violet-950/30 border border-violet-500/20 mr-6 text-slate-200"}`}>
              <div className="text-[9px] text-slate-500 mb-1">{m.role.toUpperCase()} · {m.time}</div>
              <div className="whitespace-pre-wrap leading-relaxed">{m.content}</div>
            </div>
          ))}
          {jarvisLoading && <div className="text-xs font-mono text-violet-400 animate-pulse">JARVIS analyzing telemetry & synthesizing remediations…</div>}
        </div>

        <div className="p-3 border-t border-violet-500/20 bg-black/40 flex gap-2">
          <input
            value={jarvisInput}
            onChange={e => setJarvisInput(e.target.value)}
            onKeyDown={e => e.key === "Enter" && handleSendJarvis()}
            placeholder="Ask JARVIS regarding test findings, packet flows, or inside/outside remediations..."
            className="flex-1 bg-black/50 border border-violet-500/30 rounded px-3 py-2 text-xs font-mono text-slate-200 outline-none focus:border-violet-400"
          />
          <button
            onClick={() => handleSendJarvis()}
            className="px-4 py-2 bg-violet-500/20 border border-violet-500/40 text-violet-300 rounded text-xs font-mono hover:bg-violet-500/30"
          >
            <Send size={13} />
          </button>
        </div>
      </GlassCard>

      {/* RIGHT PANEL: SecurOS Cybersecurity Knowledge Library Assistant */}
      <GlassCard className="flex flex-col overflow-hidden h-[600px] lg:h-full border-cyan-400/20">
        <div className="px-4 py-3 border-b border-cyan-400/15 bg-cyan-950/20 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <BookOpen size={15} className="text-cyan-400" />
            <div>
              <span className="text-xs font-mono font-semibold text-cyan-300 uppercase tracking-wider block leading-tight">SecurOS Knowledge Library Assistant</span>
              <span className="text-[9px] font-mono text-slate-400 block">ChromaDB RAG Encyclopedia · Standards, Protocols & Theory</span>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => downloadChatTranscript("Knowledge_Library", assistantMsgs)}
              className="text-[10px] font-mono px-2 py-0.5 rounded border border-cyan-400/40 text-cyan-300 hover:bg-cyan-500/20 flex items-center gap-1"
            >
              <Download size={10} /> Export .MD
            </button>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-400/30">
              ChromaDB RAG
            </span>
          </div>
        </div>

        {/* Quick Knowledge Topics */}
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
          {assistantLoading && <div className="text-xs font-mono text-cyan-400 animate-pulse">Assistant searching cybersecurity knowledge library…</div>}
        </div>

        <div className="p-3 border-t border-cyan-400/20 bg-black/40 flex gap-2">
          <input
            value={assistantInput}
            onChange={e => setAssistantInput(e.target.value)}
            onKeyDown={e => e.key === "Enter" && handleSendAssistant()}
            placeholder="Ask Knowledge Assistant (e.g. Explain Kerberoasting or TLS 1.3)..."
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
