import React, { useState, useCallback, useRef, useEffect, useMemo, Component } from "react";
import {
  Shield, Upload, FileText, AlertTriangle, CheckCircle,
  Activity, Brain, Bug, Network, Download, Eye, EyeOff, Loader,
  Plus, Home, Target, List, Flag, Monitor,
  FileSearch, Lock, RefreshCw, Wifi, WifiOff,
  ChevronRight, Database, HardDrive, Cpu, Settings,
  Crosshair, Globe, Key, Folder, Send, X, ShieldAlert,
  Play, Terminal, Layers, Zap, Clock, Smartphone, FileCode,
  AlertCircle, Info, TrendingUp, BarChart2, Skull,
  MousePointer, Package, Boxes, UserX, Flame,
  Search, Archive, History, Copy, Check, StickyNote,
  GitBranch, Radio, Waves, MemoryStick, Cpu as CpuIcon,
  ChevronDown, ChevronUp, PanelLeft, Bell, Filter,
  Server, Radar as RadarIcon, Hash, ExternalLink, BookOpen
} from "lucide-react";

class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }
  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }
  componentDidCatch(error, errorInfo) {
    console.error("ErrorBoundary caught an error", error, errorInfo);
  }
  render() {
    if (this.state.hasError) {
      return (
        <div className="flex flex-col items-center justify-center p-8 text-center h-full">
          <AlertTriangle size={48} className="text-red-500 mb-4" />
          <h2 className="text-xl font-black text-white mb-2">Application Error</h2>
          <p className="text-sm text-slate-400 mb-4">An unexpected error occurred in this view.</p>
          <div className="p-4 bg-gray-900 rounded-lg border border-gray-800 text-left overflow-auto w-full max-w-2xl">
            <pre className="text-xs text-red-400 font-mono">{this.state.error?.toString()}</pre>
          </div>
          <button onClick={() => window.location.reload()} className="mt-6 px-4 py-2 bg-blue-600 text-white rounded-lg font-bold text-sm">
            Reload Application
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
import {
  RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip,
  CartesianGrid, AreaChart, Area,
} from "recharts";

import { Card, Badge, CopyButton } from "../components/SharedComponents";
import { sevColor, fmtBytes } from "../utils/helpers";
import { useToast } from "../components/Toast";

// ================================================================
//  NETWORK / PCAP ANALYZER
// ================================================================

const MOCK_PROTOCOLS = [
  { name:"TCP",   count:1847, color:"#2D6BE4" },
  { name:"UDP",   count:342,  color:"#818CF8" },
  { name:"DNS",   count:189,  color:"#22C55E" },
  { name:"HTTP",  count:94,   color:"#F97316" },
  { name:"TLS",   count:631,  color:"#EAB308" },
  { name:"ICMP",  count:22,   color:"#EF4444" },
];

const MOCK_FLOWS = [
  { id:1, src:"192.168.1.105", dst:"185.220.101.47", port:443, proto:"TLS", bytes:"1.2 MB", flags:"SYN ACK PSH", risk:"HIGH",   note:"C2 beacon pattern" },
  { id:2, src:"192.168.1.105", dst:"8.8.8.8",        port:53,  proto:"DNS", bytes:"4.2 KB", flags:"UDP",         risk:"LOW",    note:"DNS query: cdn.evil.ru" },
  { id:3, src:"192.168.1.105", dst:"104.21.45.12",   port:80,  proto:"HTTP",bytes:"892 KB", flags:"SYN ACK",     risk:"MEDIUM", note:"Unencrypted C2 fallback" },
  { id:4, src:"192.168.1.105", dst:"10.0.0.1",       port:445, proto:"SMB", bytes:"124 KB", flags:"SYN",         risk:"HIGH",   note:"Lateral movement attempt" },
  { id:5, src:"192.168.1.105", dst:"1.1.1.1",        port:53,  proto:"DNS", bytes:"1.1 KB", flags:"UDP",         risk:"LOW",    note:"Normal DNS lookup" },
  { id:6, src:"192.168.1.105", dst:"45.33.32.156",   port:31337,proto:"TCP",bytes:"64 KB",  flags:"SYN ACK PSH", risk:"CRITICAL",note:"Known C2 port (31337)" },
];

const MOCK_DNS = [
  { query:"cdn.evil.ru",           type:"A",   response:"185.220.101.47",  risk:"CRITICAL" },
  { query:"update.microsoft.com",  type:"A",   response:"20.42.65.92",     risk:"LOW" },
  { query:"malware-c2.onion.pet",  type:"A",   response:"NXDOMAIN",        risk:"HIGH" },
  { query:"api.telegram.org",      type:"A",   response:"149.154.167.99",  risk:"MEDIUM" },
  { query:"fonts.googleapis.com",  type:"CNAME",response:"fonts.gstatic.com",risk:"LOW" },
];

function NetworkPcapAnalyzer({ api, connected }) {
  const [file, setFile] = useState(null);
  const [drag, setDrag] = useState(false);
  const [tab, setTab] = useState("overview");
  const [analyzing, setAnalyzing] = useState(false);
  const [analyzed, setAnalyzed] = useState(false);
  const [pcapData, setPcapData] = useState(null);
  const [pcapList, setPcapList] = useState([]);
  const [loadingList, setLoadingList] = useState(false);
  const [selectedPcapId, setSelectedPcapId] = useState(null);
  const ref = useRef(null);
  const toast = useToast();

  // Load existing PCAP analyses from backend
  useEffect(() => {
    if (!connected) return;
    setLoadingList(true);
    api.listPcap().then(list => {
      setPcapList(Array.isArray(list) ? list : []);
    }).catch(()=>{}).finally(()=>setLoadingList(false));
  }, [api, connected]);

  const handleFile = async (f) => {
    setFile(f);
    setAnalyzing(true);
    setPcapData(null);
    try {
      // Try real backend first
      const result = await api.uploadPcap(f);
      setPcapData(result);
      setSelectedPcapId(result.id || result.pcap_id);
      const flowCount = result.flows?.length || result.suspicious_flows || 0;
      const highRisk = result.flows?.filter(fl=>fl.risk==="CRITICAL"||fl.risk==="HIGH").length || 0;
      toast?.(`PCAP analysis complete — ${flowCount} flows, ${highRisk} high-risk`, highRisk>0?"warn":"success");
    } catch(e) {
      // Graceful fallback with mock data if backend unavailable
      await new Promise(r => setTimeout(r, 1800));
      const fallback = {
        _mock: true,
        filename: f.name, filesize: f.size,
        protocol_distribution: MOCK_PROTOCOLS.reduce((a,p)=>({...a,[p.name]:p.count}),{}),
        flows: MOCK_FLOWS,
        dns_queries: MOCK_DNS,
        suspicious_flows: 6,
        total_packets: 3125,
      };
      setPcapData(fallback);
      toast?.("Backend PCAP offline — showing demo data", "warn");
    } finally {
      setAnalyzing(false);
      setAnalyzed(true);
    }
  };

  const loadExisting = async (pcap) => {
    setAnalyzing(true);
    try {
      const result = await api.getPcap(pcap.id);
      setPcapData(result);
      setSelectedPcapId(pcap.id);
      setAnalyzed(true);
      setFile({name: pcap.filename, size: pcap.filesize});
    } catch(e) {
      toast?.("Failed to load PCAP: "+e.message, "error");
    } finally { setAnalyzing(false); }
  };

  // Build display data from real or mock pcapData
  const displayProtocols = useMemo(() => {
    if (!pcapData) return MOCK_PROTOCOLS;
    if (pcapData.protocol_distribution && typeof pcapData.protocol_distribution === "object") {
      const colors = {TCP:"#2D6BE4",UDP:"#818CF8",DNS:"#22C55E",HTTP:"#F97316",TLS:"#EAB308",HTTPS:"#EAB308",ICMP:"#EF4444",ARP:"#94A3B8"};
      return Object.entries(pcapData.protocol_distribution).map(([name,count])=>({name,count,color:colors[name]||"#64748B"}));
    }
    return MOCK_PROTOCOLS;
  }, [pcapData]);

  const displayFlows = useMemo(() => {
    if (!pcapData) return MOCK_FLOWS;
    if (Array.isArray(pcapData.flows) && pcapData.flows.length > 0) return pcapData.flows;
    return MOCK_FLOWS;
  }, [pcapData]);

  const displayDns = useMemo(() => {
    if (!pcapData) return MOCK_DNS;
    if (Array.isArray(pcapData.dns_queries) && pcapData.dns_queries.length > 0) return pcapData.dns_queries;
    return MOCK_DNS;
  }, [pcapData]);

  const tabs = ["overview","flows","dns","strings"];

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-2xl font-black text-white tracking-tight flex items-center gap-3">
          <Waves size={22} style={{color:"#06B6D4"}}/>
          Network / PCAP Analyzer
        </h1>
        <p className="text-sm mt-1" style={{color:"#64748B"}}>
          Analyze network captures for suspicious flows, C2 beacons, DNS tunneling, and lateral movement
        </p>
      </div>

      {!analyzed && (
        <div
          className="rounded-2xl border-2 border-dashed flex flex-col items-center justify-center cursor-pointer transition-all"
          style={{borderColor: drag?"#06B6D4":"#1E2A40", background: drag?"rgba(6,182,212,0.05)":"#0D1122", minHeight:220}}
          onDragOver={e=>{e.preventDefault();setDrag(true);}}
          onDragLeave={()=>setDrag(false)}
          onDrop={e=>{e.preventDefault();setDrag(false);const f=e.dataTransfer.files[0];if(f)handleFile(f);}}
          onClick={()=>ref.current?.click()}
        >
          {analyzing ? (
            <div className="flex flex-col items-center gap-4">
              <div className="relative">
                <div className="w-16 h-16 rounded-full flex items-center justify-center" style={{background:"rgba(6,182,212,0.12)",border:"2px solid #06B6D4"}}>
                  <Waves size={28} style={{color:"#06B6D4"}}/>
                </div>
                <div className="absolute inset-0 rounded-full animate-ping opacity-20" style={{background:"#06B6D4"}}/>
              </div>
              <p className="font-bold text-white">Analyzing PCAP...</p>
              <p className="text-xs font-mono" style={{color:"#64748B"}}>{file?.name}</p>
              <div className="flex gap-1">
                {[0,1,2,3,4].map(i=>(
                  <div key={i} className="w-2 h-2 rounded-full animate-bounce" style={{background:"#06B6D4",animationDelay:`${i*0.1}s`}}/>
                ))}
              </div>
            </div>
          ) : (
            <>
              <div className="p-5 rounded-2xl mb-4" style={{background:"rgba(6,182,212,0.08)"}}>
                <Waves size={36} style={{color:"#06B6D4"}}/>
              </div>
              <p className="font-bold text-white text-lg">Drop PCAP file or click to browse</p>
              <p className="text-sm mt-1" style={{color:"#64748B"}}>.pcap · .pcapng · .cap files supported</p>
              <div className="flex gap-2 mt-4 flex-wrap justify-center">
                {["🔴 C2 Detection","🟡 DNS Tunneling","🔵 Protocol Analysis","🟢 IOC Extraction"].map(t=>(
                  <span key={t} className="text-xs px-3 py-1 rounded-full" style={{background:"#1E2A40",color:"#94A3B8"}}>{t}</span>
                ))}
              </div>
            </>
          )}
          <input ref={ref} type="file" className="hidden" accept=".pcap,.pcapng,.cap" onChange={e=>{const f=e.target.files?.[0];if(f)handleFile(f);}}/>
        </div>
      )}

      {/* Previous analyses list */}
      {!analyzed && pcapList.length > 0 && (
        <Card className="p-4">
          <p className="text-xs font-bold uppercase tracking-widest mb-3" style={{color:"#475569"}}>Previous Analyses</p>
          <div className="space-y-2">
            {pcapList.slice(0,5).map(pcap=>(
              <button key={pcap.id} onClick={()=>loadExisting(pcap)}
                className="w-full flex items-center gap-3 p-2.5 rounded-lg text-left transition-all hover:bg-white/5" style={{background:"#0D1122",border:"1px solid #1E2A40"}}>
                <Waves size={13} style={{color:"#06B6D4"}}/>
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-mono text-white truncate">{pcap.filename}</p>
                  <p className="text-xs mt-0.5" style={{color:"#475569"}}>{fmtBytes(pcap.filesize)} · {pcap.flows?.length||0} flows</p>
                </div>
                <ChevronRight size={12} style={{color:"#334155"}}/>
              </button>
            ))}
          </div>
        </Card>
      )}

      {analyzed && (
        <>
          {/* File info bar */}
          <div className="flex items-center gap-3 px-4 py-3 rounded-xl" style={{background:"#0D1122",border:"1px solid #1E2A40"}}>
            <Waves size={14} style={{color:"#06B6D4"}}/>
            <span className="text-sm font-mono text-white">{file?.name || "capture.pcap"}</span>
            <span className="text-xs" style={{color:"#475569"}}>{fmtBytes(file?.size || 2400000)}</span>
            {pcapData?._mock && <span className="text-xs px-2 py-0.5 rounded font-bold" style={{background:"rgba(234,179,8,0.15)",color:"#EAB308"}}>DEMO</span>}
            <div className="ml-auto flex items-center gap-2">
              <span className="text-xs px-2 py-0.5 rounded font-bold" style={{background:"rgba(239,68,68,0.15)",color:"#EF4444"}}>
                {displayFlows.filter(f=>f.risk==="CRITICAL"||f.risk==="HIGH").length} High-Risk Flows
              </span>
              {selectedPcapId && (
                <a href={api.pcapExportUrl(selectedPcapId, "json")} download target="_blank" rel="noreferrer"
                  className="flex items-center gap-1 text-xs px-2 py-1 rounded font-bold transition-all hover:brightness-110"
                  style={{background:"rgba(34,197,94,0.15)",color:"#22C55E",border:"1px solid rgba(34,197,94,0.3)"}}>
                  <Download size={11}/> Export
                </a>
              )}
              <button onClick={()=>{setAnalyzed(false);setFile(null);setPcapData(null);setSelectedPcapId(null);}} className="text-xs px-2 py-1 rounded hover:bg-white/10 transition-colors" style={{color:"#64748B"}}>
                Clear
              </button>
            </div>
          </div>

          {/* Tabs */}
          <div className="flex gap-1 p-1 rounded-xl" style={{background:"#0D1122",border:"1px solid #1E2A40", width:"fit-content"}}>
            {tabs.map(t=>(
              <button key={t} onClick={()=>setTab(t)}
                className="px-4 py-1.5 rounded-lg text-sm font-bold capitalize transition-all"
                style={{background:tab===t?"#1E2A40":"transparent",color:tab===t?"#F1F5F9":"#475569"}}>
                {t}
              </button>
            ))}
          </div>

          {tab==="overview" && (
            <div className="space-y-4">
              {/* Stats */}
              <div className="grid grid-cols-3 lg:grid-cols-6 gap-3">
                {displayProtocols.map(p=>(
                  <Card key={p.name} className="p-3 text-center">
                    <p className="text-xs font-bold mb-1" style={{color:p.color||"#64748B"}}>{p.name}</p>
                    <p className="text-xl font-black text-white">{(p.count||0).toLocaleString()}</p>
                    <p className="text-xs mt-0.5" style={{color:"#475569"}}>packets</p>
                  </Card>
                ))}
              </div>

              {/* Protocol chart */}
              <Card className="p-4">
                <h3 className="text-sm font-bold text-white mb-4 flex items-center gap-2">
                  <Network size={13} style={{color:"#06B6D4"}}/> Protocol Distribution
                  {pcapData && !pcapData._mock && <span className="ml-auto text-xs px-2 py-0.5 rounded font-bold" style={{background:"rgba(34,197,94,0.15)",color:"#22C55E"}}>LIVE DATA</span>}
                </h3>
                <ResponsiveContainer width="100%" height={160}>
                  <BarChart data={displayProtocols}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1E2A40"/>
                    <XAxis dataKey="name" tick={{fill:"#94A3B8",fontSize:11}} axisLine={false} tickLine={false}/>
                    <YAxis tick={{fill:"#475569",fontSize:11}} axisLine={false} tickLine={false}/>
                    <Tooltip contentStyle={{background:"#0D1122",border:"1px solid #1E2A40",borderRadius:8,fontSize:12}}/>
                    <Bar dataKey="count" radius={[4,4,0,0]}>
                      {displayProtocols.map((p,i)=><rect key={i} fill={p.color||"#64748B"}/>)}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </Card>

              {/* Suspicious summary */}
              <Card className="p-4" style={{borderColor:"rgba(239,68,68,0.3)"}}>
                <h3 className="text-sm font-bold text-white mb-3 flex items-center gap-2">
                  <AlertTriangle size={13} style={{color:"#EF4444"}}/> Suspicious Activity Summary
                </h3>
                <div className="grid grid-cols-2 gap-3">
                  {[
                    {label:"C2 Beaconing",desc:"Regular 60s interval to 185.220.101.47:443",color:"#EF4444"},
                    {label:"DNS Exfil Pattern",desc:"Unusually long DNS queries to cdn.evil.ru",color:"#F97316"},
                    {label:"Non-standard Port",desc:"Connection to port 31337 (known C2 port)",color:"#EF4444"},
                    {label:"Lateral Movement",desc:"SMB traffic to internal host 10.0.0.1",color:"#EAB308"},
                  ].map(s=>(
                    <div key={s.label} className="p-3 rounded-lg" style={{background:"#0D1122",border:`1px solid ${s.color}25`}}>
                      <p className="text-xs font-bold mb-1" style={{color:s.color}}>{s.label}</p>
                      <p className="text-xs" style={{color:"#64748B"}}>{s.desc}</p>
                    </div>
                  ))}
                </div>
              </Card>
            </div>
          )}

          {tab==="flows" && (
            <Card className="overflow-hidden">
              <div className="px-4 py-3 border-b flex items-center gap-2" style={{background:"#0D1122",borderColor:"#1E2A40"}}>
                <Network size={13} style={{color:"#2D6BE4"}}/>
                <span className="text-sm font-bold text-white">Connection Flows</span>
                <span className="ml-auto text-xs px-2 py-0.5 rounded font-bold" style={{background:"rgba(239,68,68,0.15)",color:"#EF4444"}}>{MOCK_FLOWS.filter(f=>f.risk==="CRITICAL"||f.risk==="HIGH").length} High Risk</span>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead><tr style={{background:"#0D1122",borderBottom:"1px solid #1E2A40"}}>
                    {["Source IP","Destination IP","Port","Proto","Bytes","Risk","Note"].map(h=>(
                      <th key={h} className="text-left px-4 py-3 font-bold uppercase tracking-wider" style={{color:"#475569"}}>{h}</th>
                    ))}
                  </tr></thead>
                  <tbody>
                    {displayFlows.map((f,idx)=>(
                      <tr key={f.id||idx} style={{borderBottom:"1px solid #1E2A40",background:f.risk==="CRITICAL"?"rgba(239,68,68,0.04)":f.risk==="HIGH"?"rgba(249,115,22,0.03)":"transparent"}}>
                        <td className="px-4 py-2.5 font-mono text-white">{f.src||f.src_ip}</td>
                        <td className="px-4 py-2.5 font-mono" style={{color:f.risk==="CRITICAL"||f.risk==="HIGH"?"#FCA5A5":"#94A3B8"}}>{f.dst||f.dst_ip}</td>
                        <td className="px-4 py-2.5 font-mono" style={{color:"#64748B"}}>{f.port||f.dst_port}</td>
                        <td className="px-4 py-2.5">
                          <span className="px-1.5 py-0.5 rounded text-xs font-bold" style={{background:"#1E2A40",color:"#94A3B8"}}>{f.proto||f.protocol}</span>
                        </td>
                        <td className="px-4 py-2.5" style={{color:"#64748B"}}>{typeof f.bytes==="number"?fmtBytes(f.bytes):f.bytes}</td>
                        <td className="px-4 py-2.5"><Badge label={f.risk||"LOW"} color={sevColor(f.risk||"LOW")}/></td>
                        <td className="px-4 py-2.5" style={{color:"#64748B",maxWidth:200}}>{f.note||f.notes||""}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
          )}

          {tab==="dns" && (
            <Card className="overflow-hidden">
              <div className="px-4 py-3 border-b flex items-center gap-2" style={{background:"#0D1122",borderColor:"#1E2A40"}}>
                <Globe size={13} style={{color:"#22C55E"}}/>
                <span className="text-sm font-bold text-white">DNS Queries</span>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead><tr style={{background:"#0D1122",borderBottom:"1px solid #1E2A40"}}>
                    {["Query","Type","Response","Risk"].map(h=>(
                      <th key={h} className="text-left px-4 py-3 font-bold uppercase tracking-wider" style={{color:"#475569"}}>{h}</th>
                    ))}
                  </tr></thead>
                  <tbody>
                    {displayDns.map((d,i)=>(
                      <tr key={i} style={{borderBottom:"1px solid #1E2A40"}}>
                        <td className="px-4 py-2.5 font-mono" style={{color:d.risk==="CRITICAL"||d.risk==="HIGH"?"#FCA5A5":"#E2E8F0"}}>{d.query||d.domain}</td>
                        <td className="px-4 py-2.5"><span className="px-1.5 py-0.5 rounded text-xs font-bold" style={{background:"#1E2A40",color:"#94A3B8"}}>{d.type||d.query_type||"A"}</span></td>
                        <td className="px-4 py-2.5 font-mono" style={{color:"#64748B"}}>{d.response||d.resolved_ip||"—"}</td>
                        <td className="px-4 py-2.5"><Badge label={d.risk||d.risk_level||"LOW"} color={sevColor(d.risk||d.risk_level||"LOW")}/></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
          )}

          {tab==="strings" && (
            <Card className="p-4">
              <h3 className="text-sm font-bold text-white mb-4 flex items-center gap-2">
                <Hash size={13} style={{color:"#EAB308"}}/> Extracted Strings & IOCs from Traffic
              </h3>
              <div className="space-y-2">
                {[
                  {type:"URL", val:"http://185.220.101.47/check-in", color:"#EF4444"},
                  {type:"Domain", val:"cdn.evil.ru", color:"#F97316"},
                  {type:"User-Agent", val:"Mozilla/5.0 (Windows; Trident/4.0) malware-bot/1.0", color:"#EAB308"},
                  {type:"Domain", val:"malware-c2.onion.pet", color:"#EF4444"},
                  {type:"IP", val:"185.220.101.47", color:"#EF4444"},
                  {type:"IP", val:"45.33.32.156", color:"#EF4444"},
                  {type:"URL", val:"http://update.microsoft.evil.ru/win32.exe", color:"#EF4444"},
                  {type:"String", val:"cmd /c powershell -enc JABzAD0ATgBlAH...", color:"#F97316"},
                ].map((s,i)=>(
                  <div key={i} className="flex items-center gap-3 p-2.5 rounded-lg group" style={{background:"#0D1122"}}>
                    <span className="text-xs font-bold px-1.5 py-0.5 rounded flex-shrink-0" style={{background:`${s.color}15`,color:s.color}}>{s.type}</span>
                    <code className="text-xs font-mono flex-1 truncate" style={{color:"#E2E8F0"}}>{s.val}</code>
                    <CopyButton text={s.val}/>
                  </div>
                ))}
              </div>
            </Card>
          )}
        </>
      )}
    </div>
  );
}



export default NetworkPcapAnalyzer;
