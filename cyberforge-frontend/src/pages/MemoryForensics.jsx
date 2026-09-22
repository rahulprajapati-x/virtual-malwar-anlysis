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
//  MEMORY FORENSICS
// ================================================================

const MOCK_PROCESSES = [
  { pid:4,    ppid:0,    name:"System",       cpu:"0.1%", mem:"2 MB",  suspicious:false, children:[
    { pid:316,  ppid:4,    name:"smss.exe",     cpu:"0.0%", mem:"1 MB",  suspicious:false, children:[
      { pid:424,  ppid:316,  name:"csrss.exe",   cpu:"0.2%", mem:"8 MB",  suspicious:false, children:[] },
      { pid:500,  ppid:316,  name:"wininit.exe", cpu:"0.1%", mem:"6 MB",  suspicious:false, children:[
        { pid:588,  ppid:500,  name:"services.exe",cpu:"0.5%", mem:"14 MB", suspicious:false, children:[
          { pid:812,  ppid:588,  name:"svchost.exe", cpu:"1.2%", mem:"28 MB", suspicious:false, children:[] },
          { pid:1024, ppid:588,  name:"malware.exe", cpu:"8.4%", mem:"84 MB", suspicious:true,  children:[
            { pid:1248, ppid:1024, name:"cmd.exe",    cpu:"0.0%", mem:"4 MB",  suspicious:true,  children:[
              { pid:1360, ppid:1248, name:"powershell.exe",cpu:"3.1%",mem:"32 MB",suspicious:true, children:[] },
            ]},
          ]},
          { pid:1100, ppid:588,  name:"lsass.exe",  cpu:"0.8%", mem:"22 MB", suspicious:false, children:[] },
        ]},
      ]},
    ]},
  ]},
  { pid:2048, ppid:0,    name:"explorer.exe", cpu:"0.9%", mem:"54 MB", suspicious:false, children:[] },
  { pid:3304, ppid:2048, name:"chrome.exe",   cpu:"4.2%", mem:"210 MB",suspicious:false, children:[] },
];

const MOCK_INJECTED = [
  { pid:2048, process:"explorer.exe", base:"0x7FF8A0001000", size:"4 KB",  perms:"RWX", note:"Injected shellcode — likely process injection stage" },
  { pid:812,  process:"svchost.exe",  base:"0x00401000",     size:"12 KB", perms:"RWX", note:"Reflective DLL injection artifact" },
];

function ProcessRow({ proc, depth = 0 }) {
  const [expanded, setExpanded] = useState(depth < 2);
  const hasChildren = proc.children && proc.children.length > 0;
  return (
    <>
      <tr style={{borderBottom:"1px solid #1E2A40", background:proc.suspicious?"rgba(239,68,68,0.04)":"transparent"}}>
        <td className="px-4 py-2.5">
          <div className="flex items-center gap-1" style={{paddingLeft: depth * 20}}>
            {hasChildren ? (
              <button onClick={()=>setExpanded(e=>!e)} className="flex-shrink-0 w-4 h-4 flex items-center justify-center" style={{color:"#475569"}}>
                {expanded ? <ChevronDown size={11}/> : <ChevronRight size={11}/>}
              </button>
            ) : <div className="w-4 flex-shrink-0"/>}
            <span className="font-mono text-xs" style={{color:proc.suspicious?"#FCA5A5":"#E2E8F0"}}>{proc.name}</span>
            {proc.suspicious && <span className="text-xs px-1 py-0.5 rounded ml-1 font-black" style={{background:"rgba(239,68,68,0.2)",color:"#EF4444",fontSize:8}}>SUSPICIOUS</span>}
          </div>
        </td>
        <td className="px-4 py-2.5 font-mono text-xs" style={{color:"#64748B"}}>{proc.pid}</td>
        <td className="px-4 py-2.5 font-mono text-xs" style={{color:"#475569"}}>{proc.ppid}</td>
        <td className="px-4 py-2.5 text-xs" style={{color:proc.suspicious?"#FCA5A5":"#94A3B8"}}>{proc.cpu}</td>
        <td className="px-4 py-2.5 text-xs" style={{color:"#64748B"}}>{proc.mem}</td>
      </tr>
      {expanded && proc.children?.map(child => <ProcessRow key={child.pid} proc={child} depth={depth+1}/>)}
    </>
  );
}

function MemoryForensics({ api, connected }) {
  const [file, setFile] = useState(null);
  const [drag, setDrag] = useState(false);
  const [tab, setTab] = useState("processes");
  const [analyzed, setAnalyzed] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const ref = useRef(null);
  const toast = useToast();

  const handleFile = async (f) => {
    setFile(f);
    setAnalyzing(true);
    await new Promise(r => setTimeout(r, 2800));
    setAnalyzing(false);
    setAnalyzed(true);
    toast?.("Memory dump analyzed — 2 injected regions + 1 malicious process found", "error");
  };

  const MOCK_STRINGS = [
    {type:"URL",    val:"http://185.220.101.47/check-in", risk:"CRITICAL"},
    {type:"Domain", val:"cdn.evil.ru",                   risk:"HIGH"},
    {type:"Key",    val:"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\updater", risk:"HIGH"},
    {type:"Cmd",    val:"powershell.exe -enc JABzAD0...",risk:"HIGH"},
    {type:"Mutex",  val:"Global\\{FA5A4D64-1B22-4B7A-A8F3-FC2D}", risk:"MEDIUM"},
    {type:"String", val:"C:\\Users\\victim\\AppData\\Roaming\\malware.exe", risk:"HIGH"},
  ];

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-2xl font-black text-white tracking-tight flex items-center gap-3">
          <MemoryStick size={22} style={{color:"#818CF8"}}/>
          Memory Forensics
        </h1>
        <p className="text-sm mt-1" style={{color:"#64748B"}}>
          Volatility-inspired memory analysis — process tree, injected regions, network connections, and artifact extraction
        </p>
      </div>

      {!analyzed && (
        <div
          className="rounded-2xl border-2 border-dashed flex flex-col items-center justify-center cursor-pointer transition-all"
          style={{borderColor:drag?"#818CF8":"#1E2A40",background:drag?"rgba(129,140,248,0.05)":"#0D1122",minHeight:220}}
          onDragOver={e=>{e.preventDefault();setDrag(true);}}
          onDragLeave={()=>setDrag(false)}
          onDrop={e=>{e.preventDefault();setDrag(false);const f=e.dataTransfer.files[0];if(f)handleFile(f);}}
          onClick={()=>ref.current?.click()}
        >
          {analyzing ? (
            <div className="flex flex-col items-center gap-4">
              <div className="relative">
                <div className="w-16 h-16 rounded-full flex items-center justify-center" style={{background:"rgba(129,140,248,0.12)",border:"2px solid #818CF8"}}>
                  <MemoryStick size={28} style={{color:"#818CF8"}}/>
                </div>
                <div className="absolute inset-0 rounded-full animate-ping opacity-20" style={{background:"#818CF8"}}/>
              </div>
              <p className="font-bold text-white">Parsing Memory Dump...</p>
              <p className="text-xs font-mono" style={{color:"#64748B"}}>{file?.name}</p>
              <div className="space-y-2 w-56">
                {["Scanning process list...","Detecting injected regions...","Extracting network artifacts...","Finding suspicious strings..."].map((s,i)=>(
                  <div key={i} className="flex items-center gap-2 text-xs">
                    <div className="w-1.5 h-1.5 rounded-full animate-pulse flex-shrink-0" style={{background:"#818CF8",animationDelay:`${i*0.3}s`}}/>
                    <span style={{color:"#64748B"}}>{s}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <>
              <div className="p-5 rounded-2xl mb-4" style={{background:"rgba(129,140,248,0.08)"}}>
                <MemoryStick size={36} style={{color:"#818CF8"}}/>
              </div>
              <p className="font-bold text-white text-lg">Drop Memory Dump File</p>
              <p className="text-sm mt-1" style={{color:"#64748B"}}>.dmp · .vmem · .mem · .raw files supported</p>
              <div className="flex gap-2 mt-4 flex-wrap justify-center">
                {["🌳 Process Tree","💉 Injected Regions","🌐 Network Artifacts","🔤 String Extraction"].map(t=>(
                  <span key={t} className="text-xs px-3 py-1 rounded-full" style={{background:"#1E2A40",color:"#94A3B8"}}>{t}</span>
                ))}
              </div>
              <p className="text-xs mt-4 px-4 text-center" style={{color:"#334155"}}>
                No execution — static analysis of memory images only
              </p>
            </>
          )}
          <input ref={ref} type="file" className="hidden" accept=".dmp,.vmem,.mem,.raw,.bin" onChange={e=>{const f=e.target.files?.[0];if(f)handleFile(f);}}/>
        </div>
      )}

      {analyzed && (
        <>
          <div className="flex items-center gap-3 px-4 py-3 rounded-xl" style={{background:"#0D1122",border:"1px solid #1E2A40"}}>
            <MemoryStick size={14} style={{color:"#818CF8"}}/>
            <span className="text-sm font-mono text-white">{file?.name || "memdump.dmp"}</span>
            <span className="text-xs" style={{color:"#475569"}}>{fmtBytes(file?.size || 536870912)} RAM image</span>
            <div className="ml-auto flex items-center gap-2">
              <span className="text-xs px-2 py-0.5 rounded font-bold" style={{background:"rgba(239,68,68,0.15)",color:"#EF4444"}}>⚠ Malware Detected</span>
              <button onClick={()=>{setAnalyzed(false);setFile(null);}} className="text-xs px-2 py-1 rounded hover:bg-white/10 transition-colors" style={{color:"#64748B"}}>Clear</button>
            </div>
          </div>

          {/* Tabs */}
          <div className="flex gap-1 p-1 rounded-xl" style={{background:"#0D1122",border:"1px solid #1E2A40",width:"fit-content"}}>
            {["processes","injected","strings"].map(t=>(
              <button key={t} onClick={()=>setTab(t)}
                className="px-4 py-1.5 rounded-lg text-sm font-bold capitalize transition-all"
                style={{background:tab===t?"#1E2A40":"transparent",color:tab===t?"#F1F5F9":"#475569"}}>
                {t==="injected"?"Injected Regions":t.charAt(0).toUpperCase()+t.slice(1)}
                {t==="injected" && <span className="ml-1.5 text-xs px-1 py-0.5 rounded font-black" style={{background:"rgba(239,68,68,0.2)",color:"#EF4444"}}>2</span>}
              </button>
            ))}
          </div>

          {tab==="processes" && (
            <Card className="overflow-hidden">
              <div className="px-4 py-3 border-b flex items-center gap-2" style={{background:"#0D1122",borderColor:"#1E2A40"}}>
                <GitBranch size={13} style={{color:"#818CF8"}}/>
                <span className="text-sm font-bold text-white">Process Tree</span>
                <span className="ml-auto text-xs px-2 py-0.5 rounded font-bold" style={{background:"rgba(239,68,68,0.15)",color:"#EF4444"}}>1 Suspicious</span>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead><tr style={{background:"#0D1122",borderBottom:"1px solid #1E2A40"}}>
                    {["Process","PID","PPID","CPU","Memory"].map(h=>(
                      <th key={h} className="text-left px-4 py-3 font-bold uppercase tracking-wider" style={{color:"#475569"}}>{h}</th>
                    ))}
                  </tr></thead>
                  <tbody>
                    {MOCK_PROCESSES.map(p=><ProcessRow key={p.pid} proc={p} depth={0}/>)}
                  </tbody>
                </table>
              </div>
            </Card>
          )}

          {tab==="injected" && (
            <div className="space-y-3">
              <Card className="p-4" style={{borderColor:"rgba(239,68,68,0.3)"}}>
                <h3 className="text-sm font-bold text-white mb-3 flex items-center gap-2">
                  <Zap size={13} style={{color:"#EF4444"}}/> Injected Memory Regions (RWX)
                </h3>
                <p className="text-xs mb-4" style={{color:"#64748B"}}>
                  Regions with Read+Write+Execute permissions not mapped to any disk image — strong indicator of process injection or shellcode
                </p>
                {MOCK_INJECTED.map((r,i)=>(
                  <div key={i} className="p-4 rounded-xl mb-3" style={{background:"#0D1122",border:"1px solid rgba(239,68,68,0.25)"}}>
                    <div className="flex items-center gap-3 mb-2">
                      <Badge label="RWX" color="#EF4444"/>
                      <span className="font-mono text-sm font-bold text-white">{r.process}</span>
                      <span className="text-xs" style={{color:"#475569"}}>PID {r.pid}</span>
                    </div>
                    <div className="grid grid-cols-3 gap-3 text-xs mb-2">
                      <div><span style={{color:"#475569"}}>Base Address: </span><code className="text-white font-mono">{r.base}</code></div>
                      <div><span style={{color:"#475569"}}>Size: </span><span className="text-white">{r.size}</span></div>
                      <div><span style={{color:"#475569"}}>Permissions: </span><Badge label={r.perms} color="#EF4444"/></div>
                    </div>
                    <p className="text-xs" style={{color:"#FCA5A5"}}>⚠ {r.note}</p>
                  </div>
                ))}
              </Card>
            </div>
          )}

          {tab==="strings" && (
            <Card className="p-4">
              <h3 className="text-sm font-bold text-white mb-4 flex items-center gap-2">
                <Search size={13} style={{color:"#EAB308"}}/> Suspicious Strings Extracted from Memory
              </h3>
              <div className="space-y-2">
                {MOCK_STRINGS.map((s,i)=>(
                  <div key={i} className="flex items-center gap-3 p-2.5 rounded-lg group" style={{background:"#0D1122"}}>
                    <span className="text-xs font-bold px-1.5 py-0.5 rounded flex-shrink-0" style={{background:`${sevColor(s.risk)}15`,color:sevColor(s.risk)}}>{s.type}</span>
                    <code className="text-xs font-mono flex-1 truncate" style={{color:"#E2E8F0"}}>{s.val}</code>
                    <Badge label={s.risk} color={sevColor(s.risk)}/>
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



export default MemoryForensics;
