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

import { Card } from "../components/SharedComponents";
import { createApiClient } from "../api/client";
import { useToast } from "../components/Toast";

// ================================================================
//  SETTINGS
// ================================================================

function SettingsPanel({ apiBase, setApiBase, connected, onTest, currentUser }) {
  const [tab, setTab] = useState("connection");
  const [draft, setDraft] = useState(apiBase);
  const [vtKey, setVtKey] = useState(() => localStorage.getItem("cf_vt_key")||"" );
  const [abuseKey, setAbuseKey] = useState(() => localStorage.getItem("cf_abuse_key")||"" );
  const [pingMs, setPingMs] = useState(null);
  const [pinging, setPinging] = useState(false);
  const [health, setHealth] = useState(null);
  const [savingKeys, setSavingKeys] = useState(false);
  const toast = useToast();

  useEffect(() => {
    if (connected) {
      const api2 = createApiClient(apiBase);
      api2.health().then(setHealth).catch(()=>{});
    }
  }, [connected, apiBase]);

  const testConn = async () => {
    setPinging(true); setPingMs(null);
    const t0 = Date.now();
    try {
      setApiBase(draft);
      await onTest(draft);
      setPingMs(Date.now()-t0);
      toast?.("Connection successful!","success");
    } catch { toast?.("Connection failed","error"); }
    finally { setPinging(false); }
  };

  const saveKeys = () => {
    setSavingKeys(true);
    localStorage.setItem("cf_vt_key", vtKey);
    localStorage.setItem("cf_abuse_key", abuseKey);
    setTimeout(()=>{ setSavingKeys(false); toast?.("API keys saved locally","success"); },400);
  };

  const TABS = [
    {id:"connection",label:"Connection",icon:Wifi},
    {id:"apikeys",label:"API Keys",icon:Key},
    {id:"account",label:"Account",icon:Shield},
    {id:"about",label:"About",icon:Info},
  ];

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-black text-white tracking-tight">Settings</h1>
        <p className="text-sm mt-1" style={{color:"#64748B"}}>Configure backend, API keys, account, and platform info</p>
      </div>

      {/* Tab bar */}
      <div className="flex gap-1 p-1 rounded-xl" style={{background:"#0D1122",border:"1px solid #1E2A40",width:"fit-content"}}>
        {TABS.map(t=>(
          <button key={t.id} onClick={()=>setTab(t.id)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-bold transition-all"
            style={{background:tab===t.id?"#1E2A40":"transparent",color:tab===t.id?"#F1F5F9":"#475569"}}>
            <t.icon size={13}/>{t.label}
          </button>
        ))}
      </div>

      {/* CONNECTION TAB */}
      {tab==="connection" && (
        <Card className="p-5 space-y-4">
          <div>
            <p className="text-xs font-bold text-white mb-1.5">Backend API URL</p>
            <div className="flex gap-2">
              <input value={draft} onChange={e=>setDraft(e.target.value)}
                className="flex-1 px-3 py-2.5 rounded-lg text-sm text-white outline-none font-mono transition-all focus:ring-1 ring-blue-500" style={{background:"#0D1122",border:"1px solid #1E2A40"}}/>
              <button onClick={testConn} disabled={pinging}
                className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-bold text-white transition-all hover:brightness-110"
                style={{background:pinging?"#1E2A40":"#2D6BE4"}}>
                {pinging?<><Loader size={13} className="animate-spin"/>Testing…</>:<><Wifi size={13}/>Save &amp; Test</>}
              </button>
            </div>
            <p className="text-xs mt-2" style={{color:"#475569"}}>Run locally: <code className="font-mono text-blue-400">uvicorn app.main:app --reload --port 8000</code></p>
          </div>

          {/* Status row */}
          <div className="flex items-center gap-3 p-3 rounded-xl" style={{background:"#070E1B",border:"1px solid #1E2A40"}}>
            <div className="w-2.5 h-2.5 rounded-full flex-shrink-0" style={{background:connected?"#22C55E":"#EF4444",boxShadow:`0 0 8px ${connected?"#22C55E":"#EF4444"}`}}/>
            <div>
              <p className="text-sm font-bold" style={{color:connected?"#22C55E":"#EF4444"}}>{connected?"Backend Connected":"Backend Offline"}</p>
              {pingMs&&<p className="text-xs" style={{color:"#475569"}}>Latency: {pingMs}ms</p>}
            </div>
          </div>

          {/* Service health */}
          {health && (
            <div>
              <p className="text-xs font-bold mb-2" style={{color:"#475569"}}>SERVICE STATUS</p>
              <div className="space-y-2">
                {[
                  {label:"YARA Engine",     ok:health.yara_engine==="ready",   val:health.yara_engine},
                  {label:"VirusTotal API",  ok:health.virustotal_configured,   val:health.virustotal_configured?"Configured":"Not set"},
                  {label:"AbuseIPDB API",   ok:health.abuseipdb_configured,    val:health.abuseipdb_configured?"Configured":"Not set"},
                  {label:"Database",        ok:health.database==="connected",   val:health.database},
                ].map(s=>(
                  <div key={s.label} className="flex items-center justify-between p-2.5 rounded-lg" style={{background:"#111827",border:"1px solid #1E2A40"}}>
                    <span className="text-xs font-bold text-white">{s.label}</span>
                    <span className="text-xs font-mono" style={{color:s.ok?"#22C55E":"#EF4444"}}>{s.val}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </Card>
      )}

      {/* API KEYS TAB */}
      {tab==="apikeys" && (
        <Card className="p-5 space-y-4">
          <div className="p-3 rounded-xl flex items-start gap-2" style={{background:"rgba(59,130,246,0.08)",border:"1px solid rgba(59,130,246,0.2)"}}>
            <Info size={13} style={{color:"#3B82F6",flexShrink:0,marginTop:1}}/>
            <p className="text-xs" style={{color:"#94A3B8"}}>Keys are saved locally in your browser. Set them server-side in the backend <code className="text-blue-400">.env</code> file for full integration.</p>
          </div>
          {[
            {label:"VirusTotal API Key", key:"vtKey", val:vtKey, set:setVtKey, placeholder:"Enter VT API v3 key…", link:"https://www.virustotal.com/gui/my-apikey", color:"#3B82F6"},
            {label:"AbuseIPDB API Key",  key:"abuse", val:abuseKey, set:setAbuseKey, placeholder:"Enter AbuseIPDB key…", link:"https://www.abuseipdb.com/account/api", color:"#F97316"},
          ].map(f=>(
            <div key={f.key}>
              <div className="flex items-center justify-between mb-1.5">
                <p className="text-xs font-bold text-white">{f.label}</p>
                <a href={f.link} target="_blank" rel="noreferrer" className="text-xs flex items-center gap-1" style={{color:f.color}}>
                  <ExternalLink size={10}/> Get Key
                </a>
              </div>
              <input value={f.val} onChange={e=>f.set(e.target.value)} type="password" placeholder={f.placeholder}
                className="w-full px-3 py-2.5 rounded-lg text-sm text-white outline-none font-mono transition-all focus:ring-1 ring-blue-500" style={{background:"#0D1122",border:"1px solid #1E2A40"}}/>
            </div>
          ))}
          <button onClick={saveKeys} disabled={savingKeys}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-bold text-white transition-all hover:brightness-110"
            style={{background:savingKeys?"#1E2A40":"#22C55E"}}>
            {savingKeys?<><Loader size={13} className="animate-spin"/>Saving…</>:<><Check size={13}/>Save API Keys</>}
          </button>
        </Card>
      )}

      {/* ACCOUNT TAB */}
      {tab==="account" && (
        <Card className="p-5 space-y-4">
          {currentUser ? (
            <div className="flex items-center gap-4 p-4 rounded-xl" style={{background:"#0D1122",border:"1px solid #1E2A40"}}>
              <div className="w-12 h-12 rounded-full flex items-center justify-center text-xl font-black" style={{background:"linear-gradient(135deg,#2D6BE4,#7C3AED)",color:"white"}}>
                {(currentUser.username||"A").charAt(0).toUpperCase()}
              </div>
              <div>
                <p className="font-black text-white">{currentUser.username}</p>
                <p className="text-xs" style={{color:"#64748B"}}>{currentUser.role||"Analyst"} · {currentUser.email||"No email set"}</p>
              </div>
              <span className="ml-auto text-xs font-bold px-2 py-1 rounded" style={{background:"rgba(34,197,94,0.15)",color:"#22C55E"}}>Active</span>
            </div>
          ) : (
            <div className="p-4 rounded-xl text-center" style={{background:"#0D1122",border:"1px solid #1E2A40"}}>
              <Shield size={24} style={{color:"#334155"}} className="mx-auto mb-2"/>
              <p className="text-sm" style={{color:"#475569"}}>Not signed in</p>
            </div>
          )}
          <div className="p-3 rounded-xl" style={{background:"rgba(234,179,8,0.08)",border:"1px solid rgba(234,179,8,0.2)"}}>
            <p className="text-xs font-bold mb-1" style={{color:"#EAB308"}}>Change Password</p>
            <p className="text-xs" style={{color:"#64748B"}}>Use the backend API directly: <code className="text-yellow-400">POST /api/auth/change-password</code></p>
          </div>
        </Card>
      )}

      {/* ABOUT TAB */}
      {tab==="about" && (
        <Card className="p-5 space-y-4">
          <div className="flex items-center gap-4">
            <div className="p-3 rounded-xl" style={{background:"rgba(45,107,228,0.12)",border:"1px solid rgba(45,107,228,0.3)"}}>
              <Shield size={28} style={{color:"#2D6BE4"}}/>
            </div>
            <div>
              <p className="font-black text-white text-lg">CyberForge</p>
              <p className="text-xs" style={{color:"#64748B"}}>Forensics Platform v3.0 · FastAPI + React</p>
            </div>
          </div>
          {[
            ["Frontend","React 18 + Vite + Recharts","#3B82F6"],
            ["Backend","FastAPI + SQLAlchemy + PostgreSQL","#22C55E"],
            ["Analysis Engine","YARA + pefile + IOC regex","#F97316"],
            ["AI Assistant","Claude (Anthropic) via CIPHER","#7C3AED"],
            ["Auth","JWT RS256 + bcrypt","#EAB308"],
            ["PCAP","dpkt / scapy real parsing","#06B6D4"],
          ].map(([k,v,c])=>(
            <div key={k} className="flex items-center justify-between p-2.5 rounded-lg" style={{background:"#0D1122",border:"1px solid #1E2A40"}}>
              <span className="text-xs font-bold text-white">{k}</span>
              <span className="text-xs font-mono" style={{color:c}}>{v}</span>
            </div>
          ))}
        </Card>
      )}
    </div>
  );
}


export default SettingsPanel;
