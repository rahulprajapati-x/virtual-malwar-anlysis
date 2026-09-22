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

// ================================================================
//  VIRTUAL ENVIRONMENT (SANDBOX ENTRY POINT)
// ================================================================

function VirtualEnvironment({ onFile, analyzing, currentFile, error, sample, onViewResults }) {
  const [drag, setDrag] = useState(false);
  const ref = useRef(null);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-black text-white tracking-tight flex items-center gap-3">
          <Monitor size={28} style={{color:"#22C55E"}}/>
          Virtual Sandbox Environment
        </h1>
        <p className="text-sm mt-2" style={{color:"#64748B"}}>
          Isolated dynamic sandbox. Simulates real user installing & running malware — captures every process, API call, network connection, registry change, and file system event.
        </p>
      </div>

      {sample && !analyzing && (
        <Card className="p-4 flex items-center justify-between gap-4 animate-fade-in"
          style={{background:"rgba(34,197,94,0.08)", borderColor:"rgba(34,197,94,0.3)"}}>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-[#22C55E]/20 border border-[#22C55E]/40 flex items-center justify-center text-[#22C55E] flex-shrink-0">
              <CheckCircle size={20}/>
            </div>
            <div>
              <p className="text-xs font-bold text-[#22C55E]">Active Sandbox Detonation Results Ready</p>
              <p className="text-sm font-black text-white">{sample.filename}</p>
              <p className="text-xs text-slate-400">Verdict: <span className="font-bold text-red-400">{sample.threat_level}</span> ({sample.risk_score}/100)</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {onViewResults && (
              <button onClick={onViewResults}
                className="px-4 py-2 rounded-xl text-xs font-bold text-white bg-[#22C55E] hover:bg-[#22C55E]/90 transition-all flex items-center gap-1.5 shadow-lg shadow-green-500/20">
                <Eye size={13}/> View Full Report
              </button>
            )}
          </div>
        </Card>
      )}

      {error && (
        <Card className="p-3 flex items-center gap-2" style={{borderColor:"rgba(239,68,68,0.4)"}}>
          <AlertTriangle size={14} style={{color:"#EF4444"}}/>
          <span className="text-xs" style={{color:"#FCA5A5"}}>{error}</span>
        </Card>
      )}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="col-span-2">
           <div
            className="rounded-2xl border-2 border-dashed flex flex-col items-center justify-center cursor-pointer transition-all relative overflow-hidden"
            style={{borderColor: drag ? "#22C55E":"#1E2A40", background: drag?"rgba(34,197,94,0.05)":"#0D1122", minHeight:320}}
            onDragOver={e=>{e.preventDefault();setDrag(true);}}
            onDragLeave={()=>setDrag(false)}
            onDrop={e=>{e.preventDefault();setDrag(false);const f=e.dataTransfer.files[0];if(f)onFile(f);}}
            onClick={()=>ref.current?.click()}
          >
             <div className="absolute inset-0 bg-gradient-to-b from-[rgba(34,197,94,0.03)] to-transparent pointer-events-none"/>

             {analyzing ? (
               <div className="flex flex-col items-center z-10">
                 <div className="relative mb-6">
                   <div className="w-20 h-20 rounded-full flex items-center justify-center bg-[rgba(34,197,94,0.1)] border-2 border-[#22C55E]">
                     <Monitor size={32} style={{color:"#22C55E"}}/>
                   </div>
                   <div className="absolute inset-0 rounded-full animate-ping opacity-30 bg-[#22C55E]"/>
                 </div>
                 <h2 className="text-xl font-black text-white mb-2">Detonating in Sandbox...</h2>
                 <p className="text-sm font-mono text-[#64748B] mb-6">{currentFile?.name}</p>
                 <div className="flex items-center gap-2 text-xs text-[#22C55E]">
                   <Loader size={14} className="animate-spin"/> Capturing behavioral telemetry
                 </div>
               </div>
             ) : (
               <div className="flex flex-col items-center z-10 p-8 text-center">
                 <div className="w-20 h-20 rounded-full bg-[rgba(34,197,94,0.1)] flex items-center justify-center mb-5 transition-transform hover:scale-110 border border-[rgba(34,197,94,0.3)]">
                   <Terminal size={32} style={{color:"#22C55E"}}/>
                 </div>
                 <p className="font-black text-white text-xl mb-2">Drop Malware to Detonate</p>
                 <p className="text-sm text-[#64748B] mb-4">Simulates real human installing & running the app inside an isolated VM</p>
                 <p className="text-xs text-[#334155] mb-6">Every step shown: download → install dialogs → UAC → process spawn → registry → C2 → exfil</p>
                 <div className="flex items-center gap-3 flex-wrap justify-center">
                   <div className="px-3 py-1.5 rounded bg-[rgba(34,197,94,0.1)] text-[#22C55E] text-xs font-bold border border-[rgba(34,197,94,0.3)]">🪟 Windows EXE</div>
                   <div className="px-3 py-1.5 rounded bg-[rgba(34,197,94,0.1)] text-[#22C55E] text-xs font-bold border border-[rgba(34,197,94,0.3)]">📱 Android APK</div>
                   <div className="px-3 py-1.5 rounded bg-[rgba(34,197,94,0.1)] text-[#22C55E] text-xs font-bold border border-[rgba(34,197,94,0.3)]">📄 Documents</div>
                 </div>
               </div>
             )}
             <input ref={ref} type="file" className="hidden" onChange={e=>{const f=e.target.files?.[0];if(f)onFile(f);}}/>
          </div>
        </div>

        <div className="space-y-4">
           <Card className="p-5" style={{background: "linear-gradient(180deg, #111827 0%, #0D1122 100%)", borderTop: "2px solid #22C55E"}}>
             <h3 className="text-sm font-black text-white mb-4 uppercase tracking-wider flex items-center gap-2">
                <Zap size={14} style={{color:"#22C55E"}}/> Sandbox Specs
             </h3>
             <div className="space-y-3 text-xs">
                {[
                  ["Isolation", "Air-gapped VM", "#22C55E"],
                  ["Network", "Intercepted", "#EF4444"],
                  ["Timeout", "90 seconds", "#EAB308"],
                  ["API Hook", "Win32 / ART", "#3B82F6"],
                  ["Profiles", "Win/Android/Doc", "#818CF8"],
                  ["Steps", "Full install flow", "#22C55E"],
                ].map(([k,v,c])=>(
                  <div key={k} className="flex justify-between border-b border-[#1E2A40] pb-2">
                    <span className="text-[#64748B]">{k}</span>
                    <span className="font-mono font-bold" style={{color:c}}>{v}</span>
                  </div>
                ))}
             </div>
           </Card>

           <Card className="p-4" style={{borderColor:"rgba(34,197,94,0.2)", background:"rgba(34,197,94,0.05)"}}>
              <p className="text-xs font-bold text-[#22C55E] mb-2 flex items-center gap-1.5">
                <Activity size={12}/> What You'll See
              </p>
              <div className="space-y-1.5 text-xs text-[#64748B]">
                {[
                  "📥 File download simulation",
                  "🛡 UAC/SmartScreen dialogs",
                  "⚙ Installer steps (Next→Next→Install)",
                  "🔧 Registry key creation",
                  "💉 Process injection events",
                  "🌐 C2 beaconing attempts",
                  "🔐 Credential theft",
                  "📡 Data exfiltration (blocked)",
                  "📋 Full harm report at end",
                ].map((item, i) => (
                  <p key={i}>{item}</p>
                ))}
              </div>
           </Card>
        </div>
      </div>
    </div>
  );
}


export default VirtualEnvironment;
