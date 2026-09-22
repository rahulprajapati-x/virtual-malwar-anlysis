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

// ================================================================
//  GLOBAL SEARCH MODAL  (Cmd+K)
// ================================================================

function GlobalSearchModal({ open, onClose, api, onNavigate }) {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const inputRef = useRef(null);

  useEffect(() => {
    if (open) { setQuery(""); setResults([]); setTimeout(() => inputRef.current?.focus(), 80); }
  }, [open]);

  useEffect(() => {
    if (!query.trim() || query.length < 2) { setResults([]); return; }
    const t = setTimeout(async () => {
      setLoading(true);
      try {
        const [samples, iocs, cases] = await Promise.allSettled([
          api.listSamples(`?limit=50`),
          api.iocs(`?limit=100`),
          api.listCases(),
        ]);
        const q = query.toLowerCase();
        const found = [];
        if (samples.status === "fulfilled" && Array.isArray(samples.value)) {
          samples.value.filter(s => s.filename?.toLowerCase().includes(q) || s.sha256?.toLowerCase().includes(q))
            .slice(0,4).forEach(s => found.push({ type:"sample", label: s.filename, sub: `Risk: ${s.risk_score}/100 · ${s.threat_level}`, id: s.id, color: "#3B82F6" }));
        }
        if (iocs.status === "fulfilled" && Array.isArray(iocs.value)) {
          iocs.value.filter(i => i.value?.toLowerCase().includes(q))
            .slice(0,4).forEach(i => found.push({ type:"ioc", label: i.value, sub: `${i.ioc_type} · ${i.family}`, color: "#818CF8" }));
        }
        if (cases.status === "fulfilled" && Array.isArray(cases.value)) {
          cases.value.filter(c => c.name?.toLowerCase().includes(q) || c.case_number?.toLowerCase().includes(q))
            .slice(0,3).forEach(c => found.push({ type:"case", label: c.name, sub: `${c.case_number} · ${c.severity}`, id: c.id, color: "#F97316" }));
        }
        setResults(found);
      } catch {}
      finally { setLoading(false); }
    }, 300);
    return () => clearTimeout(t);
  }, [query, api]);

  if (!open) return null;
  return (
    <div className="fixed inset-0 z-[9998] flex items-start justify-center pt-24 px-4" style={{background:"rgba(0,0,0,0.75)",backdropFilter:"blur(6px)"}} onClick={onClose}>
      <div className="w-full max-w-xl rounded-2xl overflow-hidden shadow-2xl" style={{background:"#0D1122",border:"1px solid #2D3A55"}} onClick={e=>e.stopPropagation()}>
        <div className="flex items-center gap-3 px-4 py-3 border-b" style={{borderColor:"#1E2A40"}}>
          <Search size={16} style={{color:"#475569",flexShrink:0}}/>
          <input ref={inputRef} value={query} onChange={e=>setQuery(e.target.value)}
            placeholder="Search samples, IOCs, cases…" className="flex-1 bg-transparent text-white text-sm outline-none placeholder-slate-600"
            onKeyDown={e=>e.key==="Escape"&&onClose()}/>
          {loading && <Loader size={14} className="animate-spin" style={{color:"#475569"}}/>}
          <span className="text-xs px-1.5 py-0.5 rounded" style={{background:"#1E2A40",color:"#475569"}}>Esc</span>
        </div>
        <div className="max-h-80 overflow-y-auto">
          {results.length === 0 && query.length >= 2 && !loading && (
            <div className="px-4 py-8 text-center text-sm" style={{color:"#475569"}}>No results for "{query}"</div>
          )}
          {results.length === 0 && query.length < 2 && (
            <div className="px-4 py-6">
              <p className="text-xs font-bold uppercase tracking-wider mb-3" style={{color:"#334155"}}>Quick Jump</p>
              {["dashboard","upload","sandbox-env","cipher","cases","iocdb","pcap","memory"].map(v=>(
                <button key={v} onClick={()=>{onNavigate(v);onClose();}}
                  className="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm text-left transition-all hover:bg-white/5" style={{color:"#94A3B8"}}>
                  <ChevronRight size={12}/> {v.charAt(0).toUpperCase()+v.slice(1).replace(/-/g," ")}
                </button>
              ))}
            </div>
          )}
          {results.map((r,i) => (
            <button key={i} onClick={()=>{ if(r.type==="sample"&&r.id) onNavigate("analysis",r.id); else if(r.type==="case") onNavigate("cases"); else onNavigate("iocdb"); onClose(); }}
              className="w-full flex items-center gap-3 px-4 py-3 text-left transition-all hover:bg-white/5" style={{borderBottom:"1px solid #1E2A40"}}>
              <span className="text-xs font-bold px-1.5 py-0.5 rounded flex-shrink-0"
                style={{background:`${r.color}18`,color:r.color}}>{r.type}</span>
              <div className="flex-1 min-w-0">
                <p className="text-sm text-white font-mono truncate">{r.label}</p>
                <p className="text-xs mt-0.5" style={{color:"#475569"}}>{r.sub}</p>
              </div>
              <ChevronRight size={12} style={{color:"#334155",flexShrink:0}}/>
            </button>
          ))}
        </div>
        <div className="px-4 py-2 flex items-center gap-4 text-xs" style={{background:"#070E1B",color:"#334155",borderTop:"1px solid #1E2A40"}}>
          <span>↩ select</span><span>↑↓ navigate</span><span>Esc close</span>
        </div>
      </div>
    </div>
  );
}

export { GlobalSearchModal };
