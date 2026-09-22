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

import { Card, Badge, EmptyState } from "../components/SharedComponents";
import { sevColor } from "../utils/helpers";

// ================================================================
//  IOC DATABASE
// ================================================================

function IOCDatabase({ api, connected, onExplain }) {
  const [iocs, setIocs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const typeColor = {domain:"#818CF8",ip:"#2D6BE4",hash:"#22C55E",url:"#F97316",regkey:"#EAB308",filepath:"#94A3B8",mutex:"#EF4444",wallet:"#F97316"};

  useEffect(() => {
    if (!connected) { setLoading(false); return; }
    api.iocs("?limit=200").then(setIocs).catch(console.error).finally(()=>setLoading(false));
  }, [api, connected]);

  const filtered = useMemo(() => {
    if (!search.trim()) return iocs;
    const q = search.toLowerCase();
    return iocs.filter(ioc => 
      ioc.value.toLowerCase().includes(q) || 
      ioc.ioc_type.toLowerCase().includes(q) || 
      (ioc.family && ioc.family.toLowerCase().includes(q))
    );
  }, [iocs, search]);

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-black text-white tracking-tight">IOC Database</h1>
          <p className="text-sm mt-1" style={{color:"#64748B"}}>Indicators of Compromise extracted from all analyzed samples</p>
        </div>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input 
              type="text" 
              value={search} 
              onChange={e => setSearch(e.target.value)}
              placeholder="Search IOCs, types, families..." 
              className="pl-9 pr-4 py-2 rounded-lg text-sm text-white outline-none w-64 transition-all focus:ring-2 ring-blue-500" 
              style={{background:"#0D1122",border:"1px solid #1E2A40"}}
            />
          </div>
          <button onClick={()=>window.open(`${api.reportUrl("").replace(/\/api\/reports.*/,"")}/api/iocs/export`,"_blank")}
            className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-bold text-white" style={{background:"#22C55E"}}>
            <Download size={13}/> Export JSON
          </button>
        </div>
      </div>

      {!connected ? <EmptyState icon={WifiOff} title="Backend not connected"/> :
       loading ? <div className="flex justify-center py-12"><Loader size={20} className="animate-spin" style={{color:"#2D6BE4"}}/></div> :
       iocs.length===0 ? <EmptyState icon={Database} title="No IOCs in database yet" sub="Analyze samples to populate this list"/> : (
        <Card className="overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead><tr style={{background:"#0D1122",borderBottom:"1px solid #1E2A40"}}>
                <th className="text-left px-4 py-3 font-bold uppercase tracking-wider" style={{color:"#475569"}}>Type</th>
                <th className="text-left px-4 py-3 font-bold uppercase tracking-wider" style={{color:"#475569"}}>Indicator</th>
                <th className="text-left px-4 py-3 font-bold uppercase tracking-wider" style={{color:"#475569"}}>Family</th>
                <th className="text-left px-4 py-3 font-bold uppercase tracking-wider" style={{color:"#475569"}}>Confidence</th>
                <th className="text-left px-4 py-3 font-bold uppercase tracking-wider" style={{color:"#475569"}}>Added</th>
              </tr></thead>
              <tbody>
                {filtered.map(ioc=>(
                  <tr key={ioc.id} className="group" style={{borderBottom:"1px solid #1E2A40"}}>
                    <td className="px-4 py-3"><span className="text-xs font-bold px-2 py-0.5 rounded" style={{color:typeColor[ioc.ioc_type]||"#64748B",background:`${typeColor[ioc.ioc_type]||"#64748B"}1A`}}>{ioc.ioc_type}</span></td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <code className="font-mono text-white" style={{fontSize:11}}>{ioc.value}</code>
                        {onExplain && (
                          <button onClick={() => onExplain("Indicator of Compromise", ioc.value, `Type: ${ioc.ioc_type}. Family: ${ioc.family}`)}
                            className="opacity-0 group-hover:opacity-100 transition-opacity p-1 hover:bg-[#1E2A40] rounded text-[#A78BFA]" title="Explain IOC">
                            <Brain size={12}/>
                          </button>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3" style={{color:"#94A3B8"}}>{ioc.family}</td>
                    <td className="px-4 py-3"><Badge label={ioc.confidence} color={sevColor(ioc.confidence)}/></td>
                    <td className="px-4 py-3" style={{color:"#475569"}}>{new Date(ioc.first_seen).toLocaleDateString()}</td>
                  </tr>
                ))}
                {filtered.length === 0 && search && (
                  <tr>
                    <td colSpan="5" className="px-4 py-8 text-center text-slate-500">No IOCs match your search query.</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  );
}


export default IOCDatabase;
