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
//  CASES
// ================================================================

function Cases({ api, connected, refreshKey, onViewTimeline }) {
  const [cases, setCases] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ name:"", description:"", severity:"MEDIUM", analyst:"", agency:"" });
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    if (!connected) { setLoading(false); return; }
    setLoading(true);
    try { setCases(await api.listCases()); } catch(e) { console.error(e); }
    finally { setLoading(false); }
  }, [api, connected]);

  useEffect(() => { load(); }, [load, refreshKey]);

  const submit = async () => {
    if (!form.name.trim()) return;
    setSaving(true);
    try {
      await api.createCase(form);
      setForm({ name:"", description:"", severity:"MEDIUM", analyst:"", agency:"" });
      setShowForm(false);
      load();
    } catch(e) { console.error(e); }
    finally { setSaving(false); }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-black text-white tracking-tight">Case Management</h1>
          <p className="text-sm mt-1" style={{color:"#64748B"}}>Active investigations and digital forensics case files</p>
        </div>
        <button onClick={()=>setShowForm(v=>!v)} className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-bold text-white" style={{background:"#2D6BE4"}}>
          <Plus size={13}/> New Case
        </button>
      </div>

      {showForm && (
        <Card className="p-4 space-y-3">
          <input placeholder="Case name" value={form.name} onChange={e=>setForm({...form,name:e.target.value})}
            className="w-full px-3 py-2 rounded-lg text-sm text-white outline-none" style={{background:"#0D1122",border:"1px solid #1E2A40"}}/>
          <textarea placeholder="Description" value={form.description} onChange={e=>setForm({...form,description:e.target.value})}
            className="w-full px-3 py-2 rounded-lg text-sm text-white outline-none" style={{background:"#0D1122",border:"1px solid #1E2A40"}} rows={2}/>
          <div className="grid grid-cols-3 gap-2">
            <select value={form.severity} onChange={e=>setForm({...form,severity:e.target.value})}
              className="px-3 py-2 rounded-lg text-sm text-white outline-none" style={{background:"#0D1122",border:"1px solid #1E2A40"}}>
              {["CRITICAL","HIGH","MEDIUM","LOW"].map(s=><option key={s} value={s}>{s}</option>)}
            </select>
            <input placeholder="Analyst" value={form.analyst} onChange={e=>setForm({...form,analyst:e.target.value})}
              className="px-3 py-2 rounded-lg text-sm text-white outline-none" style={{background:"#0D1122",border:"1px solid #1E2A40"}}/>
            <input placeholder="Agency / Unit" value={form.agency} onChange={e=>setForm({...form,agency:e.target.value})}
              className="px-3 py-2 rounded-lg text-sm text-white outline-none" style={{background:"#0D1122",border:"1px solid #1E2A40"}}/>
          </div>
          <button onClick={submit} disabled={saving||!form.name.trim()}
            className="px-4 py-2 rounded-lg text-sm font-bold text-white" style={{background:saving?"#1E2A40":"#22C55E"}}>
            {saving ? "Creating…" : "Create Case"}
          </button>
        </Card>
      )}

      {!connected ? <EmptyState icon={WifiOff} title="Backend not connected"/> :
       loading ? <div className="flex justify-center py-12"><Loader size={20} className="animate-spin" style={{color:"#2D6BE4"}}/></div> :
       cases.length===0 ? <EmptyState icon={Flag} title="No cases yet" sub="Create your first investigation case above"/> : (
        <div className="space-y-2">
          {cases.map(c=>(
            <Card key={c.id} className="p-4 group">
              <div className="flex items-start gap-3">
                <div className="w-1 self-stretch rounded-full flex-shrink-0" style={{background:sevColor(c.severity)}}/>
                <div className="flex-1">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2 flex-wrap mb-1">
                      <span className="font-mono text-xs" style={{color:"#475569"}}>{c.case_number}</span>
                      <Badge label={c.severity} color={sevColor(c.severity)}/>
                      <Badge label={c.status} color={c.status==="Active"?"#2D6BE4":c.status==="Closed"?"#475569":"#F59E0B"}/>
                    </div>
                    <div className="flex items-center gap-1.5">
                      {onViewTimeline && (
                        <button onClick={() => onViewTimeline(c)}
                          className="opacity-0 group-hover:opacity-100 transition-opacity flex items-center gap-1 text-xs px-2 py-1 rounded"
                          style={{background:"rgba(129,140,248,0.15)", color:"#818CF8", border:"1px solid rgba(129,140,248,0.3)"}}>
                          <Clock size={11}/> Timeline
                        </button>
                      )}
                      {c.status !== "Closed" && (
                        <button onClick={async () => {
                          try {
                            await api.updateCase(c.id, { status: "Closed" });
                            load();
                          } catch(e) { console.error(e); }
                        }} className="opacity-0 group-hover:opacity-100 transition-opacity flex items-center gap-1 text-xs px-2 py-1 rounded" style={{background:"#1E2A40", color:"#94A3B8"}}>
                          <Archive size={12}/> Close Case
                        </button>
                      )}
                    </div>
                  </div>
                  <p className="font-bold text-white">{c.name}</p>
                  {c.description && <p className="text-xs mt-0.5" style={{color:"#475569"}}>{c.description}</p>}
                  <div className="flex flex-wrap gap-4 mt-2 text-xs" style={{color:"#334155"}}>
                    <span>👤 {c.analyst || "Unassigned"}</span>
                    <span>📁 {c.sample_count} sample{c.sample_count!==1?"s":""}</span>
                    <span>📅 {new Date(c.created_at).toLocaleDateString()}</span>
                  </div>
                </div>
              </div>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}


export default Cases;
