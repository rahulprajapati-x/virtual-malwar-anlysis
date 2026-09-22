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

import { useToast } from "../components/Toast";

// ================================================================
//  CASE TIMELINE
// ================================================================

function CaseTimeline({ caseData, api, onClose }) {
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [note, setNote] = useState("");
  const [savingNote, setSavingNote] = useState(false);
  const toast = useToast();

  useEffect(() => {
    if (!caseData?.id) return;
    setLoading(true);
    // Try to load audit log from backend
    api.getCaseAudit(caseData.id).then(data => {
      setEvents(Array.isArray(data) ? data : []);
    }).catch(() => {
      // Fallback demo events
      setEvents([
        { id:1, type:"case_created", actor:"analyst", timestamp: caseData.created_at, note:`Case ${caseData.case_number} created` },
        { id:2, type:"sample_added", actor:"analyst", timestamp: new Date(Date.now()-3600000).toISOString(), note:"Sample malware.exe added (Risk: 87/100 CRITICAL)" },
        { id:3, type:"note_added",   actor:"analyst", timestamp: new Date(Date.now()-1800000).toISOString(), note:"Confirmed C2 communication to 185.220.101.47" },
        { id:4, type:"status_change",actor:"system",  timestamp: new Date(Date.now()-600000).toISOString(),  note:"Status changed: Open → Active" },
      ]);
    }).finally(() => setLoading(false));
  }, [api, caseData]);

  const addNote = async () => {
    if (!note.trim()) return;
    setSavingNote(true);
    try {
      await api.addCaseNote(caseData.id, note.trim()).catch(() => {});
      const newEvent = {
        id: Date.now(), type:"note_added", actor:"analyst",
        timestamp: new Date().toISOString(), note: note.trim()
      };
      setEvents(prev => [...prev, newEvent]);
      setNote("");
      toast?.("Note added to case timeline", "success");
    } catch(e) {
      toast?.("Failed to save note", "error");
    } finally { setSavingNote(false); }
  };

  const typeConfig = {
    case_created:  { icon: Flag,        color:"#22C55E", label:"Case Created" },
    sample_added:  { icon: Upload,      color:"#2D6BE4", label:"Sample Added" },
    note_added:    { icon: StickyNote,  color:"#818CF8", label:"Note Added" },
    status_change: { icon: RefreshCw,   color:"#F97316", label:"Status Changed" },
    case_closed:   { icon: Archive,     color:"#64748B", label:"Case Closed" },
  };

  const exportTimeline = () => {
    const data = {
      case: { id: caseData.id, number: caseData.case_number, name: caseData.name, analyst: caseData.analyst },
      events: events.map(e => ({ ...e, timestamp: new Date(e.timestamp).toISOString() })),
      exported_at: new Date().toISOString(),
      exported_by: "analyst",
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type:"application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `chain-of-custody-${caseData.case_number}.json`; a.click();
    URL.revokeObjectURL(url);
    toast?.("Chain-of-custody exported", "success");
  };

  return (
    <div className="fixed inset-0 z-50 flex items-end justify-end p-4 pointer-events-none">
      <div className="pointer-events-auto animate-slide-right w-full max-w-md flex flex-col rounded-2xl overflow-hidden shadow-2xl"
        style={{background:"#0D1122", border:"1px solid #1E2A40", maxHeight:"90vh"}}>
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b" style={{borderColor:"#1E2A40"}}>
          <div>
            <p className="text-xs font-bold" style={{color:"#475569"}}>{caseData.case_number}</p>
            <h2 className="text-sm font-black text-white mt-0.5">{caseData.name}</h2>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={exportTimeline} className="flex items-center gap-1 text-xs px-2 py-1.5 rounded-lg font-bold transition-all hover:brightness-110"
              style={{background:"rgba(34,197,94,0.15)",color:"#22C55E",border:"1px solid rgba(34,197,94,0.3)"}}>
              <Download size={11}/> Export CoC
            </button>
            <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-white/10 transition-colors" style={{color:"#475569"}}><X size={16}/></button>
          </div>
        </div>

        {/* Timeline */}
        <div className="flex-1 overflow-y-auto p-5">
          <p className="text-xs font-bold uppercase tracking-widest mb-5" style={{color:"#334155"}}>Investigation Timeline</p>
          {loading ? (
            <div className="space-y-4">
              {[1,2,3].map(i=><div key={i} className="skeleton-box h-16 rounded-xl"/>)}
            </div>
          ) : (
            <div className="relative">
              {/* Vertical line */}
              <div className="absolute left-4 top-3 bottom-3 w-0.5" style={{background:"#1E2A40"}}/>
              <div className="space-y-4 pl-12">
                {events.map((ev, i) => {
                  const cfg = typeConfig[ev.type] || { icon: Clock, color:"#64748B", label: ev.type };
                  const Icon = cfg.icon;
                  return (
                    <div key={ev.id} className="relative animate-fade-in" style={{animationDelay:`${i*60}ms`}}>
                      {/* Node */}
                      <div className="absolute -left-[2.25rem] w-7 h-7 rounded-full flex items-center justify-center"
                        style={{background:`${cfg.color}15`, border:`2px solid ${cfg.color}`, top:0}}>
                        <Icon size={11} style={{color:cfg.color}}/>
                      </div>
                      {/* Event card */}
                      <div className="p-3 rounded-xl" style={{background:"#111827",border:"1px solid #1E2A40"}}>
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-xs font-bold" style={{color:cfg.color}}>{cfg.label}</span>
                          <span className="text-xs" style={{color:"#334155"}}>
                            {new Date(ev.timestamp).toLocaleString()}
                          </span>
                        </div>
                        <p className="text-xs" style={{color:"#94A3B8"}}>{ev.note}</p>
                        <p className="text-xs mt-1" style={{color:"#334155"}}>By: {ev.actor}</p>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>

        {/* Add note */}
        <div className="p-4 border-t" style={{borderColor:"#1E2A40"}}>
          <p className="text-xs font-bold text-white mb-2 flex items-center gap-1">
            <StickyNote size={11}/> Add Investigation Note
          </p>
          <div className="flex gap-2">
            <input
              value={note} onChange={e=>setNote(e.target.value)}
              onKeyDown={e=>e.key==="Enter"&&addNote()}
              placeholder="Enter note... (chain-of-custody record)"
              className="flex-1 px-3 py-2 rounded-lg text-xs text-white outline-none"
              style={{background:"#111827",border:"1px solid #1E2A40"}}
            />
            <button onClick={addNote} disabled={savingNote||!note.trim()}
              className="px-3 py-2 rounded-lg text-xs font-bold text-white flex-shrink-0 transition-all"
              style={{background:savingNote||!note.trim()?"#1E2A40":"#818CF8"}}>
              {savingNote ? <Loader size={12} className="animate-spin"/> : <Send size={12}/>}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}


export default CaseTimeline;
