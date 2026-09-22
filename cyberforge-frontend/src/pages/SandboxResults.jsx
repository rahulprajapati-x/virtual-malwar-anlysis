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
import { SANDBOX_EVENT_META, SANDBOX_TYPE_META } from "./SandboxTimeline";
import MachineHarmReport from "./MachineHarmReport";

// ================================================================
//  SANDBOX TIMELINE COMPONENT (original results view)
// ================================================================

function SandboxTimeline({ dyn, api, sampleId, onRerun, rerunning, sample }) {
  const [visibleCount, setVisibleCount] = useState(0);
  const [activeSection, setActiveSection] = useState("timeline");

  useEffect(() => {
    setVisibleCount(0);
    if (!dyn?.events?.length) return;
    let i = 0;
    const iv = setInterval(() => {
      i++;
      setVisibleCount(i);
      if (i >= dyn.events.length) clearInterval(iv);
    }, 60);
    return () => clearInterval(iv);
  }, [dyn]);

  if (!dyn || dyn.sandbox_type === "unsupported") {
    return (
      <Card className="p-8 text-center">
        <Terminal size={32} className="mx-auto mb-3" style={{color:"#334155"}}/>
        <p className="font-bold text-white text-base mb-1">No Sandbox Data</p>
        <p className="text-xs mb-5" style={{color:"#475569"}}>
          {dyn?.error || "Sandbox was not enabled during analysis, or this file type has no sandbox profile."}
        </p>
        {sampleId && (
          <button onClick={onRerun} disabled={rerunning}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-bold text-white"
            style={{background: rerunning ? "#1E2A40" : "#EF4444"}}>
            {rerunning ? <Loader size={13} className="animate-spin"/> : <Terminal size={13}/>}
            {rerunning ? "Running Sandbox…" : "Run Sandbox Now"}
          </button>
        )}
      </Card>
    );
  }

  const typeMeta = SANDBOX_TYPE_META[dyn.sandbox_type] || SANDBOX_TYPE_META.windows;
  const TypeIcon = typeMeta.icon;
  const verdictColor = dyn.sandbox_verdict === "MALICIOUS" ? "#EF4444"
    : dyn.sandbox_verdict === "SUSPICIOUS" ? "#F97316" : "#22C55E";

  const sections = [
    { id: "timeline", label: `Timeline (${dyn.events.length})`, icon: Activity },
    { id: "network",  label: `Network (${dyn.network_iocs.length})`, icon: Globe },
    { id: "files",    label: `Files (${dyn.dropped_files.length})`, icon: Folder },
    { id: "registry", label: `Registry (${dyn.registry_changes.length})`, icon: Database },
    ...(dyn.permissions_requested.length > 0 ? [{ id: "perms", label: `Permissions (${dyn.permissions_requested.length})`, icon: Smartphone }] : []),
    { id: "harm_report", label: "Harm Report", icon: Skull },
  ];

  return (
    <div className="space-y-4">
      {/* Header */}
      <Card className="p-4" style={{borderColor:"rgba(239,68,68,0.3)", background:"rgba(239,68,68,0.03)"}}>
        <div className="flex items-start justify-between gap-3 flex-wrap">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl" style={{background: `${typeMeta.color}1A`}}>
              <TypeIcon size={20} style={{color: typeMeta.color}}/>
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-sm font-black text-white">{typeMeta.label}</span>
                <span className="text-xs font-black px-2 py-0.5 rounded-full"
                  style={{background:`${verdictColor}1A`, color:verdictColor, border:`1px solid ${verdictColor}40`}}>
                  {dyn.sandbox_verdict}
                </span>
                {dyn.risk_delta > 0 && (
                  <span className="text-xs font-bold px-2 py-0.5 rounded-full"
                    style={{background:"rgba(239,68,68,0.12)", color:"#EF4444", border:"1px solid rgba(239,68,68,0.3)"}}>
                    +{dyn.risk_delta} risk delta
                  </span>
                )}
                {dyn.timeout_hit && (
                  <span className="text-xs font-bold px-2 py-0.5 rounded-full"
                    style={{background:"rgba(234,179,8,0.12)", color:"#EAB308"}}>
                    TIMEOUT
                  </span>
                )}
              </div>
              <p className="text-xs mt-0.5" style={{color:"#475569"}}>
                {dyn.events.length} behavioral events recorded •{" "}
                {(dyn.execution_time_ms / 1000).toFixed(1)}s simulated execution •{" "}
                {dyn.network_iocs.length} network connection attempts (all blocked)
              </p>
            </div>
          </div>
          <button onClick={onRerun} disabled={rerunning}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold text-white flex-shrink-0"
            style={{background: rerunning ? "#1E2A40" : "rgba(239,68,68,0.2)", border:"1px solid rgba(239,68,68,0.4)"}}>
            {rerunning ? <Loader size={11} className="animate-spin"/> : <RefreshCw size={11}/>}
            {rerunning ? "Re-running…" : "Re-run Sandbox"}
          </button>
        </div>
      </Card>

      {/* Section tabs */}
      <div className="flex gap-1.5 overflow-x-auto pb-1">
        {sections.map(s => (
          <button key={s.id} onClick={() => setActiveSection(s.id)}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-bold flex-shrink-0 transition-all"
            style={{
              background: activeSection===s.id ? (s.id === "harm_report" ? "rgba(239,68,68,0.25)" : "rgba(239,68,68,0.18)") : "#111827",
              color: activeSection===s.id ? "#EF4444" : "#64748B",
              border: `1px solid ${activeSection===s.id ? "rgba(239,68,68,0.5)" : "#1E2A40"}`,
            }}>
            <s.icon size={11}/> {s.label}
          </button>
        ))}
      </div>

      {/* Timeline */}
      {activeSection === "timeline" && (
        <div className="space-y-2">
          {dyn.events.length === 0 && (
            <Card className="p-8 text-center">
              <p className="text-sm text-white">No behavioral events recorded.</p>
            </Card>
          )}
          {dyn.events.slice(0, visibleCount).map((ev, i) => {
            const meta = SANDBOX_EVENT_META[ev.event_type] || { icon: Terminal, color: "#64748B", label: ev.event_type };
            const EvIcon = meta.icon;
            return (
              <div key={i}
                className="flex items-start gap-3 p-3 rounded-xl transition-all"
                style={{
                  background: "#0D1122",
                  border: `1px solid ${ev.severity === "CRITICAL" ? "rgba(239,68,68,0.25)" : ev.severity === "HIGH" ? "rgba(249,115,22,0.15)" : "#1E2A40"}`,
                  opacity: 1,
                  animation: "fadeSlideIn 0.25s ease forwards",
                }}>
                <code className="text-xs font-mono flex-shrink-0 mt-0.5 w-16 text-right"
                  style={{color:"#334155"}}>{ev.timestamp_fmt}</code>
                <div className="p-1.5 rounded-lg flex-shrink-0" style={{background:`${meta.color}15`}}>
                  <EvIcon size={12} style={{color: meta.color}}/>
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap mb-0.5">
                    <span className="text-xs font-bold px-1.5 py-0.5 rounded"
                      style={{background:`${meta.color}15`, color:meta.color, fontSize:9}}>{meta.label}</span>
                    {ev.blocked && (
                      <span className="text-xs font-bold px-1.5 py-0.5 rounded"
                        style={{background:"rgba(234,179,8,0.1)", color:"#EAB308", fontSize:9}}>BLOCKED</span>
                    )}
                    <Badge label={ev.severity} color={sevColor(ev.severity)}/>
                    {ev.mitre_id && (
                      <code className="text-xs font-mono" style={{color:"#818CF8", fontSize:9}}>
                        {ev.mitre_id}
                      </code>
                    )}
                  </div>
                  <p className="text-xs text-white leading-relaxed">{ev.description}</p>
                  {ev.resource && (
                    <code className="text-xs font-mono mt-0.5 block truncate" style={{color:"#475569"}}>
                      {ev.resource}
                    </code>
                  )}
                  {ev.mitre_name && (
                    <p style={{fontSize:9, color:"#334155", marginTop:2}}>MITRE: {ev.mitre_name}</p>
                  )}
                </div>
              </div>
            );
          })}
          {visibleCount < dyn.events.length && (
            <div className="flex justify-center py-2">
              <Loader size={16} className="animate-spin" style={{color:"#EF4444"}}/>
            </div>
          )}
        </div>
      )}

      {/* Network IOCs */}
      {activeSection === "network" && (
        <div className="space-y-2">
          {dyn.network_iocs.length === 0
            ? <EmptyState icon={Globe} title="No network connections attempted"/>
            : dyn.network_iocs.map((n, i) => (
              <Card key={i} className="p-3 flex items-center gap-3">
                <div className="p-1.5 rounded-lg" style={{background:"rgba(129,140,248,0.12)"}}>
                  <Globe size={12} style={{color:"#818CF8"}}/>
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <code className="text-xs font-mono font-bold text-white">{n.value}</code>
                    <span className="text-xs font-mono" style={{color:"#475569"}}>:{n.port}</span>
                    <Badge label={n.proto} color="#818CF8"/>
                    <span className="text-xs font-bold px-1.5 py-0.5 rounded"
                      style={{background:"rgba(234,179,8,0.12)", color:"#EAB308", fontSize:9}}>
                      BLOCKED + LOGGED
                    </span>
                  </div>
                  <p style={{fontSize:9, color:"#334155", marginTop:2}}>
                    {n.type === "domain" ? "C2 domain" : "C2 IP"} — connection intercepted, never delivered
                  </p>
                </div>
              </Card>
            ))}
        </div>
      )}

      {/* Dropped Files */}
      {activeSection === "files" && (
        <div className="space-y-2">
          {dyn.dropped_files.length === 0
            ? <EmptyState icon={Folder} title="No files dropped during execution"/>
            : dyn.dropped_files.map((f, i) => (
              <Card key={i} className="p-3 flex items-center gap-3">
                <div className="p-1.5 rounded-lg" style={{background:"rgba(34,197,94,0.1)"}}>
                  <Folder size={12} style={{color:"#22C55E"}}/>
                </div>
                <code className="text-xs font-mono text-white flex-1">{f}</code>
                <Badge label="DROPPED" color="#F97316"/>
              </Card>
            ))}
        </div>
      )}

      {/* Registry Changes */}
      {activeSection === "registry" && (
        <div className="space-y-2">
          {dyn.registry_changes.length === 0
            ? <EmptyState icon={Database} title="No registry modifications recorded"/>
            : dyn.registry_changes.map((r, i) => (
              <Card key={i} className="p-3 flex items-center gap-3">
                <div className="p-1.5 rounded-lg" style={{background:"rgba(234,179,8,0.1)"}}>
                  <Key size={12} style={{color:"#EAB308"}}/>
                </div>
                <div className="flex-1 min-w-0">
                  <code className="text-xs font-mono text-white block truncate">{r}</code>
                  <p style={{fontSize:9, color:"#EAB308", marginTop:2}}>Persistence — T1547.001</p>
                </div>
                <Badge label="WRITTEN" color="#EAB308"/>
              </Card>
            ))}
        </div>
      )}

      {/* Android Permissions */}
      {activeSection === "perms" && (
        <div className="space-y-2">
          {dyn.permissions_requested.map((p, i) => {
            const isDangerous = ["READ_SMS","SEND_SMS","RECEIVE_SMS","BIND_DEVICE_ADMIN",
              "BIND_ACCESSIBILITY_SERVICE","PROCESS_OUTGOING_CALLS"].includes(p);
            return (
              <Card key={i} className="p-3 flex items-center gap-3"
                style={{borderColor: isDangerous ? "rgba(239,68,68,0.2)" : "#1E2A40"}}>
                <div className="p-1.5 rounded-lg"
                  style={{background: isDangerous ? "rgba(239,68,68,0.12)" : "rgba(249,115,22,0.1)"}}>
                  <Smartphone size={12} style={{color: isDangerous ? "#EF4444" : "#F97316"}}/>
                </div>
                <div className="flex-1">
                  <code className="text-xs font-mono font-bold text-white">
                    android.permission.{p}
                  </code>
                  {isDangerous && (
                    <p style={{fontSize:9, color:"#EF4444", marginTop:2}}>⚠ DANGEROUS permission — high abuse potential</p>
                  )}
                </div>
                <Badge label="GRANTED" color={isDangerous ? "#EF4444" : "#F97316"}/>
              </Card>
            );
          })}
        </div>
      )}

      {/* HARM REPORT TAB */}
      {activeSection === "harm_report" && (
        <MachineHarmReport dyn={dyn} sample={sample} fileType={dyn.sandbox_type}/>
      )}
    </div>
  );
}



export default SandboxTimeline;
