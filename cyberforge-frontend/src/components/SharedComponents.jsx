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

import { useCopy } from "../hooks/useBackend";

// ================================================================
//  SHARED COMPONENTS
// ================================================================

const Card = ({ children, className = "", style = {} }) => (
  <div className={`rounded-xl ${className}`}
    style={{ background:"#111827", border:"1px solid #1E2A40", ...style }}>
    {children}
  </div>
);

const Badge = ({ label, color }) => (
  <span className="text-xs font-bold px-2 py-0.5 rounded-md"
    style={{ color, background:`${color}1A`, border:`1px solid ${color}40` }}>
    {label}
  </span>
);

const EmptyState = ({ icon:Icon, title, sub }) => (
  <div className="flex flex-col items-center justify-center py-12 text-center">
    <Icon size={28} style={{color:"#334155"}} className="mb-3"/>
    <p className="text-sm font-bold text-white">{title}</p>
    {sub && <p className="text-xs mt-1" style={{color:"#475569"}}>{sub}</p>}
  </div>
);

const CopyButton = ({ text, size = 12 }) => {
  const { copy, copied } = useCopy();
  const isCopied = copied === text;
  return (
    <button
      onClick={(e) => { e.stopPropagation(); copy(text); }}
      className="flex-shrink-0 p-1 rounded transition-all hover:bg-white/10"
      title="Copy to clipboard"
      style={{ color: isCopied ? "#22C55E" : "#475569" }}
    >
      {isCopied ? <Check size={size}/> : <Copy size={size}/>}
    </button>
  );
};

// ── Source label tag: [STATIC] / [DYNAMIC] / [BOTH] ───────────────────────
const SourceTag = ({ source }) => {
  if (!source) return null;
  const cfg = source === "dynamic" ? { label: "DYNAMIC", color: "#F97316" }
    : source === "both"    ? { label: "BOTH",    color: "#22C55E" }
    : { label: "STATIC",  color: "#3B82F6" };
  return (
    <span className="text-xs font-black px-1.5 py-0.5 rounded flex-shrink-0"
      style={{background:`${cfg.color}18`, color:cfg.color, border:`1px solid ${cfg.color}30`, fontSize:8}}>
      {cfg.label}
    </span>
  );
};

// ── Score Breakdown panel ─────────────────────────────────────────────────
const ScoreBreakdown = ({ breakdown, staticScore, finalScore, analysisDepth }) => {
  const [open, setOpen] = useState(false);
  if (!breakdown || breakdown.length === 0) return null;
  return (
    <div className="rounded-xl overflow-hidden" style={{border:"1px solid #1E2A40"}}>
      <button
        className="w-full flex items-center justify-between px-4 py-3 text-sm font-bold text-white"
        style={{background:"#0D1122"}}
        onClick={() => setOpen(o => !o)}
      >
        <span className="flex items-center gap-2">
          <span style={{color:"#818CF8"}}>⚖</span> Score Breakdown
          <span className="text-xs font-normal px-2 py-0.5 rounded" style={{background:"#1E2A40",color:"#64748B"}}>
            {breakdown.length} factors
          </span>
          {analysisDepth === "static+dynamic" && (
            <span className="text-xs font-black px-2 py-0.5 rounded" style={{background:"rgba(34,197,94,0.15)",color:"#22C55E",fontSize:9}}>STATIC+DYNAMIC MERGED</span>
          )}
        </span>
        <span style={{color:"#475569", fontSize:12}}>{open ? "▲" : "▼"}</span>
      </button>
      {open && (
        <div className="p-4 space-y-1.5" style={{background:"#070E1B"}}>
          {breakdown.map((item, i) => (
            <div key={i} className="flex items-center justify-between gap-2 py-1" style={{borderBottom:"1px solid #0D1122"}}>
              <div className="flex items-center gap-2 flex-1 min-w-0">
                <SourceTag source={item.source}/>
                <span className="text-xs truncate" style={{color:"#94A3B8"}}>{item.label}</span>
              </div>
              {item.points > 0 && (
                <span className="text-xs font-black flex-shrink-0 font-mono" style={{color:item.source==="dynamic"?"#F97316":"#3B82F6"}}>+{item.points}</span>
              )}
              {item.points === 0 && (
                <span className="text-xs flex-shrink-0" style={{color:"#334155"}}>floor</span>
              )}
            </div>
          ))}
          <div className="flex items-center justify-between pt-2 mt-1" style={{borderTop:"2px solid #1E2A40"}}>
            <span className="text-xs font-bold" style={{color:"#64748B"}}>Static Score</span>
            <span className="font-mono font-black text-sm" style={{color:"#3B82F6"}}>{staticScore}/100</span>
          </div>
          {analysisDepth === "static+dynamic" && (
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold" style={{color:"#64748B"}}>Final Score (Weighted)</span>
              <span className="font-mono font-black text-sm" style={{color:"#F97316"}}>{finalScore}/100</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

// ── Verdict Conflict Banner ───────────────────────────────────────────────
const VerdictConflictBanner = ({ sample }) => {
  const data = sample?.analysis_data || {};
  if (!data.verdict_conflict) return null;
  return (
    <div className="rounded-xl p-4 flex items-start gap-3 animate-pulse-border"
      style={{background:"rgba(234,179,8,0.08)", border:"2px solid rgba(234,179,8,0.5)"}}>
      <AlertTriangle size={18} style={{color:"#EAB308", flexShrink:0, marginTop:1}}/>
      <div className="flex-1 min-w-0">
        <p className="text-sm font-black text-white mb-1">⚠ VERDICT CONFLICT DETECTED</p>
        <div className="flex flex-wrap gap-3 mb-2">
          <span className="text-xs px-2 py-1 rounded font-bold" style={{background:"rgba(59,130,246,0.15)",color:"#3B82F6"}}>
            [STATIC] {data.static_threat_level || "—"} ({data.static_score || 0}/100)
          </span>
          <span className="text-xs font-bold" style={{color:"#475569"}}>vs</span>
          <span className="text-xs px-2 py-1 rounded font-bold" style={{background:"rgba(249,115,22,0.15)",color:"#F97316"}}>
            [DYNAMIC] {data.dynamic?.sandbox_verdict || "—"}
          </span>
          <span className="text-xs font-bold" style={{color:"#475569"}}>→</span>
          <span className="text-xs px-2 py-1 rounded font-bold" style={{background:"rgba(239,68,68,0.15)",color:"#EF4444"}}>
            FINAL: {sample?.threat_level || data.static_threat_level}
          </span>
        </div>
        <p className="text-xs leading-relaxed" style={{color:"#94A3B8"}}>
          {data.verdict_conflict_explanation || "Static and dynamic verdicts differ significantly. Dynamic analysis takes precedence."}
        </p>
        <p className="text-xs mt-2 font-bold" style={{color:"#EAB308"}}>
          ⚠ This discrepancy has been logged. Do not rely on static analysis alone for this file.
        </p>
      </div>
    </div>
  );
};

// ── Analysis Depth Badge ──────────────────────────────────────────────────
const AnalysisDepthBadge = ({ depth, onRunSandbox, rerunning }) => {
  const isFull = depth === "static+dynamic";
  return (
    <div className="flex items-center gap-2">
      <span className="text-xs font-black px-2 py-1 rounded-lg flex items-center gap-1"
        style={{
          background: isFull ? "rgba(34,197,94,0.15)" : "rgba(100,116,139,0.15)",
          color: isFull ? "#22C55E" : "#94A3B8",
          border: `1px solid ${isFull ? "rgba(34,197,94,0.3)" : "rgba(100,116,139,0.3)"}`,
        }}>
        {isFull ? "✅" : "🔬"}
        {isFull ? " Full Analysis (Static + Dynamic)" : " Basic Analysis (Static Only)"}
      </span>
      {!isFull && onRunSandbox && (
        <button onClick={onRunSandbox} disabled={rerunning}
          className="text-xs font-bold px-2 py-1 rounded-lg flex items-center gap-1"
          style={{background:"rgba(239,68,68,0.15)",color:"#EF4444",border:"1px solid rgba(239,68,68,0.3)"}}>
          {rerunning ? <><span className="animate-spin text-xs">⟳</span> Running…</> : <>▶ Run in Sandbox</>}
        </button>
      )}
    </div>
  );
};


const ConnectionBanner = ({ connected, apiBase, onRetry }) => {
  if (connected) return null;
  return (
    <Card className="p-4 mb-4 flex items-start gap-3" style={{borderColor:"rgba(239,68,68,0.4)"}}>
      <WifiOff size={16} style={{color:"#EF4444"}} className="flex-shrink-0 mt-0.5"/>
      <div className="flex-1">
        <p className="text-sm font-bold text-white">Backend not reachable</p>
        <p className="text-xs mt-1" style={{color:"#94A3B8"}}>
          Couldn't connect to <code className="font-mono">{apiBase}</code>. Make sure the
          CyberForge FastAPI backend is running (<code className="font-mono">uvicorn app.main:app</code>)
          and reachable from this browser.
        </p>
      </div>
      <button onClick={onRetry} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold text-white flex-shrink-0"
        style={{background:"#2D6BE4"}}>
        <RefreshCw size={11}/> Retry
      </button>
    </Card>
  );
};

export { Card, Badge, EmptyState, CopyButton, SourceTag, ScoreBreakdown, VerdictConflictBanner, AnalysisDepthBadge, ConnectionBanner };
