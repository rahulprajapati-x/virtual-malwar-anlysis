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
//  STATIC ANALYSIS STREAM COMPONENT
// ================================================================

function StaticAnalysisStream({ sample, apiBase, onComplete, error, currentFile }) {
  const [stages, setStages] = useState([]);
  const [currentStage, setCurrentStage] = useState("Initializing analysis stream...");
  const [elapsed, setElapsed] = useState(0);

  const ALL_STAGES = [
     { id: "hashing", label: "Computing cryptographic hashes" },
     { id: "file_typing", label: "Detecting MIME type and extensions" },
     { id: "pe_parsing", label: "Parsing PE structure (if executable)" },
     { id: "structural_analysis", label: "Checking structural anomalies" },
     { id: "document_analysis", label: "Deep document analysis (if Office/PDF)" },
     { id: "apk_analysis", label: "Parsing Android manifest (if APK)" },
     { id: "entropy_analysis", label: "Calculating chunk entropy map" },
     { id: "string_analysis", label: "Extracting and classifying strings" },
     { id: "yara_scan", label: "Running YARA threat signatures" },
     { id: "ioc_extraction", label: "Extracting Indicators of Compromise" },
     { id: "mitre_mapping", label: "Mapping to MITRE ATT&CK framework" },
     { id: "virustotal_lookup", label: "Querying VirusTotal intelligence" },
     { id: "malwarebazaar_lookup", label: "Cross-referencing MalwareBazaar database" }
  ];

  useEffect(() => {
    if (!sample?.id) return;
    const wsUrl = apiBase.replace(/^http/, "ws") + "/api/samples/stream/" + sample.id;
    const ws = new WebSocket(wsUrl);
    let timer;

    ws.onmessage = (msg) => {
      try {
        const event = JSON.parse(msg.data);
        if (event.stage === "finalizing_report") {
          setTimeout(() => onComplete(event.sample), 500);
        } else {
          setStages(prev => {
            if(prev.find(p => p.stage === event.stage)) return prev;
            return [...prev, event];
          });
          const stageDef = ALL_STAGES.find(s => s.id === event.stage);
          setCurrentStage(stageDef ? stageDef.label + "..." : `Running: ${event.stage}...`);
          setElapsed(0);
        }
      } catch(e){}
    };

    ws.onclose = (e) => {
      if (e.code !== 1000 && e.code !== 1005) {
        setStages(prev => {
          if (!prev.find(p => p.stage === "finalizing_report")) {
            setCurrentStage("Connection lost or analysis failed.");
          }
          return prev;
        });
      }
    };

    timer = setInterval(() => {
       setElapsed(p => p + 100);
    }, 100);

    return () => {
       ws.close();
       clearInterval(timer);
    };
  }, [sample, apiBase, onComplete]);

  return (
    <div className="flex flex-col items-center justify-center py-16 animate-fade-in">
      <div className="relative mb-8">
        <div className="w-24 h-24 rounded-full flex items-center justify-center bg-[rgba(45,107,228,0.12)] border-2 border-[#2D6BE4]">
          <Shield size={38} style={{color:"#2D6BE4"}}/>
        </div>
        <div className="absolute inset-0 rounded-full animate-ping opacity-20 bg-[#2D6BE4]"/>
      </div>
      <h2 className="text-xl font-black text-white mb-1">Deep Static Analysis in Progress</h2>
      <p className="text-sm mb-6 font-mono" style={{color:"#64748B"}}>{sample?.filename || currentFile?.name}</p>

      <div className="w-[450px] space-y-3 bg-[#0D1122] border border-[#1E2A40] p-4 rounded-xl shadow-lg">
        {ALL_STAGES.map((s) => {
          const completedEvent = stages.find(ev => ev.stage === s.id);
          const isCurrent = !completedEvent && currentStage.includes(s.label.split(' ')[0]);

          if (completedEvent && completedEvent.duration_ms === 0) return null;

          return (
            <div key={s.id} className="flex flex-col" style={{display: (completedEvent || isCurrent) ? "flex" : "none"}}>
              <div className="flex items-center justify-between text-xs transition-opacity duration-300">
                <div className="flex items-center gap-2.5">
                  {completedEvent ? <CheckCircle size={14} style={{color:"#22C55E"}}/>
                    : isCurrent ? <Loader size={14} style={{color:"#2D6BE4"}} className="animate-spin"/>
                    : <div className="w-3.5 h-3.5 rounded-full border border-[#1E2A40] flex-shrink-0"/>}
                  <span style={{color: completedEvent ? "#22C55E" : isCurrent ? "#F1F5F9" : "#334155", fontWeight: isCurrent ? "bold" : "normal"}}>
                    {s.label}
                  </span>
                </div>
                {completedEvent ? (
                  <span className="font-mono" style={{color:"#64748B"}}>{completedEvent.duration_ms}ms</span>
                ) : isCurrent ? (
                  <span className="font-mono animate-pulse" style={{color:"#2D6BE4"}}>{(elapsed/1000).toFixed(1)}s</span>
                ) : null}
              </div>
              {completedEvent && completedEvent.matches !== undefined && (
                 <div className="ml-6 mt-1 text-[10px] text-[#FCA5A5] font-mono">Found {completedEvent.matches} matches</div>
              )}
            </div>
          );
        })}
      </div>

      {error && <p className="mt-4 text-xs text-[#EF4444]">{error}</p>}
    </div>
  );
}


export default StaticAnalysisStream;
