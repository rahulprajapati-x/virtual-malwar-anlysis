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
import HexAnalyzer from "./HexAnalyzer";

import { createApiClient, TokenStore } from './api/client';
import { scoreToThreat, sevColor, fmtBytes } from './utils/helpers';
import { ToastProvider, useToast } from './components/Toast';
import { GlobalSearchModal } from './components/GlobalSearch';
import { NotifProvider, useNotif, NotifPanel } from './components/NotifPanel';
import LoginScreen from './components/LoginScreen';
import { ConnectionBanner, Card, Badge } from './components/SharedComponents';
import ExplanationModal from './components/ExplanationModal';
import Dashboard from './pages/Dashboard';
import FileUploader from './pages/FileUpload';
import StaticAnalysisStream from './pages/StaticStream';
import RealisticSandboxInstaller from './pages/SandboxSimulator';
import MachineHarmReport from './pages/MachineHarmReport';
import SandboxResults from './pages/SandboxResults';
import AnalysisResults from './pages/AnalysisResults';
import CipherAI from './pages/CipherAI';
import Cases from './pages/Cases';
import MitreMatrix from './pages/MitreMatrix';
import IOCDatabase from './pages/IocDatabase';
import SettingsPanel from './pages/Settings';
import VirtualEnvironment from './pages/VirtualEnvironment';
import NetworkPcapAnalyzer from './pages/PcapAnalyzer';
import MemoryForensics from './pages/MemoryForensics';
import CaseTimeline from './pages/CaseTimeline';

const DEFAULT_API_BASE = "http://localhost:8000";

// ================================================================
//  MAIN APP
// ================================================================

function CyberForgeApp() {
  const { toast } = useToast();
  const [apiBase, setApiBase] = useState(DEFAULT_API_BASE);
  const api = useMemo(() => createApiClient(apiBase), [apiBase]);

  // ── Auth state ────────────────────────────────────────────────
  const [authUser, setAuthUser] = useState(() => {
    const stored = TokenStore.get();
    return stored ? { username: stored.username || "analyst", role: stored.role || "analyst" } : null;
  });
  const [authChecked, setAuthChecked] = useState(false);

  // Verify stored token on mount
  useEffect(() => {
    const token = TokenStore.getToken();
    if (!token) { setAuthChecked(true); return; }
    api.getMe().then(me => { setAuthUser(me); setAuthChecked(true); })
      .catch(() => { TokenStore.clear(); setAuthUser(null); setAuthChecked(true); });
  }, []); // eslint-disable-line

  const handleLogin = useCallback((data) => {
    setAuthUser({ username: data.username || "analyst", role: data.role || "analyst", email: data.email });
  }, []);

  const handleLogout = useCallback(() => {
    TokenStore.clear();
    setAuthUser(null);
    setView("dashboard");
  }, []);

  // ── Global Search ─────────────────────────────────────────────
  const [searchOpen, setSearchOpen] = useState(false);
  useEffect(() => {
    const handler = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") { e.preventDefault(); setSearchOpen(v=>!v); }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  // ── Notifications panel ───────────────────────────────────────
  const [notifOpen, setNotifOpen] = useState(false);

  const [connected, setConnected] = useState(false);
  const [view, setView] = useState(() => {
    try {
      return sessionStorage.getItem("cyberforge_active_view") || "dashboard";
    } catch { return "dashboard"; }
  });
  const currentViewRef = useRef(view);
  useEffect(() => {
    currentViewRef.current = view;
    try {
      sessionStorage.setItem("cyberforge_active_view", view);
    } catch {}
  }, [view]);

  const [analyzing, setAnalyzing] = useState(false);
  const [currentFile, setFile] = useState(() => {
    try {
      const f = sessionStorage.getItem("cyberforge_sandbox_file");
      return f ? JSON.parse(f) : null;
    } catch { return null; }
  });
  const [sample, setSample] = useState(() => {
    try {
      const s = sessionStorage.getItem("cyberforge_active_sample");
      return s ? JSON.parse(s) : null;
    } catch { return null; }
  });
  const [uploadError, setUploadError] = useState(null);
  const [casesRefresh, setCasesRefresh] = useState(0);
  const [enableSandbox, setEnableSandbox] = useState(() => {
    try {
      return sessionStorage.getItem("cyberforge_sandbox_enabled") === "true";
    } catch { return false; }
  });
  const [sandboxInstallDone, setSandboxInstallDone] = useState(() => {
    try {
      return sessionStorage.getItem("cyberforge_sandbox_done") === "true";
    } catch { return false; }
  });
  const [caseTimeline, setCaseTimeline] = useState(null);

  // Sync sample and sandbox state
  useEffect(() => {
    if (sample && !sample._streaming) {
      try {
        sessionStorage.setItem("cyberforge_active_sample", JSON.stringify(sample));
      } catch {}
    }
  }, [sample]);

  useEffect(() => {
    try {
      sessionStorage.setItem("cyberforge_sandbox_enabled", String(enableSandbox));
    } catch {}
  }, [enableSandbox]);

  useEffect(() => {
    try {
      sessionStorage.setItem("cyberforge_sandbox_done", String(sandboxInstallDone));
    } catch {}
  }, [sandboxInstallDone]);

  // Sample history state (persisted to localStorage)
  const [sampleHistory, setSampleHistory] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem("cyberforge_history") || "[]");
    } catch { return []; }
  });

  // Track sample changes to update history
  useEffect(() => {
    if (sample && sample.id && !sample._streaming) {
      setSampleHistory(prev => {
        const filtered = prev.filter(s => s.id !== sample.id);
        const next = [{
          id: sample.id, 
          filename: sample.filename, 
          risk_score: sample.risk_score, 
          threat_level: sample.threat_level,
          analyzed_at: sample.analyzed_at || sample.submitted_at
        }, ...filtered].slice(0, 5);
        localStorage.setItem("cyberforge_history", JSON.stringify(next));
        return next;
      });
    }
  }, [sample]);

  const loadSampleFromHistory = async (id) => {
    try {
      const fullSample = await api.getSample(id);
      setSample(fullSample);
      setView("analysis");
    } catch(e) {
      console.error("Failed to load sample from history", e);
    }
  };

  const [chatInput, setInput] = useState("");
  const [chatLoading, setChat] = useState(false);
  const [chatMessages, setMsgs] = useState([{
    role:"assistant",
    content:"🛡️ CIPHER Online — AI Investigation Assistant\n\nConnected to your CyberForge backend. Deploy me for: malware behavior analysis, IOC interpretation, MITRE ATT&CK context, and incident triage guidance.\n\nUpload a sample for full analysis context, or ask me directly:\n• \"How does Ryuk ransomware propagate?\"\n• \"Explain process injection via process hollowing\"\n• \"What TTPs does APT28 use?\"",
    isInitial:true
  }]);

  const [explainState, setExplainState] = useState({ open: false, loading: false, data: null, error: null });

  const handleExplain = async (type, value, context) => {
    setExplainState({ open: true, loading: true, data: null, error: null });
    try {
      const res = await api.explainIndicator(type, value, context);
      setExplainState({ open: true, loading: false, data: res.explanation, error: null });
    } catch(e) {
      setExplainState({ open: true, loading: false, data: null, error: e.message || "Failed to get explanation" });
    }
  };

  const checkConnection = useCallback(async (base) => {
    try {
      const testApi = createApiClient(base || apiBase);
      await testApi.health();
      setConnected(true);
    } catch { setConnected(false); }
  }, [apiBase]);

  useEffect(() => { checkConnection(); }, []); // eslint-disable-line

  const MAX_FILE_SIZE = 500 * 1024 * 1024; // 500 MB

  const handleStaticFile = useCallback(async (file) => {
    // Client-side size guard — backend also enforces this
    if (file.size > MAX_FILE_SIZE) {
      setUploadError(`File too large: ${(file.size / 1024 / 1024).toFixed(1)} MB. Maximum allowed size is 500 MB.`);
      return;
    }
    setFile(file);
    setUploadError(null);
    setEnableSandbox(false);
    setView("upload-stream");
    try {
      const resp = await api.uploadStream(file, null, "analyst", false);
      setSample({ id: resp.sample_id, filename: file.name, _streaming: true });
    } catch (e) {
      setUploadError(e.message || "Upload failed");
      setView("upload");
    }
  }, [api]);

  // Sandbox flow: show realistic installation simulator FIRST, then proceed to real analysis
  const handleSandboxFile = useCallback(async (file) => {
    const fileMeta = { name: file.name, size: file.size, type: file.type };
    setFile(file);
    setUploadError(null);
    setEnableSandbox(true);
    setSandboxInstallDone(false);
    try {
      sessionStorage.setItem("cyberforge_sandbox_file", JSON.stringify(fileMeta));
      sessionStorage.setItem("cyberforge_sandbox_enabled", "true");
      sessionStorage.setItem("cyberforge_sandbox_done", "false");
      sessionStorage.removeItem("cyberforge_installer_state");
    } catch {}
    setView("sandbox-install"); // Show the realistic installer first
  }, []);

  const handleResetSandbox = useCallback(() => {
    setFile(null);
    setEnableSandbox(false);
    setSandboxInstallDone(false);
    setAnalyzing(false);
    setUploadError(null);
    try {
      sessionStorage.removeItem("cyberforge_sandbox_file");
      sessionStorage.removeItem("cyberforge_sandbox_enabled");
      sessionStorage.removeItem("cyberforge_sandbox_done");
      sessionStorage.removeItem("cyberforge_installer_state");
      sessionStorage.removeItem("cyberforge_active_sample");
    } catch {}
    setView("sandbox-env");
  }, []);

  // Called when the realistic installer finishes its animation
  const handleSandboxInstallComplete = useCallback(async () => {
    if (currentFile && currentFile.size > MAX_FILE_SIZE) {
      setUploadError(`File too large: ${(currentFile.size / 1024 / 1024).toFixed(1)} MB. Maximum allowed size is 500 MB.`);
      setView("upload");
      return;
    }
    setSandboxInstallDone(true);
    try {
      sessionStorage.setItem("cyberforge_sandbox_done", "true");
    } catch {}
    setAnalyzing(true);
    if (currentViewRef.current === "sandbox-install") {
      setView("analysis");
    } else {
      toast("⚡ Sandbox installer completed. Capturing behavioral traces in background...", "info");
    }

    try {
      const result = await api.uploadSync(currentFile, null, "analyst", true);
      setSample(result);
      try {
        sessionStorage.setItem("cyberforge_active_sample", JSON.stringify(result));
      } catch {}
      if (currentViewRef.current === "analysis" || currentViewRef.current === "sandbox-install") {
        setView("analysis");
      } else {
        toast(`✅ Sandbox analysis completed for "${currentFile.name}"! Click "Analysis Results" to view.`, "success");
      }
    } catch (e) {
      setUploadError(e.message || "Upload failed");
    } finally {
      setAnalyzing(false);
    }
  }, [api, currentFile, toast]);

  const sendChat = async () => {
    if (!chatInput.trim() || chatLoading) return;
    const userMsg = chatInput.trim();
    setInput("");
    const next = [...chatMessages, {role:"user",content:userMsg}];
    setMsgs(next);
    setChat(true);
    try {
      const apiMsgs = next.filter(m=>!m.isInitial).map(m=>({role:m.role,content:m.content}));
      const res = await api.cipherChat(apiMsgs, sample?.id);
      setMsgs(prev=>[...prev,{role:"assistant",content:res.reply}]);
    } catch (e) {
      setMsgs(prev=>[...prev,{role:"assistant",content:`⚠ Connection error: ${e.message}. Check that ANTHROPIC_API_KEY is set on the backend and the server is reachable.`}]);
    } finally { setChat(false); }
  };

  const fileToCase = async () => {
    if (!sample) return;
    try {
      const newCase = await api.createCase({
        name: `Analysis: ${sample.filename}`,
        description: `Auto-filed from sample analysis. Risk: ${sample.risk_score}/100 (${sample.threat_level}).`,
        severity: sample.threat_level === "CLEAN" ? "LOW" : sample.threat_level,
        analyst: "analyst",
      });
      const updated = await api.assignCase(sample.id, newCase.id);
      setSample(prev => ({ ...prev, case_id: newCase.id }));
      setCasesRefresh(k=>k+1);
    } catch (e) { console.error(e); }
  };

  const isInstallerRunning = Boolean(currentFile && enableSandbox && !sandboxInstallDone);
  const isSandboxActive = Boolean(currentFile && enableSandbox && (!sandboxInstallDone || analyzing));

  const sandboxBadge = isInstallerRunning
    ? { badge: "RUNNING ⚡", badgeColor: "#EF4444" }
    : (analyzing && enableSandbox)
    ? { badge: "ANALYZING ⏳", badgeColor: "#F97316" }
    : { badge: "SANDBOX", badgeColor: "#22C55E" };

  const nav = [
    {id:"dashboard", label:"Dashboard",    icon:Home},
    {id:"upload",    label:"Analyze File",  icon:Upload},
    {id:"sandbox-env",label:"Virtual Env",  icon:Monitor, badge:sandboxBadge.badge, badgeColor:sandboxBadge.badgeColor},
    ...(sample ? [{id:"analysis", label:"Analysis Results", icon:Bug, badge:sample.threat_level, badgeColor:scoreToThreat(sample.risk_score).color}] : []),
    {id:"cipher",   label:"CIPHER AI",      icon:Brain,  badge:"AI",      badgeColor:"#7C3AED"},
    {id:"cases",    label:"Cases",          icon:List},
    {id:"mitre",    label:"ATT&CK Matrix",  icon:Target},
    {id:"iocdb",    label:"IOC Database",   icon:Database},
    {id:"pcap",     label:"Network / PCAP", icon:Waves,  badge:"NEW",     badgeColor:"#06B6D4"},
    {id:"memory",   label:"Memory Forensics",icon:MemoryStick, badge:"NEW", badgeColor:"#818CF8"},
    {id:"settings", label:"Settings",       icon:Settings},
  ];

  const isNavActive = (itemId) => {
    if (itemId === "sandbox-env") {
      return view === "sandbox-env" || view === "sandbox-install" || (view === "analysis" && enableSandbox);
    }
    return view === itemId;
  };

  const handleNavClick = (itemId) => {
    if (itemId === "sandbox-env") {
      if (isInstallerRunning) {
        setView("sandbox-install");
        return;
      }
      if (enableSandbox && analyzing) {
        setView("analysis");
        return;
      }
      if (enableSandbox && sample) {
        setView("analysis");
        return;
      }
      setView("sandbox-env");
      return;
    }
    setView(itemId);
  };

  // Navigate + optionally load sample
  const navigateTo = useCallback(async (destination, sampleId) => {
    if (sampleId) {
      try {
        const fullSample = await api.getSample(sampleId);
        setSample(fullSample);
        setView("analysis");
      } catch(e) { setView(destination); }
    } else {
      setView(destination);
    }
  }, [api]);

  // Show loading until auth is checked
  if (!authChecked) {
    return (
      <div className="fixed inset-0 flex items-center justify-center" style={{background:"#060A18"}}>
        <div className="flex flex-col items-center gap-4">
          <Shield size={32} style={{color:"#2D6BE4"}} className="animate-pulse"/>
          <p className="text-sm" style={{color:"#334155"}}>Verifying session…</p>
        </div>
      </div>
    );
  }

  // Show login if not authenticated
  if (!authUser) {
    return <LoginScreen api={api} onLogin={handleLogin}/>;
  }

  return (
    <div className="flex" style={{background:"#060A18",minHeight:"100vh",color:"#F1F5F9",fontFamily:"system-ui,-apple-system,sans-serif"}}>
      {/* ── PREMIUM SIDEBAR ─────────────────────────────── */}
      <div className="flex flex-col flex-shrink-0 sidebar-transition"
        style={{width:228, background:"linear-gradient(180deg, #080D1F 0%, #060A18 100%)", borderRight:"1px solid rgba(255,255,255,0.06)", minHeight:"100vh", position:"sticky", top:0, height:"100vh"}}>

        {/* Logo */}
        <div className="px-4 py-4" style={{borderBottom:"1px solid rgba(255,255,255,0.05)"}}>
          <div className="flex items-center gap-2.5 mb-3">
            <div className="p-1.5 rounded-xl animate-neon" style={{background:"rgba(45,107,228,0.2)", border:"1px solid rgba(45,107,228,0.35)", color:"#2D6BE4"}}>
              <Shield size={16} style={{color:"#60A5FA"}}/>
            </div>
            <div className="flex-1 min-w-0">
              <p className="font-black text-white tracking-tight" style={{fontSize:13, letterSpacing:"-0.01em",
                background:"linear-gradient(135deg,#fff,#93C5FD)", WebkitBackgroundClip:"text", WebkitTextFillColor:"transparent"
              }}>CYBER FORGE</p>
              <p style={{fontSize:8, color:"#334155", letterSpacing:"0.12em", WebkitTextFillColor:"#334155"}}>FORENSICS PLATFORM v3.0</p>
            </div>
            <NotifBellButton onOpen={()=>setNotifOpen(v=>!v)}/>
          </div>
          {/* Search */}
          <button onClick={()=>setSearchOpen(true)}
            className="w-full flex items-center gap-2 px-3 py-2 rounded-xl text-left transition-all hover:bg-white/5"
            style={{background:"rgba(255,255,255,0.03)", border:"1px solid rgba(255,255,255,0.06)"}}>
            <Search size={11} style={{color:"#334155"}}/>
            <span className="text-xs flex-1" style={{color:"#334155"}}>Search…</span>
            <span className="text-xs px-1.5 py-0.5 rounded" style={{background:"rgba(255,255,255,0.06)", color:"#334155", fontSize:9}}>⌘K</span>
          </button>
        </div>

        {/* Nav */}
        <nav className="flex-1 p-3 space-y-0.5 overflow-y-auto">
          <p className="text-xs font-bold px-2 mb-2 mt-1 uppercase tracking-widest" style={{color:"#1E2A40"}}>Navigation</p>
          {nav.map(item=>(
            <button key={item.id} onClick={()=>handleNavClick(item.id)}
              className={`w-full flex items-center gap-2.5 px-3 py-2.5 rounded-xl text-left transition-all text-sm relative ${isNavActive(item.id) ? "nav-item-active" : ""}`}
              style={{
                background: isNavActive(item.id) ? undefined : "transparent",
                color: isNavActive(item.id) ? "#60A5FA" : "#475569",
              }}>
              <item.icon size={14} style={{color: isNavActive(item.id) ? "#60A5FA" : "#475569", flexShrink:0}}/>
              <span className="flex-1 font-semibold sidebar-label" style={{fontSize:13}}>{item.label}</span>
              {item.badge && (
                <span className="text-xs px-1.5 py-0.5 rounded-md font-black sidebar-badge"
                  style={{background:`${item.badgeColor}20`, color:item.badgeColor, border:`1px solid ${item.badgeColor}30`}}>
                  {item.badge}
                </span>
              )}
            </button>
          ))}

          {/* Recent samples */}
          {sampleHistory.length > 0 && (
            <div className="mt-5 pt-4" style={{borderTop:"1px solid rgba(255,255,255,0.04)"}}>
              <p className="text-xs font-bold px-2 mb-2 uppercase tracking-widest flex items-center gap-1.5" style={{color:"#1E2A40"}}>
                <History size={11}/> Recent Samples
              </p>
              <div className="space-y-0.5">
                {sampleHistory.map(hist => (
                  <button key={hist.id} onClick={() => loadSampleFromHistory(hist.id)}
                    className="w-full flex flex-col px-3 py-1.5 rounded-xl text-left transition-all hover:bg-white/5 group"
                    title={hist.filename}>
                    <span className="text-xs font-medium truncate w-full transition-colors" style={{color:"#64748B"}}>{hist.filename}</span>
                    <div className="flex items-center gap-2 mt-0.5">
                      <span className="text-xs px-1 py-0.5 rounded font-black"
                        style={{background:`${scoreToThreat(hist.risk_score).color}15`, color:scoreToThreat(hist.risk_score).color, fontSize:9}}>
                        {hist.risk_score}/100
                      </span>
                      <span className="text-slate-600" style={{fontSize:10}}>
                        {new Date(hist.analyzed_at).toLocaleDateString()}
                      </span>
                    </div>
                  </button>
                ))}
              </div>
            </div>
          )}
        </nav>

        {/* Bottom: status + user */}
        <div className="p-3 space-y-2.5" style={{borderTop:"1px solid rgba(255,255,255,0.05)"}}>
          {/* Connection status */}
          <div className="flex items-center gap-2 px-2">
            <span className="live-dot w-2 h-2 rounded-full flex-shrink-0" style={{background:connected?"#22C55E":"#EF4444", boxShadow:connected?"0 0 8px #22C55E":"0 0 8px #EF4444"}}/>
            <span className="text-xs" style={{color:connected?"#475569":"#EF4444"}}>{connected ? "Backend Online" : "Offline"}</span>
          </div>
          {/* User card */}
          {authUser && (
            <div className="flex items-center gap-2.5 px-2.5 py-2 rounded-xl" style={{background:"rgba(255,255,255,0.03)", border:"1px solid rgba(255,255,255,0.05)"}}>
              <div className="w-7 h-7 rounded-xl flex items-center justify-center text-xs font-black flex-shrink-0"
                style={{background:"linear-gradient(135deg,#2D6BE4,#7C3AED)", color:"white", boxShadow:"0 4px 10px rgba(45,107,228,0.3)"}}>
                {(authUser.username||"A").charAt(0).toUpperCase()}
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-xs font-bold text-white truncate">{authUser.username}</p>
                <p className="text-xs" style={{color:"#334155", fontSize:10}}>{authUser.role || "analyst"}</p>
              </div>
              <button onClick={handleLogout} title="Sign out"
                className="p-1.5 rounded-lg transition-all hover:bg-red-500/10 hover:text-red-400" style={{color:"#334155"}}>
                <X size={11}/>
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 overflow-y-auto" style={{maxHeight:"100vh"}}>
        <ErrorBoundary>
          <div className="p-6 max-w-5xl mx-auto">
            <ConnectionBanner connected={connected} apiBase={apiBase} onRetry={()=>checkConnection()}/>

            {/* Persistent Sandbox Background Runner Banner */}
            {isSandboxActive && view !== "sandbox-install" && (
              <div className="mb-4 p-3.5 rounded-xl flex items-center justify-between gap-3 animate-fade-in"
                style={{
                  background: "linear-gradient(90deg, rgba(34,197,94,0.12), rgba(45,107,228,0.12))",
                  border: "1px solid rgba(34,197,94,0.3)",
                  boxShadow: "0 0 20px rgba(34,197,94,0.08)"
                }}>
                <div className="flex items-center gap-3 min-w-0">
                  <div className="relative flex items-center justify-center">
                    <div className="w-2.5 h-2.5 rounded-full bg-[#22C55E]" />
                    <div className="absolute w-4 h-4 rounded-full bg-[#22C55E] animate-ping opacity-40" />
                  </div>
                  <Monitor size={17} style={{color:"#22C55E", flexShrink:0}} />
                  <div className="min-w-0">
                    <p className="text-xs font-bold text-white truncate flex items-center gap-2">
                      <span>Sandbox Running in Background:</span>
                      <span className="font-mono text-[#22C55E] bg-[#22C55E]/10 px-2 py-0.5 rounded text-[11px] border border-[#22C55E]/20">
                        {currentFile?.name}
                      </span>
                    </p>
                    <p className="text-[11px] text-slate-400 mt-0.5">
                      {!sandboxInstallDone
                        ? "Simulating OS installation & capturing behavioral traces in real-time..."
                        : analyzing
                        ? "Detonating payload & generating forensic telemetry..."
                        : "Execution complete — results ready"}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2 flex-shrink-0">
                  <button
                    onClick={() => setView(!sandboxInstallDone ? "sandbox-install" : "analysis")}
                    className="px-3.5 py-1.5 rounded-lg text-xs font-bold text-white bg-[#22C55E]/20 hover:bg-[#22C55E]/30 border border-[#22C55E]/40 transition-all flex items-center gap-1.5 shadow-sm"
                  >
                    <Eye size={12} /> View Sandbox
                  </button>
                  <button
                    onClick={handleResetSandbox}
                    className="px-2.5 py-1.5 rounded-lg text-xs font-medium text-slate-400 hover:text-red-400 hover:bg-red-500/10 transition-all flex items-center gap-1"
                    title="Stop and reset sandbox"
                  >
                    <X size={12} /> Stop
                  </button>
                </div>
              </div>
            )}

            {view==="dashboard" && <Dashboard api={api} connected={connected} onAnalyze={()=>setView("upload")} onNavigate={navigateTo}/>}

            {view==="sandbox-env" && !isInstallerRunning && (
              <VirtualEnvironment
                onFile={handleSandboxFile}
                analyzing={false}
                currentFile={currentFile}
                error={uploadError}
                sample={sample}
                onViewResults={() => setView("analysis")}
              />
            )}

            {/* NEW: Realistic installation simulator view — Kept mounted so tab switching doesn't stop it */}
            {isInstallerRunning && (
              <div style={{ display: view === "sandbox-install" ? "block" : "none" }}>
                <RealisticSandboxInstaller
                  fileName={currentFile?.name}
                  fileType={currentFile?.type}
                  onComplete={handleSandboxInstallComplete}
                  onReset={handleResetSandbox}
                />
              </div>
            )}

            {/* Static stream view — Kept mounted during streaming */}
            {sample?._streaming ? (
              <div style={{ display: view === "upload-stream" ? "block" : "none" }}>
                <StaticAnalysisStream
                  sample={sample}
                  apiBase={apiBase}
                  onComplete={(fullSample) => {
                    setSample(fullSample);
                    if (currentViewRef.current === "upload-stream") {
                      setView("analysis");
                    }
                  }}
                  onFile={handleStaticFile}
                  error={uploadError}
                  currentFile={currentFile}
                />
              </div>
            ) : (
              view === "upload-stream" && (
                <StaticAnalysisStream
                  sample={sample}
                  apiBase={apiBase}
                  onComplete={(fullSample) => {
                    setSample(fullSample);
                    setView("analysis");
                  }}
                  onFile={handleStaticFile}
                  error={uploadError}
                  currentFile={currentFile}
                />
              )
            )}

            {(view==="upload"||(view==="analysis"&&!sample&&!analyzing)) && (
              <FileUploader onFile={handleStaticFile} analyzing={false} currentFile={currentFile} error={uploadError}
                enableSandbox={enableSandbox} setEnableSandbox={setEnableSandbox}/>
            )}

            {view==="analysis"&&analyzing && (
              enableSandbox
                ? <VirtualEnvironment onFile={handleSandboxFile} analyzing={true} currentFile={currentFile} />
                : <FileUploader onFile={handleStaticFile} analyzing={true} currentFile={currentFile}
                    enableSandbox={enableSandbox} setEnableSandbox={setEnableSandbox}/>
            )}

            {view==="analysis"&&sample&&!analyzing && (
              <AnalysisResults sample={sample} api={api} onChat={()=>setView("cipher")}
                onFileToCase={fileToCase}
                onSampleUpdate={(updated) => setSample(prev => ({...prev, ...updated}))}
                onExplain={handleExplain}/>
            )}

            {view==="cipher" && (
              <CipherAI messages={chatMessages} input={chatInput} setInput={setInput} onSend={sendChat} loading={chatLoading} sample={sample}/>
            )}
            {view==="cases" && <Cases api={api} connected={connected} refreshKey={casesRefresh}
              onViewTimeline={(c) => setCaseTimeline(c)}/>}
            {view==="mitre" && <MitreMatrix api={api} connected={connected} onExplain={handleExplain}/>}
            {view==="iocdb" && <IOCDatabase api={api} connected={connected} onExplain={handleExplain}/>}
            {view==="pcap" && <NetworkPcapAnalyzer api={api} connected={connected}/>}
            {view==="memory" && <MemoryForensics api={api} connected={connected}/>}
            {view==="settings" && <SettingsPanel apiBase={apiBase} setApiBase={setApiBase} connected={connected} onTest={checkConnection} currentUser={authUser}/>}
          </div>
        </ErrorBoundary>
      </div>
      <ExplanationModal {...explainState} onClose={() => setExplainState(s => ({...s, open: false}))} />
      {caseTimeline && (
        <CaseTimeline caseData={caseTimeline} api={api} onClose={() => setCaseTimeline(null)}/>
      )}
      <GlobalSearchModal open={searchOpen} onClose={()=>setSearchOpen(false)} api={api} onNavigate={navigateTo}/>
      <NotifPanel open={notifOpen} onClose={()=>setNotifOpen(false)}/>
    </div>
  );
}

// ── Notification bell button (reads context) ───────────────────
function NotifBellButton({ onOpen }) {
  const { unread } = useNotif();
  return (
    <button onClick={onOpen} className="relative p-1.5 rounded-lg hover:bg-white/10 transition-colors flex-shrink-0" style={{color:"#475569"}}>
      <Bell size={14}/>
      {unread>0 && (
        <span className="absolute -top-0.5 -right-0.5 w-4 h-4 rounded-full flex items-center justify-center text-white"
          style={{background:"#EF4444",fontSize:8,fontWeight:900}}>{unread>9?"9+":unread}</span>
      )}
    </button>
  );
}

// ── Root export with providers wrapped ────────────────────────
export default function CyberForge() {
  return (
    <NotifProvider>
      <ToastProvider>
        <CyberForgeApp />
      </ToastProvider>
    </NotifProvider>
  );
}

// Eye and EyeOff are imported from lucide-react at the top of this file
