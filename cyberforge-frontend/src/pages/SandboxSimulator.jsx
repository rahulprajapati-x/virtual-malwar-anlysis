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
//  REALISTIC SANDBOX INSTALLATION SIMULATOR
// ================================================================

// Simulates exactly how a human would install & run an app on Windows/Android
// Shows every step with proper OS-like dialogs and process events

const INSTALL_PHASES = {
  windows: [
    { id: "download",    label: "Downloading File",              icon: Download,     color: "#3B82F6",  desc: "Browser downloading executable from internet", duration: 1200 },
    { id: "smartscreen", label: "SmartScreen Warning",           icon: ShieldAlert,  color: "#EAB308",  desc: "Windows SmartScreen: 'Unknown publisher — Run anyway?'", duration: 900 },
    { id: "uac",         label: "UAC Elevation Dialog",          icon: Shield,       color: "#F97316",  desc: "User Account Control: Do you allow this app to make changes?", duration: 800 },
    { id: "installer",   label: "Installer Launched",            icon: Package,      color: "#3B82F6",  desc: "Setup.exe starts. User clicks 'Next > Next > Install'", duration: 1100 },
    { id: "extract",     label: "Extracting Files",              icon: Boxes,        color: "#818CF8",  desc: "Decompressing payload files to %APPDATA%\\...", duration: 1300 },
    { id: "registry",    label: "Writing Registry Keys",         icon: Database,     color: "#EAB308",  desc: "HKCU\\Run key created for auto-start on login", duration: 700 },
    { id: "services",    label: "Installing Background Service",  icon: Settings,     color: "#F97316",  desc: "CreateService() — service set to AUTO_START", duration: 900 },
    { id: "process",     label: "Main Process Started",          icon: Play,         color: "#22C55E",  desc: "malware.exe (PID 4921) spawned by installer", duration: 600 },
    { id: "inject",      label: "Process Injection Detected",    icon: Zap,          color: "#EF4444",  desc: "VirtualAllocEx → WriteProcessMemory → CreateRemoteThread into explorer.exe", duration: 1000 },
    { id: "c2",          label: "C2 Beacon Established",         icon: Globe,        color: "#EF4444",  desc: "HTTPS POST to 185.220.101.47:443 — command & control connected", duration: 800 },
    { id: "persistence", label: "Persistence Mechanisms Set",    icon: Lock,         color: "#EF4444",  desc: "Startup folder + registry run key + scheduled task created", duration: 700 },
    { id: "exfil",       label: "Data Exfiltration Attempt",     icon: Network,      color: "#EF4444",  desc: "Stealing browser cookies, saved passwords, documents — BLOCKED", duration: 1000 },
  ],
  android: [
    { id: "download",     label: "APK Downloaded",               icon: Download,     color: "#3B82F6",  desc: "apk file downloaded from unknown source (not Play Store)", duration: 1000 },
    { id: "sideload",     label: "Unknown Sources Enabled",       icon: ShieldAlert,  color: "#EAB308",  desc: "Settings → Security → 'Install from unknown sources' — ENABLED", duration: 800 },
    { id: "install",      label: "APK Installing",               icon: Package,      color: "#3B82F6",  desc: "Android Package Manager installing application...", duration: 1200 },
    { id: "perms",        label: "Permissions Dialog",           icon: Smartphone,   color: "#F97316",  desc: "App requests: SMS, Contacts, Camera, Location, Accessibility — ALL GRANTED", duration: 1000 },
    { id: "launch",       label: "App First Launch",             icon: Play,         color: "#22C55E",  desc: "com.malware.app starts, loads config from remote server", duration: 700 },
    { id: "accessibility",label: "Accessibility Service Abuse",  icon: Eye,          color: "#EF4444",  desc: "App binds to AccessibilityService — can read ALL screen content and simulate user taps", duration: 900 },
    { id: "overlay",      label: "Phishing Overlay Active",      icon: Layers,       color: "#EF4444",  desc: "Fake bank UI overlay drawn on screen — credential harvesting active", duration: 800 },
    { id: "sms",          label: "SMS Interception Active",      icon: Smartphone,   color: "#EF4444",  desc: "BroadcastReceiver for SMS_RECEIVED — all incoming OTPs intercepted", duration: 700 },
    { id: "deviceadmin",  label: "Device Admin Rights Obtained", icon: ShieldAlert,  color: "#EF4444",  desc: "DevicePolicyManager activated — malware can lock/wipe device remotely", duration: 900 },
    { id: "exfil",        label: "Data Stolen & Transmitted",    icon: Network,      color: "#EF4444",  desc: "Contacts, SMS history, photos, GPS location → C2 server — BLOCKED", duration: 1000 },
  ],
  document: [
    { id: "open",        label: "Document Opened",              icon: FileText,     color: "#3B82F6",  desc: "User double-clicks malicious.docx from email attachment", duration: 900 },
    { id: "protected",   label: "Protected View Warning",       icon: ShieldAlert,  color: "#EAB308",  desc: "Microsoft Word: 'PROTECTED VIEW — Be careful, this file is from the internet'", duration: 700 },
    { id: "bypass",      label: "User Clicks 'Enable Content'", icon: MousePointer, color: "#F97316",  desc: "User clicks 'Enable Editing' and then 'Enable Content' (macros activated)", duration: 800 },
    { id: "macro",       label: "VBA Macro Executes",           icon: FileCode,     color: "#EF4444",  desc: "AutoOpen() macro runs — obfuscated VBA code deobfuscated and executed", duration: 1000 },
    { id: "powershell",  label: "PowerShell Spawned",           icon: Terminal,     color: "#EF4444",  desc: "WINWORD.EXE → cmd.exe → powershell.exe -enc JABzAD0ATgBlAHcA...", duration: 900 },
    { id: "download",    label: "Stage-2 Payload Downloaded",   icon: Download,     color: "#EF4444",  desc: "PowerShell downloads payload.exe from C2 — GET http://cdn.evil.ru/p.exe", duration: 1100 },
    { id: "execute",     label: "Payload Executed",             icon: Play,         color: "#EF4444",  desc: "payload.exe launched silently — full malware now running on system", duration: 700 },
    { id: "persistence", label: "Persistence Established",      icon: Lock,         color: "#EF4444",  desc: "Scheduled task created: runs payload.exe every 5 minutes", duration: 800 },
    { id: "exfil",       label: "Document Theft Attempt",       icon: Folder,       color: "#EF4444",  desc: "Searching *.docx *.xlsx *.pdf — uploading to attacker server — BLOCKED", duration: 1000 },
  ],
};

function RealisticSandboxInstaller({ fileName, fileType, onComplete, onReset }) {
  const [currentPhase, setCurrentPhase] = useState(() => {
    try {
      const s = JSON.parse(sessionStorage.getItem("cyberforge_installer_state") || "{}");
      return typeof s.currentPhase === "number" ? s.currentPhase : -1;
    } catch { return -1; }
  });
  const [completedPhases, setCompletedPhases] = useState(() => {
    try {
      const s = JSON.parse(sessionStorage.getItem("cyberforge_installer_state") || "{}");
      return Array.isArray(s.completedPhases) ? s.completedPhases : [];
    } catch { return []; }
  });
  const [status, setStatus] = useState(() => {
    try {
      const s = JSON.parse(sessionStorage.getItem("cyberforge_installer_state") || "{}");
      return s.status || "Booting sandbox VM...";
    } catch { return "Booting sandbox VM..."; }
  });
  const [timer, setTimer] = useState(() => {
    try {
      const s = JSON.parse(sessionStorage.getItem("cyberforge_installer_state") || "{}");
      return typeof s.timer === "number" ? s.timer : 0;
    } catch { return 0; }
  });
  const [vmStatus, setVmStatus] = useState(() => {
    try {
      const s = JSON.parse(sessionStorage.getItem("cyberforge_installer_state") || "{}");
      return s.vmStatus || "BOOTING";
    } catch { return "BOOTING"; }
  });
  const [riskScore, setRiskScore] = useState(() => {
    try {
      const s = JSON.parse(sessionStorage.getItem("cyberforge_installer_state") || "{}");
      return typeof s.riskScore === "number" ? s.riskScore : 0;
    } catch { return 0; }
  });
  const logRef = useRef(null);

  const ext = (fileName || "").split('.').pop().toLowerCase();
  const profileKey = ['apk','aab'].includes(ext) ? 'android'
    : ['pdf','doc','docx','xls','xlsx','pptx','rtf'].includes(ext) ? 'document'
    : 'windows';

  const phases = INSTALL_PHASES[profileKey] || INSTALL_PHASES.windows;

  const vmLabels = {
    windows: "Windows 10 Pro x64 (Build 19041)",
    android: "Android 11 (API Level 30) — Pixel 3a",
    document: "Windows 10 Pro x64 + Office 2019",
  };

  useEffect(() => {
    const timerIv = setInterval(() => setTimer(t => t + 1), 1000);
    return () => clearInterval(timerIv);
  }, []);

  useEffect(() => {
    try {
      sessionStorage.setItem("cyberforge_installer_state", JSON.stringify({
        currentPhase,
        completedPhases,
        status,
        timer,
        vmStatus,
        riskScore
      }));
    } catch {}
  }, [currentPhase, completedPhases, status, timer, vmStatus, riskScore]);

  useEffect(() => {
    let cancelled = false;

    const runPhases = async () => {
      if (completedPhases.length >= phases.length) {
        setVmStatus("DONE");
        setStatus("Analysis complete. Behavioral telemetry captured.");
        return;
      }

      if (vmStatus === "BOOTING") {
        await new Promise(r => setTimeout(r, 1200));
        if (cancelled) return;
        setVmStatus("RUNNING");
        setStatus("VM ready. Starting installation simulation...");
        await new Promise(r => setTimeout(r, 600));
      }

      const startIdx = completedPhases.length;
      for (let i = startIdx; i < phases.length; i++) {
        if (cancelled) return;
        setCurrentPhase(i);
        setStatus(phases[i].desc);
        
        // Risk accumulates based on phase color
        if (phases[i].color === "#EF4444") setRiskScore(r => Math.min(100, r + 18));
        else if (phases[i].color === "#F97316") setRiskScore(r => Math.min(100, r + 8));
        else if (phases[i].color === "#EAB308") setRiskScore(r => Math.min(100, r + 4));

        await new Promise(r => setTimeout(r, phases[i].duration + Math.random() * 300));
        if (cancelled) return;
        setCompletedPhases(prev => (prev.includes(i) ? prev : [...prev, i]));
      }

      if (!cancelled) {
        setStatus("Analysis complete. Generating behavioral report...");
        setVmStatus("DONE");
        await new Promise(r => setTimeout(r, 1200));
        if (!cancelled) onComplete();
      }
    };

    runPhases();
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [currentPhase, completedPhases]);

  const totalDone = completedPhases.length;
  const progress = Math.round((totalDone / phases.length) * 100);

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-black text-white tracking-tight flex items-center gap-3">
            <div className="w-3 h-3 rounded-full animate-pulse"
              style={{background: vmStatus==="DONE"?"#22C55E":"#EF4444", boxShadow:`0 0 10px ${vmStatus==="DONE"?"#22C55E":"#EF4444"}`}}/>
            {vmStatus === "BOOTING" ? "Booting Sandbox VM..." :
             vmStatus === "DONE"    ? "Sandbox Analysis Complete" :
             "LIVE SANDBOX EXECUTION"}
          </h1>
          <p className="text-sm mt-1" style={{color:"#64748B"}}>
            {vmLabels[profileKey]} • File: <span className="font-mono text-white">{fileName}</span>
          </p>
        </div>
        <div className="flex items-center gap-3">
          {onReset && (
            <button
              onClick={onReset}
              className="px-3 py-1.5 rounded-lg text-xs font-semibold text-slate-400 hover:text-red-400 hover:bg-red-500/10 border border-slate-700 hover:border-red-500/30 transition-all flex items-center gap-1.5"
              title="Stop simulation and reset sandbox"
            >
              <X size={12}/> Stop & Reset
            </button>
          )}
          <div className="text-right">
            <p className="text-xs font-bold" style={{color:"#FCA5A5"}}>LIVE RISK SCORE</p>
            <p className="text-3xl font-black font-mono" style={{color: riskScore>70?"#EF4444":riskScore>40?"#F97316":"#EAB308"}}>
              {riskScore}<span className="text-sm">/100</span>
            </p>
          </div>
        </div>
      </div>

      {/* VM Screen Simulation */}
      <Card className="overflow-hidden relative" style={{background:"#000", height:220, borderColor:"#1E2A40"}}>
        {/* Scanlines overlay */}
        <div className="absolute inset-0 pointer-events-none z-10"
          style={{backgroundImage:"repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.05) 2px, rgba(0,0,0,0.05) 4px)"}}/>

        {/* VM Desktop Header Bar */}
        <div className="flex items-center gap-2 px-4 py-2 border-b" style={{background:"#1a1a2e", borderColor:"#333"}}>
          <div className="flex gap-1.5">
            <div className="w-3 h-3 rounded-full bg-[#EF4444]"/>
            <div className="w-3 h-3 rounded-full bg-[#EAB308]"/>
            <div className="w-3 h-3 rounded-full bg-[#22C55E]"/>
          </div>
          <span className="text-xs font-mono text-gray-400 flex-1 text-center">
            {profileKey === "android" ? "📱 Android Emulator — AVD Manager" : `🖥 ${vmLabels[profileKey]} — Sandbox VM`}
          </span>
          <span className="text-xs font-mono" style={{color:"#22C55E"}}>
            {vmStatus === "BOOTING" ? "BOOTING..." : vmStatus === "DONE" ? "ANALYSIS DONE" : `⏱ ${String(Math.floor(timer/60)).padStart(2,'0')}:${String(timer%60).padStart(2,'0')}`}
          </span>
        </div>

        {/* VM Content Area */}
        <div className="flex-1 flex items-center justify-center relative" style={{height:170}}>
          {vmStatus === "BOOTING" ? (
            <div className="flex flex-col items-center gap-3">
              <Monitor size={40} style={{color:"#334155"}} className="animate-pulse"/>
              <p className="text-xs font-mono text-gray-500 animate-pulse">Initializing virtual machine...</p>
              <div className="flex gap-1">
                {[0,1,2,3,4].map(i => (
                  <div key={i} className="w-2 h-2 rounded-full bg-blue-600 animate-bounce" style={{animationDelay:`${i*0.1}s`}}/>
                ))}
              </div>
            </div>
          ) : currentPhase >= 0 && currentPhase < phases.length ? (
            <div className="absolute inset-0 p-4 flex flex-col">
              {/* Simulated OS Window */}
              <div className="rounded-lg overflow-hidden flex-1"
                style={{border:`1px solid ${phases[currentPhase]?.color || "#333"}40`, background:"rgba(0,0,0,0.8)"}}>
                <div className="flex items-center gap-2 px-3 py-1.5"
                  style={{background:`${phases[currentPhase]?.color || "#333"}15`, borderBottom:`1px solid ${phases[currentPhase]?.color || "#333"}30`}}>
                  {phases[currentPhase] && (() => {
                    const Icon = phases[currentPhase].icon;
                    return <Icon size={12} style={{color: phases[currentPhase].color}}/>;
                  })()}
                  <span className="text-xs font-bold" style={{color: phases[currentPhase]?.color}}>
                    {phases[currentPhase]?.label}
                  </span>
                  <div className="ml-auto flex gap-1">
                    <div className="w-2 h-2 rounded bg-gray-600"/>
                    <div className="w-2 h-2 rounded bg-gray-600"/>
                    <div className="w-2 h-2 rounded bg-red-700"/>
                  </div>
                </div>
                <div className="p-4 flex items-center justify-between">
                  <div className="flex-1">
                    <p className="text-xs font-mono" style={{color:"#94A3B8"}}>{phases[currentPhase]?.desc}</p>
                    <div className="mt-2 flex items-center gap-2">
                      <Loader size={10} className="animate-spin" style={{color: phases[currentPhase]?.color}}/>
                      <span className="text-xs font-mono" style={{color: phases[currentPhase]?.color}}>Processing...</span>
                    </div>
                  </div>
                </div>
              </div>
              {/* Taskbar */}
              <div className="flex items-center gap-2 mt-1 px-2 py-1 rounded" style={{background:"rgba(0,0,0,0.9)", border:"1px solid #1E2A40"}}>
                <span className="text-xs font-mono text-gray-600">🚩 Start</span>
                <div className="flex gap-1 ml-2">
                  {completedPhases.slice(-4).map((pi) => (
                    <div key={pi} className="text-xs font-mono px-1.5 py-0.5 rounded-sm"
                      style={{background:`${phases[pi]?.color || "#333"}20`, color: phases[pi]?.color || "#888", fontSize:8}}>
                      {phases[pi]?.label?.split(' ').slice(0,2).join(' ')}
                    </div>
                  ))}
                </div>
                <span className="ml-auto text-xs font-mono text-gray-600">
                  {new Date().toLocaleTimeString('en-IN', {hour:'2-digit',minute:'2-digit'})}
                </span>
              </div>
            </div>
          ) : vmStatus === "DONE" ? (
            <div className="flex flex-col items-center gap-2">
              <CheckCircle size={40} style={{color:"#22C55E"}}/>
              <p className="text-sm font-bold text-white">Sandbox Execution Complete</p>
              <p className="text-xs text-gray-500">All behavioral telemetry captured</p>
            </div>
          ) : null}
        </div>
      </Card>

      {/* Progress Bar */}
      <div>
        <div className="flex justify-between mb-1.5 text-xs">
          <span style={{color:"#64748B"}}>Installation Progress</span>
          <span className="font-bold" style={{color:"#EF4444"}}>{progress}% Complete</span>
        </div>
        <div className="h-2 rounded-full" style={{background:"#1E2A40"}}>
          <div className="h-2 rounded-full transition-all duration-500"
            style={{width:`${progress}%`, background:"linear-gradient(90deg, #2D6BE4, #EF4444)"}}/>
        </div>
      </div>

      {/* Phase Timeline — main attraction */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Left: Step-by-step phase list */}
        <Card className="p-0 overflow-hidden">
          <div className="px-4 py-3 border-b flex items-center gap-2" style={{background:"#0D1122", borderColor:"#1E2A40"}}>
            <Activity size={13} style={{color:"#2D6BE4"}}/>
            <span className="text-xs font-bold text-white">Installation Timeline</span>
            <span className="ml-auto text-xs px-2 py-0.5 rounded font-bold" style={{background:"rgba(239,68,68,0.15)", color:"#EF4444"}}>
              LIVE
            </span>
          </div>
          <div ref={logRef} className="overflow-y-auto" style={{maxHeight:340}}>
            {phases.map((phase, i) => {
              const done = completedPhases.includes(i);
              const active = currentPhase === i && !done;
              const pending = !done && !active;
              const PhaseIcon = phase.icon;
              return (
                <div key={phase.id}
                  className="flex items-start gap-3 px-4 py-3 border-b transition-all duration-300"
                  style={{
                    borderColor:"#1E2A40",
                    background: active ? `${phase.color}08` : "transparent",
                    opacity: pending ? 0.4 : 1,
                  }}>
                  {/* Timeline dot + line */}
                  <div className="flex flex-col items-center flex-shrink-0">
                    <div className="w-7 h-7 rounded-full flex items-center justify-center"
                      style={{
                        background: done ? `${phase.color}20` : active ? `${phase.color}15` : "#1E2A40",
                        border: `2px solid ${done ? phase.color : active ? phase.color : "#334155"}`,
                      }}>
                      {done ? <CheckCircle size={13} style={{color: phase.color}}/> :
                       active ? <Loader size={13} style={{color: phase.color}} className="animate-spin"/> :
                       <PhaseIcon size={11} style={{color: "#475569"}}/>}
                    </div>
                    {i < phases.length - 1 && (
                      <div className="w-0.5 mt-1 flex-1 min-h-[20px]"
                        style={{background: done ? phase.color + "40" : "#1E2A40"}}/>
                    )}
                  </div>

                  {/* Content */}
                  <div className="flex-1 pb-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-bold" style={{color: done || active ? "white" : "#475569"}}>
                        {phase.label}
                      </span>
                      {done && (
                        <span className="text-xs font-black px-1.5 py-0.5 rounded"
                          style={{background:`${phase.color}20`, color: phase.color, fontSize:8}}>
                          DONE
                        </span>
                      )}
                      {active && (
                        <span className="text-xs font-black px-1.5 py-0.5 rounded animate-pulse"
                          style={{background:`${phase.color}20`, color: phase.color, fontSize:8}}>
                          IN PROGRESS
                        </span>
                      )}
                    </div>
                    <p className="text-xs mt-0.5 leading-relaxed"
                      style={{color: active ? "#94A3B8" : "#475569"}}>
                      {phase.desc}
                    </p>
                  </div>
                </div>
              );
            })}
          </div>
        </Card>

        {/* Right: Live system log terminal */}
        <Card className="p-0 overflow-hidden">
          <div className="px-4 py-3 border-b flex items-center gap-2" style={{background:"#0D1122", borderColor:"#1E2A40"}}>
            <Terminal size={13} style={{color:"#22C55E"}}/>
            <span className="text-xs font-bold text-white">System Process Log</span>
            <div className="ml-auto flex gap-1.5">
              <div className="w-2 h-2 rounded-full bg-[#EF4444]"/>
              <div className="w-2 h-2 rounded-full bg-[#EAB308]"/>
              <div className="w-2 h-2 rounded-full bg-[#22C55E]"/>
            </div>
          </div>
          <div className="p-3 font-mono text-xs overflow-y-auto" style={{background:"#050A14", maxHeight:340, color:"#22C55E"}}>
            <div style={{color:"#64748B"}}>{">"} CyberForge Sandbox v3.1 — Behavioral Engine</div>
            <div style={{color:"#64748B"}}>{">"} Target: {fileName}</div>
            <div style={{color:"#64748B"}}>{">"} Profile: {profileKey.toUpperCase()}</div>
            <div className="mt-2">
              {vmStatus === "BOOTING" && <div className="animate-pulse" style={{color:"#3B82F6"}}>[SYS] Initializing VM environment...</div>}
              {(vmStatus === "RUNNING" || vmStatus === "DONE") && (
                <>
                  <div style={{color:"#22C55E"}}>[SYS] VM boot complete ✓</div>
                  <div style={{color:"#22C55E"}}>[SYS] Network isolation confirmed (air-gapped)</div>
                  <div style={{color:"#22C55E"}}>[SYS] API hooking enabled — monitoring {profileKey === "android" ? "Dalvik/ART" : "Win32 API"}</div>
                  <div className="mt-1" style={{color:"#64748B"}}>─────────────────────────────</div>
                </>
              )}
              {completedPhases.map((pi) => {
                const p = phases[pi];
                const logColor = p.color === "#EF4444" ? "#FCA5A5" : p.color === "#F97316" ? "#FB923C" : p.color === "#EAB308" ? "#FDE047" : "#22C55E";
                return (
                  <div key={pi} style={{color: logColor, marginTop:2}}>
                    [{String(Math.floor(pi * 1.8)).padStart(2,'0')}:{String(Math.round((pi*1.8 % 1) * 60)).padStart(2,'0')}] [{p.id.toUpperCase()}] {p.desc}
                  </div>
                );
              })}
              {currentPhase >= 0 && currentPhase < phases.length && !completedPhases.includes(currentPhase) && (
                <div className="animate-pulse mt-1" style={{color:"#3B82F6"}}>
                  [{String(Math.floor(currentPhase * 1.8)).padStart(2,'0')}:{String(Math.round((currentPhase*1.8 % 1) * 60)).padStart(2,'0')}] [{phases[currentPhase]?.id?.toUpperCase()}] {phases[currentPhase]?.desc} ...
                </div>
              )}
              {vmStatus === "DONE" && (
                <>
                  <div className="mt-1" style={{color:"#64748B"}}>─────────────────────────────</div>
                  <div style={{color:"#22C55E"}}>[SYS] Execution complete. Snapshot captured.</div>
                  <div style={{color:"#22C55E"}}>[SYS] Generating behavioral report...</div>
                </>
              )}
              <div className="mt-1 animate-pulse" style={{color:"#22C55E"}}>█</div>
            </div>
          </div>
        </Card>
      </div>

      {/* Status Bar */}
      <Card className="p-3 flex items-center gap-3" style={{borderColor: riskScore > 60 ? "rgba(239,68,68,0.4)" : "rgba(234,179,8,0.3)"}}>
        <div className="flex-1">
          <p className="text-xs font-bold text-white">{status}</p>
        </div>
        {vmStatus !== "DONE" && (
          <div className="flex items-center gap-2 text-xs" style={{color:"#64748B"}}>
            <Loader size={12} className="animate-spin"/>
            Runtime: {String(Math.floor(timer/60)).padStart(2,'0')}:{String(timer%60).padStart(2,'0')}
          </div>
        )}
      </Card>
    </div>
  );
}


export default RealisticSandboxInstaller;
