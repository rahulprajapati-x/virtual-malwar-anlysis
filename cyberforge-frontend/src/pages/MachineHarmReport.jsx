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
//  MACHINE HARM REPORT — HOW THIS MALWARE CAN HURT YOUR PC
// ================================================================

function MachineHarmReport({ dyn, sample, fileType }) {
  const [expandedSection, setExpandedSection] = useState(null);

  const ext = (sample?.filename || "").split('.').pop().toLowerCase();
  const isWindows = ['exe','dll','msi','bat','ps1','vbs','scr'].includes(ext);
  const isAndroid = ['apk','aab'].includes(ext);
  const isDocument = ['pdf','doc','docx','xls','xlsx','pptx'].includes(ext);

  const threatLevel = dyn?.sandbox_verdict || "SUSPICIOUS";
  const riskScore = sample?.risk_score || 65;

  // Build harm categories based on what the sandbox detected
  const harmCategories = [];

  // === Immediate Device Damage ===
  const immediateHarms = [];
  if (dyn?.events?.some(e => e.event_type === "file_encrypt")) {
    immediateHarms.push({
      harm: "File Encryption (Ransomware)",
      detail: "All your personal files — documents, photos, videos, databases — get encrypted with AES-256 + RSA-2048. You cannot open them without the attacker's private key. Ransom demand is typically $500–$5000 in Bitcoin.",
      icon: Lock, color: "#EF4444", severity: "CRITICAL"
    });
  }
  if (dyn?.events?.some(e => e.event_type === "file_delete")) {
    immediateHarms.push({
      harm: "File Deletion / Data Destruction",
      detail: "Malware deletes system files, backup copies, and personal data. Shadow copy backups are also wiped. Full data recovery may be impossible without backups.",
      icon: X, color: "#EF4444", severity: "CRITICAL"
    });
  }
  if (dyn?.events?.some(e => e.event_type === "file_drop")) {
    immediateHarms.push({
      harm: "Malicious File Drops",
      detail: "Attacker drops additional payloads, rootkits, or remote access tools on your system. Each dropped file expands the attack surface and can introduce new malware families.",
      icon: Folder, color: "#F97316", severity: "HIGH"
    });
  }

  // === System Control & Persistence ===
  const persistenceHarms = [];
  if (dyn?.events?.some(e => e.event_type === "registry_write")) {
    persistenceHarms.push({
      harm: "Registry Persistence (Auto-Start on Boot)",
      detail: "A registry key is written to HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run. Every time you turn on your computer, the malware automatically restarts — even after manual deletion attempts.",
      icon: Database, color: "#EAB308", severity: "HIGH"
    });
  }
  if (dyn?.events?.some(e => e.event_type === "service_create")) {
    persistenceHarms.push({
      harm: "Malicious Windows Service Installed",
      detail: "A background service is registered with Windows Service Manager (set to AUTO_START). This service survives reboots, runs with elevated privileges, and is hidden from normal task managers.",
      icon: Settings, color: "#F97316", severity: "HIGH"
    });
  }
  if (dyn?.events?.some(e => e.event_type === "process_inject" || e.event_type === "process_hollow")) {
    persistenceHarms.push({
      harm: "Process Injection / Hollowing",
      detail: "Malware injects its code into legitimate Windows processes (explorer.exe, svchost.exe). This makes detection extremely difficult as the malware runs disguised as a trusted system process. Antivirus scans may miss it entirely.",
      icon: Zap, color: "#EF4444", severity: "CRITICAL"
    });
  }

  // === Data Theft & Privacy ===
  const privacyHarms = [];
  if (dyn?.events?.some(e => e.event_type === "api_credential")) {
    privacyHarms.push({
      harm: "Password & Credential Theft",
      detail: "Malware accesses Windows Credential Manager, browser saved passwords, and LSASS memory to steal your login credentials. Your banking passwords, email accounts, and social media are at immediate risk.",
      icon: Key, color: "#EF4444", severity: "CRITICAL"
    });
  }
  if (dyn?.events?.some(e => e.event_type === "api_keylog")) {
    privacyHarms.push({
      harm: "Keyboard Logging (Keylogger)",
      detail: "Every keystroke you type is recorded — including passwords you type manually, credit card numbers, messages, and search queries. This data is silently transmitted to the attacker's server.",
      icon: Cpu, color: "#EF4444", severity: "CRITICAL"
    });
  }
  if (dyn?.events?.some(e => e.event_type === "api_screen")) {
    privacyHarms.push({
      harm: "Screenshot Capture",
      detail: "Periodic screenshots of your desktop are taken and sent to the attacker. This can expose sensitive documents, banking portals, private messages, and anything visible on your screen.",
      icon: Monitor, color: "#F97316", severity: "HIGH"
    });
  }
  if (dyn?.events?.some(e => e.event_type === "apk_sms_intercept")) {
    privacyHarms.push({
      harm: "SMS & OTP Interception",
      detail: "All incoming SMS messages are intercepted, including two-factor authentication codes (OTPs). Attackers can bypass 2FA on your bank, email, and social accounts using stolen OTPs in real time.",
      icon: Smartphone, color: "#EF4444", severity: "CRITICAL"
    });
  }
  if (dyn?.events?.some(e => e.event_type === "apk_overlay")) {
    privacyHarms.push({
      harm: "Phishing Overlay Attack",
      detail: "A fake login screen is drawn over your real banking or payment app. You think you are logging into your bank — but you are actually entering credentials directly into the attacker's fake UI. Your login is stolen without you knowing.",
      icon: Layers, color: "#EF4444", severity: "CRITICAL"
    });
  }

  // === Network & Remote Control ===
  const networkHarms = [];
  if (dyn?.network_iocs?.length > 0) {
    networkHarms.push({
      harm: "Command & Control (C2) Communication",
      detail: `Malware tries to connect to ${dyn.network_iocs.length} remote server(s) controlled by the attacker. Once connected, the attacker can issue commands, download more malware, steal data, or use your machine as part of a botnet. ALL ${dyn.network_iocs.length} connection(s) were BLOCKED by the sandbox.`,
      icon: Globe, color: "#818CF8", severity: "HIGH"
    });
  }
  if (dyn?.events?.some(e => e.event_type === "apk_exfil")) {
    networkHarms.push({
      harm: "Data Exfiltration to Remote Server",
      detail: "Your personal data (contacts, photos, location history, SMS logs, banking details) is packaged and transmitted to the attacker's server over HTTPS. The encrypted connection makes this hard to detect on your router.",
      icon: Network, color: "#EF4444", severity: "CRITICAL"
    });
  }
  if (dyn?.events?.some(e => e.event_type === "api_token")) {
    networkHarms.push({
      harm: "Access Token Hijacking",
      detail: "Windows access tokens from other running processes are stolen. This allows the malware to impersonate privileged users, bypass UAC controls, and perform actions as SYSTEM or Administrator without the real user's knowledge.",
      icon: ShieldAlert, color: "#F97316", severity: "HIGH"
    });
  }

  // === Advanced Threats ===
  const advancedHarms = [];
  if (dyn?.events?.some(e => e.event_type === "apk_device_admin")) {
    advancedHarms.push({
      harm: "Device Administrator Takeover",
      detail: "Malware has gained Device Administrator rights on your Android phone. It can now remotely lock your device, wipe all data, change PIN/password, and prevent uninstallation. Removing it requires factory reset.",
      icon: ShieldAlert, color: "#EF4444", severity: "CRITICAL"
    });
  }
  if (dyn?.events?.some(e => e.event_type === "apk_accessibility")) {
    advancedHarms.push({
      harm: "Accessibility Service Exploitation",
      detail: "Android's Accessibility Service (meant for disabled users) is abused to read all on-screen content, simulate taps, and interact with other apps — including your banking apps — without your permission.",
      icon: Eye, color: "#EF4444", severity: "CRITICAL"
    });
  }
  if (dyn?.events?.some(e => e.event_type === "doc_macro" || e.event_type === "doc_ole")) {
    advancedHarms.push({
      harm: "Macro / OLE Exploit Execution",
      detail: "Office document macros or OLE objects execute malicious code the moment you open the file. No download required — just opening the document starts the infection chain. Full system compromise can happen within seconds.",
      icon: FileCode, color: "#EF4444", severity: "CRITICAL"
    });
  }

  // Build sections array (only non-empty ones)
  const sections = [
    { id: "immediate",    title: "💥 Immediate Damage",         items: immediateHarms,    bgColor: "rgba(239,68,68,0.05)", borderColor: "rgba(239,68,68,0.3)" },
    { id: "persistence",  title: "🔒 System Takeover",          items: persistenceHarms,  bgColor: "rgba(249,115,22,0.05)", borderColor: "rgba(249,115,22,0.3)" },
    { id: "privacy",      title: "👁 Privacy & Data Theft",     items: privacyHarms,      bgColor: "rgba(239,68,68,0.05)", borderColor: "rgba(239,68,68,0.3)" },
    { id: "network",      title: "🌐 Remote Control & Exfil",   items: networkHarms,      bgColor: "rgba(129,140,248,0.05)", borderColor: "rgba(129,140,248,0.3)" },
    { id: "advanced",     title: "💀 Advanced Exploitation",    items: advancedHarms,     bgColor: "rgba(239,68,68,0.05)", borderColor: "rgba(239,68,68,0.3)" },
  ].filter(s => s.items.length > 0);

  // Fallback if no dynamic data
  if (sections.length === 0) {
    sections.push(
      {
        id: "generic_windows", title: "💥 Potential Damage",
        bgColor: "rgba(239,68,68,0.05)", borderColor: "rgba(239,68,68,0.3)",
        items: isAndroid ? [
          { harm: "Personal Data Theft", detail: "Android malware can steal contacts, SMS messages, photos, call logs, banking app sessions, and location history. All data is transmitted to remote attackers.", icon: Smartphone, color: "#EF4444", severity: "CRITICAL" },
          { harm: "Account Takeover", detail: "By intercepting OTPs and overlaying fake login screens, attackers can take over your bank account, email, and social media without needing your password.", icon: Key, color: "#EF4444", severity: "CRITICAL" },
        ] : isDocument ? [
          { harm: "Drive-By Infection via Document", detail: "Simply opening this file triggers macro execution or JavaScript exploits. Your machine becomes infected without downloading anything extra. All it takes is one click to open the attachment.", icon: FileCode, color: "#EF4444", severity: "CRITICAL" },
          { harm: "Corporate Network Lateral Movement", detail: "Once infected, the malware scans your local network for other machines to infect. Office document malware is the #1 initial access vector for ransomware attacks on enterprises.", icon: Network, color: "#F97316", severity: "HIGH" },
        ] : [
          { harm: "Full System Compromise", detail: "A Windows executable malware can take complete control of your computer — installing keyloggers, stealing passwords, encrypting files, joining botnets, and establishing persistent backdoors.", icon: Skull, color: "#EF4444", severity: "CRITICAL" },
          { harm: "Financial Fraud", detail: "Browser credentials, saved credit cards, banking session cookies — all can be stolen. Attackers can initiate fraudulent bank transfers or make purchases using your payment methods.", icon: Key, color: "#EF4444", severity: "CRITICAL" },
        ]
      }
    );
  }

  const totalHarms = sections.reduce((acc, s) => acc + s.items.length, 0);
  const criticalCount = sections.flatMap(s => s.items).filter(i => i.severity === "CRITICAL").length;

  return (
    <div className="space-y-4 mt-6">
      {/* Section header */}
      <div className="p-4 rounded-xl" style={{background:"rgba(239,68,68,0.08)", border:"2px solid rgba(239,68,68,0.4)"}}>
        <div className="flex items-center gap-3 mb-3">
          <div className="p-2 rounded-xl" style={{background:"rgba(239,68,68,0.2)"}}>
            <Skull size={20} style={{color:"#EF4444"}}/>
          </div>
          <div>
            <h2 className="text-lg font-black text-white">⚠ How This Malware Can Harm Your Machine</h2>
            <p className="text-xs mt-0.5" style={{color:"#94A3B8"}}>
              Detailed analysis of {totalHarms} identified threat vectors • {criticalCount} CRITICAL risks
            </p>
          </div>
          <div className="ml-auto text-right">
            <div className="text-3xl font-black font-mono" style={{color:"#EF4444"}}>{riskScore}<span className="text-sm">/100</span></div>
            <div className="text-xs font-bold" style={{color:"#EF4444"}}>THREAT SCORE</div>
          </div>
        </div>

        {/* Risk overview pills */}
        <div className="flex gap-2 flex-wrap">
          <span className="text-xs font-bold px-2 py-1 rounded-lg" style={{background:"rgba(239,68,68,0.2)", color:"#EF4444"}}>
            🔴 {criticalCount} Critical Risks
          </span>
          <span className="text-xs font-bold px-2 py-1 rounded-lg" style={{background:"rgba(249,115,22,0.2)", color:"#F97316"}}>
            🟠 {sections.flatMap(s=>s.items).filter(i=>i.severity==="HIGH").length} High Risks
          </span>
          <span className="text-xs font-bold px-2 py-1 rounded-lg" style={{background:"rgba(129,140,248,0.2)", color:"#818CF8"}}>
            📡 {dyn?.network_iocs?.length || 0} C2 Servers Blocked
          </span>
          <span className="text-xs font-bold px-2 py-1 rounded-lg" style={{background:"rgba(234,179,8,0.2)", color:"#EAB308"}}>
            📁 {dyn?.dropped_files?.length || 0} Files Dropped
          </span>
        </div>
      </div>

      {/* Harm Sections */}
      {sections.map((section) => (
        <div key={section.id} className="rounded-xl overflow-hidden" style={{border:`1px solid ${section.borderColor}`, background: section.bgColor}}>
          <button
            className="w-full text-left px-4 py-3 flex items-center justify-between"
            onClick={() => setExpandedSection(expandedSection === section.id ? null : section.id)}
            style={{background: "rgba(0,0,0,0.2)"}}
          >
            <span className="font-black text-white text-sm">{section.title}</span>
            <div className="flex items-center gap-2">
              <span className="text-xs px-2 py-0.5 rounded font-bold" style={{background:"rgba(239,68,68,0.2)", color:"#EF4444"}}>
                {section.items.length} threat{section.items.length > 1 ? "s" : ""}
              </span>
              <ChevronRight size={14} style={{color:"#475569", transform: expandedSection === section.id ? "rotate(90deg)" : "rotate(0deg)", transition:"transform 0.2s"}}/>
            </div>
          </button>

          {(expandedSection === section.id || expandedSection === null) && (
            <div className="divide-y" style={{borderColor:"rgba(255,255,255,0.05)"}}>
              {section.items.map((item, idx) => {
                const HarmIcon = item.icon;
                return (
                  <div key={idx} className="p-4 flex items-start gap-4">
                    <div className="p-2.5 rounded-xl flex-shrink-0" style={{background:`${item.color}15`}}>
                      <HarmIcon size={18} style={{color: item.color}}/>
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                        <span className="text-sm font-black text-white">{item.harm}</span>
                        <span className="text-xs font-black px-2 py-0.5 rounded"
                          style={{background:`${item.color}20`, color: item.color, border:`1px solid ${item.color}40`}}>
                          {item.severity}
                        </span>
                      </div>
                      <p className="text-xs leading-relaxed" style={{color:"#94A3B8"}}>{item.detail}</p>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      ))}

      {/* What to do section */}
      <div className="p-4 rounded-xl" style={{background:"rgba(34,197,94,0.05)", border:"1px solid rgba(34,197,94,0.3)"}}>
        <h3 className="text-sm font-black text-white mb-3 flex items-center gap-2">
          <CheckCircle size={15} style={{color:"#22C55E"}}/> Recommended Response Actions
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          {[
            { step: "1", action: "DO NOT run this file on a real machine", color: "#EF4444" },
            { step: "2", action: "Submit hash to VirusTotal for community intelligence", color: "#3B82F6" },
            { step: "3", action: "Block all identified C2 IPs/domains at firewall level", color: "#F97316" },
            { step: "4", action: "Add YARA rules to your EDR/AV for detection", color: "#EAB308" },
            { step: "5", action: "File a case and document IOCs for your SOC team", color: "#818CF8" },
            { step: "6", action: "Check network logs for any past communication with C2 servers", color: "#22C55E" },
          ].map(item => (
            <div key={item.step} className="flex items-center gap-2 p-2 rounded-lg" style={{background:"rgba(0,0,0,0.3)"}}>
              <span className="w-5 h-5 rounded-full text-xs font-black flex items-center justify-center flex-shrink-0"
                style={{background: item.color, color:"white"}}>
                {item.step}
              </span>
              <span className="text-xs" style={{color:"#94A3B8"}}>{item.action}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Bottom disclaimer */}
      <div className="p-3 rounded-lg flex items-start gap-2" style={{background:"rgba(45,107,228,0.08)", border:"1px solid rgba(45,107,228,0.2)"}}>
        <Info size={13} style={{color:"#3B82F6", flexShrink:0, marginTop:1}}/>
        <p className="text-xs" style={{color:"#64748B"}}>
          <strong style={{color:"#94A3B8"}}>Educational Notice:</strong> This analysis was performed inside an isolated sandbox VM. No real system was harmed. The behavioral events above were captured by intercepting API calls, file system operations, and network traffic within the sandboxed environment. All network connections were blocked before reaching the internet.
        </p>
      </div>
    </div>
  );
}


export default MachineHarmReport;
