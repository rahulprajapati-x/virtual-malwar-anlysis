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
//  SANDBOX TIMELINE COMPONENT (Post-execution results)
// ================================================================

const SANDBOX_EVENT_META = {
  process_start:   { icon: Play,     color: "#3B82F6", label: "Process" },
  process_inject:  { icon: Zap,      color: "#EF4444", label: "Injection" },
  process_hollow:  { icon: Zap,      color: "#EF4444", label: "Hollowing" },
  file_drop:       { icon: Folder,   color: "#22C55E", label: "File Drop" },
  file_delete:     { icon: X,        color: "#EF4444", label: "File Del" },
  file_encrypt:    { icon: Lock,     color: "#EF4444", label: "Encrypt" },
  file_enum:       { icon: FileSearch,color:"#EAB308", label: "File Enum" },
  registry_write:  { icon: Database, color: "#EAB308", label: "Registry" },
  registry_delete: { icon: Database, color: "#EF4444", label: "Registry" },
  service_create:  { icon: Settings, color: "#F97316", label: "Service" },
  network_connect: { icon: Globe,    color: "#818CF8", label: "Network" },
  network_dns:     { icon: Network,  color: "#818CF8", label: "DNS" },
  api_credential:  { icon: Key,      color: "#EF4444", label: "Credential" },
  api_screen:      { icon: Monitor,  color: "#64748B", label: "Screenshot" },
  api_keylog:      { icon: Cpu,      color: "#EF4444", label: "Keylog" },
  api_token:       { icon: ShieldAlert, color: "#F97316", label: "Token" },
  api_debug_check: { icon: Eye,      color: "#EAB308", label: "Evasion" },
  api_sleep:       { icon: Clock,    color: "#475569", label: "Evasion" },
  apk_permission:  { icon: Smartphone, color: "#F97316", label: "Permission" },
  apk_sms_intercept:{ icon: Smartphone, color: "#EF4444", label: "SMS" },
  apk_overlay:     { icon: Layers,   color: "#EF4444", label: "Overlay" },
  apk_accessibility:{ icon: Smartphone, color: "#EF4444", label: "A11y Abuse" },
  apk_device_admin:{ icon: ShieldAlert, color: "#EF4444", label: "DevAdmin" },
  apk_exfil:       { icon: Network,  color: "#EF4444", label: "Exfil" },
  doc_macro:       { icon: FileCode, color: "#EF4444", label: "Macro" },
  doc_ole:         { icon: FileCode, color: "#EF4444", label: "OLE" },
  doc_dde:         { icon: FileCode, color: "#EF4444", label: "DDE" },
  doc_js:          { icon: FileCode, color: "#F97316", label: "JS Eval" },
  doc_exploit:     { icon: Bug,      color: "#EF4444", label: "Exploit" },
  doc_download:    { icon: Download, color: "#EF4444", label: "Download" },
  doc_child_process:{ icon: Play,    color: "#EF4444", label: "Child Proc" },
  screenshot:      { icon: Monitor,  color: "#475569", label: "Screenshot" },
};

const SANDBOX_TYPE_META = {
  windows:  { icon: Monitor,    color: "#2D6BE4", label: "Windows Sandbox" },
  android:  { icon: Smartphone, color: "#22C55E", label: "Android Sandbox" },
  document: { icon: FileCode,   color: "#F97316", label: "Document Sandbox" },
};


export { SANDBOX_EVENT_META, SANDBOX_TYPE_META };
