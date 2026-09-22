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
//  TOAST SYSTEM
// ================================================================

const ToastContext = React.createContext(null);

function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);
  const addToast = useCallback((msg, type = "info", duration = 3500) => {
    const id = Date.now() + Math.random();
    setToasts(prev => [...prev, { id, msg, type }]);
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), duration);
  }, []);
  const removeToast = (id) => setToasts(prev => prev.filter(t => t.id !== id));
  return (
    <ToastContext.Provider value={addToast}>
      {children}
      <div className="fixed bottom-5 right-5 z-[9999] flex flex-col gap-2 pointer-events-none" style={{maxWidth:340}}>
        {toasts.map(t => (
          <div key={t.id} className="toast-enter pointer-events-auto flex items-start gap-3 px-4 py-3 rounded-xl shadow-2xl"
            style={{
              background: t.type==="success"?"#0D2918":t.type==="error"?"#1E0A0A":t.type==="warn"?"#1A1500":"#0D1122",
              border: `1px solid ${t.type==="success"?"rgba(34,197,94,0.4)":t.type==="error"?"rgba(239,68,68,0.4)":t.type==="warn"?"rgba(234,179,8,0.4)":"rgba(59,130,246,0.4)"}`,
              backdropFilter:"blur(12px)",
            }}>
            {t.type==="success" && <CheckCircle size={15} style={{color:"#22C55E",flexShrink:0,marginTop:1}}/>}
            {t.type==="error"   && <AlertTriangle size={15} style={{color:"#EF4444",flexShrink:0,marginTop:1}}/>}
            {t.type==="warn"    && <AlertCircle size={15} style={{color:"#EAB308",flexShrink:0,marginTop:1}}/>}
            {t.type==="info"    && <Info size={15} style={{color:"#3B82F6",flexShrink:0,marginTop:1}}/>}
            <span className="text-sm text-white leading-snug flex-1">{t.msg}</span>
            <button onClick={() => removeToast(t.id)} className="text-slate-500 hover:text-white flex-shrink-0 transition-colors"><X size={13}/></button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}
const useToast = () => React.useContext(ToastContext);

export { ToastProvider, useToast };
