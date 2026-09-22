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
//  NOTIFICATIONS PANEL
// ================================================================

const NotifContext = React.createContext(null);

function NotifProvider({ children }) {
  const [notifs, setNotifs] = useState([
    { id:1, title:"System Ready", sub:"CyberForge backend connected", time:"just now", read:false, color:"#22C55E" },
  ]);
  const addNotif = useCallback((title, sub, color="#3B82F6") => {
    const id = Date.now();
    setNotifs(prev => [{ id, title, sub, time:"just now", read:false, color }, ...prev].slice(0,20));
  }, []);
  const markRead = useCallback((id) => setNotifs(prev => prev.map(n => n.id===id?{...n,read:true}:n)), []);
  const markAllRead = useCallback(() => setNotifs(prev => prev.map(n=>({...n,read:true}))), []);
  const unread = notifs.filter(n=>!n.read).length;
  return (
    <NotifContext.Provider value={{notifs,addNotif,markRead,markAllRead,unread}}>
      {children}
    </NotifContext.Provider>
  );
}
const useNotif = () => React.useContext(NotifContext);

function NotifPanel({ open, onClose }) {
  const { notifs, markRead, markAllRead, unread } = useNotif();
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-[9990]" onClick={onClose}>
      <div className="absolute top-14 left-4 w-80 rounded-2xl overflow-hidden shadow-2xl"
        style={{background:"#0D1122",border:"1px solid #1E2A40"}} onClick={e=>e.stopPropagation()}>
        <div className="flex items-center justify-between px-4 py-3 border-b" style={{borderColor:"#1E2A40"}}>
          <span className="text-sm font-black text-white">Notifications</span>
          {unread>0&&<button onClick={markAllRead} className="text-xs" style={{color:"#3B82F6"}}>Mark all read</button>}
        </div>
        <div className="max-h-72 overflow-y-auto">
          {notifs.length===0&&<div className="px-4 py-8 text-center text-sm" style={{color:"#475569"}}>No notifications</div>}
          {notifs.map(n=>(
            <div key={n.id} onClick={()=>markRead(n.id)}
              className="flex items-start gap-3 px-4 py-3 cursor-pointer transition-all hover:bg-white/5"
              style={{background:n.read?"transparent":"rgba(45,107,228,0.04)",borderBottom:"1px solid #1E2A40"}}>
              <div className="w-2 h-2 rounded-full mt-1.5 flex-shrink-0" style={{background:n.read?"#1E2A40":n.color}}/>
              <div className="flex-1 min-w-0">
                <p className="text-xs font-bold" style={{color:n.read?"#64748B":"#F1F5F9"}}>{n.title}</p>
                <p className="text-xs mt-0.5" style={{color:"#475569"}}>{n.sub}</p>
                <p className="text-xs mt-1" style={{color:"#334155"}}>{n.time}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export { NotifProvider, useNotif, NotifPanel };
