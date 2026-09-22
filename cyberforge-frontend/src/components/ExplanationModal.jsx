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
//  EXPLANATION MODAL
// ================================================================

function ExplanationModal({ open, onClose, loading, data, error }) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="bg-[#0D1122] border border-[#1E2A40] rounded-2xl w-full max-w-lg overflow-hidden shadow-2xl flex flex-col max-h-[85vh]">
        <div className="flex items-center justify-between p-4 border-b border-[#1E2A40]">
          <div className="flex items-center gap-2 text-white font-black">
            <Brain size={18} className="text-[#7C3AED]"/> Threat Context Briefing
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-white transition-colors"><X size={18}/></button>
        </div>
        <div className="p-6 overflow-y-auto">
          {loading ? (
             <div className="space-y-4">
               <div className="skeleton-box h-4 w-3/4 rounded"></div>
               <div className="skeleton-box h-4 w-full rounded"></div>
               <div className="skeleton-box h-4 w-5/6 rounded"></div>
               <div className="skeleton-box h-4 w-1/2 rounded mt-8"></div>
               <div className="skeleton-box h-4 w-full rounded"></div>
               <div className="flex items-center gap-2 mt-6 text-[#7C3AED] text-sm font-bold">
                 <Loader className="animate-spin" size={14}/> CIPHER is analyzing context...
               </div>
             </div>
          ) : error ? (
             <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-xl flex gap-3 text-red-400 text-sm">
               <AlertTriangle size={16} className="shrink-0 mt-0.5"/>
               <span>{error}</span>
             </div>
          ) : (
             <div className="text-sm text-slate-300 leading-relaxed whitespace-pre-wrap" 
                  dangerouslySetInnerHTML={{__html: data?.replace(/\*\*(.*?)\*\*/g, '<strong class="text-white">$1</strong>')}} />
          )}
        </div>
      </div>
    </div>
  );
}

export default ExplanationModal;
