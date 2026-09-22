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

import { Card, EmptyState } from "../components/SharedComponents";

// ================================================================
//  MITRE ATT&CK MATRIX
// ================================================================

function MitreMatrix({ api, connected, onExplain }) {
  const [matrix, setMatrix] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!connected) { setLoading(false); return; }
    api.mitreMatrix().then(setMatrix).catch(console.error).finally(()=>setLoading(false));
  }, [api, connected]);

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-black text-white tracking-tight">MITRE ATT&CK Matrix</h1>
        <p className="text-sm mt-1" style={{color:"#64748B"}}>
          {matrix ? `${matrix.total_techniques_detected} technique(s) detected across ${matrix.total_samples_analyzed} analyzed sample(s)` : "Adversary techniques mapped from analyzed samples"}
        </p>
      </div>
      {!connected ? <EmptyState icon={WifiOff} title="Backend not connected"/> :
       loading ? <div className="flex justify-center py-12"><Loader size={20} className="animate-spin" style={{color:"#2D6BE4"}}/></div> :
       !matrix || matrix.total_techniques_detected===0 ? (
        <EmptyState icon={Crosshair} title="No techniques detected yet" sub="Analyze samples to populate the org-wide ATT&CK heatmap"/>
      ) : (
        <div className="grid gap-3" style={{gridTemplateColumns:"repeat(auto-fill, minmax(165px, 1fr))"}}>
          {matrix.matrix.filter(t=>t.techniques.length>0).map(tactic=>(
            <Card key={tactic.tactic_id} className="p-3">
              <p className="text-xs font-black mb-2.5 uppercase tracking-wider" style={{color:"#818CF8"}}>{tactic.tactic_name}</p>
              <div className="space-y-1.5">
                {tactic.techniques.map(t=>(
                  <div key={t.id} className="p-2 rounded-lg relative group" style={{background:"rgba(239,68,68,0.12)",border:"1px solid rgba(239,68,68,0.3)"}}>
                    <div className="flex justify-between items-start">
                      <p className="font-mono mb-0.5" style={{fontSize:9,color:"#F87171"}}>{t.id} ×{t.count}</p>
                      {onExplain && (
                        <button onClick={(e) => { e.stopPropagation(); onExplain("mitre technique", t.id, `Tactic: ${tactic.tactic_name}. Technique: ${t.name}`); }}
                          className="opacity-0 group-hover:opacity-100 transition-opacity p-0.5 hover:bg-white/10 rounded" title="Explain technique">
                          <Brain size={10} className="text-[#A78BFA]"/>
                        </button>
                      )}
                    </div>
                    <p style={{fontSize:10,color:"#FCA5A5"}}>{t.name}</p>
                  </div>
                ))}
              </div>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}


export default MitreMatrix;
