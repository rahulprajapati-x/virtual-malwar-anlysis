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

import { Card, Badge, EmptyState } from "../components/SharedComponents";
import { scoreToThreat, sevColor, fmtBytes } from "../utils/helpers";
import { useCountUp } from "../hooks/useBackend";


// ================================================================
//  DASHBOARD  — Premium v3
// ================================================================

/* Live Threat Ticker */
function ThreatTicker({ samples }) {
  if (!samples || samples.length === 0) return null;
  const items = [...samples, ...samples];
  return (
    <div className="overflow-hidden relative" style={{height:32, background:"rgba(239,68,68,0.06)", border:"1px solid rgba(239,68,68,0.15)", borderRadius:8}}>
      <div className="ticker-content flex items-center gap-6 h-full" style={{paddingLeft:"100%"}}>
        {items.map((s, i) => {
          const t = scoreToThreat(s.risk_score);
          return (
            <span key={i} className="flex items-center gap-2 text-xs flex-shrink-0" style={{color:"#94A3B8"}}>
              <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{background:t.color}}/>
              <span className="font-mono" style={{color:"#CBD5E1"}}>{s.filename}</span>
              <span className="font-black px-1.5 py-0.5 rounded" style={{background:t.bg, color:t.color}}>{t.label}</span>
              <span style={{color:"#334155"}}>·</span>
              <span style={{color:"#475569"}}>{s.risk_score}/100</span>
            </span>
          );
        })}
      </div>
      <div className="absolute left-0 top-0 bottom-0 w-12 pointer-events-none" style={{background:"linear-gradient(90deg,#060A18,transparent)"}}/>
      <div className="absolute right-0 top-0 bottom-0 w-12 pointer-events-none" style={{background:"linear-gradient(-90deg,#060A18,transparent)"}}/>
    </div>
  );
}

function HealthPill({ label, ok }) {
  return (
    <div className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg" style={{
      background: ok ? "rgba(34,197,94,0.08)" : "rgba(100,116,139,0.08)",
      border: `1px solid ${ok ? "rgba(34,197,94,0.2)" : "rgba(100,116,139,0.18)"}`,
    }}>
      <span className="live-dot w-1.5 h-1.5 rounded-full" style={{background: ok ? "#22C55E" : "#475569"}}/>
      <span className="text-xs font-semibold" style={{color: ok ? "#86EFAC" : "#64748B"}}>{label}</span>
    </div>
  );
}

function StatCard({ label, value, sub, icon: Icon, color, loading, trend }) {
  const numVal = parseInt(String(value).replace(/,/g, ""), 10) || 0;
  const animated = useCountUp(loading ? 0 : numVal, 900);
  return (
    <div className="relative overflow-hidden rounded-2xl p-4 animate-fade-in" style={{
      background: "linear-gradient(135deg, rgba(255,255,255,0.04) 0%, rgba(255,255,255,0.01) 100%)",
      border: `1px solid ${color}25`,
      boxShadow: `0 4px 24px rgba(0,0,0,0.3), inset 0 1px 0 rgba(255,255,255,0.05)`,
    }}>
      <div className="absolute top-0 right-0 w-24 h-24 rounded-full pointer-events-none" style={{background:`radial-gradient(circle at 80% 20%, ${color}18 0%, transparent 70%)`}}/>
      <div className="relative z-10">
        <div className="flex items-start justify-between mb-3">
          <p className="text-xs font-bold uppercase tracking-widest" style={{color:"#475569"}}>{label}</p>
          <div className="p-2 rounded-xl" style={{background:`${color}15`, border:`1px solid ${color}25`}}>
            <Icon size={15} style={{color}}/>
          </div>
        </div>
        {loading ? (
          <div className="skeleton-box h-9 w-24 rounded-lg"/>
        ) : (
          <p className="text-3xl font-black text-white count-up tracking-tight" key={numVal}>
            {animated.toLocaleString()}
          </p>
        )}
        <div className="flex items-center gap-1.5 mt-1.5">
          {trend > 0 && <TrendingUp size={11} style={{color:"#22C55E"}}/>}
          <p className="text-xs font-semibold" style={{color: trend > 0 ? "#22C55E" : "#475569"}}>{sub}</p>
        </div>
      </div>
      <div className="absolute bottom-0 left-0 right-0 h-0.5 opacity-60" style={{background:`linear-gradient(90deg, transparent, ${color}, transparent)`}}/>
    </div>
  );
}

function Dashboard({ api, connected, onAnalyze, onNavigate }) {
  const [stats, setStats] = useState(null);
  const [weekly, setWeekly] = useState([]);
  const [families, setFamilies] = useState([]);
  const [cases, setCases] = useState([]);
  const [recentSamples, setRecentSamples] = useState([]);
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState(null);
  const [health, setHealth] = useState(null);

  const load = useCallback(async () => {
    if (!connected) { setLoading(false); return; }
    setLoading(true);
    try {
      const [s, w, f, c, h] = await Promise.all([
        api.dashboardStats(), api.weeklyActivity(), api.threatFamilies(),
        api.listCases(),
        api.health().catch(() => null),
      ]);
      setStats(s); setWeekly(w); setFamilies(f); setCases(c); setHealth(h);
      try {
        const recent = await api.listSamples("?limit=8&sort=desc");
        setRecentSamples(Array.isArray(recent) ? recent : []);
      } catch {}
      setLastRefresh(new Date());
    } catch (e) { console.error(e); }
    finally { setLoading(false); }
  }, [api, connected]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    if (!connected) return;
    const iv = setInterval(load, 30000);
    return () => clearInterval(iv);
  }, [load, connected]);

  const radarData = useMemo(() => {
    const cats = ["Ransomware","Infostealer","C2 Beacon","Persistence","Injection","Packer"];
    return cats.map(cat => ({
      subject: cat,
      count: families.filter(f => f.name.toLowerCase().includes(cat.toLowerCase().split(" ")[0])).reduce((a,b)=>a+b.count,0)
       || Math.max(0, families.length > 0 ? (families[cats.indexOf(cat) % families.length]?.count || 0) : 0),
    }));
  }, [families]);

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-black text-white tracking-tight flex items-center gap-2.5">
            <span className="live-dot w-2.5 h-2.5 rounded-full" style={{background:"#22C55E", boxShadow:"0 0 10px #22C55E"}}/>
            Operations Dashboard
          </h1>
          <p className="text-sm mt-0.5 flex items-center gap-2" style={{color:"#64748B"}}>
            CyberForge Forensics Command
            {lastRefresh && (
              <span className="text-xs px-2 py-0.5 rounded-full" style={{background:"#0D1122",color:"#334155"}}>
                Refreshed {lastRefresh.toLocaleTimeString()}
              </span>
            )}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={load} disabled={loading} className="p-2 rounded-lg transition-all hover:bg-white/5" style={{color:"#475569"}} title="Refresh">
            <RefreshCw size={14} className={loading ? "animate-spin" : ""}/>
          </button>
          <button onClick={onAnalyze} className="btn-primary flex items-center gap-2 px-4 py-2 rounded-xl font-bold text-sm text-white">
            <Upload size={14}/> Analyze Sample
          </button>
        </div>
      </div>

      {/* Live Threat Ticker */}
      {recentSamples.length > 0 && (
        <div>
          <div className="flex items-center gap-2 mb-1.5">
            <Radio size={10} style={{color:"#EF4444"}}/>
            <span className="text-xs font-bold uppercase tracking-widest" style={{color:"#EF4444"}}>Live Threat Feed</span>
          </div>
          <ThreatTicker samples={recentSamples}/>
        </div>
      )}

      {/* System Health */}
      {health && (
        <div className="flex items-center gap-2 flex-wrap p-3 rounded-xl" style={{background:"#070E1B", border:"1px solid #1E2A40"}}>
          <Server size={12} style={{color:"#22C55E"}}/>
          <span className="text-xs font-black text-white mr-1">System Status</span>
          <HealthPill label="API Online" ok={true}/>
          <HealthPill label={`YARA ${health.yara_engine === "ready" ? "Ready" : "Offline"}`} ok={health.yara_engine === "ready"}/>
          <HealthPill label={`VirusTotal ${health.virustotal_configured ? "✓" : "—"}`} ok={health.virustotal_configured}/>
          <HealthPill label={`AbuseIPDB ${health.abuseipdb_configured ? "✓" : "—"}`} ok={health.abuseipdb_configured}/>
          <HealthPill label={`DB ${health.database === "connected" ? "Connected" : "Offline"}`} ok={health.database === "connected"}/>
        </div>
      )}

      {!connected ? (
        <div className="flex flex-col items-center justify-center py-20">
          <WifiOff size={36} style={{color:"#1E2A40"}} className="mb-4"/>
          <p className="font-bold text-white mb-1">Backend not connected</p>
          <p className="text-sm" style={{color:"#475569"}}>Connect to your CyberForge API to see live statistics</p>
        </div>
      ) : loading ? (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          {[1,2,3,4].map(i => <div key={i} className="skeleton-box h-28 rounded-2xl"/>)}
        </div>
      ) : (
        <>
          {/* Quick Actions */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 stagger">
            {[
              { label:"Upload Sample", icon:Upload,  color:"#2D6BE4", action:()=>onNavigate?.("upload") },
              { label:"Run Sandbox",   icon:Monitor,  color:"#22C55E", action:()=>onNavigate?.("sandbox-env") },
              { label:"Open Case",     icon:Plus,     color:"#F97316", action:()=>onNavigate?.("cases") },
              { label:"CIPHER AI",     icon:Brain,    color:"#7C3AED", action:()=>onNavigate?.("cipher") },
            ].map(qa=>(
              <button key={qa.label} onClick={qa.action}
                className="flex items-center gap-2.5 px-4 py-3 rounded-xl text-sm font-bold transition-all hover:brightness-125 animate-fade-in"
                style={{background:`${qa.color}12`, border:`1px solid ${qa.color}28`}}>
                <div className="p-1.5 rounded-lg" style={{background:`${qa.color}20`}}>
                  <qa.icon size={13} style={{color:qa.color}}/>
                </div>
                <span style={{color:qa.color}}>{qa.label}</span>
              </button>
            ))}
          </div>

          {/* Stat Cards */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 stagger">
            <StatCard label="Files Analyzed" value={stats?.total_files_analyzed||0}
              sub={`+${stats?.files_today||0} today`} icon={FileSearch} color="#3B82F6" loading={loading} trend={stats?.files_today}/>
            <StatCard label="Active Cases" value={stats?.active_cases||0}
              sub="Open investigations" icon={Flag} color="#F97316" loading={loading}/>
            <StatCard label="Threats Found" value={stats?.total_threats_found||0}
              sub={`+${stats?.threats_today||0} today`} icon={AlertTriangle} color="#EF4444" loading={loading} trend={stats?.threats_today}/>
            <StatCard label="IOCs Extracted" value={stats?.total_iocs_extracted||0}
              sub="Across all samples" icon={Target} color="#818CF8" loading={loading}/>
          </div>

          {/* Charts Row */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <Card className="p-4 col-span-2">
              <h3 className="text-sm font-bold text-white mb-4 flex items-center gap-2">
                <Activity size={13} style={{color:"#2D6BE4"}}/> 7-Day Activity
                <span className="ml-auto text-xs" style={{color:"#334155"}}>Files vs Threats</span>
              </h3>
              {weekly.every(w=>w.files===0 && w.threats===0) ? (
                <EmptyState icon={Activity} title="No activity yet" sub="Analyze a sample to see trends"/>
              ) : (
                <ResponsiveContainer width="100%" height={190}>
                  <AreaChart data={weekly}>
                    <defs>
                      <linearGradient id="tg3" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#EF4444" stopOpacity={0.4}/>
                        <stop offset="95%" stopColor="#EF4444" stopOpacity={0}/>
                      </linearGradient>
                      <linearGradient id="fg3" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#2D6BE4" stopOpacity={0.4}/>
                        <stop offset="95%" stopColor="#2D6BE4" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1E2A40" vertical={false}/>
                    <XAxis dataKey="day" tick={{fill:"#475569",fontSize:10}} axisLine={false} tickLine={false}/>
                    <YAxis tick={{fill:"#475569",fontSize:10}} axisLine={false} tickLine={false}/>
                    <Tooltip contentStyle={{background:"#0D1122",border:"1px solid #1E2A40",borderRadius:12,color:"#F1F5F9",fontSize:12,boxShadow:"0 8px 24px rgba(0,0,0,0.4)"}}/>
                    <Area type="monotone" dataKey="threats" stroke="#EF4444" fill="url(#tg3)" strokeWidth={2.5} name="Threats"/>
                    <Area type="monotone" dataKey="files" stroke="#2D6BE4" fill="url(#fg3)" strokeWidth={2.5} name="Files Analyzed"/>
                  </AreaChart>
                </ResponsiveContainer>
              )}
            </Card>
            <Card className="p-4">
              <h3 className="text-sm font-bold text-white mb-4 flex items-center gap-2">
                <RadarIcon size={13} style={{color:"#818CF8"}}/> Threat Categories
              </h3>
              {families.length === 0 ? (
                <EmptyState icon={Bug} title="No detections yet" sub="YARA matches populate this"/>
              ) : (
                <ResponsiveContainer width="100%" height={190}>
                  <RadarChart data={radarData} margin={{top:5,right:20,bottom:5,left:20}}>
                    <PolarGrid stroke="#1E2A40"/>
                    <PolarAngleAxis dataKey="subject" tick={{fill:"#64748B",fontSize:9}}/>
                    <PolarRadiusAxis tick={false} axisLine={false}/>
                    <Radar name="Threats" dataKey="count" stroke="#818CF8" fill="#818CF8" fillOpacity={0.25} strokeWidth={2}/>
                    <Tooltip contentStyle={{background:"#0D1122",border:"1px solid #1E2A40",borderRadius:8,fontSize:12}}/>
                  </RadarChart>
                </ResponsiveContainer>
              )}
            </Card>
          </div>

          {/* Bottom Row */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Card className="p-4">
              <h3 className="text-sm font-bold text-white mb-4 flex items-center gap-2">
                <Bug size={13} style={{color:"#F97316"}}/> Malware Family Breakdown
              </h3>
              {families.length===0 ? (
                <EmptyState icon={Bug} title="No families yet" sub="YARA-matched samples populate this"/>
              ) : (
                <ResponsiveContainer width="100%" height={185}>
                  <BarChart data={families.slice(0,7)} layout="vertical">
                    <CartesianGrid strokeDasharray="3 3" stroke="#1E2A40" vertical={true} horizontal={false}/>
                    <XAxis type="number" tick={{fill:"#475569",fontSize:10}} axisLine={false} tickLine={false}/>
                    <YAxis type="category" dataKey="name" tick={{fill:"#94A3B8",fontSize:10}} axisLine={false} tickLine={false} width={80}/>
                    <Tooltip contentStyle={{background:"#0D1122",border:"1px solid #1E2A40",borderRadius:10,color:"#F1F5F9",fontSize:12}}/>
                    <Bar dataKey="count" radius={[0,5,5,0]} name="Detections">
                      {families.slice(0,7).map((_, i) => {
                        const colors = ["#EF4444","#F97316","#EAB308","#2D6BE4","#818CF8","#22C55E","#06B6D4"];
                        return <rect key={i} fill={colors[i % colors.length]}/>;
                      })}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              )}
            </Card>

            <Card className="p-4">
              <h3 className="text-sm font-bold text-white mb-3 flex items-center gap-2">
                <Radio size={13} style={{color:"#EF4444"}}/> Recent Detections
                <span className="ml-auto flex items-center gap-1.5 text-xs px-2 py-0.5 rounded-full font-black" style={{background:"rgba(239,68,68,0.12)",color:"#EF4444",border:"1px solid rgba(239,68,68,0.25)"}}>
                  <span className="live-dot w-1.5 h-1.5 rounded-full" style={{background:"#EF4444"}}/>LIVE
                </span>
              </h3>
              {recentSamples.length === 0 ? (
                <EmptyState icon={FileSearch} title="No samples yet" sub="Upload a file to see live threat feed"/>
              ) : (
                <div className="space-y-1.5">
                  {recentSamples.slice(0,5).map((s, i) => {
                    const threat = scoreToThreat(s.risk_score);
                    return (
                      <div key={s.id} className="flex items-center gap-3 px-3 py-2.5 rounded-xl animate-fade-in transition-all hover:brightness-110"
                        style={{background:"#0D1122", border:"1px solid #1A2540", animationDelay:`${i*60}ms`}}>
                        <div className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{background:threat.color, boxShadow:`0 0 6px ${threat.color}`}}/>
                        <div className="flex-1 min-w-0">
                          <p className="text-xs font-mono text-white truncate">{s.filename}</p>
                          <p className="text-xs mt-0.5" style={{color:"#475569"}}>
                            {s.file_type_mime || s.file_type || "unknown"} · {fmtBytes(s.file_size)}
                          </p>
                        </div>
                        <span className="text-xs font-black px-2 py-0.5 rounded-lg flex-shrink-0"
                          style={{color:threat.color, background:threat.bg, border:`1px solid ${threat.color}30`}}>
                          {s.risk_score}/100
                        </span>
                      </div>
                    );
                  })}
                </div>
              )}
            </Card>
          </div>

          {/* Active Investigations */}
          <Card className="p-4">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Flag size={13} style={{color:"#F97316"}}/> Active Investigations
              </h3>
              <span className="text-xs px-2.5 py-1 rounded-full font-semibold" style={{background:"rgba(249,115,22,0.1)",color:"#F97316",border:"1px solid rgba(249,115,22,0.2)"}}>
                {cases.filter(c=>c.status==="Active").length} active
              </span>
            </div>
            {cases.length===0 ? (
              <EmptyState icon={Flag} title="No cases yet" sub="Create a case from the Cases tab to start tracking an investigation"/>
            ) : (
              <div className="space-y-2">
                {cases.slice(0,5).map((c,i)=>(
                  <div key={c.id} className="flex items-start gap-3 px-3 py-3 rounded-xl transition-all hover:bg-white/3 animate-fade-in"
                    style={{background:"#0A0F20", border:"1px solid #1A2540", animationDelay:`${i*50}ms`}}>
                    <div className="w-2 h-2 rounded-full mt-1.5 flex-shrink-0" style={{background:sevColor(c.severity), boxShadow:`0 0 8px ${sevColor(c.severity)}`}}/>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-sm font-semibold text-white">{c.name}</span>
                        <Badge label={c.severity} color={sevColor(c.severity)}/>
                        <Badge label={c.status} color={c.status==="Active"?"#2D6BE4":c.status==="Closed"?"#475569":"#F59E0B"}/>
                      </div>
                      <p className="text-xs mt-1" style={{color:"#334155"}}>
                        {c.case_number} · {c.analyst||"Unassigned"} · {c.sample_count} sample(s)
                      </p>
                    </div>
                    <ChevronRight size={14} style={{color:"#334155",flexShrink:0}}/>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </>
      )}
    </div>
  );
}


export default Dashboard;

