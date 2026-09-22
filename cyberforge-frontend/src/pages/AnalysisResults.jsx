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
import HexAnalyzer from "../HexAnalyzer";

import { Card, Badge, EmptyState, ScoreBreakdown, VerdictConflictBanner, AnalysisDepthBadge } from "../components/SharedComponents";
import { scoreToThreat, sevColor, fmtBytes } from "../utils/helpers";
import SandboxTimeline from "./SandboxResults";

// ================================================================
//  ANALYSIS RESULTS (real backend schema)
// ================================================================

function AnalysisResults({ sample, api, onChat, onFileToCase, onSampleUpdate, onExplain }) {
  const [tab, setTab] = useState("overview");
  const [rerunning, setRerunning] = useState(false);
  const data = sample.analysis_data || {};
  const threat = scoreToThreat(sample.risk_score, sample.file_type);
  const pe = data.pe_info;
  const yara = data.yara || {};
  const iocs = data.iocs || {};
  const mitre = data.mitre || [];
  const behaviors = data.behaviors || [];
  const vt = data.virustotal;
  const dyn = data.dynamic || null;
  const analysisDepth = data.analysis_depth || "static";
  // NEW: IP geolocation + domain intel + VT domain verdicts
  const ipGeo = data.ip_geo_results || {};   // { "1.2.3.4": { country, flag, isp, ... } }
  const domainIntel = data.domain_intel || []; // [ { domain, c2_score, risk_level, reasons, is_ddns } ]
  const vtDomainResults = data.vt_domain_results || {}; // { "domain.com": { verdict, detection_ratio, malicious, vt_link } }

  const handleRerunSandbox = async () => {
    if (rerunning) return;
    setRerunning(true);
    try {
      const updated = await api.runSandbox(sample.id);
      if (onSampleUpdate) onSampleUpdate(updated);
      setTab("sandbox");
    } catch (e) {
      console.error("Sandbox re-run failed:", e);
    } finally {
      setRerunning(false);
    }
  };

  const radarData = [
    { subject:"Persistence", A: Math.min(100, (behaviors.filter(b=>b.mitre?.includes("T1547")||b.mitre?.includes("T1543")).length)*35 + sample.risk_score*0.3) },
    { subject:"Evasion",     A: Math.min(100, (pe?.high_entropy_sections||0)*25 + (pe?.packer_detected?30:0) + sample.risk_score*0.25) },
    { subject:"C2/Network",  A: Math.min(100, (iocs.domains?.length||0)*15 + (iocs.ips?.length||0)*10 + sample.risk_score*0.2) },
    { subject:"Credential",  A: Math.min(100, behaviors.filter(b=>b.mitre?.includes("T1003")||b.mitre?.includes("T1555")).length*40 + sample.risk_score*0.15) },
    { subject:"Discovery",   A: Math.min(100, mitre.filter(m=>m.tactic==="Discovery").length*30 + sample.risk_score*0.2) },
    { subject:"Impact",      A: Math.min(100, mitre.filter(m=>m.tactic==="Impact").length*35 + sample.risk_score*0.35) },
  ];

  const hasSandbox = dyn && dyn.sandbox_type !== "unsupported" && dyn.sandbox_type !== "error";

  const tabs = [
    {id:"overview", label:"Overview", icon:Eye},
    {id:"static",   label:"Static",   icon:FileSearch},
    {id:"yara",     label:"YARA",     icon:Target},
    {id:"ioc",      label:"IOCs",     icon:Globe},
    {id:"mitre",    label:"ATT&CK",   icon:Crosshair},
    {id:"behavior", label:"Behavior", icon:Activity},
    {id:"hex",      label:"Hex View", icon:FileCode},
    {id:"sandbox",  label:"Sandbox",  icon:Terminal,
     badge: hasSandbox ? dyn.sandbox_verdict : null,
     badgeColor: hasSandbox ? (dyn.sandbox_verdict==="MALICIOUS" ? "#EF4444" : dyn.sandbox_verdict==="SUSPICIOUS" ? "#F97316" : "#22C55E") : "#64748B"},
  ];

  const iocCount = (iocs.domains?.length||0)+(iocs.ips?.length||0)+(iocs.urls?.length||0)+
    (iocs.registry_keys?.length||0)+(iocs.file_paths?.length||0)+(iocs.mutexes?.length||0)+(iocs.crypto_wallets?.length||0);

  return (
    <div className="space-y-4">
      <Card className="p-4">
        <div className="flex items-start justify-between gap-3 flex-wrap">
          <div className="flex items-start gap-3">
            <div className="p-2.5 rounded-xl" style={{background:threat.bg}}>
              <Bug size={22} style={{color:threat.color}}/>
            </div>
            <div>
              <p className="font-black text-white font-mono text-base">{sample.filename}</p>
              <p className="text-xs mt-0.5" style={{color:"#475569"}}>
                {fmtBytes(sample.file_size)}  •  {sample.file_type}  •  {new Date(sample.analyzed_at || sample.submitted_at).toLocaleString()}
              </p>
              <div className="flex flex-wrap gap-1.5 mt-2">
                <Badge label={`RISK ${sample.risk_score}/100`} color={threat.color}/>
                <Badge label={sample.threat_level} color={threat.color}/>
                {yara.total_matches>0 && <Badge label={`${yara.total_matches} YARA MATCH`} color="#F97316"/>}
                {mitre.length>0 && <Badge label={`${mitre.length} ATT&CK TECH`} color="#818CF8"/>}
                {vt?.found && <Badge label={`VT: ${vt.detection_ratio}`} color={sevColor(vt.verdict)}/>}
                {vt && !vt.found && <Badge label="⚠ UNKNOWN SAMPLE" color="#EAB308"/>}
              </div>
              <div className="mt-2">
                <AnalysisDepthBadge depth={analysisDepth} onRunSandbox={handleRerunSandbox} rerunning={rerunning}/>
              </div>
            </div>
          </div>
          <div className="flex gap-2 flex-shrink-0">
            <button onClick={()=>window.open(api.reportUrl(sample.id), "_blank")}
              className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-bold text-white"
              style={{background:"#22C55E"}}>
              <Download size={13}/> PDF Report
            </button>
            <button onClick={onChat}
              className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-bold text-white"
              style={{background:"#7C3AED"}}>
              <Brain size={13}/> Ask CIPHER
            </button>
          </div>
        </div>

        <div className="mt-4 space-y-1.5">
          {[
            {label:"SHA-256", value:sample.sha256},
            {label:"MD5",     value:sample.md5},
            {label:"SHA-1",   value:sample.sha1},
          ].map(h=>(
            <div key={h.label} className="flex items-center gap-3 p-2 rounded-lg" style={{background:"#0D1122"}}>
              <span className="text-xs font-bold w-14 flex-shrink-0" style={{color:"#475569"}}>{h.label}</span>
              <code className="text-xs font-mono text-white truncate">{h.value || "—"}</code>
            </div>
          ))}
        </div>

        {!sample.case_id && (
          <button onClick={onFileToCase}
            className="mt-3 flex items-center gap-2 text-xs font-bold px-3 py-1.5 rounded-lg"
            style={{background:"#1E2A40",color:"#94A3B8"}}>
            <Folder size={12}/> File this sample into a case
          </button>
        )}
      </Card>

      <div className="flex gap-1.5 overflow-x-auto pb-1">
        {tabs.map(t=>(
          <button key={t.id} onClick={()=>setTab(t.id)}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-bold flex-shrink-0 transition-all"
            style={{
              background: tab===t.id ? (t.id==="sandbox" ? "rgba(239,68,68,0.18)" : "#2D6BE4") : "#111827",
              color: tab===t.id ? (t.id==="sandbox" ? "#EF4444" : "white") : "#64748B",
              border:`1px solid ${tab===t.id ? (t.id==="sandbox" ? "rgba(239,68,68,0.5)" : "#2D6BE4") : "#1E2A40"}`,
            }}>
            <t.icon size={11}/> {t.label}
            {t.badge && (
              <span className="text-xs font-black px-1 py-0.5 rounded ml-0.5"
                style={{background:`${t.badgeColor}22`, color:t.badgeColor, fontSize:8}}>
                {t.badge}
              </span>
            )}
          </button>
        ))}
      </div>

      {tab==="overview" && (
        <div className="space-y-4">
          {/* Verdict Conflict Banner — shown at the top when conflict detected */}
          <VerdictConflictBanner sample={sample}/>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Card className="p-4">
              <h3 className="text-sm font-bold text-white mb-4">Threat DNA Profile</h3>
              <ResponsiveContainer width="100%" height={210}>
                <RadarChart data={radarData} cx="50%" cy="50%">
                  <PolarGrid stroke="#1E2A40"/>
                  <PolarAngleAxis dataKey="subject" tick={{fill:"#64748B",fontSize:10}}/>
                  <PolarRadiusAxis angle={30} domain={[0,100]} tick={false} axisLine={false}/>
                  <Radar dataKey="A" stroke={threat.color} fill={threat.color} fillOpacity={0.22} strokeWidth={2}/>
                </RadarChart>
              </ResponsiveContainer>
            </Card>
            <div className="space-y-3">
              <Card className="p-4">
                <div className="space-y-1.5">
                  <div className="flex justify-between text-xs" style={{color:"#64748B"}}>
                    <span>Risk Score</span><span className="font-black text-base" style={{color:threat.color}}>{sample.risk_score}/100</span>
                  </div>
                  <div className="h-2.5 rounded-full" style={{background:"#1E2A40"}}>
                    <div className="h-2.5 rounded-full" style={{width:`${sample.risk_score}%`,background:`linear-gradient(90deg, ${threat.color}80, ${threat.color})`}}/>
                  </div>
                  {/* Show both scores when dynamic ran */}
                  {data.static_score !== undefined && analysisDepth === "static+dynamic" && (
                    <div className="flex items-center justify-between text-xs mt-1">
                      <span style={{color:"#3B82F6"}}>🔬 Static: {data.static_score}/100 ({data.static_threat_level})</span>
                      <span style={{color:"#F97316"}}>⚡ Dynamic: merged into {sample.risk_score}/100</span>
                    </div>
                  )}
                </div>
              </Card>
              <Card className="p-4">
                <h3 className="text-sm font-bold text-white mb-3">IOC Summary ({iocCount})</h3>
                {[
                  {key:"domains",label:"C2 Domains",color:"#818CF8"},{key:"ips",label:"Malicious IPs",color:"#2D6BE4"},
                  {key:"urls",label:"URLs",color:"#F97316"},{key:"registry_keys",label:"Registry Keys",color:"#EAB308"},
                  {key:"file_paths",label:"File Drops",color:"#22C55E"},{key:"mutexes",label:"Mutexes",color:"#EF4444"},
                  {key:"crypto_wallets",label:"Crypto Wallets",color:"#F97316"},
                ].map(item=>(
                  <div key={item.key} className="flex items-center justify-between py-1.5" style={{borderBottom:"1px solid #1E2A40"}}>
                    <span className="text-xs" style={{color:"#94A3B8"}}>{item.label}</span>
                    <span className="text-xs font-black" style={{color:(iocs[item.key]?.length>0)?item.color:"#2D3748"}}>{iocs[item.key]?.length||0}</span>
                  </div>
                ))}
              </Card>
              {vt?.found && (
                <Card className="p-4">
                  <h3 className="text-sm font-bold text-white mb-2">VirusTotal</h3>
                  <p className="text-xs" style={{color:"#94A3B8"}}>Detection: <b style={{color:sevColor(vt.verdict)}}>{vt.detection_ratio}</b> engines ({vt.verdict})</p>
                  {vt.threat_names?.length>0 && <p className="text-xs mt-1" style={{color:"#475569"}}>Known as: {vt.threat_names.slice(0,3).join(", ")}</p>}
                </Card>
              )}
              {vt && !vt.found && (
                <Card className="p-3 flex items-center gap-2" style={{borderColor:"rgba(234,179,8,0.4)"}}>
                  <AlertTriangle size={14} style={{color:"#EAB308"}}/>
                  <div>
                    <p className="text-xs font-bold" style={{color:"#EAB308"}}>⚠ Unknown Sample — Not in VirusTotal</p>
                    <p className="text-xs mt-0.5" style={{color:"#64748B"}}>Hash not found. May be new/modified malware or zero-day. Treat as SUSPICIOUS.</p>
                  </div>
                </Card>
              )}
            </div>
          </div>

          {/* Score Breakdown */}
          <ScoreBreakdown
            breakdown={data.score_breakdown}
            staticScore={data.static_score ?? sample.risk_score}
            finalScore={sample.risk_score}
            analysisDepth={analysisDepth}
          />
        </div>
      )}

      {tab==="static" && (
        <div className="space-y-4">
          {!pe ? (
            <EmptyState icon={FileSearch} title="No PE data" sub="Static PE parsing only applies to Windows executables (EXE/DLL/MSI)"/>
          ) : (
            <>
              <Card className="p-4">
                <h3 className="text-sm font-bold text-white mb-3">PE Header</h3>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  {[["Machine",pe.machine_type_desc],["Subsystem",pe.subsystem],["Entry Point",pe.entry_point],
                    ["Compile Time",pe.compile_time],["Sections",pe.number_of_sections],["Import Hash",pe.import_hash||"—"]].map(([k,v])=>(
                    <div key={k} className="p-2 rounded-lg" style={{background:"#0D1122"}}>
                      <p style={{color:"#475569"}}>{k}</p><p className="text-white font-mono mt-0.5 truncate">{v}</p>
                    </div>
                  ))}
                </div>
                {pe.packer_detected && (
                  <div className="mt-3"><Badge label={`PACKER: ${pe.packer_detected}`} color="#F97316"/></div>
                )}
              </Card>

              <Card className="p-4">
                <h3 className="text-sm font-bold text-white mb-3">PE Sections</h3>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead><tr style={{color:"#475569"}}>
                      <th className="text-left pb-2 pr-4">Section</th><th className="text-left pb-2 pr-4">Size</th>
                      <th className="text-left pb-2 pr-4">Entropy</th><th className="text-left pb-2 pr-4">Perms</th><th className="text-left pb-2">Flag</th>
                    </tr></thead>
                    <tbody>
                      {pe.sections.map(s=>(
                        <tr key={s.name} style={{borderTop:"1px solid #1E2A40"}}>
                          <td className="py-2 pr-4 font-mono text-white">{s.name}</td>
                          <td className="py-2 pr-4" style={{color:"#94A3B8"}}>{s.raw_size.toLocaleString()} B</td>
                          <td className="py-2 pr-4"><span style={{color:s.entropy>7.5?"#EF4444":s.entropy>6.5?"#F97316":"#22C55E"}}>{s.entropy}</span></td>
                          <td className="py-2 pr-4 font-mono" style={{color:"#94A3B8"}}>{s.permissions}</td>
                          <td className="py-2">{s.suspicious ? <Badge label="⚠ SUSPICIOUS" color="#EF4444"/> : <Badge label="OK" color="#22C55E"/>}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Card>

              {pe.imports?.length>0 && (
                <Card className="p-4">
                  <h3 className="text-sm font-bold text-white mb-3">Import Table</h3>
                  <div className="space-y-4">
                    {pe.imports.slice(0,8).map(imp=>(
                      <div key={imp.dll}>
                        <p className="text-xs font-bold mb-2" style={{color:imp.suspicious_count>0?"#F97316":"#64748B"}}>
                          {imp.dll} {imp.suspicious_count>0 && `(${imp.suspicious_count} suspicious)`}
                        </p>
                        <div className="flex flex-wrap gap-1.5">
                          {imp.functions.slice(0,15).map(fn=>(
                            <span key={fn} className="text-xs font-mono px-2 py-0.5 rounded"
                              style={{background: imp.suspicious_functions?.includes(fn)?"rgba(239,68,68,0.15)":"#1E2A40",
                                       color: imp.suspicious_functions?.includes(fn)?"#FCA5A5":"#94A3B8"}}>{fn}</span>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </Card>
              )}

              {pe.interesting_strings?.length>0 && (
                <Card className="p-4">
                  <h3 className="text-sm font-bold text-white mb-3">Interesting Strings</h3>
                  <div className="space-y-2">
                    {pe.interesting_strings.slice(0,15).map((s,i)=>(
                      <code key={i} className="block text-xs p-2.5 rounded-lg font-mono" style={{background:"#0D1122",color:"#F97316"}}>{s}</code>
                    ))}
                  </div>
                </Card>
              )}

              {pe.anomalies?.length>0 && (
                <Card className="p-4">
                  <h3 className="text-sm font-bold text-white mb-3">Anomalies</h3>
                  <div className="space-y-1.5">
                    {pe.anomalies.map((a,i)=>(
                      <p key={i} className="text-xs" style={{color:"#FCA5A5"}}>⚠ {a}</p>
                    ))}
                  </div>
                </Card>
              )}
            </>
          )}
        </div>
      )}

      {tab==="yara" && (
        <div className="space-y-3">
          {!yara.matches?.length ? (
            <Card className="p-10 text-center">
              <CheckCircle size={30} className="mx-auto mb-3" style={{color:"#22C55E"}}/>
              <p className="font-bold text-white">No YARA Signatures Matched</p>
              <p className="text-sm mt-1" style={{color:"#475569"}}>{yara.scanned ? "File did not trigger any known malware rules" : (yara.error || "YARA scan not run")}</p>
            </Card>
          ) : yara.matches.map((y,i)=>(
            <Card key={i} className="p-4">
              <div className="flex items-start justify-between gap-2 mb-3 group">
                <div>
                  <div className="flex items-center gap-2">
                    <code className="font-mono font-black text-white text-sm">{y.rule}</code>
                    {onExplain && (
                      <button onClick={(e) => { e.stopPropagation(); onExplain("YARA rule", y.rule, `Family: ${y.family}`); }}
                        className="opacity-0 group-hover:opacity-100 transition-opacity p-1 hover:bg-[#1E2A40] rounded text-[#A78BFA]" title="Explain YARA rule">
                        <Brain size={12}/>
                      </button>
                    )}
                  </div>
                  <p className="text-xs mt-0.5" style={{color:"#475569"}}>Family: <span style={{color:"#F97316"}}>{y.family}</span></p>
                  {y.description && <p className="text-xs mt-1" style={{color:"#64748B"}}>{y.description}</p>}
                </div>
                <Badge label={y.confidence} color={sevColor(y.confidence)}/>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {(y.hits||[]).map((h,j)=>(
                  <span key={j} className="text-xs font-mono px-2 py-0.5 rounded"
                    style={{background:"rgba(239,68,68,0.1)",color:"#FCA5A5",border:"1px solid rgba(239,68,68,0.2)"}}>{h}</span>
                ))}
              </div>
            </Card>
          ))}
        </div>
      )}

      {tab==="ioc" && (
        <div className="space-y-3">

          {/* ── DDNS / C2 Domain Warning Banner ── */}
          {(iocs.ddns_domains?.length > 0 || domainIntel.filter(d=>d.risk_level==="HIGH").length > 0) && (
            <div className="rounded-xl p-4 flex items-start gap-3" style={{background:"rgba(239,68,68,0.08)",border:"2px solid rgba(239,68,68,0.4)"}}>
              <AlertTriangle size={16} style={{color:"#EF4444",flexShrink:0,marginTop:1}}/>
              <div>
                <p className="text-sm font-black text-white mb-1">⚠ C2 INFRASTRUCTURE DETECTED</p>
                <div className="flex flex-wrap gap-2 mt-1">
                  {iocs.ddns_domains?.slice(0,4).map((d,i)=>(
                    <span key={i} className="text-xs font-mono px-2 py-0.5 rounded" style={{background:"rgba(239,68,68,0.15)",color:"#FCA5A5",border:"1px solid rgba(239,68,68,0.3)"}}>
                      🔴 {d}
                    </span>
                  ))}
                  {domainIntel.filter(d=>d.risk_level==="HIGH" && !iocs.ddns_domains?.includes(d.domain)).slice(0,3).map((d,i)=>(
                    <span key={i} className="text-xs font-mono px-2 py-0.5 rounded" style={{background:"rgba(249,115,22,0.15)",color:"#FCA5A5",border:"1px solid rgba(249,115,22,0.3)"}}>
                      🟠 {d.domain}
                    </span>
                  ))}
                </div>
                <p className="text-xs mt-2" style={{color:"#94A3B8"}}>
                  {iocs.ddns_domains?.length > 0 && `${iocs.ddns_domains.length} Dynamic DNS domain(s) detected — commonly used for C2 to evade static IP blocking. `}
                  These domains are high-priority indicators for threat hunting.
                </p>
              </div>
            </div>
          )}

          {/* ── IP Addresses with Geolocation ── */}
          {(iocs.ips?.length > 0 || iocs.private_ips?.length > 0 || iocs.ip_ports?.length > 0) && (() => {
            const abuseMap = {};
            (data.abuseipdb || []).forEach(r => { if (r?.ip) abuseMap[r.ip] = r; });
            const C2_PORTS = new Set([4444,4445,4446,4447,4448,1234,1337,31337,8080,8443,8888,9090,6666,6667,6668,6669,5555,7777,9999,2222,3333,4443,8444,9001,9030,9050,9051,1080,3128,8118,65535]);
            const ipPortList = iocs.ip_ports || [];
            return (
              <Card className="p-4">
                <div className="flex items-center gap-2 mb-3">
                  <Network size={13} style={{color:"#2D6BE4"}}/>
                  <h3 className="text-sm font-bold text-white">IP Addresses</h3>
                  <span className="ml-auto text-xs px-1.5 py-0.5 rounded font-bold" style={{background:"#2D6BE41A",color:"#2D6BE4"}}>{(iocs.ips?.length||0) + (iocs.private_ips?.length||0) + ipPortList.length}</span>
                </div>

                {/* IP:Port C2 Endpoints */}
                {ipPortList.length > 0 && (
                  <div className="mb-3">
                    <p className="text-[10px] font-bold mb-1.5 uppercase tracking-wider" style={{color:"#EF4444"}}>⚠ C2 Endpoints (IP:Port)</p>
                    <div className="space-y-1.5">
                      {ipPortList.map((item,i) => {
                        const port = parseInt(item.split(":")[1] || "0");
                        const isC2Port = C2_PORTS.has(port);
                        return (
                          <div key={i} className="flex items-center justify-between p-2.5 rounded-lg group" style={{background:"rgba(239,68,68,0.08)", border:"1px solid rgba(239,68,68,0.25)"}}>
                            <code className="text-xs font-mono font-bold" style={{color:"#EF4444"}}>{item}</code>
                            <div className="flex items-center gap-1.5">
                              {isC2Port && <span className="text-[9px] font-black px-1.5 py-0.5 rounded" style={{background:"rgba(239,68,68,0.2)",color:"#EF4444",border:"1px solid rgba(239,68,68,0.4)"}}>C2 PORT</span>}
                              {onExplain && <button onClick={() => onExplain("C2 Endpoint", item, "Known C2/RAT port — possible command & control server")} className="opacity-0 group-hover:opacity-100 transition-opacity p-1 hover:bg-[#1E2A40] rounded text-[#A78BFA]"><Brain size={12}/></button>}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* Public IPs with Geo + AbuseIPDB enrichment */}
                {iocs.ips?.length > 0 && (
                  <div className="space-y-2">
                    <p className="text-[10px] font-bold mb-2 uppercase tracking-wider" style={{color:"#475569"}}>Public IPs — Geolocation & Threat Intel</p>
                    {(iocs.ips || []).map((ip,i) => {
                      const abuse = abuseMap[ip];
                      const geo = ipGeo[ip];
                      const abuseScore = abuse?.abuse_score || 0;
                      // Determine threat color
                      const isDatacenter = geo?.is_datacenter;
                      const isProxy = geo?.is_proxy;
                      const isMalicious = abuseScore > 50 || (isDatacenter && abuseScore > 10);
                      const isSuspicious = abuseScore > 10 || isProxy || isDatacenter;
                      const borderColor = isMalicious ? "rgba(239,68,68,0.4)" : isSuspicious ? "rgba(249,115,22,0.25)" : "transparent";
                      const ipColor = isMalicious ? "#EF4444" : isSuspicious ? "#F97316" : "#E2E8F0";

                      return (
                        <div key={i} className="rounded-xl p-3 group" style={{background:"#0D1122", border:`1px solid ${borderColor || "#1E2A40"}`}}>
                          {/* Row 1: IP + badges */}
                          <div className="flex items-center justify-between gap-2 mb-1.5">
                            <div className="flex items-center gap-2 flex-wrap">
                              <code className="text-sm font-mono font-bold" style={{color:ipColor}}>{ip}</code>
                              {isDatacenter && (
                                <span className="text-[9px] font-black px-1.5 py-0.5 rounded" style={{background:"rgba(239,68,68,0.15)",color:"#EF4444",border:"1px solid rgba(239,68,68,0.3)"}}>
                                  🏢 DATACENTER
                                </span>
                              )}
                              {isProxy && (
                                <span className="text-[9px] font-black px-1.5 py-0.5 rounded" style={{background:"rgba(249,115,22,0.15)",color:"#F97316",border:"1px solid rgba(249,115,22,0.3)"}}>
                                  🔀 PROXY/VPN
                                </span>
                              )}
                              {abuse && (
                                <span className="text-[9px] font-black px-1.5 py-0.5 rounded" style={{background:isMalicious?"rgba(239,68,68,0.15)":isSuspicious?"rgba(249,115,22,0.15)":"rgba(34,197,94,0.1)",color:isMalicious?"#EF4444":isSuspicious?"#F97316":"#22C55E",border:`1px solid ${isMalicious?"rgba(239,68,68,0.3)":isSuspicious?"rgba(249,115,22,0.3)":"rgba(34,197,94,0.3)"}`}}>
                                  {isMalicious?"MALICIOUS":isSuspicious?"SUSPICIOUS":"CLEAN"} {abuseScore>0?`${abuseScore}%`:""}
                                </span>
                              )}
                            </div>
                            {/* Action buttons */}
                            <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0">
                              <button onClick={() => navigator.clipboard?.writeText(ip)} className="p-1 hover:bg-[#1E2A40] rounded" title="Copy IP"><Copy size={10} style={{color:"#475569"}}/></button>
                              <a href={`https://www.abuseipdb.com/check/${ip}`} target="_blank" rel="noopener noreferrer" className="p-1 hover:bg-[#1E2A40] rounded" title="AbuseIPDB"><ExternalLink size={10} style={{color:"#3B82F6"}}/></a>
                              <a href={`https://shodan.io/host/${ip}`} target="_blank" rel="noopener noreferrer" className="p-1 hover:bg-[#1E2A40] rounded" title="Shodan"><Search size={10} style={{color:"#818CF8"}}/></a>
                              {onExplain && <button onClick={() => onExplain("IP Address", ip, `Geo: ${geo?.country||"Unknown"} ${geo?.isp||""} | AbuseIPDB: ${abuseScore}% | Datacenter: ${isDatacenter?"Yes":"No"}`) } className="p-1 hover:bg-[#1E2A40] rounded text-[#A78BFA]"><Brain size={10}/></button>}
                            </div>
                          </div>
                          {/* Row 2: Geo info */}
                          {geo?.status === "success" && (
                            <div className="flex items-center flex-wrap gap-x-3 gap-y-1">
                              <span className="text-xs" style={{color:"#64748B"}}>
                                {geo.flag} {geo.city ? `${geo.city}, ` : ""}{geo.country}
                              </span>
                              {geo.isp && (
                                <span className="text-xs" style={{color:"#475569"}} title={geo.org}>🏢 {geo.isp.length>35?geo.isp.slice(0,35)+"…":geo.isp}</span>
                              )}
                              {geo.asn && (
                                <span className="text-xs font-mono" style={{color:"#334155"}}>{geo.asn.split(" ")[0]}</span>
                              )}
                              {geo.is_mobile && (
                                <span className="text-[9px] px-1 py-0.5 rounded" style={{background:"rgba(34,197,94,0.1)",color:"#22C55E"}}>📱 MOBILE</span>
                              )}
                            </div>
                          )}
                          {/* Row 3: C2 risk reason */}
                          {geo?.c2_risk === "HIGH" && (
                            <p className="text-[10px] mt-1.5 font-medium" style={{color:"#EF4444"}}>⚠ {geo.c2_reason}</p>
                          )}
                          {geo?.c2_risk === "MEDIUM" && (
                            <p className="text-[10px] mt-1.5 font-medium" style={{color:"#F97316"}}>⚡ {geo.c2_reason}</p>
                          )}
                          {/* AbuseIPDB reports count */}
                          {abuse?.total_reports > 0 && (
                            <p className="text-[10px] mt-1" style={{color:"#475569"}}>
                              📋 {abuse.total_reports} abuse report{abuse.total_reports>1?"s":""} from {abuse.num_reporters} reporter{abuse.num_reporters>1?"s":""}
                              {abuse.last_reported ? ` · Last: ${abuse.last_reported.slice(0,10)}` : ""}
                            </p>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}

                {/* Private IPs */}
                {iocs.private_ips?.length > 0 && (
                  <div className="mt-3">
                    <p className="text-[10px] font-bold mb-1 uppercase tracking-wider" style={{color:"#475569"}}>Internal / Private IPs</p>
                    <div className="space-y-1">
                      {iocs.private_ips.map((ip,i) => (
                        <div key={i} className="flex items-center justify-between p-2 rounded-lg" style={{background:"#0D1122"}}>
                          <code className="text-xs font-mono" style={{color:"#94A3B8"}}>{ip}</code>
                          <span className="text-[9px] px-1.5 py-0.5 rounded" style={{background:"rgba(148,163,184,0.1)",color:"#64748B"}}>PRIVATE</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </Card>
            );
          })()}

          {/* ── Enhanced Domains Section with C2 Risk Scoring ── */}
          {(iocs.domains?.length > 0 || iocs.ddns_domains?.length > 0) && (() => {
            // Build merged domain list with intel
            const domainMap = {};
            domainIntel.forEach(d => { domainMap[d.domain] = d; });
            // Combine: DDNS first (marked), then other domains
            const allDomains = [
              ...(iocs.ddns_domains||[]).map(d => ({domain:d, is_ddns:true, ...(domainMap[d]||{c2_score:70,risk_level:"HIGH",reasons:["Dynamic DNS domain"]}) })),
              ...(iocs.domains||[]).filter(d => !(iocs.ddns_domains||[]).includes(d))
                                   .map(d => ({domain:d, is_ddns:false, ...(domainMap[d]||{c2_score:0,risk_level:"CLEAN",reasons:[]}) })),
            ];
            return (
              <Card className="p-4">
                <div className="flex items-center gap-2 mb-3">
                  <Globe size={13} style={{color:"#818CF8"}}/>
                  <h3 className="text-sm font-bold text-white">C2 / Network Domains</h3>
                  <span className="ml-auto text-xs px-1.5 py-0.5 rounded font-bold" style={{background:"rgba(129,140,248,0.1)",color:"#818CF8"}}>{allDomains.length}</span>
                </div>
                <div className="space-y-2">
                  {allDomains.map((item,i) => {
                    const riskColor = item.risk_level==="HIGH" ? "#EF4444" : item.risk_level==="MEDIUM" ? "#F97316" : item.risk_level==="LOW" ? "#EAB308" : "#64748B";
                    const riskBg = item.risk_level==="HIGH" ? "rgba(239,68,68,0.08)" : item.risk_level==="MEDIUM" ? "rgba(249,115,22,0.06)" : "#0D1122";
                    const borderSt = item.risk_level==="HIGH" ? "1px solid rgba(239,68,68,0.3)" : item.risk_level==="MEDIUM" ? "1px solid rgba(249,115,22,0.2)" : "1px solid #1E2A40";
                    // VT domain verdict (only populated for top HIGH/MEDIUM domains when VT key is set)
                    const vtResult = vtDomainResults[item.domain];
                    const vtVerdict = vtResult?.verdict;
                    const vtVerdictColor = vtVerdict==="MALICIOUS" ? "#EF4444" : vtVerdict==="SUSPICIOUS" ? "#F97316" : vtVerdict==="LOW_RISK" ? "#EAB308" : vtVerdict==="CLEAN" ? "#22C55E" : null;
                    return (
                      <div key={i} className="rounded-xl p-3 group" style={{background:riskBg, border:borderSt}}>
                        <div className="flex items-start justify-between gap-2">
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center flex-wrap gap-1.5 mb-1">
                              <code className="text-xs font-mono break-all" style={{color: item.risk_level==="HIGH"?"#EF4444":item.risk_level==="MEDIUM"?"#F97316":"#E2E8F0"}}>{item.domain}</code>
                              {item.is_ddns && (
                                <span className="text-[9px] font-black px-1.5 py-0.5 rounded flex-shrink-0" style={{background:"rgba(239,68,68,0.2)",color:"#EF4444",border:"1px solid rgba(239,68,68,0.4)"}}>
                                  ⚡ DDNS
                                </span>
                              )}
                              <span className="text-[9px] font-black px-1.5 py-0.5 rounded flex-shrink-0" style={{background:`${riskColor}18`,color:riskColor,border:`1px solid ${riskColor}40`}}>
                                {item.risk_level||"CLEAN"}
                              </span>
                              {(item.c2_score||0) > 0 && (
                                <span className="text-[9px] font-mono px-1.5 py-0.5 rounded flex-shrink-0" style={{color:"#475569",background:"#0D1122"}}>
                                  C2:{item.c2_score}/100
                                </span>
                              )}
                              {/* VT Verdict chip — only shown when VT returned a result */}
                              {vtResult && vtVerdictColor && (
                                <span className="text-[9px] font-black px-1.5 py-0.5 rounded flex-shrink-0"
                                  style={{background:`${vtVerdictColor}18`, color:vtVerdictColor, border:`1px solid ${vtVerdictColor}40`}}
                                  title={`VirusTotal: ${vtResult.detection_ratio || "?"} engines flagged this domain`}>
                                  VT:{vtResult.detection_ratio||"?"} {vtVerdict==="MALICIOUS"?"🔴":vtVerdict==="SUSPICIOUS"?"🟠":vtVerdict==="LOW_RISK"?"🟡":"✓"}
                                </span>
                              )}
                            </div>
                            {/* Risk bar */}
                            {(item.c2_score||0) > 0 && (
                              <div className="h-1 rounded-full mb-1.5 overflow-hidden" style={{background:"#1E2A40",width:"100%"}}>
                                <div className="h-full rounded-full transition-all" style={{width:`${Math.min(item.c2_score||0, 100)}%`, background:riskColor, opacity:0.8}}/>
                              </div>
                            )}
                            {/* VT categories if available */}
                            {vtResult?.categories && Object.keys(vtResult.categories).length > 0 && (
                              <div className="flex flex-wrap gap-1 mb-1">
                                {Object.values(vtResult.categories).slice(0,2).map((cat,ci) => (
                                  <span key={ci} className="text-[9px] px-1.5 py-0.5 rounded" style={{background:"rgba(239,68,68,0.08)",color:"#FCA5A5",border:"1px solid rgba(239,68,68,0.15)"}}>
                                    📂 {cat}
                                  </span>
                                ))}
                              </div>
                            )}
                            {/* Reasons */}
                            {item.reasons?.length > 0 && (
                              <div className="flex flex-wrap gap-1">
                                {item.reasons.slice(0,2).map((r,ri) => (
                                  <span key={ri} className="text-[9px] px-1.5 py-0.5 rounded" style={{background:"#1E2A40",color:"#64748B"}}>{r}</span>
                                ))}
                              </div>
                            )}
                          </div>
                          {/* Action buttons */}
                          <div className="flex flex-col gap-1 opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0">
                            <button onClick={() => navigator.clipboard?.writeText(item.domain)} className="p-1 hover:bg-[#1E2A40] rounded" title="Copy"><Copy size={10} style={{color:"#475569"}}/></button>
                            <a href={vtResult?.vt_link || `https://www.virustotal.com/gui/domain/${item.domain}`} target="_blank" rel="noopener noreferrer" className="p-1 hover:bg-[#1E2A40] rounded" title="VirusTotal"><ExternalLink size={10} style={{color:"#22C55E"}}/></a>
                            {onExplain && <button onClick={() => onExplain("Domain", item.domain, `C2 Score: ${item.c2_score||0}/100. Risk: ${item.risk_level}. VT: ${vtVerdict||"not checked"}. ${(item.reasons||[]).join("; ")}`)} className="p-1 hover:bg-[#1E2A40] rounded text-[#A78BFA]"><Brain size={10}/></button>}
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </Card>
            );
          })()}

          {/* ── C2 Framework Signatures (Grouped by Framework) ── */}
          {iocs.c2_signatures?.length > 0 && (() => {
            // Framework classification rules — ordered by priority
            const FRAMEWORKS = [
              {
                id: "cobalt_strike",
                label: "Cobalt Strike",
                icon: "🎯",
                color: "#EF4444",
                match: s => s.includes("cobalt") || s.includes("beacon") || s.includes("sleep_mask") || s.includes("artifact.kit") || s.includes("csagent") || s.includes("csbeacon"),
              },
              {
                id: "metasploit",
                label: "Metasploit / Meterpreter",
                icon: "💣",
                color: "#F97316",
                match: s => s.includes("meterpreter") || s.includes("metasploit") || s.includes("msfvenom") || s.includes("metsrv") || s.includes("reflectivedll") || s.includes("reflectiveloader") || s.includes("/multi/handler"),
              },
              {
                id: "sliver",
                label: "Sliver C2",
                icon: "⚔️",
                color: "#818CF8",
                match: s => s.includes("sliver"),
              },
              {
                id: "havoc",
                label: "Havoc C2",
                icon: "💀",
                color: "#C026D3",
                match: s => s.includes("havoc") || s.includes("teamserver"),
              },
              {
                id: "brute_ratel",
                label: "Brute Ratel",
                icon: "🐗",
                color: "#DC2626",
                match: s => s.includes("bruteratel") || s.includes("brc4") || s.includes("badger.bin"),
              },
              {
                id: "empire",
                label: "PowerShell Empire / PoshC2",
                icon: "⚡",
                color: "#7C3AED",
                match: s => s.includes("empire") || s.includes("poshc2") || s.includes("implant.ps1"),
              },
              {
                id: "rat",
                label: "Remote Access Trojan (RAT)",
                icon: "🐀",
                color: "#F59E0B",
                match: s => s.includes("njrat") || s.includes("asyncrat") || s.includes("quasar") || s.includes("remcos") || s.includes("darkcomet") || s.includes("nanocore") || s.includes("xworm") || s.includes("dcrat") || s.includes("gh0st"),
              },
              {
                id: "other",
                label: "Other C2 Patterns",
                icon: "🔴",
                color: "#EAB308",
                match: () => true, // catch-all
              },
            ];

            // Bucket sigs into groups
            const groups = {};
            FRAMEWORKS.forEach(fw => { groups[fw.id] = []; });

            iocs.c2_signatures.forEach(sig => {
              const s = sig.toLowerCase();
              for (const fw of FRAMEWORKS) {
                if (fw.match(s)) {
                  groups[fw.id].push(sig);
                  break;
                }
              }
            });

            // Only render groups that have at least 1 match
            const activeGroups = FRAMEWORKS.filter(fw => groups[fw.id].length > 0);

            return (
              <Card className="p-4">
                <div className="flex items-center gap-2 mb-4">
                  <Skull size={13} style={{color:"#EF4444"}}/>
                  <h3 className="text-sm font-bold text-white">C2 Framework Signatures</h3>
                  <span className="ml-auto text-xs px-1.5 py-0.5 rounded font-bold" style={{background:"rgba(239,68,68,0.1)",color:"#EF4444"}}>{iocs.c2_signatures.length}</span>
                </div>
                <div className="space-y-3">
                  {activeGroups.map(fw => {
                    const sigs = groups[fw.id];
                    return (
                      <details key={fw.id} className="group/fw" open={sigs.length <= 5}>
                        <summary className="flex items-center gap-2 cursor-pointer select-none list-none p-2 rounded-lg hover:bg-[#111827] transition-colors"
                          style={{background:"rgba(0,0,0,0.2)", border:`1px solid ${fw.color}30`}}>
                          <span className="text-sm">{fw.icon}</span>
                          <span className="text-xs font-black" style={{color: fw.color}}>{fw.label}</span>
                          <span className="text-[9px] font-black px-1.5 py-0.5 rounded ml-1"
                            style={{background:`${fw.color}20`, color:fw.color, border:`1px solid ${fw.color}40`}}>
                            {sigs.length} hit{sigs.length > 1 ? "s" : ""}
                          </span>
                          {/* Expand/collapse chevron indicator */}
                          <span className="ml-auto text-[10px] transition-transform group-open/fw:rotate-180" style={{color:"#475569"}}>▼</span>
                        </summary>
                        <div className="mt-2 space-y-1.5 pl-2">
                          {sigs.map((sig, si) => (
                            <div key={si} className="flex items-center justify-between p-2.5 rounded-lg group/sig"
                              style={{background:`${fw.color}08`, border:`1px solid ${fw.color}20`}}>
                              <div className="flex items-center gap-2 min-w-0">
                                <span className="text-[9px] font-black px-1 py-0.5 rounded flex-shrink-0"
                                  style={{background:`${fw.color}20`, color:fw.color, border:`1px solid ${fw.color}40`, letterSpacing:"0.05em"}}>
                                  {fw.label.split(" ")[0].toUpperCase()}
                                </span>
                                <code className="text-xs font-mono truncate" style={{color:"#94A3B8"}}>{sig}</code>
                              </div>
                              <div className="flex items-center gap-1 opacity-0 group-hover/sig:opacity-100 transition-opacity flex-shrink-0">
                                <button onClick={() => navigator.clipboard?.writeText(sig)} className="p-1 hover:bg-[#1E2A40] rounded" title="Copy signature">
                                  <Copy size={10} style={{color:"#475569"}}/>
                                </button>
                                {onExplain && (
                                  <button onClick={() => onExplain("C2 Framework Signature", sig, `Framework: ${fw.label}`)}
                                    className="p-1 hover:bg-[#1E2A40] rounded text-[#A78BFA]" title="Ask CIPHER">
                                    <Brain size={10}/>
                                  </button>
                                )}
                              </div>
                            </div>
                          ))}
                        </div>
                      </details>
                    );
                  })}
                </div>
              </Card>
            );
          })()}


          {/* Other IOC sections */}
          {[
            {key:"urls",label:"Malicious URLs",icon:Globe,color:"#F97316"},
            {key:"registry_keys",label:"Registry Keys",icon:Key,color:"#EAB308"},
            {key:"file_paths",label:"Dropped Files / Paths",icon:Folder,color:"#22C55E"},
            {key:"mutexes",label:"Mutexes",icon:Lock,color:"#EF4444"},
            {key:"crypto_wallets",label:"Crypto Wallet Addresses",icon:Database,color:"#F97316"},
          ].map(({key,label,icon:Icon,color})=>{
            const items = iocs[key];
            if (!items?.length) return null;
            return (
              <Card key={key} className="p-4">
                <div className="flex items-center gap-2 mb-3">
                  <Icon size={13} style={{color}}/><h3 className="text-sm font-bold text-white">{label}</h3>
                  <span className="ml-auto text-xs px-1.5 py-0.5 rounded font-bold" style={{background:`${color}1A`,color}}>{items.length}</span>
                </div>
                <div className="space-y-1.5">
                  {items.map((item,i)=>(
                    <div key={i} className="flex items-center justify-between p-2.5 rounded-lg group" style={{background:"#0D1122"}}>
                      <code className="text-xs font-mono text-[#E2E8F0] break-all">{item}</code>
                      {onExplain && (
                        <button onClick={() => onExplain("Indicator of Compromise", item, `Category: ${label}`)}
                          className="opacity-0 group-hover:opacity-100 transition-opacity p-1 hover:bg-[#1E2A40] rounded text-[#A78BFA] flex-shrink-0" title="Explain IOC">
                          <Brain size={12}/>
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              </Card>
            );
          })}
          {iocCount===0 && <EmptyState icon={Globe} title="No IOCs Detected" />}
        </div>
      )}

      {tab==="mitre" && (
        <div className="space-y-3">
          {mitre.length===0 ? <EmptyState icon={Crosshair} title="No ATT&CK Techniques Identified"/> : (
            <>
              <Card className="p-3"><p className="text-xs" style={{color:"#64748B"}}>{mitre.length} technique{mitre.length>1?"s":""} mapped from analysis indicators</p></Card>
              {mitre.map((t,i)=>(
                <Card key={i} className="p-3 flex items-start gap-3 group">
                  <div className="p-1.5 rounded-lg flex-shrink-0" style={{background:"rgba(129,140,248,0.12)"}}><Crosshair size={11} style={{color:"#818CF8"}}/></div>
                  <div className="flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <code className="text-xs font-black" style={{color:"#818CF8"}}>{t.id}</code>
                      {onExplain && (
                        <button onClick={() => onExplain("MITRE ATT&CK technique", t.id, `Tactic: ${t.tactic}. Technique: ${t.name}`)}
                          className="opacity-0 group-hover:opacity-100 transition-opacity p-1 hover:bg-[#1E2A40] rounded text-[#A78BFA]" title="Explain Technique">
                          <Brain size={12}/>
                        </button>
                      )}
                      <span className="text-sm font-bold text-white">{t.name}</span>
                      <Badge label={t.confidence} color={sevColor(t.confidence)}/>
                    </div>
                    <p className="text-xs mt-0.5" style={{color:"#475569"}}>Tactic: {t.tactic} • Source: {t.source}</p>
                  </div>
                </Card>
              ))}
            </>
          )}
        </div>
      )}

      {tab==="behavior" && (
        <div className="space-y-3">
          {behaviors.length===0
            ? <EmptyState icon={Activity} title="No notable behaviors flagged"/>
            : behaviors.map((b,i)=>(
              <Card key={i} className="p-4 group"
                style={{borderColor: b.source==="dynamic" ? "rgba(239,68,68,0.2)" : "#1E2A40"}}>
                <div className="flex items-start gap-3">
                  <div className="w-1 rounded-full self-stretch flex-shrink-0"
                    style={{background:sevColor(b.severity),minHeight:20}}/>
                  <div className="flex-1">
                    <div className="flex items-start justify-between">
                      <div className="flex items-center gap-2 mb-1.5 flex-wrap flex-1">
                        <Badge label={b.severity} color={sevColor(b.severity)}/>
                        {b.source === "dynamic"
                          ? <span className="text-xs font-black px-1.5 py-0.5 rounded"
                              style={{background:"rgba(239,68,68,0.12)", color:"#EF4444", fontSize:9, border:"1px solid rgba(239,68,68,0.3)"}}>
                              ⚡ DYNAMIC
                            </span>
                          : <span className="text-xs font-bold px-1.5 py-0.5 rounded"
                              style={{background:"rgba(45,107,228,0.12)", color:"#60A5FA", fontSize:9}}>
                              STATIC
                            </span>}
                        <span className="text-sm font-bold text-white">{b.title}</span>
                        {b.mitre && <span className="text-xs font-mono" style={{color:"#818CF8"}}>{b.mitre}</span>}
                      </div>
                      {onExplain && (
                        <button onClick={() => onExplain("malware behavior", b.title, b.description)}
                          className="opacity-0 group-hover:opacity-100 transition-opacity p-1.5 hover:bg-[#1E2A40] rounded text-[#A78BFA] flex-shrink-0" title="Ask CIPHER for context">
                          <Brain size={14}/>
                        </button>
                      )}
                    </div>
                    <p className="text-xs leading-relaxed mt-1" style={{color:"#94A3B8"}}>{b.description}</p>
                  </div>
                </div>
              </Card>
            ))}
        </div>
      )}

      {tab==="hex" && (
        <HexAnalyzer sample={sample} api={api} onExplain={onExplain} />
      )}

      {tab==="sandbox" && (
        <SandboxTimeline
          dyn={dyn}
          api={api}
          sampleId={sample.id}
          onRerun={handleRerunSandbox}
          rerunning={rerunning}
          sample={sample}
        />
      )}
    </div>
  );
}


export default AnalysisResults;
