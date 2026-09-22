import React, { useState, useRef, useEffect } from "react";
import {
  Shield, Upload, FileText, AlertTriangle, CheckCircle, Loader,
  Lock, Monitor, HardDrive, Cpu, Zap, ChevronRight
} from "lucide-react";
import { Card } from "../components/SharedComponents";

// ================================================================
//  FILE UPLOAD — Premium v2
// ================================================================

const FILE_TYPES = [
  { label:"Windows PE",  desc:"EXE, DLL, MSI — Full PE parsing",    icon:Monitor,   color:"#2D6BE4" },
  { label:"Documents",   desc:"PDF, DOCX, XLSX — IOC extraction",   icon:FileText,  color:"#F97316" },
  { label:"Scripts",     desc:"PY, JS, PS1, VBS — YARA scanning",  icon:Cpu,       color:"#EAB308" },
  { label:"Android APK", desc:"APK, AAB — Sandbox + IOC",           icon:HardDrive, color:"#22C55E" },
];

const PIPELINE_STEPS = [
  { icon:"🔐", label:"Cryptographic Hashes",     sub:"MD5 · SHA-1 · SHA-256 · SSDeep" },
  { icon:"🔬", label:"PE Structure Parsing",     sub:"Headers · imports · sections · resources" },
  { icon:"⚡", label:"YARA Detection Engine",    sub:"1000+ curated malware signatures" },
  { icon:"🌐", label:"IOC Extraction",           sub:"IPs · domains · URLs · registry keys" },
  { icon:"🗺️", label:"MITRE ATT&CK Mapping",    sub:"Tactic & technique identification" },
  { icon:"🤖", label:"AI Risk Scoring",          sub:"0–100 composite threat score" },
];

/* File type icon chip */
function FileTypeChip({ ext, size }) {
  const kb = Math.round(size / 1024);
  const color = ext.match(/exe|dll|msi/i) ? "#2D6BE4"
    : ext.match(/pdf|doc/i) ? "#F97316"
    : ext.match(/py|js|ps1/i) ? "#EAB308"
    : ext.match(/apk/i) ? "#22C55E"
    : "#818CF8";

  return (
    <div className="flex items-center gap-3 px-4 py-3 rounded-xl mt-4 animate-fade-in" style={{
      background:"rgba(255,255,255,0.03)", border:"1px solid rgba(255,255,255,0.08)"
    }}>
      <div className="w-10 h-10 rounded-xl flex items-center justify-center font-black text-sm" style={{background:`${color}20`, color}}>
        .{ext.toUpperCase()}
      </div>
      <div>
        <p className="text-sm font-bold text-white">{ext.toUpperCase()} File</p>
        <p className="text-xs" style={{color:"#64748B"}}>{kb < 1024 ? `${kb} KB` : `${(kb/1024).toFixed(1)} MB`} · Ready to analyze</p>
      </div>
      <ChevronRight size={14} style={{color:"#334155", marginLeft:"auto"}}/>
    </div>
  );
}

/* Animated analysis pipeline */
function AnalysisPipeline({ currentFile, step }) {
  return (
    <div className="flex flex-col items-center justify-center py-12 animate-fade-in">

      {/* Animated shield */}
      <div className="relative mb-8">
        <div className="w-28 h-28 rounded-3xl flex items-center justify-center animate-pulse-glow" style={{
          background:"linear-gradient(135deg, rgba(45,107,228,0.2), rgba(45,107,228,0.08))",
          border:"2px solid rgba(45,107,228,0.5)",
          boxShadow:"0 0 30px rgba(45,107,228,0.25)"
        }}>
          <Shield size={44} style={{color:"#2D6BE4"}}/>
        </div>
        {/* Rotating ring */}
        <div className="absolute inset-0 rounded-3xl border-2 animate-spin-slow" style={{
          borderColor:"transparent",
          borderTopColor:"rgba(45,107,228,0.6)",
          borderRightColor:"rgba(45,107,228,0.3)"
        }}/>
        {/* Scan line */}
        <div className="scan-line" style={{borderRadius:24}}/>
      </div>

      <h2 className="text-xl font-black text-white mb-1">Analyzing Sample</h2>
      <p className="text-sm mb-8 font-mono px-4 py-1.5 rounded-full" style={{color:"#94A3B8", background:"rgba(255,255,255,0.03)"}}>
        {currentFile?.name}
      </p>

      {/* Pipeline steps */}
      <div className="w-full max-w-sm space-y-2">
        {PIPELINE_STEPS.map((s, i) => (
          <div key={i} className="flex items-center gap-3 px-3 py-2.5 rounded-xl transition-all" style={{
            background: i < step ? "rgba(34,197,94,0.06)" : i === step ? "rgba(45,107,228,0.1)" : "rgba(255,255,255,0.02)",
            border: `1px solid ${i < step ? "rgba(34,197,94,0.2)" : i === step ? "rgba(45,107,228,0.3)" : "rgba(255,255,255,0.04)"}`,
          }}>
            <span style={{fontSize:14}}>{s.icon}</span>
            <div className="flex-1">
              <p className="text-xs font-bold" style={{color: i < step ? "#22C55E" : i === step ? "#F1F5F9" : "#334155"}}>
                {s.label}
              </p>
              <p className="text-xs" style={{color:"#334155"}}>{s.sub}</p>
            </div>
            {i < step ? (
              <CheckCircle size={14} style={{color:"#22C55E", flexShrink:0}}/>
            ) : i === step ? (
              <Loader size={14} style={{color:"#2D6BE4", flexShrink:0}} className="animate-spin"/>
            ) : (
              <div className="w-3.5 h-3.5 rounded-full border flex-shrink-0" style={{borderColor:"#1E2A40"}}/>
            )}
          </div>
        ))}
      </div>

      {/* Progress bar */}
      <div className="w-full max-w-sm mt-5 h-1 rounded-full" style={{background:"#0D1122"}}>
        <div className="h-full rounded-full transition-all progress-bar-animated" style={{
          width:`${Math.round((step / PIPELINE_STEPS.length) * 100)}%`,
          background:"linear-gradient(90deg, #2D6BE4, #818CF8)"
        }}/>
      </div>
      <p className="text-xs mt-2" style={{color:"#334155"}}>{Math.round((step / PIPELINE_STEPS.length) * 100)}% complete</p>
    </div>
  );
}

function FileUploader({ onFile, analyzing, currentFile, error, enableSandbox, setEnableSandbox }) {
  const [drag, setDrag] = useState(false);
  const [step, setStep] = useState(0);
  const [hoveredFile, setHoveredFile] = useState(null);
  const ref = useRef(null);

  useEffect(() => {
    if (!analyzing) { setStep(0); return; }
    const iv = setInterval(() => setStep(p => Math.min(p + 1, PIPELINE_STEPS.length - 1)), 480);
    return () => clearInterval(iv);
  }, [analyzing]);

  const handleDrop = (e) => {
    e.preventDefault();
    setDrag(false);
    const f = e.dataTransfer.files[0];
    if (f) onFile(f);
  };

  const handleChange = (e) => {
    const f = e.target.files?.[0];
    if (f) onFile(f);
  };

  if (analyzing) {
    return <AnalysisPipeline currentFile={currentFile} step={step}/>;
  }

  return (
    <div className="space-y-5 animate-fade-in">

      {/* Header */}
      <div>
        <h1 className="text-2xl font-black text-white tracking-tight flex items-center gap-2">
          <div className="p-1.5 rounded-xl" style={{background:"rgba(45,107,228,0.15)", border:"1px solid rgba(45,107,228,0.3)"}}>
            <Upload size={18} style={{color:"#2D6BE4"}}/>
          </div>
          Submit Sample for Analysis
        </h1>
        <p className="text-sm mt-1.5" style={{color:"#64748B"}}>
          Static analysis pipeline — hashing, PE parsing, YARA, IOC extraction, MITRE ATT&CK mapping
        </p>
      </div>

      {/* Error */}
      {error && (
        <div className="flex items-center gap-2 px-3 py-2.5 rounded-xl animate-fade-in"
          style={{background:"rgba(239,68,68,0.08)", border:"1px solid rgba(239,68,68,0.3)"}}>
          <AlertTriangle size={14} style={{color:"#EF4444"}}/>
          <span className="text-xs" style={{color:"#FCA5A5"}}>{error}</span>
        </div>
      )}

      {/* Drop Zone */}
      <div
        className={drag ? "drag-active" : ""}
        style={{
          borderRadius:20,
          border:`2px dashed ${drag ? "#2D6BE4" : "#1E2A40"}`,
          background: drag ? "rgba(45,107,228,0.08)" : "linear-gradient(135deg, rgba(255,255,255,0.03), rgba(255,255,255,0.01))",
          minHeight:240,
          display:"flex",
          flexDirection:"column",
          alignItems:"center",
          justifyContent:"center",
          cursor:"pointer",
          transition:"all 0.25s ease",
          position:"relative",
          overflow:"hidden"
        }}
        onDragOver={e=>{e.preventDefault();setDrag(true);}}
        onDragLeave={()=>setDrag(false)}
        onDrop={handleDrop}
        onClick={()=>ref.current?.click()}
      >
        {/* Background hex pattern */}
        <div className="absolute inset-0 pointer-events-none opacity-30" style={{
          backgroundImage:"radial-gradient(rgba(45,107,228,0.15) 1px, transparent 1px)",
          backgroundSize:"24px 24px"
        }}/>

        <div className="relative z-10 flex flex-col items-center text-center px-8">
          <div className="relative mb-5">
            <div className="p-5 rounded-3xl" style={{
              background: drag ? "rgba(45,107,228,0.25)" : "rgba(45,107,228,0.1)",
              border:`1px solid ${drag ? "rgba(45,107,228,0.6)" : "rgba(45,107,228,0.2)"}`,
              transition:"all 0.25s ease"
            }}>
              <Upload size={38} style={{color:"#2D6BE4"}}/>
            </div>
            {drag && (
              <div className="absolute inset-0 rounded-3xl animate-ping opacity-30" style={{background:"#2D6BE4"}}/>
            )}
          </div>

          <p className="text-lg font-black text-white mb-1">
            {drag ? "Release to analyze" : "Drop file here"}
          </p>
          <p className="text-sm" style={{color:"#475569"}}>
            or <span className="underline" style={{color:"#2D6BE4"}}>click to browse</span>
          </p>
          <p className="text-xs mt-2" style={{color:"#334155"}}>
            Any format · Max 500 MB · Completely static analysis
          </p>
        </div>
        <input ref={ref} type="file" className="hidden" onChange={handleChange}/>
      </div>

      {/* Supported Types */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
        {FILE_TYPES.map(t=>(
          <div key={t.label}
            className="p-3 rounded-xl cursor-pointer transition-all hover:brightness-110"
            style={{background:`${t.color}08`, border:`1px solid ${t.color}20`}}
            onMouseEnter={()=>setHoveredFile(t.label)}
            onMouseLeave={()=>setHoveredFile(null)}>
            <div className="p-1.5 rounded-lg w-fit mb-2" style={{background:`${t.color}20`}}>
              <t.icon size={13} style={{color:t.color}}/>
            </div>
            <p className="text-xs font-bold text-white">{t.label}</p>
            <p className="text-xs mt-0.5" style={{color:"#475569"}}>{t.desc}</p>
          </div>
        ))}
      </div>

      {/* Pipeline Preview */}
      <div className="p-4 rounded-xl" style={{background:"#070E1B", border:"1px solid #1A2540"}}>
        <p className="text-xs font-black text-white mb-3 flex items-center gap-2">
          <Zap size={11} style={{color:"#F97316"}}/> Analysis Pipeline
        </p>
        <div className="flex items-center gap-1 flex-wrap">
          {PIPELINE_STEPS.map((s, i) => (
            <React.Fragment key={i}>
              <span className="text-xs px-2.5 py-1 rounded-full font-semibold" style={{background:"rgba(255,255,255,0.05)",color:"#64748B"}}>
                {s.icon} {s.label}
              </span>
              {i < PIPELINE_STEPS.length - 1 && (
                <ChevronRight size={10} style={{color:"#1E2A40", flexShrink:0}}/>
              )}
            </React.Fragment>
          ))}
        </div>
      </div>

      {/* Security note */}
      <div className="flex items-start gap-3 px-4 py-3 rounded-xl" style={{background:"rgba(34,197,94,0.05)", border:"1px solid rgba(34,197,94,0.15)"}}>
        <Lock size={13} style={{color:"#22C55E", flexShrink:0, marginTop:1}}/>
        <div>
          <p className="text-xs font-bold text-white">Static Analysis Only — No Execution</p>
          <p className="text-xs mt-0.5" style={{color:"#475569"}}>
            Files are never executed. Analysis uses hashing, PE parsing, YARA, and string extraction only.
            Use Virtual Environment for dynamic sandbox analysis.
          </p>
        </div>
      </div>
    </div>
  );
}


export default FileUploader;
