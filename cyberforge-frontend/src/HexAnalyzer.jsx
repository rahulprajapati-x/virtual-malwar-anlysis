// ================================================================
//  CYBERFORGE — ADVANCED HEX VIEWER + AI HEX INTELLIGENCE ENGINE
//  Professional-grade binary forensic analysis workstation
//  Features: Minimap · IOC Dashboard · MITRE ATT&CK · Byte Stats
//            Base64/PowerShell Decoder · YARA/Sigma Export
//            Zoom · Fullscreen · Virtual Rendering · Color Coding
// ================================================================

import React, { useState, useCallback, useRef, useEffect, useMemo } from "react";
import {
  Brain, Search, Loader, Flag, Download, Database, ShieldAlert,
  Target, BarChart2, Shield, Lock, Globe, Key, Folder, Zap,
  Terminal, Eye, EyeOff, ChevronDown, ChevronRight, X,
  Maximize2, Minimize2, AlertTriangle, ExternalLink, Copy,
  Info, Activity
} from "lucide-react";
import {
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip,
} from "recharts";


// ─────────────────────────────────────────────────────────────────
//  CONSTANTS
// ─────────────────────────────────────────────────────────────────

/* ── Artifact colour palette ── */
const ART_COLOR = {
  ipv4:"#EF4444", ipv6:"#EF4444", ip_port:"#EF4444", url:"#F97316", domain:"#EF4444",
  email:"#94A3B8", c2_endpoint:"#EF4444", c2_framework:"#DC2626", discord_webhook:"#EC4899",
  telegram_token:"#EC4899", cloud_storage:"#EC4899", registry_key:"#3B82F6",
  windows_path:"#22C55E", linux_path:"#22C55E", named_pipe:"#A78BFA",
  mutex:"#A78BFA", powershell:"#F97316", encoded_powershell:"#F97316",
  cmd_command:"#F97316", base64_blob:"#EAB308", dll_name:"#64748B",
  suspicious_api:"#F59E0B", user_agent:"#64748B", ngrok_tunnel:"#EF4444",
  tor_service:"#A78BFA", ddns_domain:"#EF4444",
  // NEW: Credentials & Secrets
  credential:"#F43F5E", api_key:"#F43F5E", crypto_wallet:"#F59E0B",
  jwt_token:"#F43F5E", ssh_key:"#F43F5E",
};

const ART_ICON = {
  ipv4:"🌐", ipv6:"🌐", ip_port:"🌐", url:"🔗", domain:"🌍", email:"📧",
  c2_endpoint:"☠️", c2_framework:"☠️", discord_webhook:"💜", telegram_token:"📱",
  cloud_storage:"☁️", registry_key:"🔑", windows_path:"📁",
  linux_path:"📁", named_pipe:"🔧", mutex:"🔒", powershell:"⚡",
  encoded_powershell:"⚡", cmd_command:"💻", base64_blob:"🔐",
  dll_name:"📦", suspicious_api:"⚠️", user_agent:"🕵️",
  ngrok_tunnel:"🔴", tor_service:"🧅", ddns_domain:"🔴",
  // NEW
  credential:"🔐", api_key:"🗝️", crypto_wallet:"₿", jwt_token:"🎫", ssh_key:"🔑",
};

const FILTER_TABS = [
  { id:"all",         label:"All" },
  { id:"critical",    label:"🔴 Critical",       types:[], risk:"CRITICAL" },
  { id:"creds",       label:"🔐 Credentials",    types:["credential","api_key","jwt_token","ssh_key"] },
  { id:"c2",          label:"☠️ C2 / IPs",       types:["ipv4","ipv6","ip_port","c2_endpoint","c2_framework","discord_webhook","telegram_token","ngrok_tunnel","tor_service","ddns_domain"] },
  { id:"url",         label:"🔗 URLs / Domains", types:["url","domain","cloud_storage"] },
  { id:"code",        label:"⚡ Code Exec",      types:["powershell","encoded_powershell","cmd_command"] },
  { id:"reg",         label:"🔑 Registry",       types:["registry_key"] },
  { id:"path",        label:"📁 Paths",          types:["windows_path","linux_path","named_pipe"] },
  { id:"b64",         label:"🔐 Base64",         types:["base64_blob"] },
  { id:"api",         label:"⚠️ APIs / DLLs",   types:["dll_name","suspicious_api"] },
  { id:"crypto",      label:"₿ Crypto",          types:["crypto_wallet"] },
  { id:"misc",        label:"Misc",              types:["mutex","email","user_agent"] },
];

/* ── IOC Dashboard categories ── */
const IOC_CATS = [
  { id:"creds",     label:"Credentials / Secrets", icon:"🔐", color:"#F43F5E",  types:["credential","api_key","jwt_token","ssh_key"] },
  { id:"ips",       label:"IP Addresses",     icon:"🌐", color:"#EF4444",  types:["ipv4","ipv6","ip_port"] },
  { id:"urls",      label:"URLs",             icon:"🔗", color:"#F97316",  types:["url"] },
  { id:"domains",   label:"Domains",          icon:"🌍", color:"#EF4444",  types:["domain","ddns_domain"] },
  { id:"c2",        label:"C2 Indicators",    icon:"☠️", color:"#EF4444",  types:["c2_endpoint","c2_framework","discord_webhook","telegram_token","ngrok_tunnel","tor_service"] },
  { id:"registry",  label:"Registry Keys",    icon:"🔑", color:"#3B82F6",  types:["registry_key"] },
  { id:"paths",     label:"File Paths",       icon:"📁", color:"#22C55E",  types:["windows_path","linux_path"] },
  { id:"ps",        label:"PowerShell / CMD", icon:"⚡", color:"#F97316",  types:["powershell","encoded_powershell","cmd_command"] },
  { id:"base64",    label:"Base64 Blobs",     icon:"🔐", color:"#EAB308",  types:["base64_blob"] },
  { id:"apis",      label:"Suspicious APIs",  icon:"⚠️", color:"#F59E0B",  types:["suspicious_api","dll_name"] },
  { id:"pipes",     label:"Pipes / Mutex",    icon:"🔧", color:"#A78BFA",  types:["named_pipe","mutex"] },
  { id:"emails",    label:"Email Addresses",  icon:"📧", color:"#94A3B8",  types:["email"] },
  { id:"cloud",     label:"Cloud Storage",    icon:"☁️", color:"#EC4899",  types:["cloud_storage"] },
  { id:"crypto",    label:"Crypto Wallets",   icon:"₿",  color:"#F59E0B",  types:["crypto_wallet"] },
];

/* ── Suspicious API explanations ── */
const API_DESC = {
  VirtualAlloc:"Shellcode memory allocation",
  VirtualAllocEx:"Remote shellcode injection",
  VirtualProtect:"Mark memory as executable",
  VirtualProtectEx:"Remote memory protection change",
  WriteProcessMemory:"Write to another process — Process Injection",
  ReadProcessMemory:"Read from another process",
  CreateRemoteThread:"Inject & execute in another process",
  CreateRemoteThreadEx:"Advanced remote thread injection",
  NtCreateThread:"Low-level thread creation (ntdll)",
  RtlCreateUserThread:"Undocumented thread creation",
  SetWindowsHookEx:"Hook keyboard/mouse input",
  UnhookWindowsHookEx:"Remove hooks (cleanup phase)",
  OpenProcess:"Open handle to another process",
  GetProcAddress:"Resolve API address dynamically",
  LoadLibraryA:"Load DLL into process",
  LoadLibraryW:"Load DLL into process (wide)",
  IsDebuggerPresent:"Anti-debug detection",
  CheckRemoteDebuggerPresent:"Anti-debug detection (remote)",
  NtQueryInformationProcess:"Anti-debug / process info query",
  URLDownloadToFile:"Download payload from internet",
  URLDownloadToFileA:"Download payload from internet",
  InternetOpenA:"Initialize WinINet (HTTP communication)",
  InternetOpenW:"Initialize WinINet (HTTP wide)",
  InternetConnectA:"Connect to remote host",
  HttpSendRequestA:"Send HTTP request",
  CryptEncrypt:"Data encryption (ransomware indicator)",
  CryptDecrypt:"Data decryption",
  CryptAcquireContextA:"Crypto context acquisition",
  AdjustTokenPrivileges:"Privilege escalation",
  LookupPrivilegeValueA:"Look up privilege for escalation",
  CreateServiceA:"Install persistent service",
  StartServiceA:"Start persistent service",
  WinExec:"Execute arbitrary command",
  ShellExecuteA:"Execute arbitrary command",
  ShellExecuteW:"Execute arbitrary command (wide)",
  DeleteFileA:"File deletion / anti-forensics",
  MoveFileExA:"File move / masquerading",
  WSASocket:"Raw socket creation",
  connect:"Network connection",
  send:"Network data send",
  recv:"Network data receive",
};

const RISK_ORDER = { CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3, INFO:4 };
const MITRE_URL = (id) => `https://attack.mitre.org/techniques/${id.replace(".","/")}/`;

/* ── Helpers ── */
const fmtBytes = (b) => {
  if (!b) return "0 B";
  if (b < 1024) return `${b} B`;
  if (b < 1024*1024) return `${(b/1024).toFixed(1)} KB`;
  if (b < 1024*1024*1024) return `${(b/1024/1024).toFixed(2)} MB`;
  return `${(b/1024/1024/1024).toFixed(2)} GB`;
};

const riskColor = (r) => ({
  CRITICAL:"#EF4444", HIGH:"#F97316", MEDIUM:"#EAB308",
  LOW:"#22C55E", INFO:"#3B82F6", CLEAN:"#22C55E"
}[r] || "#64748B");

const ZOOM_SIZES = [10, 12, 14];


// ─────────────────────────────────────────────────────────────────
//  COMPONENT
// ─────────────────────────────────────────────────────────────────

export default function HexAnalyzer({ sample, api, onExplain }) {

  /* ═══ STATE ═══ */

  // Viewer
  const CHUNK    = 8192;
  const BPR      = 16;
  const VISIBLE  = 34;

  const [hexData,        setHexData]        = useState("");
  const [totalSize,      setTotalSize]      = useState(0);
  const [viewOffset,     setViewOffset]     = useState(0);
  const [chunkBase,      setChunkBase]      = useState(-1);
  const [loading,        setLoading]        = useState(false);

  // Artifacts
  const [indicators,     setIndicators]     = useState([]);
  const [analyzing,      setAnalyzing]      = useState(false);
  const [overallRisk,    setOverallRisk]    = useState(null);
  const [analyzeProgress,setAnalyzeProgress]= useState(0);
  const [peSections,     setPeSections]     = useState([]);

  // Selection
  const [selByte,        setSelByte]        = useState(null);

  // Search
  const [searchQuery,    setSearchQuery]    = useState("");
  const [searchType,     setSearchType]     = useState("ascii");
  const [searchResults,  setSearchResults]  = useState([]);
  const [searchIdx,      setSearchIdx]      = useState(0);
  const [searching,      setSearching]      = useState(false);

  // Jump
  const [jumpInput,      setJumpInput]      = useState("");

  // Filter & panel
  const [filterTab,      setFilterTab]      = useState("all");
  const [activeArt,      setActiveArt]      = useState(null);
  const [criticalOnly,   setCriticalOnly]   = useState(false);
  const [panelTab,       setPanelTab]       = useState("artifacts"); // "artifacts" | "ioc" | "strings"

  // Strings panel
  const [stringsData,    setStringsData]    = useState(null);
  const [stringsLoading, setStringsLoading] = useState(false);
  const [stringsSearch,  setStringsSearch]  = useState("");
  const [stringsEnc,     setStringsEnc]     = useState("both");
  const [stringsCat,     setStringsCat]     = useState("all");
  const [stringsMinLen,  setStringsMinLen]  = useState(4);
  const [stringsCopied,  setStringsCopied]  = useState(null);

  // IOC Dashboard drill-down
  const [dashDrill,      setDashDrill]      = useState(null);

  // Bookmarks
  const [bookmarks,      setBookmarks]      = useState(new Set());

  // B64 / PS expanded
  const [b64Expanded,    setB64Expanded]    = useState({});
  const [psExpanded,     setPsExpanded]     = useState({});

  // Zoom & fullscreen
  const [zoomLevel,      setZoomLevel]      = useState(1); // index into ZOOM_SIZES
  const [isFullscreen,   setIsFullscreen]   = useState(false);

  // Byte stats
  const [byteStats,      setByteStats]      = useState(null);
  const [showByteStats,  setShowByteStats]  = useState(false);

  // Flash animation
  const [flashOffset,    setFlashOffset]    = useState(null);

  // Refs
  const hexBodyRef  = useRef(null);
  const rootRef     = useRef(null);
  const minimapRef  = useRef(null);

  const fontSize = ZOOM_SIZES[zoomLevel];


  /* ═══ DATA LOADING ═══ */

  const loadChunk = useCallback(async (offset) => {
    const aligned = Math.floor(offset / CHUNK) * CHUNK;
    if (aligned === chunkBase) return;
    setLoading(true);
    try {
      const res = await api.getHexChunk(sample.id, aligned, CHUNK);
      const decoded = atob(res.data);
      setHexData(decoded);
      setChunkBase(res.offset);
      setTotalSize(res.total_size);
    } catch(e) { console.error("Hex chunk load error:", e); }
    finally { setLoading(false); }
  }, [api, sample.id, chunkBase]);

  useEffect(() => { loadChunk(viewOffset); }, [viewOffset]); // eslint-disable-line


  /* ═══ ARTIFACT SCANNING ═══ */

  const runAnalysis = async () => {
    setAnalyzing(true);
    setAnalyzeProgress(0);
    const ticker = setInterval(() => setAnalyzeProgress(p => Math.min(p + 2, 92)), 250);
    try {
      const [res, peRes] = await Promise.all([
        api.analyzeHex(sample.id),
        api.hexPeSections(sample.id),
      ]);
      setIndicators(res.indicators || []);
      setOverallRisk(res.overall_risk || null);
      setPeSections(peRes.sections || []);
      setAnalyzeProgress(100);
    } catch(e) { console.error("Analysis error:", e); }
    finally { clearInterval(ticker); setTimeout(() => setAnalyzing(false), 500); }
  };

  // Load byte stats when panel is opened
  useEffect(() => {
    if (showByteStats && !byteStats) {
      api.hexStats(sample.id, 0, 65536)
        .then(setByteStats)
        .catch(e => console.error("Byte stats error:", e));
    }
  }, [showByteStats]); // eslint-disable-line


  /* ═══ SEARCH ═══ */

  const handleSearch = async () => {
    if (!searchQuery.trim()) return;
    setSearching(true);
    try {
      const res = await api.searchHex(sample.id, searchQuery, searchType);
      const offs = res.offsets || [];
      setSearchResults(offs);
      setSearchIdx(0);
      if (offs.length > 0) jumpToOffset(offs[0]);
    } catch(e) { console.error("Search error:", e); }
    finally { setSearching(false); }
  };

  const prevSearch = () => {
    if (!searchResults.length) return;
    const idx = (searchIdx - 1 + searchResults.length) % searchResults.length;
    setSearchIdx(idx); jumpToOffset(searchResults[idx]);
  };

  const nextSearch = () => {
    if (!searchResults.length) return;
    const idx = (searchIdx + 1) % searchResults.length;
    setSearchIdx(idx); jumpToOffset(searchResults[idx]);
  };


  /* ═══ NAVIGATION ═══ */

  const jumpToOffset = (offset) => {
    const clamped = Math.max(0, Math.min(offset, Math.max(0, totalSize - BPR)));
    const aligned = Math.floor(clamped / BPR) * BPR;
    setViewOffset(aligned);
    setFlashOffset(aligned);
    setTimeout(() => setFlashOffset(null), 1200);
  };

  const handleJump = () => {
    const raw = jumpInput.trim().replace(/^0x/i, "");
    const off = parseInt(raw, 16);
    if (!isNaN(off)) jumpToOffset(off);
  };

  const scrollBy = (rows) => {
    setViewOffset(prev => {
      const next = prev + rows * BPR;
      return Math.max(0, Math.min(next, Math.max(0, totalSize - BPR)));
    });
  };

  const onWheel = (e) => { e.preventDefault(); scrollBy(e.deltaY > 0 ? 3 : -3); };


  /* ═══ BOOKMARKS & COPY ═══ */

  const toggleBookmark = (off) => setBookmarks(prev => {
    const s = new Set(prev);
    s.has(off) ? s.delete(off) : s.add(off);
    return s;
  });

  const copyText = (t) => { navigator.clipboard?.writeText(t); };

  const copyHex = () => {
    if (selByte === null || chunkBase < 0) return;
    const rel = selByte - chunkBase;
    if (rel < 0 || rel >= hexData.length) return;
    copyText(hexData.charCodeAt(rel).toString(16).padStart(2,"0").toUpperCase());
  };

  const copyAscii = () => {
    if (selByte === null || chunkBase < 0) return;
    const rel = selByte - chunkBase;
    if (rel < 0 || rel >= hexData.length) return;
    const cc = hexData.charCodeAt(rel);
    copyText(cc >= 32 && cc <= 126 ? String.fromCharCode(cc) : ".");
  };


  /* ═══ ZOOM & FULLSCREEN ═══ */

  const zoomIn  = () => setZoomLevel(z => Math.min(z + 1, ZOOM_SIZES.length - 1));
  const zoomOut = () => setZoomLevel(z => Math.max(z - 1, 0));

  const toggleFullscreen = () => {
    if (!isFullscreen) {
      rootRef.current?.requestFullscreen?.().catch(() => {});
    } else {
      document.exitFullscreen?.().catch(() => {});
    }
    setIsFullscreen(!isFullscreen);
  };

  useEffect(() => {
    const handler = () => setIsFullscreen(!!document.fullscreenElement);
    document.addEventListener("fullscreenchange", handler);
    return () => document.removeEventListener("fullscreenchange", handler);
  }, []);


  /* ═══ EXPORT ═══ */

  const exportIOC = (fmt) => window.open(api.getHexIocsUrl(sample.id, fmt), "_blank");


  /* ═══ COMPUTED VALUES ═══ */

  // Filtered indicators
  const filteredIndicators = useMemo(() => {
    let list = indicators;
    if (criticalOnly) {
      list = list.filter(i => i.risk_level === "CRITICAL");
    }
    const tab = FILTER_TABS.find(t => t.id === filterTab);
    if (!tab || tab.id === "all") return list;
    if (tab.risk) return list.filter(i => i.risk_level === tab.risk);
    return list.filter(i => tab.types?.includes(i.type));
  }, [indicators, filterTab, criticalOnly]);

  // Offset → artifact map for hex highlighting
  const artMap = useMemo(() => {
    const m = new Map();
    indicators.forEach(ind => {
      for (let i = 0; i < Math.min(ind.length || 1, 256); i++) {
        const key = ind.offset + i;
        if (!m.has(key)) m.set(key, ind);
      }
    });
    return m;
  }, [indicators]);

  // Search offset set
  const searchOffsetSet = useMemo(() => new Set(searchResults), [searchResults]);

  // Summary counts
  const summary = useMemo(() => {
    const m = {};
    indicators.forEach(i => { m[i.type] = (m[i.type] || 0) + 1; });
    return m;
  }, [indicators]);

  // Selected byte info
  const selInfo = useMemo(() => {
    if (selByte === null || chunkBase < 0) return null;
    const rel = selByte - chunkBase;
    if (rel < 0 || rel >= hexData.length) return null;
    const cc = hexData.charCodeAt(rel);
    const art = artMap.get(selByte) || null;
    return {
      offset: selByte,
      hex: cc.toString(16).padStart(2,"0").toUpperCase(),
      dec: cc,
      ascii: cc >= 32 && cc <= 126 ? String.fromCharCode(cc) : ".",
      bin: cc.toString(2).padStart(8,"0"),
      art,
    };
  }, [selByte, chunkBase, hexData, artMap]);

  // IOC dashboard data
  const iocDashData = useMemo(() => {
    return IOC_CATS.map(cat => {
      const items = indicators.filter(i => cat.types.includes(i.type));
      const uniqueVals = [...new Set(items.map(i => i.value))];
      return { ...cat, count: items.length, uniqueCount: uniqueVals.length, values: uniqueVals.slice(0, 50), items };
    }).filter(c => c.count > 0);
  }, [indicators]);

  // Minimap artifact positions (normalized 0–1)
  const minimapMarkers = useMemo(() => {
    if (!totalSize || !indicators.length) return [];
    return indicators.slice(0, 500).map(ind => ({
      pos: ind.offset / totalSize,
      color: ind.color || ART_COLOR[ind.type] || "#64748B",
      risk: ind.risk_level,
    }));
  }, [indicators, totalSize]);

  // Scroll percentage
  const scrollPct = totalSize > 0 ? Math.round((viewOffset / Math.max(1, totalSize - VISIBLE * BPR)) * 100) : 0;


  /* ═══ RENDER ROWS ═══ */

  const renderRows = () => {
    if (chunkBase < 0) return null;
    const alignedStart = Math.floor(viewOffset / BPR) * BPR;
    const rows = [];

    for (let r = 0; r < VISIBLE; r++) {
      const rowOff = alignedStart + r * BPR;
      if (rowOff >= totalSize) break;

      const relOff = rowOff - chunkBase;
      const isBookmarked = bookmarks.has(rowOff);
      const isFlashing = flashOffset !== null && rowOff === flashOffset;

      if (relOff < 0 || relOff >= CHUNK) {
        rows.push(
          <div key={rowOff} className="flex items-center gap-3 font-mono py-0.5 opacity-40"
            style={{ fontSize }}>
            <span className="w-4 text-[#475569]">·</span>
            <span className="w-20 text-[#818CF8]">
              {rowOff.toString(16).padStart(8,"0").toUpperCase()}
            </span>
            <span className="text-[#475569]">Loading…</span>
          </div>
        );
        continue;
      }

      // Build per-byte data
      const byteArr = [];
      for (let b = 0; b < BPR; b++) {
        const absOff = rowOff + b;
        if (relOff + b < hexData.length) {
          const cc = hexData.charCodeAt(relOff + b);
          byteArr.push({
            absOff,
            hex: cc.toString(16).padStart(2,"0").toUpperCase(),
            ascii: (cc >= 32 && cc <= 126) ? String.fromCharCode(cc) : ".",
            art: artMap.get(absOff) || null,
            isSearch: searchOffsetSet.has(absOff),
            isSel: selByte === absOff,
          });
        } else {
          byteArr.push({ absOff, hex:"  ", ascii:" ", art:null, isSearch:false, isSel:false });
        }
      }

      const rowActive = activeArt && byteArr.some(b => b.art === activeArt);

      rows.push(
        <div
          key={rowOff}
          className="flex items-center gap-3 font-mono py-[2px] hover:bg-[#131f35] group transition-colors"
          style={{
            fontSize,
            background: isFlashing ? "rgba(124,58,237,0.2)" : rowActive ? "rgba(45,107,228,0.08)" : undefined,
            animation: isFlashing ? "hexFlash 1.2s ease-out" : undefined,
          }}
        >
          {/* Bookmark toggle */}
          <button
            onClick={() => toggleBookmark(rowOff)}
            className="w-4 opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0"
            style={{ opacity: isBookmarked ? 1 : undefined }}
          >
            <Flag size={9} style={{ color: isBookmarked ? "#EF4444" : "#334155" }}
              fill={isBookmarked ? "#EF4444" : "none"}/>
          </button>

          {/* Offset */}
          <span
            className="w-20 flex-shrink-0 select-none cursor-pointer"
            style={{
              color: isBookmarked ? "#EF4444" : "#818CF8",
              fontWeight: isBookmarked ? 900 : 400,
            }}
            onClick={() => setViewOffset(rowOff)}
          >
            {rowOff.toString(16).padStart(8,"0").toUpperCase()}
          </span>

          {/* Hex bytes — group 1 (bytes 0-7) */}
          <div className="flex gap-1 flex-shrink-0">
            {byteArr.slice(0,8).map((bd, bi) => (
              <span
                key={bi}
                onClick={() => { setSelByte(bd.absOff); if (bd.art) setActiveArt(bd.art); }}
                className="cursor-pointer rounded-sm px-[1px] transition-colors"
                style={{
                  color: bd.art ? bd.art.color : bd.isSearch ? "#FBBF24" : "#E2E8F0",
                  background: bd.isSel ? "rgba(45,107,228,0.5)" : bd.isSearch ? "rgba(251,191,36,0.15)" : undefined,
                  fontWeight: bd.art ? 700 : 400,
                  textShadow: bd.art ? `0 0 8px ${bd.art.color}60` : undefined,
                }}
                title={bd.art ? `${bd.art.label}: ${bd.art.value?.slice(0,60)}` : undefined}
              >
                {bd.hex}
              </span>
            ))}
          </div>

          <span className="text-[#1E2A40] flex-shrink-0 select-none">·</span>

          {/* Hex bytes — group 2 (bytes 8-15) */}
          <div className="flex gap-1 flex-shrink-0">
            {byteArr.slice(8,16).map((bd, bi) => (
              <span
                key={bi+8}
                onClick={() => { setSelByte(bd.absOff); if (bd.art) setActiveArt(bd.art); }}
                className="cursor-pointer rounded-sm px-[1px] transition-colors"
                style={{
                  color: bd.art ? bd.art.color : bd.isSearch ? "#FBBF24" : "#E2E8F0",
                  background: bd.isSel ? "rgba(45,107,228,0.5)" : bd.isSearch ? "rgba(251,191,36,0.15)" : undefined,
                  fontWeight: bd.art ? 700 : 400,
                  textShadow: bd.art ? `0 0 8px ${bd.art.color}60` : undefined,
                }}
                title={bd.art ? `${bd.art.label}: ${bd.art.value?.slice(0,60)}` : undefined}
              >
                {bd.hex}
              </span>
            ))}
          </div>

          {/* ASCII column */}
          <span className="text-[#334155] flex-shrink-0 select-none mx-1">│</span>
          <div className="flex flex-shrink-0">
            {byteArr.map((bd, bi) => (
              <span
                key={bi}
                onClick={() => { setSelByte(bd.absOff); if (bd.art) setActiveArt(bd.art); }}
                className="cursor-pointer text-center"
                style={{
                  width: Math.max(7, fontSize - 3),
                  color: bd.art ? bd.art.color : bd.isSearch ? "#FBBF24" : "#475569",
                  fontWeight: bd.art ? 700 : 400,
                }}
              >
                {bd.ascii}
              </span>
            ))}
          </div>
        </div>
      );
    }
    return rows;
  };


  /* ═══ RENDER ═══ */

  return (
    <div
      ref={rootRef}
      className="flex flex-col gap-3 mt-2"
      style={{
        fontFamily:"'Courier New', monospace",
        background: isFullscreen ? "#070E1B" : undefined,
        padding: isFullscreen ? 16 : undefined,
        minHeight: isFullscreen ? "100vh" : undefined,
      }}
    >
      {/* ── CSS KEYFRAME FOR FLASH ANIMATION ── */}
      <style>{`
        @keyframes hexFlash {
          0%   { background: rgba(124,58,237,0.35); }
          50%  { background: rgba(124,58,237,0.15); }
          100% { background: transparent; }
        }
        @keyframes pulseGlow {
          0%, 100% { box-shadow: 0 0 8px rgba(124,58,237,0.3); }
          50%      { box-shadow: 0 0 20px rgba(124,58,237,0.6); }
        }
      `}</style>


      {/* ══════════════════════════════════════════════════════════════════ */}
      {/* ── TOP TOOLBAR ────────────────────────────────────────────────── */}
      {/* ══════════════════════════════════════════════════════════════════ */}
      <div className="rounded-xl p-3 flex flex-wrap items-center gap-2"
        style={{ background:"#0B1120", border:"1px solid #1E2A40" }}>

        {/* Scan button */}
        <button
          onClick={runAnalysis}
          disabled={analyzing}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold text-white flex-shrink-0 transition-all hover:brightness-110"
          style={{
            background: analyzing ? "#1E2A40" : "linear-gradient(135deg,#7C3AED,#4F46E5)",
            animation: analyzing ? "pulseGlow 2s infinite" : undefined,
          }}
        >
          {analyzing ? <Loader size={12} className="animate-spin"/> : <Brain size={12}/>}
          {analyzing ? `Scanning… ${analyzeProgress}%` : "🔬 Scan Artifacts"}
        </button>

        {/* Progress bar */}
        {analyzing && (
          <div className="h-1.5 rounded-full min-w-[80px] max-w-[200px]" style={{ background:"#1E2A40" }}>
            <div className="h-1.5 rounded-full transition-all duration-300"
              style={{ width:`${analyzeProgress}%`, background:"linear-gradient(90deg,#7C3AED,#3B82F6)" }}/>
          </div>
        )}

        {/* Overall risk badge */}
        {overallRisk && (
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg flex-shrink-0"
            style={{ background:`${riskColor(overallRisk.level)}18`, border:`1px solid ${riskColor(overallRisk.level)}40` }}>
            <Shield size={10} style={{ color: riskColor(overallRisk.level) }}/>
            <span className="text-xs font-black" style={{ color: riskColor(overallRisk.level) }}>
              AI RISK: {overallRisk.level} ({overallRisk.score}/100)
            </span>
          </div>
        )}

        <div className="w-px h-5 flex-shrink-0" style={{ background:"#1E2A40" }}/>

        {/* Critical-only toggle */}
        <button
          onClick={() => setCriticalOnly(!criticalOnly)}
          className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-[10px] font-black flex-shrink-0 transition-all"
          style={{
            background: criticalOnly ? "rgba(239,68,68,0.2)" : "#111827",
            color: criticalOnly ? "#EF4444" : "#475569",
            border: `1px solid ${criticalOnly ? "rgba(239,68,68,0.4)" : "#1E2A40"}`,
          }}
        >
          🔴 CRITICAL ONLY
        </button>

        <div className="w-px h-5 flex-shrink-0" style={{ background:"#1E2A40" }}/>

        {/* Zoom */}
        <div className="flex items-center gap-1 flex-shrink-0">
          <button onClick={zoomOut} disabled={zoomLevel <= 0}
            className="px-1.5 py-1 rounded text-xs font-bold transition-all"
            style={{ background:"#1E2A40", color: zoomLevel > 0 ? "#E2E8F0" : "#334155" }}>
            A−
          </button>
          <span className="text-[10px] w-8 text-center" style={{ color:"#475569" }}>
            {fontSize}px
          </span>
          <button onClick={zoomIn} disabled={zoomLevel >= ZOOM_SIZES.length - 1}
            className="px-1.5 py-1 rounded text-xs font-bold transition-all"
            style={{ background:"#1E2A40", color: zoomLevel < ZOOM_SIZES.length-1 ? "#E2E8F0" : "#334155" }}>
            A+
          </button>
        </div>

        {/* Fullscreen */}
        <button onClick={toggleFullscreen}
          className="p-1.5 rounded-lg flex-shrink-0 transition-all"
          style={{ background:"#1E2A40", color:"#94A3B8" }}
          title={isFullscreen ? "Exit fullscreen" : "Fullscreen"}>
          {isFullscreen ? <Minimize2 size={12}/> : <Maximize2 size={12}/>}
        </button>

        <div className="w-px h-5 flex-shrink-0" style={{ background:"#1E2A40" }}/>

        {/* Search */}
        <select
          value={searchType}
          onChange={e => setSearchType(e.target.value)}
          className="text-xs rounded-lg px-2 py-1.5 outline-none flex-shrink-0"
          style={{ background:"#111827", border:"1px solid #1E2A40", color:"#94A3B8" }}
        >
          <option value="ascii">ASCII</option>
          <option value="hex">Hex</option>
          <option value="unicode">Unicode</option>
        </select>

        <input
          value={searchQuery}
          onChange={e => setSearchQuery(e.target.value)}
          onKeyDown={e => e.key === "Enter" && handleSearch()}
          placeholder="Search bytes or text…"
          className="text-xs rounded-lg px-3 py-1.5 outline-none w-44"
          style={{ background:"#111827", border:"1px solid #1E2A40", color:"white" }}
        />

        <button onClick={handleSearch} disabled={searching}
          className="p-1.5 rounded-lg flex-shrink-0 transition-all"
          style={{ background:"#2D6BE4" }}>
          {searching
            ? <Loader size={12} className="animate-spin text-white"/>
            : <Search size={12} className="text-white"/>}
        </button>

        {searchResults.length > 0 && (
          <div className="flex items-center gap-1 flex-shrink-0">
            <button onClick={prevSearch} className="p-1 rounded text-xs" style={{ background:"#1E2A40", color:"white" }}>◀</button>
            <span className="text-[10px]" style={{ color:"#94A3B8" }}>{searchIdx+1}/{searchResults.length}</span>
            <button onClick={nextSearch} className="p-1 rounded text-xs" style={{ background:"#1E2A40", color:"white" }}>▶</button>
          </div>
        )}

        <div className="w-px h-5 flex-shrink-0" style={{ background:"#1E2A40" }}/>

        {/* Jump to offset */}
        <input
          value={jumpInput}
          onChange={e => setJumpInput(e.target.value)}
          onKeyDown={e => e.key === "Enter" && handleJump()}
          placeholder="0x offset…"
          className="text-xs rounded-lg px-3 py-1.5 outline-none w-28"
          style={{ background:"#111827", border:"1px solid #1E2A40", color:"#818CF8", fontFamily:"monospace" }}
        />
        <button onClick={handleJump}
          className="text-xs px-2.5 py-1.5 rounded-lg flex-shrink-0 font-bold"
          style={{ background:"#1E2A40", color:"#818CF8" }}>Go</button>

        <div className="w-px h-5 flex-shrink-0" style={{ background:"#1E2A40" }}/>

        {/* Copy */}
        <button onClick={copyHex} disabled={selByte===null}
          className="text-xs px-2.5 py-1.5 rounded-lg flex-shrink-0 font-bold flex items-center gap-1 transition-all"
          style={{ background:"#1E2A40", color: selByte!==null ? "#E2E8F0":"#334155" }}>
          <Copy size={10}/> Hex
        </button>
        <button onClick={copyAscii} disabled={selByte===null}
          className="text-xs px-2.5 py-1.5 rounded-lg flex-shrink-0 font-bold flex items-center gap-1 transition-all"
          style={{ background:"#1E2A40", color: selByte!==null ? "#E2E8F0":"#334155" }}>
          <Copy size={10}/> ASCII
        </button>

        {/* Byte counter */}
        <span className="ml-auto text-xs flex-shrink-0 font-bold flex items-center gap-1.5"
          style={{ color:"#475569" }}>
          <Database size={10}/>
          {fmtBytes(totalSize)}
          {indicators.length > 0 && (
            <span style={{ color:"#EF4444" }}>• {indicators.length} artifacts</span>
          )}
        </span>
      </div>


      {/* ══════════════════════════════════════════════════════════════════ */}
      {/* ── MAIN 3-PANE LAYOUT ─────────────────────────────────────────── */}
      {/* ══════════════════════════════════════════════════════════════════ */}
      <div className="flex gap-3" style={{ height: isFullscreen ? "calc(100vh - 200px)" : 580, minHeight: 460 }}>

        {/* ── MINIMAP ──────────────────────────────────────────────────── */}
        <div
          ref={minimapRef}
          className="flex-shrink-0 rounded-xl relative cursor-pointer overflow-hidden"
          style={{
            width: 36,
            background:"#070E1B",
            border:"1px solid #1E2A40",
          }}
          onClick={(e) => {
            const rect = minimapRef.current?.getBoundingClientRect();
            if (!rect || !totalSize) return;
            const pct = (e.clientY - rect.top) / rect.height;
            const off = Math.floor(pct * totalSize / BPR) * BPR;
            jumpToOffset(Math.max(0, Math.min(off, totalSize - BPR)));
          }}
          title="Click to jump to position"
        >
          {/* Scan progress gradient */}
          {analyzing && (
            <div className="absolute inset-0" style={{
              background: `linear-gradient(180deg, rgba(124,58,237,0.3) ${analyzeProgress}%, transparent ${analyzeProgress}%)`,
            }}/>
          )}

          {/* Current viewport indicator */}
          {totalSize > 0 && (
            <div className="absolute left-0 right-0" style={{
              top: `${(viewOffset / totalSize) * 100}%`,
              height: `${Math.max(2, (VISIBLE * BPR / totalSize) * 100)}%`,
              background: "rgba(45,107,228,0.35)",
              borderTop: "1px solid #2D6BE4",
              borderBottom: "1px solid #2D6BE4",
            }}/>
          )}

          {/* Artifact markers */}
          {minimapMarkers.map((m, i) => (
            <div key={i} className="absolute" style={{
              top: `${m.pos * 100}%`,
              left: m.risk === "CRITICAL" ? 2 : 6,
              right: m.risk === "CRITICAL" ? 2 : 6,
              height: m.risk === "CRITICAL" ? 3 : 2,
              background: m.color,
              borderRadius: 1,
              opacity: m.risk === "CRITICAL" ? 1 : 0.7,
            }}/>
          ))}

          {/* Minimap label */}
          <div className="absolute bottom-1 left-0 right-0 text-center">
            <span className="text-[7px] font-bold" style={{ color:"#334155" }}>MAP</span>
          </div>
        </div>


        {/* ── HEX GRID ─────────────────────────────────────────────────── */}
        <div className="flex-1 flex flex-col rounded-xl overflow-hidden"
          style={{ background:"#070E1B", border:"1px solid #1E2A40" }}>

          {/* Column headers */}
          <div className="flex items-center gap-3 px-3 py-2 font-bold select-none"
            style={{ background:"#0D1122", borderBottom:"1px solid #1E2A40", color:"#334155", fontSize: Math.max(9, fontSize - 2) }}>
            <span className="w-4"/>
            <span className="w-20">OFFSET</span>
            <span className="tracking-widest">00 01 02 03 04 05 06 07 · 08 09 0A 0B 0C 0D 0E 0F</span>
            <span className="ml-1">│ ASCII</span>
          </div>

          {/* Scrollable byte area */}
          <div
            ref={hexBodyRef}
            className="flex-1 overflow-hidden px-3 py-2 relative"
            style={{ minHeight: isFullscreen ? "auto" : 420 }}
            onWheel={onWheel}
          >
            {loading && chunkBase < 0 && (
              <div className="absolute inset-0 flex items-center justify-center z-10"
                style={{ background:"rgba(7,14,27,0.85)" }}>
                <div className="flex flex-col items-center gap-2">
                  <Loader size={28} className="animate-spin" style={{ color:"#7C3AED" }}/>
                  <span className="text-xs font-bold" style={{ color:"#7C3AED" }}>Loading hex data…</span>
                </div>
              </div>
            )}
            {loading && chunkBase >= 0 && (
              <div className="absolute top-2 right-3 z-10">
                <Loader size={12} className="animate-spin" style={{ color:"#7C3AED" }}/>
              </div>
            )}
            <div className="space-y-0">{renderRows()}</div>
          </div>

          {/* Status bar */}
          <div className="flex items-center justify-between gap-3 px-3 py-2"
            style={{ background:"#0D1122", borderTop:"1px solid #1E2A40" }}>

            {/* Scrollbar slider */}
            <div className="flex items-center gap-2 flex-1 min-w-0">
              <span className="text-[10px] flex-shrink-0 font-mono" style={{ color:"#3B82F6" }}>
                0x{viewOffset.toString(16).padStart(8,"0").toUpperCase()}
              </span>
              <input
                type="range"
                min={0}
                max={Math.max(0, totalSize - VISIBLE * BPR)}
                step={BPR}
                value={viewOffset}
                onChange={e => setViewOffset(Number(e.target.value))}
                className="flex-1"
                style={{ accentColor:"#7C3AED" }}
              />
              <span className="text-[10px] flex-shrink-0 font-mono" style={{ color:"#475569" }}>
                {scrollPct}%
              </span>
            </div>

            {/* Selected byte info */}
            {selInfo && (
              <div className="flex items-center gap-2 text-[10px] font-mono flex-shrink-0"
                style={{ color:"#64748B" }}>
                <span style={{ color:"#818CF8" }}>@0x{selInfo.offset.toString(16).toUpperCase()}</span>
                <span style={{ color:"#E2E8F0" }}>0x{selInfo.hex}</span>
                <span>Dec:{selInfo.dec}</span>
                <span>Bin:{selInfo.bin}</span>
                <span style={{ color:"#22C55E" }}>'{selInfo.ascii}'</span>
                {selInfo.art && (
                  <span className="px-1.5 py-0.5 rounded text-[9px] font-bold"
                    style={{ background:`${selInfo.art.color}20`, color:selInfo.art.color }}>
                    {selInfo.art.label}
                  </span>
                )}
              </div>
            )}
          </div>
        </div>


        {/* ── RIGHT PANEL ──────────────────────────────────────────────── */}
        <div className="flex flex-col rounded-xl overflow-hidden flex-shrink-0"
          style={{ background:"#070E1B", border:"1px solid #1E2A40", width: 400, height: "100%" }}>

          {/* Panel header with tab switches */}
          <div className="px-3 py-2.5 flex items-center gap-2 flex-wrap"
            style={{ background:"#0D1122", borderBottom:"1px solid #1E2A40" }}>
            <ShieldAlert size={13} style={{ color:"#F97316" }}/>
            <div className="flex gap-1 flex-1 flex-wrap">
              <button onClick={() => setPanelTab("artifacts")}
                className="text-[10px] font-black px-2.5 py-1 rounded-md transition-all"
                style={{
                  background: panelTab === "artifacts" ? "#2D6BE4" : "transparent",
                  color: panelTab === "artifacts" ? "white" : "#475569",
                }}>
                Artifacts
              </button>
              <button onClick={() => setPanelTab("ioc")}
                className="text-[10px] font-black px-2.5 py-1 rounded-md transition-all"
                style={{
                  background: panelTab === "ioc" ? "#2D6BE4" : "transparent",
                  color: panelTab === "ioc" ? "white" : "#475569",
                }}>
                IOC Dashboard
              </button>
              <button
                onClick={() => {
                  setPanelTab("strings");
                  if (!stringsData && !stringsLoading) {
                    setStringsLoading(true);
                    api.getHexStrings(sample.id, { minLen: stringsMinLen, encoding: stringsEnc, limit: 2000 })
                      .then(d => setStringsData(d))
                      .catch(e => console.error("Strings error:", e))
                      .finally(() => setStringsLoading(false));
                  }
                }}
                className="text-[10px] font-black px-2.5 py-1 rounded-md transition-all flex items-center gap-1"
                style={{
                  background: panelTab === "strings" ? "linear-gradient(135deg,#7C3AED,#4F46E5)" : "transparent",
                  color: panelTab === "strings" ? "white" : "#475569",
                }}>
                <Terminal size={8}/> Strings
                {stringsData && (
                  <span className="opacity-70">({stringsData.total})</span>
                )}
              </button>
            </div>
            {indicators.length > 0 && (
              <span className="text-[10px] font-black px-1.5 py-0.5 rounded"
                style={{ background:"rgba(239,68,68,0.15)", color:"#EF4444" }}>
                {indicators.length}
              </span>
            )}
            {activeArt && (
              <button onClick={() => setActiveArt(null)} className="text-[10px]"
                style={{ color:"#475569" }}>
                ✕
              </button>
            )}
          </div>


          {/* ── IOC DASHBOARD ─────────────────────────────────────────── */}
          {panelTab === "ioc" && (
            <div className="flex-1 overflow-y-auto p-2 space-y-1.5">
              {indicators.length === 0 ? (
                <div className="flex flex-col items-center justify-center h-full py-12 text-center">
                  <Database size={28} style={{ color:"#1E2A40" }} className="mb-3"/>
                  <p className="text-xs font-bold text-white">No IOCs detected</p>
                  <p className="text-[11px] mt-1" style={{ color:"#475569" }}>
                    Run a scan first to populate the dashboard
                  </p>
                </div>
              ) : (
                <>
                  {/* Overall stats bar */}
                  <div className="rounded-lg p-3 mb-2" style={{ background:"#0D1122", border:"1px solid #1E2A40" }}>
                    <div className="flex items-center gap-2 mb-2">
                      <Shield size={11} style={{ color:"#7C3AED" }}/>
                      <span className="text-[10px] font-black text-white">IOC INTELLIGENCE SUMMARY</span>
                    </div>
                    <div className="grid grid-cols-3 gap-2">
                      <div className="text-center p-1.5 rounded" style={{ background:"rgba(239,68,68,0.1)" }}>
                        <div className="text-sm font-black" style={{ color:"#EF4444" }}>
                          {indicators.filter(i => i.risk_level === "CRITICAL").length}
                        </div>
                        <div className="text-[8px] font-bold" style={{ color:"#EF4444" }}>CRITICAL</div>
                      </div>
                      <div className="text-center p-1.5 rounded" style={{ background:"rgba(249,115,22,0.1)" }}>
                        <div className="text-sm font-black" style={{ color:"#F97316" }}>
                          {indicators.filter(i => i.risk_level === "HIGH").length}
                        </div>
                        <div className="text-[8px] font-bold" style={{ color:"#F97316" }}>HIGH</div>
                      </div>
                      <div className="text-center p-1.5 rounded" style={{ background:"rgba(234,179,8,0.1)" }}>
                        <div className="text-sm font-black" style={{ color:"#EAB308" }}>
                          {indicators.filter(i => i.risk_level === "MEDIUM" || i.risk_level === "LOW").length}
                        </div>
                        <div className="text-[8px] font-bold" style={{ color:"#EAB308" }}>MED/LOW</div>
                      </div>
                    </div>
                  </div>

                  {/* IOC Category cards */}
                  {iocDashData.map(cat => {
                    const isOpen = dashDrill === cat.id;
                    return (
                      <div key={cat.id} className="rounded-lg overflow-hidden transition-all"
                        style={{ background:"#0D1122", border:`1px solid ${isOpen ? cat.color+"40" : "#1E2A40"}` }}>
                        <button
                          onClick={() => setDashDrill(isOpen ? null : cat.id)}
                          className="w-full flex items-center gap-2 px-3 py-2 text-left transition-all hover:bg-[#131f35]"
                        >
                          <span className="text-sm">{cat.icon}</span>
                          <span className="text-[11px] font-bold text-white flex-1">{cat.label}</span>
                          <span className="text-[10px] font-black px-1.5 py-0.5 rounded"
                            style={{ background:`${cat.color}18`, color:cat.color }}>
                            {cat.uniqueCount}
                          </span>
                          {isOpen
                            ? <ChevronDown size={10} style={{ color:"#475569" }}/>
                            : <ChevronRight size={10} style={{ color:"#475569" }}/>}
                        </button>

                        {isOpen && (
                          <div className="px-3 pb-2 space-y-1" style={{ borderTop:"1px solid #1E2A40" }}>
                            {cat.values.map((val, vi) => (
                              <div key={vi}
                                className="flex items-center gap-2 px-2 py-1.5 rounded cursor-pointer hover:bg-[#131f35] transition-all"
                                onClick={() => {
                                  const ind = cat.items.find(i => i.value === val);
                                  if (ind) { jumpToOffset(ind.offset); setActiveArt(ind); setPanelTab("artifacts"); }
                                }}
                              >
                                <div className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background:cat.color }}/>
                                <code className="text-[10px] font-mono break-all flex-1" style={{ color:"#E2E8F0" }}>
                                  {val.length > 80 ? val.slice(0,80)+"…" : val}
                                </code>
                                <ExternalLink size={8} style={{ color:"#334155" }}/>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </>
              )}
            </div>
          )}


          {/* ── ARTIFACTS TAB ─────────────────────────────────────────── */}
          {panelTab === "artifacts" && (
            <>
              {/* Filter tabs */}
              <div className="flex gap-1 p-2 overflow-x-auto" style={{ borderBottom:"1px solid #1E2A40" }}>
                {FILTER_TABS.map(t => {
                  const cnt = t.id === "all" ? indicators.length
                    : t.risk ? indicators.filter(i => i.risk_level === t.risk).length
                    : indicators.filter(i => t.types?.includes(i.type)).length;
                  return (
                    <button key={t.id} onClick={() => setFilterTab(t.id)}
                      className="text-[10px] font-bold px-2 py-1 rounded-md flex-shrink-0 transition-all"
                      style={{
                        background: filterTab === t.id ? "#2D6BE4" : "#111827",
                        color: filterTab === t.id ? "white" : "#475569",
                        border:`1px solid ${filterTab === t.id ? "#2D6BE4" : "#1E2A40"}`,
                      }}>
                      {t.label}
                      {cnt > 0 && <span className="ml-1 opacity-60">{cnt}</span>}
                    </button>
                  );
                })}
              </div>

              {/* Artifact list */}
              <div className="flex-1 overflow-y-auto p-2 space-y-1.5">
                {indicators.length === 0 ? (
                  <div className="flex flex-col items-center justify-center h-full py-12 text-center">
                    <Target size={28} style={{ color:"#1E2A40" }} className="mb-3"/>
                    <p className="text-xs font-bold text-white">No artifacts yet</p>
                    <p className="text-[11px] mt-1" style={{ color:"#475569" }}>
                      Click "🔬 Scan Artifacts" to begin<br/>forensic analysis of the binary
                    </p>
                  </div>
                ) : filteredIndicators.length === 0 ? (
                  <div className="text-center py-8">
                    <p className="text-xs" style={{ color:"#475569" }}>No artifacts in this category</p>
                  </div>
                ) : (
                  filteredIndicators.map((ind, i) => {
                    const isActive = activeArt === ind;
                    const col = ind.color || ART_COLOR[ind.type] || "#64748B";
                    const icon = ART_ICON[ind.type] || "🔎";
                    const isB64Exp = b64Expanded[i];
                    const isPsExp = psExpanded[i];
                    const apiDesc = ind.type === "suspicious_api" ? API_DESC[ind.value] : null;

                    return (
                      <div
                        key={i}
                        onClick={() => { setActiveArt(isActive ? null : ind); jumpToOffset(ind.offset); }}
                        className="rounded-lg p-2.5 cursor-pointer transition-all"
                        style={{
                          background: isActive ? `${col}18` : "#0D1122",
                          border:`1px solid ${isActive ? col : "#1E2A40"}`,
                          boxShadow: isActive ? `0 0 12px ${col}25` : undefined,
                        }}
                      >
                        {/* ── Row 1: Type + Risk + Confidence ── */}
                        <div className="flex items-start justify-between gap-1.5 mb-1">
                          <div className="flex items-center gap-1.5 flex-1 min-w-0 flex-wrap">
                            <span className="text-[11px]">{icon}</span>
                            <span className="text-[10px] font-black px-1.5 py-0.5 rounded flex-shrink-0"
                              style={{ background:`${col}22`, color:col, border:`1px solid ${col}40` }}>
                              {ind.label || ind.type}
                            </span>
                            <span className="text-[10px] font-black px-1.5 py-0.5 rounded flex-shrink-0"
                              style={{ background:`${riskColor(ind.risk_level)}15`, color:riskColor(ind.risk_level) }}>
                              {ind.risk_level}
                            </span>
                            {/* Confirmed vs Heuristic badge */}
                            <span className="text-[8px] font-bold px-1 py-0.5 rounded flex-shrink-0"
                              style={{
                                background: ind.confirmed ? "rgba(34,197,94,0.15)" : "rgba(234,179,8,0.15)",
                                color: ind.confirmed ? "#22C55E" : "#EAB308",
                                border: `1px solid ${ind.confirmed ? "rgba(34,197,94,0.3)" : "rgba(234,179,8,0.3)"}`,
                              }}>
                              {ind.confirmed ? "✓ CONFIRMED" : "⊘ HEURISTIC"}
                            </span>
                          </div>
                          <div className="flex items-center gap-1 flex-shrink-0">
                            {/* Confidence bar */}
                            <div className="flex items-center gap-1">
                              <div className="w-12 h-1.5 rounded-full overflow-hidden" style={{ background:"#1E2A40" }}>
                                <div className="h-full rounded-full" style={{
                                  width:`${ind.confidence}%`,
                                  background: ind.confidence >= 90 ? "#EF4444" : ind.confidence >= 70 ? "#F97316" : "#EAB308",
                                }}/>
                              </div>
                              <span className="text-[9px] font-mono font-bold" style={{ color:"#475569" }}>
                                {ind.confidence}%
                              </span>
                            </div>
                          </div>
                        </div>

                        {/* ── Row 2: MITRE ATT&CK badges ── */}
                        {ind.mitre && ind.mitre.length > 0 && (
                          <div className="flex flex-wrap gap-1 mb-1">
                            {ind.mitre.map((m, mi) => (
                              <a key={mi}
                                href={MITRE_URL(m.id)}
                                target="_blank"
                                rel="noopener noreferrer"
                                onClick={e => e.stopPropagation()}
                                className="text-[8px] font-bold px-1.5 py-0.5 rounded flex items-center gap-1 transition-all hover:brightness-125"
                                style={{ background:"rgba(129,140,248,0.15)", color:"#818CF8", border:"1px solid rgba(129,140,248,0.25)" }}>
                                <Shield size={7}/> {m.id}
                                <span className="opacity-60">({m.tactic})</span>
                              </a>
                            ))}
                          </div>
                        )}

                        {/* ── Row 3: Offset + Section + Length ── */}
                        <div className="flex items-center gap-2 mb-1 flex-wrap">
                          <span className="text-[10px] font-mono" style={{ color:"#818CF8" }}>
                            @ 0x{ind.offset.toString(16).padStart(8,"0").toUpperCase()}
                          </span>
                          {ind.section && (
                            <span className="text-[9px] font-bold px-1 py-0.5 rounded"
                              style={{ background:"rgba(59,130,246,0.12)", color:"#60A5FA", border:"1px solid rgba(59,130,246,0.2)" }}>
                              [{ind.section}]
                            </span>
                          )}
                          <span className="text-[9px]" style={{ color:"#334155" }}>
                            len:{ind.length || "?"} bytes
                          </span>
                        </div>

                        {/* ── Row 4: Value ── */}
                        <code className="block text-[11px] font-mono break-all leading-relaxed"
                          style={{ color:"#E2E8F0" }}>
                          {ind.value?.length > 120 ? ind.value.slice(0,120)+"…" : ind.value}
                        </code>

                        {/* ── API Description (for suspicious APIs) ── */}
                        {apiDesc && (
                          <p className="text-[9px] mt-1 font-bold" style={{ color:"#F59E0B" }}>
                            ⚙ {apiDesc}
                          </p>
                        )}

                        {/* ── Row 5: Reason ── */}
                        <p className="text-[9px] mt-1" style={{ color:"#475569" }}>{ind.reason}</p>

                        {/* ── Row 6: Recommended Action ── */}
                        {ind.recommended_action && (
                          <div className="flex items-start gap-1.5 mt-1.5 px-2 py-1.5 rounded"
                            style={{ background:"rgba(124,58,237,0.08)", border:"1px solid rgba(124,58,237,0.15)" }}>
                            <AlertTriangle size={9} style={{ color:"#A78BFA", marginTop:1 }}/>
                            <span className="text-[9px] leading-relaxed" style={{ color:"#A78BFA" }}>
                              {ind.recommended_action}
                            </span>
                          </div>
                        )}

                        {/* ── Base64 decode section ── */}
                        {ind.type === "base64_blob" && (
                          <div className="mt-1.5">
                            <button
                              onClick={e => { e.stopPropagation(); setB64Expanded(prev => ({...prev, [i]: !prev[i]})); }}
                              className="text-[10px] px-2 py-0.5 rounded font-bold transition-all"
                              style={{ background:"rgba(234,179,8,0.15)", color:"#EAB308", border:"1px solid rgba(234,179,8,0.3)" }}>
                              {isB64Exp ? "▲ Hide Decoded" : "▼ Decode Base64"}
                            </button>
                            {isB64Exp && ind.base64_decoded && (
                              <div className="mt-1.5 rounded p-2" style={{ background:"#111827", border:"1px solid #1E2A40" }}>
                                <div className="flex gap-2 mb-1 flex-wrap">
                                  {ind.base64_decoded.secondary_findings?.contains_url && (
                                    <span className="text-[9px] px-1.5 py-0.5 rounded font-bold"
                                      style={{ background:"rgba(249,115,22,0.2)", color:"#F97316" }}>⚠ URL INSIDE</span>
                                  )}
                                  {ind.base64_decoded.secondary_findings?.contains_ip && (
                                    <span className="text-[9px] px-1.5 py-0.5 rounded font-bold"
                                      style={{ background:"rgba(239,68,68,0.2)", color:"#EF4444" }}>⚠ IP INSIDE</span>
                                  )}
                                  {ind.base64_decoded.secondary_findings?.contains_powershell && (
                                    <span className="text-[9px] px-1.5 py-0.5 rounded font-bold"
                                      style={{ background:"rgba(249,115,22,0.2)", color:"#F97316" }}>⚡ POWERSHELL</span>
                                  )}
                                  {ind.base64_decoded.secondary_findings?.contains_cmd && (
                                    <span className="text-[9px] px-1.5 py-0.5 rounded font-bold"
                                      style={{ background:"rgba(249,115,22,0.2)", color:"#F97316" }}>💻 CMD</span>
                                  )}
                                </div>
                                <code className="text-[10px] font-mono break-all block" style={{ color:"#94A3B8" }}>
                                  {ind.base64_decoded.decoded_preview}
                                </code>
                                <p className="text-[9px] mt-1" style={{ color:"#334155" }}>
                                  Decoded: {ind.base64_decoded.decoded_length} bytes
                                </p>
                              </div>
                            )}
                          </div>
                        )}

                        {/* ── PowerShell decode section ── */}
                        {ind.type === "encoded_powershell" && ind.powershell_decoded && (
                          <div className="mt-1.5">
                            <button
                              onClick={e => { e.stopPropagation(); setPsExpanded(prev => ({...prev, [i]: !prev[i]})); }}
                              className="text-[10px] px-2 py-0.5 rounded font-bold transition-all"
                              style={{ background:"rgba(249,115,22,0.15)", color:"#F97316", border:"1px solid rgba(249,115,22,0.3)" }}>
                              {isPsExp ? "▲ Hide Script" : "⚡ Decode PowerShell"}
                            </button>
                            {isPsExp && (
                              <div className="mt-1.5 rounded p-2" style={{ background:"#111827", border:"1px solid rgba(249,115,22,0.2)" }}>
                                <div className="flex items-center gap-1.5 mb-1">
                                  <span className="text-[9px] font-black px-1.5 py-0.5 rounded"
                                    style={{ background:"rgba(239,68,68,0.2)", color:"#EF4444" }}>
                                    ⚡ DECODED SCRIPT — CRITICAL
                                  </span>
                                </div>
                                <code className="text-[10px] font-mono break-all block whitespace-pre-wrap" style={{ color:"#F97316" }}>
                                  {ind.powershell_decoded.decoded_script}
                                </code>
                                <p className="text-[9px] mt-1" style={{ color:"#334155" }}>
                                  Decoded: {ind.powershell_decoded.decoded_length} bytes
                                </p>
                              </div>
                            )}
                          </div>
                        )}

                        {/* ── Credential / Secret highlight ── */}
                        {["credential","api_key","ssh_key","jwt_token"].includes(ind.type) && (
                          <div className="mt-2 rounded-lg px-3 py-2 flex items-start gap-2"
                            style={{ background:"rgba(244,63,94,0.1)", border:"1px solid rgba(244,63,94,0.4)" }}>
                            <span style={{fontSize:12,flexShrink:0,marginTop:1}}>🚨</span>
                            <div>
                              <p className="text-[10px] font-black mb-0.5" style={{color:"#F43F5E"}}>
                                CREDENTIAL EXPOSURE DETECTED
                              </p>
                              <p className="text-[9px] leading-relaxed" style={{color:"#FDA4AF"}}>
                                {ind.type === "api_key" && "Hardcoded API key or secret found in binary. Revoke this key immediately and rotate all related credentials."}
                                {ind.type === "ssh_key" && "SSH private key material embedded in binary. This is a critical security incident — rotate all SSH keys immediately."}
                                {ind.type === "jwt_token" && "JSON Web Token found in binary. This token may grant unauthorized access to protected systems. Revoke immediately."}
                                {ind.type === "credential" && "Username or password hardcoded in binary. Change the password immediately and audit all systems where this credential is used."}
                              </p>
                            </div>
                          </div>
                        )}

                        {/* ── C2 Framework highlight ── */}
                        {["c2_framework","ddns_domain"].includes(ind.type) && (
                          <div className="mt-2 rounded-lg px-3 py-2 flex items-start gap-2"
                            style={{ background:"rgba(220,38,38,0.1)", border:"1px solid rgba(220,38,38,0.4)" }}>
                            <span style={{fontSize:12,flexShrink:0,marginTop:1}}>☠️</span>
                            <div>
                              <p className="text-[10px] font-black mb-0.5" style={{color:"#DC2626"}}>
                                {ind.type === "c2_framework" ? "KNOWN MALWARE FRAMEWORK" : "DYNAMIC DNS C2 INFRASTRUCTURE"}
                              </p>
                              <p className="text-[9px] leading-relaxed" style={{color:"#FCA5A5"}}>
                                {ind.type === "c2_framework" && "Known C2 or RAT framework string identified. This binary contains signatures of active malware tooling. Isolate the system immediately."}
                                {ind.type === "ddns_domain" && "Dynamic DNS domain used — attackers use these to hide their real IP address and rotate infrastructure. Block at DNS/firewall level."}
                              </p>
                            </div>
                          </div>
                        )}

                        {/* ── Crypto wallet highlight ── */}
                        {ind.type === "crypto_wallet" && (
                          <div className="mt-2 rounded-lg px-3 py-2 flex items-start gap-2"
                            style={{ background:"rgba(245,158,11,0.1)", border:"1px solid rgba(245,158,11,0.35)" }}>
                            <span style={{fontSize:12,flexShrink:0,marginTop:1}}>₿</span>
                            <div>
                              <p className="text-[10px] font-black mb-0.5" style={{color:"#F59E0B"}}>
                                CRYPTOCURRENCY WALLET DETECTED
                              </p>
                              <p className="text-[9px] leading-relaxed" style={{color:"#FCD34D"}}>
                                Crypto wallet address found — may indicate a cryptominer, ransomware payment address, or financial theft target. Search this address on a blockchain explorer.
                              </p>
                            </div>
                          </div>
                        )}

                        {/* ── Action buttons ── */}
                        <div className="flex items-center gap-1.5 mt-2">
                          {/* Jump to Hex */}
                          <button
                            onClick={e => { e.stopPropagation(); jumpToOffset(ind.offset); }}
                            className="text-[9px] px-2 py-0.5 rounded font-bold flex items-center gap-1 transition-all hover:brightness-125"
                            style={{ background:"rgba(45,107,228,0.15)", color:"#60A5FA", border:"1px solid rgba(45,107,228,0.25)" }}>
                            <Eye size={8}/> Jump to Hex
                          </button>
                          {/* Ask CIPHER */}
                          {onExplain && (
                            <button
                              onClick={e => {
                                e.stopPropagation();
                                const context = [
                                  `Type: ${ind.label}`,
                                  `Risk: ${ind.risk_level}`,
                                  `Confidence: ${ind.confidence}%`,
                                  `Section: ${ind.section || "unknown"}`,
                                  ind.mitre?.length ? `MITRE: ${ind.mitre.map(m => m.id).join(", ")}` : "",
                                  `Reason: ${ind.reason}`,
                                ].filter(Boolean).join("\n");
                                onExplain("Hex Artifact", ind.value, context);
                              }}
                              className="text-[9px] px-2 py-0.5 rounded font-bold flex items-center gap-1 transition-all hover:brightness-125"
                              style={{ background:"rgba(167,139,250,0.15)", color:"#A78BFA", border:"1px solid rgba(167,139,250,0.25)" }}>
                              <Brain size={8}/> Ask CIPHER
                            </button>
                          )}
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            </>
          )}


          {/* ── STRINGS TAB ────────────────────────────────────────────── */}
          {panelTab === "strings" && (
            <div style={{ display:"flex", flexDirection:"column", flex:1, overflow:"hidden", height:"100%" }}>

              {/* ── Strings Toolbar ── */}
              <div style={{ padding:"10px", borderBottom:"1px solid #1E2A40", background:"#070E1B", flexShrink:0 }}>

                {/* Search + Reload row */}
                <div style={{ display:"flex", gap:6, marginBottom:6 }}>
                  <div style={{ position:"relative", flex:1 }}>
                    <Search size={11} style={{ position:"absolute", left:8, top:"50%", transform:"translateY(-50%)", color:"#334155", pointerEvents:"none" }}/>
                    <input
                      value={stringsSearch}
                      onChange={e => setStringsSearch(e.target.value)}
                      onKeyDown={e => e.key === "Enter" && (() => {
                        setStringsLoading(true);
                        api.getHexStrings(sample.id, { minLen: stringsMinLen, encoding: stringsEnc, category: stringsCat !== "all" ? stringsCat : undefined, search: stringsSearch || undefined, limit: 2000 })
                          .then(d => setStringsData(d)).catch(console.error).finally(() => setStringsLoading(false));
                      })()}
                      placeholder="Search strings… (Enter)"
                      style={{ width:"100%", paddingLeft:24, paddingRight:8, paddingTop:5, paddingBottom:5, fontSize:11, background:"#111827", border:"1px solid #1E2A40", borderRadius:6, color:"white", outline:"none", boxSizing:"border-box" }}
                    />
                  </div>
                  <button
                    onClick={() => {
                      setStringsLoading(true);
                      api.getHexStrings(sample.id, { minLen: stringsMinLen, encoding: stringsEnc, category: stringsCat !== "all" ? stringsCat : undefined, search: stringsSearch || undefined, limit: 2000 })
                        .then(d => setStringsData(d)).catch(console.error).finally(() => setStringsLoading(false));
                    }}
                    disabled={stringsLoading}
                    style={{ padding:"5px 10px", background: stringsLoading ? "#1E2A40" : "#2D6BE4", color:"white", border:"none", borderRadius:6, cursor:"pointer", display:"flex", alignItems:"center", gap:4, fontSize:10, fontWeight:900, flexShrink:0 }}
                  >
                    {stringsLoading ? <Loader size={10} className="animate-spin"/> : "↻ Run"}
                  </button>
                </div>

                {/* Options row */}
                <div style={{ display:"flex", gap:6, alignItems:"center", flexWrap:"wrap" }}>
                  <select
                    value={stringsEnc}
                    onChange={e => setStringsEnc(e.target.value)}
                    style={{ fontSize:10, background:"#111827", border:"1px solid #1E2A40", borderRadius:5, color:"#94A3B8", padding:"3px 5px", outline:"none" }}
                  >
                    <option value="both">ASCII + Wide</option>
                    <option value="ascii">ASCII only</option>
                    <option value="utf16">Wide only</option>
                  </select>
                  <div style={{ display:"flex", alignItems:"center", gap:4 }}>
                    <span style={{ fontSize:9, color:"#475569", fontWeight:700 }}>Min len:</span>
                    <input
                      type="number" min={4} max={50}
                      value={stringsMinLen}
                      onChange={e => setStringsMinLen(Number(e.target.value))}
                      style={{ width:40, fontSize:10, background:"#111827", border:"1px solid #1E2A40", borderRadius:5, color:"#818CF8", padding:"3px 4px", outline:"none", textAlign:"center" }}
                    />
                  </div>
                  {stringsData && (
                    <button
                      onClick={() => { const txt = stringsData.strings.filter(s => (stringsCat==="all"||s.category===stringsCat) && (!stringsSearch||s.value.toLowerCase().includes(stringsSearch.toLowerCase()))).slice(0,1000).map(s=>`0x${s.offset.toString(16).padStart(8,"0").toUpperCase()}  [${s.category.padEnd(10)}]  ${s.value}`).join("\n"); navigator.clipboard?.writeText(txt); }}
                      style={{ marginLeft:"auto", fontSize:9, background:"rgba(45,107,228,0.15)", color:"#60A5FA", border:"1px solid rgba(45,107,228,0.3)", borderRadius:5, padding:"3px 7px", cursor:"pointer", display:"flex", alignItems:"center", gap:3, fontWeight:700 }}
                    >
                      <Copy size={8}/> Export
                    </button>
                  )}
                </div>

                {/* Summary cards — shown after load */}
                {stringsData && (() => {
                  const cc = stringsData.category_counts || {};
                  const danger = [
                    { id:"powershell", label:"PowerShell", icon:"⚡", color:"#F97316" },
                    { id:"ip",         label:"IPs",        icon:"🌐", color:"#EF4444" },
                    { id:"url",        label:"URLs",       icon:"🔗", color:"#F97316" },
                    { id:"domain",     label:"Domains",    icon:"🌍", color:"#EF4444" },
                    { id:"registry",   label:"Registry",   icon:"🔑", color:"#3B82F6" },
                    { id:"credential", label:"Creds",      icon:"🔐", color:"#EC4899" },
                    { id:"api",        label:"APIs",       icon:"⚠️", color:"#F59E0B" },
                    { id:"path",       label:"Paths",      icon:"📁", color:"#22C55E" },
                    { id:"base64",     label:"Base64",     icon:"🔒", color:"#EAB308" },
                  ].filter(c => (cc[c.id]||0) > 0);
                  if (danger.length === 0) return null;
                  return (
                    <div style={{ display:"flex", gap:4, flexWrap:"wrap", marginTop:8 }}>
                      {danger.map(c => (
                        <button key={c.id} onClick={() => setStringsCat(stringsCat===c.id ? "all" : c.id)}
                          style={{ display:"flex", alignItems:"center", gap:3, padding:"3px 7px", borderRadius:6, fontSize:10, fontWeight:800, cursor:"pointer", background: stringsCat===c.id ? `${c.color}25` : "rgba(255,255,255,0.03)", color: stringsCat===c.id ? c.color : "#64748B", border:`1px solid ${stringsCat===c.id ? c.color+"60" : "#1E2A40"}`, transition:"all 0.15s" }}
                        >
                          {c.icon} {c.label} <span style={{ opacity:0.7 }}>{cc[c.id]}</span>
                        </button>
                      ))}
                      {stringsCat !== "all" && (
                        <button onClick={() => setStringsCat("all")}
                          style={{ padding:"3px 7px", borderRadius:6, fontSize:9, fontWeight:800, background:"rgba(255,255,255,0.05)", color:"#475569", border:"1px solid #1E2A40", cursor:"pointer" }}
                        >✕ Clear</button>
                      )}
                    </div>
                  );
                })()}
              </div>

              {/* ── Strings List ── */}
              <div style={{ flex:1, overflowY:"auto", overflowX:"hidden" }}>
                {stringsLoading ? (
                  <div style={{ display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center", padding:"40px 0", gap:8 }}>
                    <Loader size={24} className="animate-spin" style={{ color:"#7C3AED" }}/>
                    <span style={{ fontSize:11, fontWeight:700, color:"#7C3AED" }}>Extracting strings from binary…</span>
                    <span style={{ fontSize:10, color:"#334155" }}>This may take a moment for large files</span>
                  </div>
                ) : !stringsData ? (
                  <div style={{ display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center", padding:"50px 16px", textAlign:"center", gap:8 }}>
                    <Terminal size={32} style={{ color:"#1E2A40" }}/>
                    <p style={{ fontSize:12, fontWeight:700, color:"white", margin:0 }}>Strings not loaded yet</p>
                    <p style={{ fontSize:11, color:"#334155", margin:0 }}>Click ↻ Run to extract all<br/>readable strings from the binary</p>
                    <button
                      onClick={() => { setStringsLoading(true); api.getHexStrings(sample.id, { minLen: stringsMinLen, encoding: stringsEnc, limit: 2000 }).then(d => setStringsData(d)).catch(console.error).finally(() => setStringsLoading(false)); }}
                      style={{ marginTop:6, padding:"7px 18px", background:"linear-gradient(135deg,#7C3AED,#4F46E5)", color:"white", border:"none", borderRadius:8, cursor:"pointer", fontSize:11, fontWeight:800 }}
                    >
                      ⚡ Extract Strings Now
                    </button>
                  </div>
                ) : (() => {
                  const CAT_COLOR = {
                    url:"#F97316", ip:"#EF4444", domain:"#EF4444", registry:"#3B82F6",
                    path:"#22C55E", powershell:"#F97316", api:"#F59E0B", binary:"#64748B",
                    credential:"#EC4899", base64:"#EAB308", encoded:"#A78BFA", string:"#94A3B8",
                    sql:"#38BDF8",
                  };
                  const CAT_ICON = {
                    url:"🔗", ip:"🌐", domain:"🌍", registry:"🔑", path:"📁",
                    powershell:"⚡", api:"⚠️", binary:"📦", credential:"🔐",
                    base64:"🔒", encoded:"🔒", string:"📝", sql:"🗄️",
                  };
                  const DANGER_CATS = new Set(["powershell","ip","url","domain","registry","credential","api","base64","encoded"]);

                  const filtered = stringsData.strings.filter(s =>
                    (stringsCat === "all" || s.category === stringsCat) &&
                    (!stringsSearch.trim() || s.value.toLowerCase().includes(stringsSearch.toLowerCase()))
                  );

                  if (filtered.length === 0) return (
                    <div style={{ textAlign:"center", padding:"32px 0", color:"#475569", fontSize:11 }}>
                      No strings match the current filter
                    </div>
                  );

                  return (
                    <div>
                      {/* Stats row */}
                      <div style={{ display:"flex", alignItems:"center", padding:"6px 12px", background:"#0D1122", borderBottom:"1px solid #1E2A40", fontSize:10 }}>
                        <span style={{ color:"#475569" }}>
                          <span style={{ color:"#E2E8F0", fontWeight:700 }}>{filtered.length}</span> strings
                          {stringsCat !== "all" && <span style={{ color:"#7C3AED" }}> in [{stringsCat}]</span>}
                          {" / "}{stringsData.total} total
                        </span>
                        <span style={{ marginLeft:"auto", color:"#334155" }}>
                          {filtered.filter(s => DANGER_CATS.has(s.category)).length > 0 && (
                            <span style={{ color:"#EF4444", fontWeight:700 }}>⚠ {filtered.filter(s => DANGER_CATS.has(s.category)).length} suspicious</span>
                          )}
                        </span>
                      </div>

                      {/* String rows */}
                      {filtered.slice(0, 1000).map((s, idx) => {
                        const col = CAT_COLOR[s.category] || "#94A3B8";
                        const icon = CAT_ICON[s.category] || "📝";
                        const isDanger = DANGER_CATS.has(s.category);
                        const isCopied = stringsCopied === idx;
                        return (
                          <div
                            key={idx}
                            style={{
                              display:"flex", flexDirection:"column",
                              padding:"7px 12px",
                              borderBottom:"1px solid #0D1529",
                              background: isDanger ? `${col}06` : "transparent",
                              borderLeft: isDanger ? `2px solid ${col}50` : "2px solid transparent",
                            }}
                            className="group"
                            onMouseEnter={e => e.currentTarget.style.background = isDanger ? `${col}12` : "#0D1122"}
                            onMouseLeave={e => e.currentTarget.style.background = isDanger ? `${col}06` : "transparent"}
                          >
                            {/* Top row: offset + badges + actions */}
                            <div style={{ display:"flex", alignItems:"center", gap:5, marginBottom:3 }}>
                              {/* Category icon + badge */}
                              <span style={{ fontSize:10, flexShrink:0 }}>{icon}</span>
                              <span
                                style={{ fontSize:8, fontWeight:800, padding:"1px 5px", borderRadius:4, background:`${col}20`, color:col, border:`1px solid ${col}35`, flexShrink:0, letterSpacing:"0.5px", textTransform:"uppercase" }}
                              >
                                {s.category}
                              </span>
                              {/* Encoding */}
                              <span style={{
                                fontSize:8, fontWeight:800, padding:"1px 4px", borderRadius:4, flexShrink:0,
                                background: s.encoding === "UTF-16LE" ? "rgba(124,58,237,0.2)" : "rgba(34,197,94,0.1)",
                                color: s.encoding === "UTF-16LE" ? "#A78BFA" : "#4ADE80",
                              }}>
                                {s.encoding === "UTF-16LE" ? "WIDE" : "ASCII"}
                              </span>
                              {/* Length */}
                              <span style={{ fontSize:8, color:"#334155", flexShrink:0 }}>{s.value.length}c</span>
                              {/* Offset — clickable */}
                              <span
                                onClick={() => jumpToOffset(s.offset)}
                                style={{ fontSize:9, fontFamily:"monospace", color:"#4F46E5", cursor:"pointer", marginLeft:"auto", flexShrink:0 }}
                                title="Jump to offset in hex view"
                              >
                                @{s.offset.toString(16).padStart(6,"0").toUpperCase()}
                              </span>
                              {/* Copy btn */}
                              <button
                                onClick={() => { navigator.clipboard?.writeText(s.value); setStringsCopied(idx); setTimeout(() => setStringsCopied(null), 1200); }}
                                style={{ padding:"2px 5px", background: isCopied ? "rgba(34,197,94,0.2)" : "#1E2A40", border:"none", borderRadius:4, cursor:"pointer", flexShrink:0 }}
                                title="Copy value"
                              >
                                <Copy size={8} style={{ color: isCopied ? "#22C55E" : "#475569" }}/>
                              </button>
                            </div>
                            {/* Value row */}
                            <code
                              style={{
                                fontSize: isDanger ? 11 : 10,
                                fontFamily:"'Fira Code', 'Cascadia Code', monospace",
                                color: isDanger ? col : "#94A3B8",
                                wordBreak:"break-all",
                                lineHeight:1.5,
                                fontWeight: isDanger ? 600 : 400,
                              }}
                            >
                              {s.value.length > 200 ? s.value.slice(0,200)+"…" : s.value}
                            </code>
                          </div>
                        );
                      })}
                      {filtered.length > 1000 && (
                        <div style={{ textAlign:"center", padding:"12px 0", fontSize:10, color:"#334155" }}>
                          Showing 1000 of {filtered.length} — use search to narrow down
                        </div>
                      )}
                    </div>
                  );
                })()}
              </div>
            </div>
          )}
        </div>
      </div>


      {/* ══════════════════════════════════════════════════════════════════ */}
      {/* ── BYTE STATISTICS PANEL (collapsible) ────────────────────────── */}
      {/* ══════════════════════════════════════════════════════════════════ */}
      <div className="rounded-xl overflow-hidden" style={{ background:"#0B1120", border:"1px solid #1E2A40" }}>
        <button
          onClick={() => setShowByteStats(!showByteStats)}
          className="w-full flex items-center gap-2 px-4 py-2.5 text-left transition-all hover:bg-[#0D1122]"
        >
          <BarChart2 size={13} style={{ color:"#7C3AED" }}/>
          <span className="text-xs font-black text-white">Byte Statistics & Entropy</span>
          {byteStats && (
            <span className="text-[10px] font-mono ml-2" style={{ color:"#A78BFA" }}>
              Entropy: {byteStats.entropy.toFixed(2)} / 8.00
            </span>
          )}
          <span className="ml-auto text-[10px]" style={{ color:"#475569" }}>
            {showByteStats ? "▲" : "▼"}
          </span>
        </button>

        {showByteStats && (
          <div className="px-4 pb-4" style={{ borderTop:"1px solid #1E2A40" }}>
            {!byteStats ? (
              <div className="flex items-center justify-center py-8">
                <Loader size={16} className="animate-spin" style={{ color:"#7C3AED" }}/>
                <span className="text-xs ml-2" style={{ color:"#475569" }}>Loading statistics…</span>
              </div>
            ) : (
              <div className="mt-3 space-y-3">
                {/* Entropy indicator */}
                <div className="flex items-center gap-3">
                  <span className="text-[10px] font-bold" style={{ color:"#94A3B8" }}>ENTROPY</span>
                  <div className="flex-1 h-3 rounded-full overflow-hidden" style={{ background:"#1E2A40" }}>
                    <div className="h-full rounded-full transition-all" style={{
                      width:`${(byteStats.entropy / 8) * 100}%`,
                      background: byteStats.entropy > 7.5
                        ? "linear-gradient(90deg, #EF4444, #DC2626)"
                        : byteStats.entropy > 6.5
                          ? "linear-gradient(90deg, #F97316, #EA580C)"
                          : byteStats.entropy > 4
                            ? "linear-gradient(90deg, #EAB308, #CA8A04)"
                            : "linear-gradient(90deg, #22C55E, #16A34A)",
                    }}/>
                  </div>
                  <span className="text-[11px] font-mono font-bold" style={{
                    color: byteStats.entropy > 7.5 ? "#EF4444" : byteStats.entropy > 6.5 ? "#F97316" : "#22C55E"
                  }}>
                    {byteStats.entropy.toFixed(4)}
                  </span>
                  <span className="text-[9px] font-bold px-1.5 py-0.5 rounded" style={{
                    background: byteStats.entropy > 7.5 ? "rgba(239,68,68,0.15)" : byteStats.entropy > 6.5 ? "rgba(249,115,22,0.15)" : "rgba(34,197,94,0.15)",
                    color: byteStats.entropy > 7.5 ? "#EF4444" : byteStats.entropy > 6.5 ? "#F97316" : "#22C55E",
                  }}>
                    {byteStats.entropy > 7.5 ? "⚠ PACKED/ENCRYPTED" : byteStats.entropy > 6.5 ? "HIGH ENTROPY" : "NORMAL"}
                  </span>
                </div>

                {/* Byte frequency chart */}
                <div>
                  <span className="text-[10px] font-bold" style={{ color:"#94A3B8" }}>TOP BYTE FREQUENCIES</span>
                  <div className="mt-1" style={{ height: 160 }}>
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={byteStats.frequencies?.slice(0, 16) || []}
                        margin={{ top:5, right:5, bottom:5, left:5 }}>
                        <XAxis dataKey="hex" tick={{ fontSize:9, fill:"#475569" }} axisLine={false} tickLine={false}/>
                        <YAxis tick={{ fontSize:9, fill:"#334155" }} axisLine={false} tickLine={false} width={35}/>
                        <Tooltip
                          contentStyle={{ background:"#0D1122", border:"1px solid #1E2A40", borderRadius:8, fontSize:11 }}
                          labelStyle={{ color:"#E2E8F0", fontWeight:900 }}
                          itemStyle={{ color:"#94A3B8" }}
                          formatter={(val, name) => [`${val} (${((val / byteStats.total_bytes) * 100).toFixed(1)}%)`, "Count"]}
                        />
                        <Bar dataKey="count" radius={[3,3,0,0]}
                          fill="url(#byteGradient)"/>
                        <defs>
                          <linearGradient id="byteGradient" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%" stopColor="#7C3AED" stopOpacity={0.9}/>
                            <stop offset="100%" stopColor="#4F46E5" stopOpacity={0.5}/>
                          </linearGradient>
                        </defs>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                <div className="text-[9px]" style={{ color:"#334155" }}>
                  Analyzed {fmtBytes(byteStats.total_bytes)} from offset 0x{(byteStats.offset || 0).toString(16).toUpperCase()}
                </div>
              </div>
            )}
          </div>
        )}
      </div>


      {/* ══════════════════════════════════════════════════════════════════ */}
      {/* ── IOC EXPORT PANEL ───────────────────────────────────────────── */}
      {/* ══════════════════════════════════════════════════════════════════ */}
      {indicators.length > 0 && (
        <div className="rounded-xl p-4" style={{ background:"#0B1120", border:"1px solid #1E2A40" }}>
          <div className="flex items-start justify-between gap-4 flex-wrap">

            {/* IOC Summary */}
            <div>
              <p className="text-xs font-black text-white mb-2 flex items-center gap-2">
                <Database size={12} style={{ color:"#3B82F6" }}/> IOC Summary
              </p>
              <div className="flex flex-wrap gap-2">
                {[
                  { types:["ipv4","ipv6"],              label:"IPs",      color:"#EF4444" },
                  { types:["url"],                      label:"URLs",     color:"#F97316" },
                  { types:["domain"],                   label:"Domains",  color:"#F97316" },
                  { types:["c2_endpoint","discord_webhook","telegram_token","ngrok_tunnel","tor_service"], label:"C2", color:"#EF4444" },
                  { types:["registry_key"],             label:"Registry", color:"#3B82F6" },
                  { types:["windows_path","linux_path"],label:"Paths",    color:"#22C55E" },
                  { types:["mutex","named_pipe"],        label:"Mutex/Pipes",color:"#A78BFA" },
                  { types:["base64_blob"],              label:"Base64",   color:"#EAB308" },
                  { types:["powershell","encoded_powershell","cmd_command"], label:"PowerShell", color:"#F97316" },
                  { types:["dll_name"],                 label:"DLLs",     color:"#64748B" },
                  { types:["suspicious_api"],           label:"APIs",     color:"#F59E0B" },
                  { types:["email"],                    label:"Emails",   color:"#94A3B8" },
                  { types:["cloud_storage"],            label:"Cloud",    color:"#EC4899" },
                ].map(cat => {
                  const count = cat.types.reduce((acc, t) => acc + (summary[t] || 0), 0);
                  if (!count) return null;
                  return (
                    <button key={cat.label}
                      onClick={() => {
                        const tab = FILTER_TABS.find(f => f.types?.some(ft => cat.types.includes(ft)));
                        if (tab) { setFilterTab(tab.id); setPanelTab("artifacts"); }
                      }}
                      className="text-[11px] font-bold px-2 py-1 rounded-lg transition-all hover:brightness-110 cursor-pointer"
                      style={{ background:`${cat.color}18`, color:cat.color, border:`1px solid ${cat.color}30` }}>
                      {cat.label}: {count}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Export buttons */}
            <div>
              <p className="text-xs font-black text-white mb-2 flex items-center gap-2">
                <Download size={12} style={{ color:"#22C55E" }}/> Export IOCs
              </p>
              <div className="flex flex-wrap gap-2">
                {[
                  { fmt:"json",    label:"JSON",     color:"#F97316" },
                  { fmt:"csv",     label:"CSV",      color:"#22C55E" },
                  { fmt:"txt",     label:"TXT",      color:"#94A3B8" },
                  { fmt:"stix",    label:"STIX 2.1", color:"#3B82F6" },
                  { fmt:"openioc", label:"OpenIOC",  color:"#818CF8" },
                  { fmt:"yara",    label:"YARA",     color:"#EF4444" },
                  { fmt:"sigma",   label:"Sigma",    color:"#EC4899" },
                ].map(e => (
                  <button key={e.fmt} onClick={() => exportIOC(e.fmt)}
                    className="flex items-center gap-1.5 text-xs font-bold px-3 py-1.5 rounded-lg transition-all hover:brightness-110"
                    style={{ background:`${e.color}18`, color:e.color, border:`1px solid ${e.color}40` }}>
                    <Download size={11}/> {e.label}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Color legend */}
          <div className="mt-3 pt-3 flex flex-wrap gap-3" style={{ borderTop:"1px solid #1E2A40" }}>
            <span className="text-[10px] font-bold" style={{ color:"#334155" }}>COLOR LEGEND:</span>
            {[
              { color:"#EF4444", label:"C2 / IP / Critical",    types:["c2_endpoint","ipv4","ipv6","ngrok_tunnel"] },
              { color:"#F97316", label:"URL / PowerShell",      types:["url","powershell","encoded_powershell","cmd_command"] },
              { color:"#3B82F6", label:"Registry",              types:["registry_key"] },
              { color:"#A78BFA", label:"Mutex / Pipes / TOR",   types:["mutex","named_pipe","tor_service"] },
              { color:"#22C55E", label:"File Path",             types:["windows_path","linux_path"] },
              { color:"#EAB308", label:"Base64",                types:["base64_blob"] },
              { color:"#EC4899", label:"Discord / Telegram",    types:["discord_webhook","telegram_token","cloud_storage"] },
              { color:"#F59E0B", label:"Suspicious API",        types:["suspicious_api"] },
              { color:"#64748B", label:"DLL / User-Agent",      types:["dll_name","user_agent"] },
            ].map(l => (
              <button key={l.label}
                onClick={() => {
                  const tab = FILTER_TABS.find(f => f.types?.some(ft => l.types.includes(ft)));
                  if (tab) { setFilterTab(tab.id); setPanelTab("artifacts"); }
                }}
                className="flex items-center gap-1.5 text-[10px] cursor-pointer transition-all hover:brightness-125">
                <span className="w-2.5 h-2.5 rounded-full flex-shrink-0" style={{ background:l.color }}/>
                <span style={{ color:"#475569" }}>{l.label}</span>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
