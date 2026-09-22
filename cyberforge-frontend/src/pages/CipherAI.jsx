import React, { useState, useRef, useEffect, useCallback } from "react";
import { Brain, ShieldAlert, Send, Copy, Check, Zap, Target, FileText, AlertTriangle, RefreshCw, ChevronRight, Sparkles } from "lucide-react";

// ================================================================
//  CIPHER AI — Premium v2
// ================================================================

/* Typewriter text renderer */
function TypewriterText({ text, speed = 12, onDone }) {
  const [displayed, setDisplayed] = useState("");
  const idxRef = useRef(0);

  useEffect(() => {
    setDisplayed("");
    idxRef.current = 0;
  }, [text]);

  useEffect(() => {
    if (idxRef.current >= text.length) { onDone?.(); return; }
    const t = setTimeout(() => {
      idxRef.current++;
      setDisplayed(text.slice(0, idxRef.current));
    }, speed);
    return () => clearTimeout(t);
  }, [displayed, text, speed, onDone]);

  const done = idxRef.current >= text.length;
  return (
    <span className={!done ? "typewriter-cursor" : ""} style={{whiteSpace:"pre-wrap", lineHeight:1.65}}>
      {displayed}
    </span>
  );
}

/* Simple markdown renderer for AI messages */
function MdText({ content }) {
  const lines = content.split("\n");
  return (
    <div style={{whiteSpace:"pre-wrap", lineHeight:1.65, fontSize:12.5}}>
      {lines.map((line, i) => {
        // Code block start/end
        if (line.startsWith("```")) {
          return null; // handled in block logic
        }
        // Heading
        if (line.startsWith("### ")) return <p key={i} className="text-white font-black mt-2 mb-1" style={{fontSize:12}}>{line.slice(4)}</p>;
        if (line.startsWith("## "))  return <p key={i} className="text-white font-black mt-2 mb-1" style={{fontSize:13}}>{line.slice(3)}</p>;
        if (line.startsWith("# "))   return <p key={i} className="text-white font-black mt-2 mb-1" style={{fontSize:14}}>{line.slice(2)}</p>;
        // Bullet
        if (line.startsWith("- ") || line.startsWith("* ")) {
          return (
            <p key={i} className="flex gap-1.5 mt-0.5">
              <span style={{color:"#7C3AED", flexShrink:0}}>▸</span>
              <span>{formatInline(line.slice(2))}</span>
            </p>
          );
        }
        // Numbered list
        if (/^\d+\. /.test(line)) {
          const match = line.match(/^(\d+)\. (.*)/);
          return (
            <p key={i} className="flex gap-1.5 mt-0.5">
              <span style={{color:"#7C3AED", flexShrink:0, minWidth:16}}>{match[1]}.</span>
              <span>{formatInline(match[2])}</span>
            </p>
          );
        }
        return <p key={i} className="mt-0.5">{formatInline(line)}</p>;
      })}
    </div>
  );
}

function formatInline(text) {
  // bold **text**, inline code `text`
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/);
  return parts.map((p, i) => {
    if (p.startsWith("**") && p.endsWith("**")) return <strong key={i} className="text-white font-black">{p.slice(2,-2)}</strong>;
    if (p.startsWith("`") && p.endsWith("`")) return <code key={i} className="px-1 py-0.5 rounded text-xs font-mono" style={{background:"rgba(124,58,237,0.2)",color:"#A78BFA"}}>{p.slice(1,-1)}</code>;
    return <span key={i}>{p}</span>;
  });
}

/* Message bubble */
function MessageBubble({ msg, isLatest, isStreaming }) {
  const [copied, setCopied] = useState(false);

  const copy = () => {
    navigator.clipboard.writeText(msg.content);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  if (msg.role === "user") {
    return (
      <div className="flex justify-end animate-slide-up">
        <div className="max-w-[86%] rounded-2xl rounded-br-md px-4 py-3" style={{
          background:"linear-gradient(135deg, #2D6BE4, #1A4FC7)",
          boxShadow:"0 4px 16px rgba(45,107,228,0.35)"
        }}>
          <p className="text-sm text-white leading-relaxed">{msg.content}</p>
          {msg.ts && <p className="text-xs mt-1.5 opacity-50 text-right">{msg.ts}</p>}
        </div>
      </div>
    );
  }

  return (
    <div className="flex justify-start animate-slide-up">
      <div className="max-w-[88%] group">
        <div className="rounded-2xl rounded-bl-md px-4 py-3" style={{
          background:"linear-gradient(135deg, rgba(255,255,255,0.04), rgba(255,255,255,0.02))",
          border:"1px solid rgba(124,58,237,0.2)",
          boxShadow:"0 4px 16px rgba(0,0,0,0.2)"
        }}>
          <div className="flex items-center gap-2 mb-2">
            <div className="p-1 rounded-md" style={{background:"rgba(124,58,237,0.2)"}}>
              <Brain size={10} style={{color:"#A78BFA"}}/>
            </div>
            <span className="text-xs font-black" style={{color:"#A78BFA"}}>CIPHER</span>
            <span className="text-xs ml-auto" style={{color:"#334155"}}>{msg.ts}</span>
          </div>
          {isLatest && isStreaming ? (
            <TypewriterText text={msg.content} speed={8}/>
          ) : (
            <MdText content={msg.content}/>
          )}
        </div>
        <button onClick={copy} className="mt-1 ml-1 flex items-center gap-1 text-xs opacity-0 group-hover:opacity-100 transition-opacity" style={{color:"#475569"}}>
          {copied ? <><Check size={10} style={{color:"#22C55E"}}/><span style={{color:"#22C55E"}}>Copied!</span></> : <><Copy size={10}/><span>Copy</span></>}
        </button>
      </div>
    </div>
  );
}

/* Quick Action chip */
function QuickChip({ label, icon: Icon, color, onClick }) {
  return (
    <button onClick={onClick}
      className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold flex-shrink-0 transition-all hover:brightness-125"
      style={{background:`${color}12`, border:`1px solid ${color}28`, color}}>
      <Icon size={11} style={{color}}/>
      {label}
    </button>
  );
}

function CipherAI({ messages, input, setInput, onSend, loading, sample }) {
  const endRef = useRef(null);
  const inputRef = useRef(null);
  const [streamIdx, setStreamIdx] = useState(-1);

  useEffect(() => {
    endRef.current?.scrollIntoView({behavior:"smooth"});
    // Mark latest assistant message as streaming
    const lastAssist = messages.map((m,i)=>[m,i]).filter(([m])=>m.role==="assistant").pop();
    if (lastAssist) setStreamIdx(lastAssist[1]);
  }, [messages]);

  const handleKey = (e) => {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); onSend(); }
  };

  const suggestions = sample ? [
    { label:"What type of malware?", icon:Brain, color:"#7C3AED" },
    { label:"List all IOCs", icon:Target, color:"#EF4444" },
    { label:"MITRE ATT&CK TTPs", icon:AlertTriangle, color:"#F97316" },
    { label:"Draft incident report", icon:FileText, color:"#2D6BE4" },
    { label:"Containment steps", icon:ShieldAlert, color:"#22C55E" },
  ] : [
    { label:"How does ransomware work?", icon:Brain, color:"#7C3AED" },
    { label:"Explain process injection", icon:AlertTriangle, color:"#F97316" },
    { label:"What is Cobalt Strike?", icon:Target, color:"#EF4444" },
    { label:"Triage methodology", icon:FileText, color:"#2D6BE4" },
  ];

  return (
    <div className="flex flex-col" style={{height:"82vh"}}>

      {/* Header */}
      <div className="flex items-center gap-3 mb-4 pb-4" style={{borderBottom:"1px solid #1A2540"}}>
        <div className="relative">
          <div className="p-2.5 rounded-2xl" style={{background:"linear-gradient(135deg, rgba(124,58,237,0.25), rgba(124,58,237,0.1))", border:"1px solid rgba(124,58,237,0.3)"}}>
            <Brain size={22} style={{color:"#A78BFA"}}/>
          </div>
          <span className="absolute -top-1 -right-1 w-3 h-3 rounded-full live-dot" style={{background:"#22C55E", boxShadow:"0 0 8px #22C55E", border:"2px solid #060A18"}}/>
        </div>
        <div className="flex-1">
          <h1 className="text-xl font-black text-white tracking-tight flex items-center gap-2">
            CIPHER
            <span className="text-xs font-normal px-2 py-0.5 rounded-full" style={{background:"rgba(124,58,237,0.15)",color:"#A78BFA"}}>AI v2.0</span>
          </h1>
          <p className="text-xs" style={{color:"#475569"}}>Forensic Investigation Assistant · powered by your backend</p>
        </div>
        <button onClick={() => { setInput(""); onSend && messages.length > 1 && null; }}
          className="p-2 rounded-lg transition-all hover:bg-white/5" style={{color:"#334155"}} title="Clear context">
          <RefreshCw size={13}/>
        </button>
      </div>

      {/* Sample Context */}
      {sample && (
        <div className="flex items-center gap-3 px-3 py-2.5 rounded-xl mb-4 animate-fade-in" style={{
          background:"linear-gradient(135deg, rgba(124,58,237,0.1), rgba(45,107,228,0.05))",
          border:"1px solid rgba(124,58,237,0.25)"
        }}>
          <div className="p-1.5 rounded-lg" style={{background:"rgba(124,58,237,0.2)"}}>
            <ShieldAlert size={13} style={{color:"#A78BFA"}}/>
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-xs font-bold text-white truncate">{sample.filename}</p>
            <p className="text-xs" style={{color:"#7C3AED"}}>Risk Score: {sample.risk_score}/100 · {sample.threat_level} · Context loaded</p>
          </div>
          <Sparkles size={12} style={{color:"#7C3AED", flexShrink:0}}/>
        </div>
      )}

      {/* Messages */}
      <div className="flex-1 overflow-y-auto space-y-4 pr-1 mb-3">
        {messages.length === 0 && (
          <div className="flex flex-col items-center justify-center h-full text-center py-12">
            <div className="p-4 rounded-3xl mb-4" style={{background:"rgba(124,58,237,0.1)", border:"1px solid rgba(124,58,237,0.2)"}}>
              <Brain size={32} style={{color:"#7C3AED"}}/>
            </div>
            <h2 className="text-lg font-black text-white mb-1">Ask CIPHER Anything</h2>
            <p className="text-sm" style={{color:"#475569"}}>
              {sample ? "Sample context loaded. Ask me about this malware." : "Your AI forensics assistant is ready."}
            </p>
          </div>
        )}

        {messages.map((msg, i) => (
          <MessageBubble
            key={i}
            msg={{...msg, ts: msg.ts || ""}}
            isLatest={i === messages.length - 1}
            isStreaming={i === streamIdx && loading}
          />
        ))}

        {loading && (
          <div className="flex justify-start animate-fade-in">
            <div className="px-4 py-3 rounded-2xl rounded-bl-md" style={{background:"rgba(124,58,237,0.1)", border:"1px solid rgba(124,58,237,0.2)"}}>
              <div className="flex items-center gap-2">
                <Brain size={11} style={{color:"#A78BFA"}}/>
                <div className="flex gap-1">
                  <span className="typing-dot"/>
                  <span className="typing-dot"/>
                  <span className="typing-dot"/>
                </div>
                <span className="text-xs" style={{color:"#475569"}}>Analyzing…</span>
              </div>
            </div>
          </div>
        )}
        <div ref={endRef}/>
      </div>

      {/* Quick Suggestions */}
      {messages.length <= 1 && (
        <div className="flex gap-2 overflow-x-auto pb-2 mb-2" style={{scrollbarWidth:"none"}}>
          {suggestions.map(s => (
            <QuickChip key={s.label} label={s.label} icon={s.icon} color={s.color}
              onClick={() => { setInput(s.label); setTimeout(() => onSend(), 50); }}/>
          ))}
        </div>
      )}

      {/* Input */}
      <div className="relative" style={{
        background:"linear-gradient(135deg, rgba(255,255,255,0.04), rgba(255,255,255,0.01))",
        border:"1px solid rgba(124,58,237,0.25)",
        borderRadius:16,
        boxShadow:"0 4px 16px rgba(0,0,0,0.2)"
      }}>
        <textarea
          ref={inputRef}
          rows={2}
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={handleKey}
          placeholder={sample ? `Ask about ${sample.filename}…` : "Ask about malware, TTPs, IOCs, forensics…"}
          className="w-full bg-transparent text-sm text-white placeholder-slate-600 resize-none outline-none px-4 pt-3 pb-12"
          style={{fontFamily:"inherit"}}
        />
        <div className="absolute bottom-0 left-0 right-0 flex items-center justify-between px-3 pb-3">
          <span className="text-xs" style={{color:"#334155"}}>Enter to send · Shift+Enter for newline</span>
          <button
            onClick={onSend}
            disabled={loading || !input.trim()}
            className="flex items-center gap-2 px-4 py-1.5 rounded-xl text-sm font-bold text-white transition-all disabled:opacity-30 btn-primary"
          >
            {loading ? <RefreshCw size={13} className="animate-spin"/> : <Send size={13}/>}
            Send
          </button>
        </div>
      </div>
    </div>
  );
}


export default CipherAI;
