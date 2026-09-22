import React, { useState, useEffect, useRef } from "react";
import { Shield, Eye, EyeOff, Loader, AlertTriangle, Lock, Zap, Brain, Target } from "lucide-react";
import { TokenStore } from "../api/client";

// ================================================================
//  LOGIN SCREEN — Premium v2 (Glassmorphism + Hex Grid)
// ================================================================

/* Floating particle */
function Particle({ style }) {
  return <div className="particle" style={style}/>;
}

function LoginScreen({ api, onLogin }) {
  const [username, setUser] = useState("");
  const [password, setPass] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [showPass, setShowPass] = useState(false);
  const [seeding, setSeeding] = useState(false);
  const [focused, setFocused] = useState(null);
  const [mounted, setMounted] = useState(false);

  useEffect(() => { setTimeout(() => setMounted(true), 50); }, []);

  // Random particles
  const particles = [
    { width:80, height:80, top:"10%",  left:"15%",  animationDuration:"7s",  animationDelay:"0s",   opacity:0.15 },
    { width:120,height:120,top:"70%",  left:"5%",   animationDuration:"9s",  animationDelay:"1s",   opacity:0.1  },
    { width:60, height:60, top:"30%",  left:"85%",  animationDuration:"6s",  animationDelay:"2s",   opacity:0.2  },
    { width:100,height:100,top:"80%",  left:"80%",  animationDuration:"11s", animationDelay:"0.5s", opacity:0.12 },
    { width:40, height:40, top:"50%",  left:"50%",  animationDuration:"8s",  animationDelay:"3s",   opacity:0.1  },
    { width:70, height:70, top:"15%",  left:"65%",  animationDuration:"10s", animationDelay:"1.5s", opacity:0.15 },
  ];

  const handleLogin = async (e) => {
    e?.preventDefault();
    if (!username.trim() || !password.trim()) { setError("Enter username and password."); return; }
    setLoading(true); setError("");
    try {
      const data = await api.login(username.trim(), password.trim());
      TokenStore.set(data);
      onLogin(data);
    } catch(e) {
      setError(e.message?.includes("401") ? "Invalid credentials. Try seeding admin below." : (e.message || "Login failed."));
    } finally { setLoading(false); }
  };

  const seedAdmin = async () => {
    setSeeding(true); setError("");
    try {
      await api.seedAdmin();
      setUser("admin"); setPass("CyberForge@2026");
    } catch(e) {
      setError("Seed admin: " + (e.message || "failed — admin may already exist"));
    } finally { setSeeding(false); }
  };

  return (
    <div className="fixed inset-0 flex items-center justify-center hex-grid-bg overflow-hidden"
      style={{fontFamily:"system-ui,-apple-system,sans-serif"}}>

      {/* Particles */}
      {particles.map((p, i) => <Particle key={i} style={p}/>)}

      {/* Central radial glow */}
      <div className="absolute top-1/2 left-1/2 pointer-events-none" style={{
        transform:"translate(-50%,-50%)",
        width:600, height:600,
        background:"radial-gradient(circle, rgba(45,107,228,0.12) 0%, rgba(124,58,237,0.06) 40%, transparent 70%)",
        borderRadius:"50%"
      }}/>

      {/* Top-right accent */}
      <div className="absolute top-0 right-0 pointer-events-none" style={{
        width:400, height:400,
        background:"radial-gradient(circle at top right, rgba(124,58,237,0.1) 0%, transparent 60%)"
      }}/>

      {/* Login Card */}
      <div className={`relative z-10 w-full max-w-sm px-4 transition-all duration-700 ${mounted ? "opacity-100 translate-y-0" : "opacity-0 translate-y-8"}`}>

        {/* Logo section */}
        <div className="text-center mb-8 animate-fade-in">
          <div className="relative inline-flex items-center justify-center mb-5">
            {/* Outer ring */}
            <div className="absolute w-24 h-24 rounded-full border animate-spin-slow" style={{
              borderColor:"transparent",
              borderTopColor:"rgba(45,107,228,0.5)",
              borderRightColor:"rgba(45,107,228,0.2)"
            }}/>
            {/* Inner */}
            <div className="w-16 h-16 rounded-2xl flex items-center justify-center animate-neon" style={{
              background:"linear-gradient(135deg, rgba(45,107,228,0.3), rgba(124,58,237,0.2))",
              border:"1px solid rgba(45,107,228,0.5)",
              color:"#2D6BE4"
            }}>
              <Shield size={28} style={{color:"#60A5FA"}}/>
            </div>
          </div>

          <h1 className="text-3xl font-black text-white tracking-tight" style={{
            background:"linear-gradient(135deg, #fff, #93C5FD)",
            WebkitBackgroundClip:"text", WebkitTextFillColor:"transparent"
          }}>CYBER FORGE</h1>
          <p className="text-xs mt-2 tracking-widest uppercase font-bold" style={{color:"#334155"}}>
            AI Forensics Platform · v3.0
          </p>

          {/* Feature pills */}
          <div className="flex items-center justify-center gap-2 mt-3">
            {[{icon:Brain, label:"AI", color:"#7C3AED"},{icon:Target, label:"YARA", color:"#EF4444"},{icon:Zap, label:"Real-time", color:"#F97316"}].map(f=>(
              <span key={f.label} className="flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold" style={{
                background:`${f.color}12`, color:f.color, border:`1px solid ${f.color}25`
              }}>
                <f.icon size={9} style={{color:f.color}}/>{f.label}
              </span>
            ))}
          </div>
        </div>

        {/* Glassmorphism Card */}
        <div className="rounded-3xl p-6 animate-scale-in" style={{
          background:"linear-gradient(135deg, rgba(13,17,34,0.9), rgba(7,14,27,0.95))",
          border:"1px solid rgba(255,255,255,0.08)",
          backdropFilter:"blur(20px)",
          WebkitBackdropFilter:"blur(20px)",
          boxShadow:"0 30px 80px rgba(0,0,0,0.6), inset 0 1px 0 rgba(255,255,255,0.06)"
        }}>
          <p className="text-sm font-black text-white mb-1">Analyst Sign In</p>
          <p className="text-xs mb-5" style={{color:"#475569"}}>Authenticate to access forensics platform</p>

          {error && (
            <div className="mb-4 px-3 py-2.5 rounded-xl flex items-start gap-2 animate-fade-in" style={{
              background:"rgba(239,68,68,0.08)", border:"1px solid rgba(239,68,68,0.25)"
            }}>
              <AlertTriangle size={12} style={{color:"#EF4444", flexShrink:0, marginTop:1}}/>
              <span className="text-xs" style={{color:"#FCA5A5"}}>{error}</span>
            </div>
          )}

          <form onSubmit={handleLogin} className="space-y-3">
            {/* Username */}
            <div>
              <label className="text-xs font-bold mb-1.5 block flex items-center gap-1.5" style={{color:"#64748B"}}>
                <Lock size={10}/> USERNAME
              </label>
              <input
                value={username}
                onChange={e=>setUser(e.target.value)}
                placeholder="analyst"
                onFocus={()=>setFocused("user")}
                onBlur={()=>setFocused(null)}
                className="w-full px-4 py-3 rounded-xl text-sm text-white outline-none transition-all"
                style={{
                  background:"rgba(255,255,255,0.04)",
                  border:`1px solid ${focused==="user" ? "rgba(45,107,228,0.7)" : "rgba(255,255,255,0.08)"}`,
                  boxShadow: focused==="user" ? "0 0 0 3px rgba(45,107,228,0.1)" : "none",
                  fontFamily:"inherit"
                }}
                autoComplete="username"
              />
            </div>

            {/* Password */}
            <div>
              <label className="text-xs font-bold mb-1.5 block flex items-center gap-1.5" style={{color:"#64748B"}}>
                <Lock size={10}/> PASSWORD
              </label>
              <div className="relative">
                <input
                  value={password}
                  onChange={e=>setPass(e.target.value)}
                  type={showPass?"text":"password"}
                  placeholder="••••••••"
                  onFocus={()=>setFocused("pass")}
                  onBlur={()=>setFocused(null)}
                  className="w-full px-4 py-3 rounded-xl text-sm text-white outline-none pr-11 transition-all"
                  style={{
                    background:"rgba(255,255,255,0.04)",
                    border:`1px solid ${focused==="pass" ? "rgba(45,107,228,0.7)" : "rgba(255,255,255,0.08)"}`,
                    boxShadow: focused==="pass" ? "0 0 0 3px rgba(45,107,228,0.1)" : "none",
                    fontFamily:"inherit"
                  }}
                  autoComplete="current-password"
                />
                <button
                  type="button"
                  onClick={()=>setShowPass(v=>!v)}
                  className="absolute right-3.5 top-1/2 -translate-y-1/2 transition-colors hover:text-white"
                  style={{color:"#475569"}}>
                  {showPass ? <Eye size={14}/> : <EyeOff size={14}/>}
                </button>
              </div>
            </div>

            {/* Submit */}
            <button
              type="submit"
              disabled={loading}
              className="w-full py-3 rounded-xl text-sm font-black text-white mt-1 flex items-center justify-center gap-2 transition-all"
              style={{
                background: loading ? "rgba(255,255,255,0.05)" : "linear-gradient(135deg, #2D6BE4, #7C3AED)",
                border: loading ? "1px solid rgba(255,255,255,0.1)" : "1px solid rgba(45,107,228,0.5)",
                boxShadow: loading ? "none" : "0 8px 24px rgba(45,107,228,0.35)",
              }}>
              {loading ? (
                <><Loader size={14} className="animate-spin"/> Authenticating…</>
              ) : (
                <>Sign In <span className="opacity-60">→</span></>
              )}
            </button>
          </form>

          {/* Seed admin */}
          <div className="mt-4 pt-4" style={{borderTop:"1px solid rgba(255,255,255,0.06)"}}>
            <p className="text-xs text-center mb-2.5" style={{color:"#334155"}}>
              First time? Seed the default admin account:
            </p>
            <button
              onClick={seedAdmin}
              disabled={seeding}
              className="w-full py-2.5 rounded-xl text-xs font-bold transition-all hover:bg-white/5"
              style={{color:"#475569", border:"1px solid rgba(255,255,255,0.06)"}}>
              {seeding ? "Seeding…" : "⚡ Seed Admin (admin / CyberForge@2026)"}
            </button>
          </div>
        </div>

        <p className="text-center text-xs mt-5" style={{color:"#1A2540"}}>
          AI-Powered Malware Analysis &amp; Digital Forensics
        </p>
      </div>
    </div>
  );
}

export default LoginScreen;
