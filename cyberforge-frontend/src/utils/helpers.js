// ================================================================
//  UTILITIES
// ================================================================


const scoreToThreat = (score, fileType) => {
  const ext = (fileType || "").toLowerCase();
  const isExeType = ["exe","dll","scr","bat","ps1","hta","pif","vbs","msi"].includes(ext);
  if (score >= 80) return { label: "CRITICAL", color: "#EF4444", bg: "rgba(239,68,68,0.12)" };
  if (score >= 60) return { label: "HIGH",     color: "#F97316", bg: "rgba(249,115,22,0.12)" };
  if (score >= 40) return { label: "MEDIUM",   color: "#EAB308", bg: "rgba(234,179,8,0.12)" };
  if (score >= 20) return { label: "LOW",      color: "#22C55E", bg: "rgba(34,197,94,0.12)" };
  // EXE-type files can never be CLEAN
  if (isExeType)   return { label: "LOW",      color: "#22C55E", bg: "rgba(34,197,94,0.12)" };
  return                  { label: "CLEAN",    color: "#22C55E", bg: "rgba(34,197,94,0.08)" };
};


const sevColor = (sev) =>
  ({ CRITICAL: "#EF4444", HIGH: "#F97316", MEDIUM: "#EAB308", LOW: "#22C55E",
     CLEAN: "#22C55E", INFO: "#3B82F6", ACTIVE: "#3B82F6", MALICIOUS:"#EF4444",
     SUSPICIOUS:"#F97316", LOW_RISK:"#EAB308" }[sev] || "#64748B");

const fmtBytes = (b) => {
  if (!b) return "0 B";
  if (b < 1024) return `${b} B`;
  if (b < 1024*1024) return `${(b/1024).toFixed(1)} KB`;
  return `${(b/1024/1024).toFixed(2)} MB`;
};


export { scoreToThreat, sevColor, fmtBytes };
