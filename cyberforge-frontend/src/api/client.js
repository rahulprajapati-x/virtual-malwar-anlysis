// ================================================================
//  API CLIENT
// ================================================================


const DEFAULT_API_BASE = "http://localhost:8000";

// Token storage helpers
const TokenStore = {
  get: () => { try { return JSON.parse(localStorage.getItem("cf_auth") || "null"); } catch { return null; } },
  set: (data) => localStorage.setItem("cf_auth", JSON.stringify(data)),
  clear: () => localStorage.removeItem("cf_auth"),
  getToken: () => TokenStore.get()?.access_token || null,
};

function createApiClient(apiBase) {
  const request = async (path, options = {}) => {
    const token = TokenStore.getToken();
    const isFormData = options.body instanceof FormData;

    const headers = {
      ...(!isFormData ? { "Content-Type": "application/json" } : {}),
      ...(token ? { "Authorization": `Bearer ${token}` } : {}),
      ...options.headers,
    };

    const res = await fetch(`${apiBase}${path}`, { ...options, headers });

    if (!res.ok) {
      let detail = res.statusText;
      try { const j = await res.json(); detail = j.detail || detail; } catch {}
      throw new Error(`${res.status}: ${detail}`);
    }
    const ct = res.headers.get("content-type") || "";
    if (ct.includes("application/json")) return res.json();
    return res;
  };

  return {
    health:        () => request("/api/health"),
    dashboardStats:() => request("/api/dashboard/stats"),
    weeklyActivity:() => request("/api/dashboard/weekly-activity"),
    threatFamilies:() => request("/api/dashboard/threat-families"),
    uploadSync: (file, caseId, submittedBy, enableDynamic) => {
      const fd = new FormData();
      fd.append("file", file);
      if (caseId) fd.append("case_id", caseId);
      fd.append("submitted_by", submittedBy || "analyst");
      fd.append("enable_dynamic", enableDynamic ? "true" : "false");
      return request("/api/samples/upload-sync", { method: "POST", body: fd });
    },
    uploadStream: (file, caseId, submittedBy, enableDynamic) => {
      const fd = new FormData();
      fd.append("file", file);
      if (caseId) fd.append("case_id", caseId);
      fd.append("submitted_by", submittedBy || "analyst");
      fd.append("enable_dynamic", enableDynamic ? "true" : "false");
      fd.append("enable_stream", "true");
      return request("/api/samples/upload", { method: "POST", body: fd });
    },
    runSandbox: (sampleId) => request(`/api/samples/${sampleId}/sandbox`, { method: "POST" }),
    getSample:  (id) => request(`/api/samples/${id}`),
    listSamples:(params = "") => request(`/api/samples${params}`),
    listCases:  () => request("/api/cases"),
    createCase: (payload) => request("/api/cases", { method: "POST", body: JSON.stringify(payload) }),
    updateCase: (id, payload) => request(`/api/cases/${id}`, { method: "PATCH", body: JSON.stringify(payload) }),
    assignCase: (sampleId, caseId) => {
      const fd = new FormData();
      fd.append("case_id", caseId);
      return request(`/api/samples/${sampleId}/case`, { method: "PATCH", body: fd });
    },
    cipherChat: (messages, sampleId) => request("/api/cipher/chat", {
      method: "POST",
      body: JSON.stringify({ messages, sample_id: sampleId || null }),
    }),
    mitreMatrix: () => request("/api/mitre/matrix"),
    iocs:       (params = "") => request(`/api/iocs${params}`),
    iocsExportUrl: () => `${apiBase}/api/iocs/export`,
    reportUrl:  (sampleId) => `${apiBase}/api/reports/sample/${sampleId}/pdf`,
    explainIndicator: (type, value, context) => request("/api/cipher/explain", {
      method: "POST",
      body: JSON.stringify({ type, value, context }),
    }),
    addCaseNote: (caseId, note) => request(`/api/cases/${caseId}/notes`, {
      method: "POST",
      body: JSON.stringify({ note, actor: "analyst" }),
    }),
    getCaseAudit: (caseId) => request(`/api/cases/${caseId}/audit`),

    // ── PCAP Analysis (Real backend) ──────────────────────────
    uploadPcap: (file) => {
      const fd = new FormData();
      fd.append("file", file);
      return request("/api/pcap/upload", { method: "POST", body: fd });
    },
    listPcap: () => request("/api/pcap"),
    getPcap: (id) => request(`/api/pcap/${id}`),
    pcapExportUrl: (id, format) => `${apiBase}/api/pcap/${id}/export?format=${format}`,

    // ── Hex Analyzer ──────────────────────────────────────────
    getHexChunk:    (sampleId, offset, size) => request(`/api/samples/${sampleId}/hex?offset=${offset}&size=${size}`),
    analyzeHex:     (sampleId) => request(`/api/samples/${sampleId}/hex/analyze`, { method: "POST" }),
    searchHex:      (sampleId, query, type) => request(`/api/samples/${sampleId}/hex/search`, {
      method: "POST",
      body: JSON.stringify({ query, search_type: type }),
    }),
    getHexIocsUrl:  (sampleId, format) => `${apiBase}/api/samples/${sampleId}/hex/iocs?format=${format}`,
    hexStats:       (sampleId, offset, size) => request(`/api/samples/${sampleId}/hex/stats?offset=${offset}&size=${size}`),
    hexPeSections:  (sampleId) => request(`/api/samples/${sampleId}/hex/pe-sections`),
    getHexStrings:  (sampleId, params = {}) => {
      const q = new URLSearchParams();
      if (params.minLen)      q.set("min_len",      params.minLen);
      if (params.encoding)    q.set("encoding",     params.encoding);
      if (params.category)    q.set("category",     params.category);
      if (params.search)      q.set("search",       params.search);
      if (params.offsetStart) q.set("offset_start", params.offsetStart);
      if (params.limit)       q.set("limit",        params.limit);
      return request(`/api/samples/${sampleId}/hex/strings?${q.toString()}`);
    },

    // ── Authentication ────────────────────────────────────────
    login: (username, password) => {
      const fd = new FormData();
      fd.append("username", username);
      fd.append("password", password);
      return request("/api/auth/login", { method: "POST", body: fd });
    },
    refreshToken: (refreshToken) => request("/api/auth/refresh", {
      method: "POST",
      body: JSON.stringify({ refresh_token: refreshToken }),
    }),
    getMe: () => request("/api/auth/me"),
    seedAdmin: () => request("/api/auth/seed-admin", { method: "POST" }),
    createUser: (payload) => request("/api/auth/users", { method: "POST", body: JSON.stringify(payload) }),
    listUsers: () => request("/api/auth/users"),
    changePassword: (currentPw, newPw) => request("/api/auth/change-password", {
      method: "POST",
      body: JSON.stringify({ current_password: currentPw, new_password: newPw }),
    }),
  };
}



export { createApiClient, TokenStore };
