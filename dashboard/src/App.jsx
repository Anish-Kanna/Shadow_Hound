import React, { createContext, useContext, useState, useEffect } from "react";
import { BrowserRouter as Router, Routes, Route, Navigate, Link, useNavigate } from "react-router-dom";

// ── Auth Context ──────────────────────────────────────────────────────────────

const AuthContext = createContext(null);

export function useAuth() {
  return useContext(AuthContext);
}

function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem("shadowhound_token"));

  useEffect(() => {
    if (token) {
      fetch("/api/v1/auth/me", { headers: { Authorization: `Bearer ${token}` } })
        .then((r) => (r.ok ? r.json() : null))
        .then((u) => setUser(u))
        .catch(() => { setToken(null); localStorage.removeItem("shadowhound_token"); });
    }
  }, [token]);

  const login = async (email, password) => {
    const res = await fetch("/api/v1/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    if (!res.ok) throw new Error("Invalid credentials");
    const data = await res.json();
    localStorage.setItem("shadowhound_token", data.access_token);
    setToken(data.access_token);
  };

  const logout = () => {
    localStorage.removeItem("shadowhound_token");
    setToken(null);
    setUser(null);
  };

  const authFetch = async (url, options = {}) => {
    const res = await fetch(url, {
      ...options,
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json", ...options.headers },
    });
    if (res.status === 401) { logout(); return null; }
    return res;
  };

  return (
    <AuthContext.Provider value={{ user, token, login, logout, authFetch }}>
      {children}
    </AuthContext.Provider>
  );
}

// ── API helpers ───────────────────────────────────────────────────────────────

function useAPI() {
  const { authFetch } = useAuth();
  const base = "/api/v1";

  return {
    getHunts: (params = "") => authFetch(`${base}/hunts${params}`).then((r) => r?.json()),
    getHunt: (id) => authFetch(`${base}/hunts/${id}`).then((r) => r?.json()),
    createHunt: (body) => authFetch(`${base}/hunts`, { method: "POST", body: JSON.stringify(body) }).then((r) => r?.json()),
    cancelHunt: (id) => authFetch(`${base}/hunts/${id}/cancel`, { method: "POST", body: JSON.stringify({}) }).then((r) => r?.json()),
    getReport: (id) => authFetch(`${base}/hunts/${id}/report`).then((r) => (r && r.ok ? r.json() : null)),
    approveQuery: (huntId, queryId, body = {}) =>
      authFetch(`${base}/hunts/${huntId}/queries/${queryId}/approve`, { method: "POST", body: JSON.stringify(body) }).then((r) => r?.json()),
    rejectQuery: (huntId, queryId, reason) =>
      authFetch(`${base}/hunts/${huntId}/queries/${queryId}/reject`, { method: "POST", body: JSON.stringify({ rejection_reason: reason }) }).then((r) => r?.json()),
    bulkApprove: (huntId, queryIds) =>
      authFetch(`${base}/hunts/${huntId}/queries/bulk-approve`, { method: "POST", body: JSON.stringify({ query_ids: queryIds }) }).then((r) => r?.json()),
  };
}

// ── Shared styles ─────────────────────────────────────────────────────────────

const COLORS = {
  dark: "#1F3864", mid: "#2E5FA3", accent: "#4A90D9",
  light: "#D6E4F0", bg: "#F2F4F7", text: "#1A1A2E",
  danger: "#C0392B", warning: "#F39C12", success: "#27AE60",
};

const STATUS_COLORS = {
  pending: COLORS.bg, hypothesizing: COLORS.accent, planning: COLORS.accent,
  awaiting_approval: COLORS.warning, executing: COLORS.accent,
  analyzing: COLORS.accent, reporting: COLORS.accent,
  completed: COLORS.success, failed: COLORS.danger, cancelled: "#888",
};

const VERDICT_COLORS = {
  confirmed_threat: COLORS.danger, inconclusive: COLORS.warning,
  no_finding: COLORS.success, pending: "#888",
};

// ── Login Page ────────────────────────────────────────────────────────────────

function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true); setError("");
    try {
      await login(email, password);
      navigate("/");
    } catch {
      setError("Invalid email or password");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ minHeight: "100vh", background: COLORS.dark, display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div style={{ background: "white", borderRadius: 8, padding: 48, width: 380, boxShadow: "0 20px 60px rgba(0,0,0,0.3)" }}>
        <div style={{ textAlign: "center", marginBottom: 32 }}>
          <div style={{ fontSize: 28, fontWeight: 700, color: COLORS.dark }}>ShadowHound</div>
          <div style={{ fontSize: 14, color: "#666", marginTop: 4 }}>Threat Hunting Agent</div>
        </div>
        <form onSubmit={handleSubmit}>
          <input
            type="email" placeholder="Email" value={email} onChange={(e) => setEmail(e.target.value)}
            style={inputStyle} required
          />
          <input
            type="password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)}
            style={{ ...inputStyle, marginTop: 12 }} required
          />
          {error && <div style={{ color: COLORS.danger, fontSize: 13, marginTop: 8 }}>{error}</div>}
          <button type="submit" disabled={loading} style={primaryBtnStyle}>
            {loading ? "Signing in…" : "Sign In"}
          </button>
        </form>
      </div>
    </div>
  );
}

// ── Layout ────────────────────────────────────────────────────────────────────

function Layout({ children }) {
  const { user, logout } = useAuth();
  return (
    <div style={{ display: "flex", minHeight: "100vh", background: COLORS.bg, fontFamily: "Arial, sans-serif" }}>
      {/* Sidebar */}
      <div style={{ width: 220, background: COLORS.dark, display: "flex", flexDirection: "column", padding: "24px 0" }}>
        <div style={{ padding: "0 24px 24px", borderBottom: `1px solid rgba(255,255,255,0.1)` }}>
          <div style={{ fontSize: 18, fontWeight: 700, color: "white" }}>ShadowHound</div>
          <div style={{ fontSize: 12, color: "rgba(255,255,255,0.5)", marginTop: 2 }}>Threat Hunter</div>
        </div>
        <nav style={{ padding: "16px 0", flex: 1 }}>
          {[
            { to: "/", label: "Dashboard" },
            { to: "/hunts", label: "Hunt Sessions" },
            { to: "/hunts/new", label: "New Hunt" },
            { to: "/approval", label: "Approval Queue" },
          ].map(({ to, label }) => (
            <Link key={to} to={to} style={{ display: "block", padding: "10px 24px", color: "rgba(255,255,255,0.8)", textDecoration: "none", fontSize: 14 }}>
              {label}
            </Link>
          ))}
        </nav>
        <div style={{ padding: "16px 24px", borderTop: `1px solid rgba(255,255,255,0.1)` }}>
          <div style={{ color: "rgba(255,255,255,0.6)", fontSize: 12 }}>{user?.full_name}</div>
          <div style={{ color: "rgba(255,255,255,0.4)", fontSize: 11 }}>{user?.role}</div>
          <button onClick={logout} style={{ marginTop: 8, color: COLORS.accent, background: "none", border: "none", cursor: "pointer", fontSize: 12, padding: 0 }}>
            Sign out
          </button>
        </div>
      </div>
      {/* Main */}
      <div style={{ flex: 1, padding: 32, overflowY: "auto" }}>{children}</div>
    </div>
  );
}

// ── Dashboard ─────────────────────────────────────────────────────────────────

function Dashboard() {
  const api = useAPI();
  const [stats, setStats] = useState(null);
  const [recent, setRecent] = useState([]);

  useEffect(() => {
    api.getHunts("?page=1&page_size=5").then((data) => {
      if (data) {
        setRecent(data.items || []);
        const items = data.items || [];
        setStats({
          total: data.total,
          active: items.filter((h) => !["completed","failed","cancelled"].includes(h.status)).length,
          threats: items.filter((h) => h.verdict === "confirmed_threat").length,
          pending_approval: items.filter((h) => h.status === "awaiting_approval").length,
        });
      }
    });
  }, []);

  return (
    <div>
      <h1 style={{ color: COLORS.dark, marginBottom: 8 }}>Dashboard</h1>
      <p style={{ color: "#666", marginBottom: 32 }}>Threat Hunting Operations Overview</p>

      {stats && (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16, marginBottom: 32 }}>
          {[
            { label: "Total Hunts", value: stats.total, color: COLORS.mid },
            { label: "Active", value: stats.active, color: COLORS.accent },
            { label: "Threats Confirmed", value: stats.threats, color: COLORS.danger },
            { label: "Awaiting Approval", value: stats.pending_approval, color: COLORS.warning },
          ].map(({ label, value, color }) => (
            <div key={label} style={{ background: "white", borderRadius: 8, padding: 20, borderLeft: `4px solid ${color}`, boxShadow: "0 1px 4px rgba(0,0,0,0.08)" }}>
              <div style={{ fontSize: 28, fontWeight: 700, color }}>{value}</div>
              <div style={{ fontSize: 13, color: "#666", marginTop: 4 }}>{label}</div>
            </div>
          ))}
        </div>
      )}

      <div style={{ background: "white", borderRadius: 8, padding: 24, boxShadow: "0 1px 4px rgba(0,0,0,0.08)" }}>
        <h3 style={{ color: COLORS.dark, marginBottom: 16 }}>Recent Hunts</h3>
        {recent.map((hunt) => (
          <HuntRow key={hunt.id} hunt={hunt} />
        ))}
        {recent.length === 0 && <div style={{ color: "#888", fontSize: 14 }}>No hunts yet. Start a new hunt to begin.</div>}
      </div>
    </div>
  );
}

// ── Hunt List ─────────────────────────────────────────────────────────────────

function HuntList() {
  const api = useAPI();
  const [data, setData] = useState({ items: [], total: 0 });
  const [page, setPage] = useState(1);

  useEffect(() => {
    api.getHunts(`?page=${page}&page_size=20`).then((d) => d && setData(d));
  }, [page]);

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 24 }}>
        <h1 style={{ color: COLORS.dark }}>Hunt Sessions</h1>
        <Link to="/hunts/new" style={{ ...primaryBtnStyle, textDecoration: "none", display: "inline-block", width: "auto", padding: "10px 20px" }}>
          New Hunt
        </Link>
      </div>
      <div style={{ background: "white", borderRadius: 8, boxShadow: "0 1px 4px rgba(0,0,0,0.08)" }}>
        {data.items.map((hunt) => <HuntRow key={hunt.id} hunt={hunt} />)}
        {data.items.length === 0 && <div style={{ padding: 24, color: "#888" }}>No hunt sessions found.</div>}
      </div>
      {data.total > 20 && (
        <div style={{ marginTop: 16, display: "flex", gap: 8, justifyContent: "center" }}>
          <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1} style={secondaryBtnStyle}>Prev</button>
          <span style={{ padding: "8px 12px", color: "#666" }}>Page {page}</span>
          <button onClick={() => setPage(p => p + 1)} disabled={page * 20 >= data.total} style={secondaryBtnStyle}>Next</button>
        </div>
      )}
    </div>
  );
}

function HuntRow({ hunt }) {
  if (!hunt) return null;
  const statusStr = hunt.status ? String(hunt.status) : "unknown";
  const verdictStr = hunt && hunt.verdict ? String(hunt.verdict) : "pending";
  const statusColor = STATUS_COLORS[statusStr] || "#888";
  const verdictColor = VERDICT_COLORS[verdictStr] || "#888";

  return (
    <Link to={`/hunts/${hunt.id}`} style={{ display: "flex", alignItems: "center", padding: "16px 24px", borderBottom: `1px solid ${COLORS.bg}`, textDecoration: "none", color: COLORS.text }}>
      <div style={{ flex: 1 }}>
        <div style={{ fontWeight: 600, fontSize: 15 }}>{hunt.title}</div>
        <div style={{ fontSize: 12, color: "#888", marginTop: 2 }}>
          {hunt.trigger_type} · {hunt.created_at ? new Date(hunt.created_at).toLocaleString() : "just now"}
        </div>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <span style={{ background: statusColor, color: "white", padding: "4px 12px", borderRadius: 12, fontSize: 12, fontWeight: 600 }}>
          {statusStr.replace(/_/g, " ").toUpperCase()}
        </span>
        {verdictStr !== "pending" && (
          <span style={{ background: verdictColor, color: "white", padding: "4px 12px", borderRadius: 12, fontSize: 12, fontWeight: 600 }}>
            {verdictStr.replace(/_/g, " ").toUpperCase()}
          </span>
        )}
        {typeof hunt.final_confidence === "number" && (
          <span style={{ fontSize: 13, color: "#666", fontWeight: 600 }}>{hunt.final_confidence.toFixed(0)}%</span>
        )}
      </div>
    </Link>
  );
}

// ── New Hunt Form ─────────────────────────────────────────────────────────────

function NewHunt() {
  const api = useAPI();
  const navigate = useNavigate();
  const [form, setForm] = useState({
    title: "", trigger_type: "analyst_request",
    trigger_context: { description: "", threat_actor: "", cve: "", affected_systems: "" },
    max_iterations: 5, confidence_threshold: 70,
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true); setError("");
    const payload = {
      ...form,
      trigger_context: Object.fromEntries(
        Object.entries(form.trigger_context).filter(([, v]) => v.trim() !== "")
      ),
    };
    const result = await api.createHunt(payload);
    if (result?.id) {
      navigate(`/hunts/${result.id}`);
    } else {
      setError("Failed to create hunt. Please try again.");
      setLoading(false);
    }
  };

  return (
    <div style={{ maxWidth: 680 }}>
      <h1 style={{ color: COLORS.dark, marginBottom: 8 }}>New Hunt Session</h1>
      <p style={{ color: "#666", marginBottom: 32 }}>Configure and launch a new threat hunting session</p>

      <form onSubmit={handleSubmit} style={{ background: "white", borderRadius: 8, padding: 32, boxShadow: "0 1px 4px rgba(0,0,0,0.08)" }}>
        <label style={labelStyle}>Hunt Title *</label>
        <input style={inputStyle} value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} placeholder="e.g. Suspected lateral movement via WMI" required />

        <label style={{ ...labelStyle, marginTop: 20 }}>Trigger Type *</label>
        <select style={inputStyle} value={form.trigger_type} onChange={(e) => setForm({ ...form, trigger_type: e.target.value })}>
          <option value="analyst_request">Analyst Request</option>
          <option value="scheduled">Scheduled Hunt</option>
          <option value="intel_alert">Threat Intel Alert</option>
        </select>

        <label style={{ ...labelStyle, marginTop: 20 }}>Context: Description</label>
        <textarea style={{ ...inputStyle, height: 80, resize: "vertical" }}
          value={form.trigger_context.description}
          onChange={(e) => setForm({ ...form, trigger_context: { ...form.trigger_context, description: e.target.value } })}
          placeholder="Describe what you want to hunt for or what triggered this hunt…"
        />

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginTop: 16 }}>
          <div>
            <label style={labelStyle}>Threat Actor (optional)</label>
            <input style={inputStyle} value={form.trigger_context.threat_actor}
              onChange={(e) => setForm({ ...form, trigger_context: { ...form.trigger_context, threat_actor: e.target.value } })}
              placeholder="e.g. APT29, Lazarus Group" />
          </div>
          <div>
            <label style={labelStyle}>CVE (optional)</label>
            <input style={inputStyle} value={form.trigger_context.cve}
              onChange={(e) => setForm({ ...form, trigger_context: { ...form.trigger_context, cve: e.target.value } })}
              placeholder="e.g. CVE-2024-XXXX" />
          </div>
        </div>

        <label style={{ ...labelStyle, marginTop: 16 }}>Affected Systems (optional)</label>
        <input style={inputStyle} value={form.trigger_context.affected_systems}
          onChange={(e) => setForm({ ...form, trigger_context: { ...form.trigger_context, affected_systems: e.target.value } })}
          placeholder="e.g. Windows endpoints, AD controllers, finance network segment" />

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginTop: 20 }}>
          <div>
            <label style={labelStyle}>Max Iterations</label>
            <input type="number" min={1} max={10} style={inputStyle} value={form.max_iterations}
              onChange={(e) => setForm({ ...form, max_iterations: parseInt(e.target.value) })} />
          </div>
          <div>
            <label style={labelStyle}>Confidence Threshold (%)</label>
            <input type="number" min={50} max={99} style={inputStyle} value={form.confidence_threshold}
              onChange={(e) => setForm({ ...form, confidence_threshold: parseInt(e.target.value) })} />
          </div>
        </div>

        {error && <div style={{ color: COLORS.danger, fontSize: 13, marginTop: 12 }}>{error}</div>}

        <div style={{ display: "flex", gap: 12, marginTop: 24 }}>
          <button type="submit" disabled={loading} style={primaryBtnStyle}>
            {loading ? "Launching…" : "Launch Hunt"}
          </button>
          <Link to="/hunts" style={{ ...secondaryBtnStyle, textDecoration: "none", display: "inline-block" }}>
            Cancel
          </Link>
        </div>
      </form>
    </div>
  );
}

// ── Hunt Detail ───────────────────────────────────────────────────────────────

function HuntDetail() {
  const { id } = useParams();
  const api = useAPI();
  const [hunt, setHunt] = useState(null);
  const [tab, setTab] = useState("overview");
  const [pollInterval, setPollInterval] = useState(null);

  useEffect(() => {
    const load = () => api.getHunt(id).then((h) => h && setHunt(h));
    load();
    const iv = setInterval(load, 2000);
    return () => clearInterval(iv);
  }, [id]);

  if (!hunt) return <div style={{ padding: 32, color: "#888" }}>Loading hunt…</div>;

  const isActive = !["completed", "failed", "cancelled"].includes(hunt.status);
  const pendingQueries = (hunt.queries || []).filter((q) => q.status === "pending_approval");

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 24 }}>
        <div>
          <h1 style={{ color: COLORS.dark, marginBottom: 4 }}>{hunt.title}</h1>
          <div style={{ color: "#888", fontSize: 13 }}>
            {hunt.trigger_type} · Started {hunt.started_at ? new Date(hunt.started_at).toLocaleString() : "not yet"}
          </div>
        </div>
        <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
          <span style={{ background: STATUS_COLORS[hunt.status] || "#eee", color: "white", padding: "6px 14px", borderRadius: 16, fontSize: 13, fontWeight: 600 }}>
            {hunt.status.replace(/_/g, " ").toUpperCase()}
          </span>
          {isActive && (
            <button onClick={() => api.cancelHunt(hunt.id)} style={{ ...secondaryBtnStyle, color: COLORS.danger, borderColor: COLORS.danger }}>
              Cancel Hunt
            </button>
          )}
        </div>
      </div>

      {pendingQueries.length > 0 && (
        <div style={{ background: "#FFF3CD", border: `1px solid ${COLORS.warning}`, borderRadius: 8, padding: 16, marginBottom: 24 }}>
          <strong style={{ color: "#856404" }}>⚠️ {pendingQueries.length} quer{pendingQueries.length === 1 ? "y" : "ies"} awaiting your approval</strong>
          <p style={{ color: "#856404", margin: "4px 0 0", fontSize: 13 }}>
            The hunt is paused. Review and approve queries to continue.
          </p>
          <button onClick={() => setTab("queries")} style={{ ...primaryBtnStyle, marginTop: 8, width: "auto", padding: "8px 16px" }}>
            Review Queries
          </button>
        </div>
      )}

      {/* Stats bar */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 12, marginBottom: 24 }}>
        {[
          { label: "Iteration", value: `${hunt.current_iteration}/${hunt.max_iterations}` },
          { label: "Hypotheses", value: (hunt.hypotheses || []).length },
          { label: "Queries", value: (hunt.queries || []).length },
          { label: "Evidence", value: (hunt.evidence || []).length },
          { label: "Confidence", value: hunt.final_confidence ? `${hunt.final_confidence.toFixed(0)}%` : "—" },
        ].map(({ label, value }) => (
          <div key={label} style={{ background: "white", borderRadius: 8, padding: 16, textAlign: "center", boxShadow: "0 1px 4px rgba(0,0,0,0.08)" }}>
            <div style={{ fontSize: 22, fontWeight: 700, color: COLORS.mid }}>{value}</div>
            <div style={{ fontSize: 11, color: "#888" }}>{label}</div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div style={{ display: "flex", gap: 2, marginBottom: 20, borderBottom: `2px solid ${COLORS.bg}` }}>
        {["overview", "hypotheses", "queries", "evidence", "report"].map((t) => (
          <button key={t} onClick={() => setTab(t)} style={{
            padding: "10px 20px", background: "none", border: "none", cursor: "pointer",
            color: tab === t ? COLORS.mid : "#888", fontWeight: tab === t ? 700 : 400,
            borderBottom: tab === t ? `2px solid ${COLORS.mid}` : "2px solid transparent",
            textTransform: "capitalize", fontSize: 14,
          }}>{t}</button>
        ))}
      </div>

      {tab === "overview" && <HuntOverview hunt={hunt} />}
      {tab === "hypotheses" && <HypothesesTab hypotheses={hunt.hypotheses || []} />}
      {tab === "queries" && <QueriesTab hunt={hunt} onRefresh={() => api.getHunt(id).then((h) => h && setHunt(h))} />}
      {tab === "evidence" && <EvidenceTab evidence={hunt.evidence || []} />}
      {tab === "report" && <ReportTab huntId={hunt.id} status={hunt.status} />}
    </div>
  );
}

function HuntOverview({ hunt }) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
      <div style={{ background: "white", borderRadius: 8, padding: 20, boxShadow: "0 1px 4px rgba(0,0,0,0.08)" }}>
        <h3 style={{ color: COLORS.dark, marginBottom: 12 }}>Trigger Context</h3>
        {Object.entries(hunt.trigger_context || {}).map(([k, v]) => (
          <div key={k} style={{ marginBottom: 8 }}>
            <div style={{ fontSize: 11, color: "#888", textTransform: "uppercase" }}>{k.replace(/_/g, " ")}</div>
            <div style={{ fontSize: 14, color: COLORS.text }}>{v || "—"}</div>
          </div>
        ))}
      </div>
      <div style={{ background: "white", borderRadius: 8, padding: 20, boxShadow: "0 1px 4px rgba(0,0,0,0.08)" }}>
        <h3 style={{ color: COLORS.dark, marginBottom: 12 }}>Hunt Settings</h3>
        {[
          ["Max Iterations", hunt.max_iterations],
          ["Confidence Threshold", `${hunt.confidence_threshold}%`],
          ["Analyst", hunt.analyst_id?.slice(0, 8) + "…"],
          ["Created", new Date(hunt.created_at).toLocaleString()],
        ].map(([k, v]) => (
          <div key={k} style={{ display: "flex", justifyContent: "space-between", padding: "6px 0", borderBottom: `1px solid ${COLORS.bg}` }}>
            <span style={{ color: "#888", fontSize: 13 }}>{k}</span>
            <span style={{ color: COLORS.text, fontSize: 13, fontWeight: 600 }}>{v}</span>
          </div>
        ))}
      </div>
      {hunt.error_message && (
        <div style={{ gridColumn: "1 / -1", background: "#FEE", border: `1px solid ${COLORS.danger}`, borderRadius: 8, padding: 16, color: COLORS.danger }}>
          <strong>Error:</strong> {hunt.error_message}
        </div>
      )}
    </div>
  );
}

function HypothesesTab({ hypotheses }) {
  const sorted = [...hypotheses].sort((a, b) => a.priority_rank - b.priority_rank);
  return (
    <div>
      {sorted.map((h) => (
        <div key={h.id} style={{ background: "white", borderRadius: 8, padding: 20, marginBottom: 12, boxShadow: "0 1px 4px rgba(0,0,0,0.08)", borderLeft: `4px solid ${h.is_active ? COLORS.accent : COLORS.bg}` }}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
            <span style={{ fontWeight: 700, color: COLORS.dark }}>#{h.priority_rank} — {h.priority_label.toUpperCase()}</span>
            <span style={{ fontSize: 12, color: "#888" }}>Iteration {h.iteration}</span>
          </div>
          <p style={{ color: COLORS.text, margin: "0 0 12px", lineHeight: 1.5 }}>{h.description}</p>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
            {[...(h.mitre_tactics || []), ...(h.mitre_techniques || [])].map((t) => (
              <span key={t} style={{ background: COLORS.light, color: COLORS.mid, padding: "2px 8px", borderRadius: 4, fontSize: 12, fontFamily: "monospace" }}>{t}</span>
            ))}
          </div>
        </div>
      ))}
      {hypotheses.length === 0 && <div style={{ color: "#888" }}>No hypotheses generated yet.</div>}
    </div>
  );
}

function QueriesTab({ hunt, onRefresh }) {
  const api = useAPI();
  const [rejectingId, setRejectingId] = useState(null);
  const [rejectReason, setRejectReason] = useState("");
  const [editingId, setEditingId] = useState(null);
  const [editedQuery, setEditedQuery] = useState("");

  const handleApprove = async (queryId) => {
    const body = editingId === queryId && editedQuery ? { modified_query: editedQuery } : {};
    await api.approveQuery(hunt.id, queryId, body);
    setEditingId(null); setEditedQuery("");
    onRefresh();
  };

  const handleReject = async (queryId) => {
    if (!rejectReason.trim()) return;
    await api.rejectQuery(hunt.id, queryId, rejectReason);
    setRejectingId(null); setRejectReason("");
    onRefresh();
  };

  const handleBulkApprove = async () => {
    const pending = (hunt.queries || []).filter((q) => q.status === "pending_approval").map((q) => q.id);
    if (pending.length === 0) return;
    await api.bulkApprove(hunt.id, pending);
    onRefresh();
  };

  const queries = hunt.queries || [];
  const pendingCount = queries.filter((q) => q.status === "pending_approval").length;

  return (
    <div>
      {pendingCount > 0 && (
        <div style={{ marginBottom: 16, display: "flex", justifyContent: "flex-end" }}>
          <button onClick={handleBulkApprove} style={{ ...primaryBtnStyle, width: "auto", padding: "8px 20px" }}>
            Approve All ({pendingCount})
          </button>
        </div>
      )}
      {queries.map((q) => (
        <div key={q.id} style={{ background: "white", borderRadius: 8, padding: 20, marginBottom: 12, boxShadow: "0 1px 4px rgba(0,0,0,0.08)", borderLeft: `4px solid ${q.status === "pending_approval" ? COLORS.warning : q.status === "approved" || q.status === "executed" ? COLORS.success : q.status === "rejected" ? COLORS.danger : "#ccc"}` }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
            <span style={{ fontWeight: 700, color: COLORS.dark, fontSize: 14 }}>{q.data_source.toUpperCase()} · {q.query_language}</span>
            <span style={{
              fontSize: 12, fontWeight: 700, padding: "4px 12px", borderRadius: 12,
              background: q.status === "pending_approval" ? "#FFFBEB" : q.status === "approved" || q.status === "executed" ? "#F0FDF4" : "#FEF2F2",
              color: q.status === "pending_approval" ? "#B45309" : q.status === "approved" || q.status === "executed" ? "#15803D" : "#B91C1C",
              border: `1px solid ${q.status === "pending_approval" ? "#FCD34D" : q.status === "approved" || q.status === "executed" ? "#86EFAC" : "#FCA5A5"}`
            }}>{q.status.replace(/_/g, " ").toUpperCase()}</span>
          </div>
          <p style={{ fontSize: 13.5, color: "#334155", fontWeight: 500, margin: "0 0 12px", lineHeight: 1.4 }}>{q.query_rationale}</p>

          {editingId === q.id ? (
            <textarea value={editedQuery} onChange={(e) => setEditedQuery(e.target.value)}
              style={{ ...inputStyle, fontFamily: "monospace", fontSize: 13, height: 120, color: "#0F172A", background: "#F8FAFC", border: "1px solid #94A3B8" }} />
          ) : (
            <pre style={{
              background: "#0F172A",
              color: "#38BDF8",
              padding: "14px 16px",
              borderRadius: 6,
              fontSize: 13,
              fontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace",
              fontWeight: 500,
              lineHeight: 1.5,
              border: "1px solid #1E293B",
              overflowX: "auto",
              margin: "0 0 14px",
              whiteSpace: "pre-wrap",
              boxShadow: "inset 0 1px 3px rgba(0,0,0,0.5)"
            }}>
              {q.modified_query || q.query_text}
            </pre>
          )}

          {q.rows_returned !== null && q.rows_returned !== undefined && (
            <div style={{ fontSize: 12, color: "#888", marginBottom: 8 }}>
              {q.rows_returned} rows · {q.execution_duration_ms}ms
            </div>
          )}

          {q.rejection_reason && (
            <div style={{ color: COLORS.danger, fontSize: 13, marginBottom: 8 }}>Rejection reason: {q.rejection_reason}</div>
          )}

          {q.status === "pending_approval" && (
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              <button onClick={() => handleApprove(q.id)} style={{ ...primaryBtnStyle, width: "auto", padding: "7px 16px" }}>Approve</button>
              <button onClick={() => { setEditingId(editingId === q.id ? null : q.id); setEditedQuery(q.query_text); }} style={{ ...secondaryBtnStyle, width: "auto", padding: "7px 16px" }}>
                {editingId === q.id ? "Cancel Edit" : "Edit & Approve"}
              </button>
              {rejectingId === q.id ? (
                <>
                  <input value={rejectReason} onChange={(e) => setRejectReason(e.target.value)}
                    placeholder="Rejection reason (required)" style={{ ...inputStyle, width: 200, display: "inline" }} />
                  <button onClick={() => handleReject(q.id)} style={{ ...secondaryBtnStyle, width: "auto", padding: "7px 16px", color: COLORS.danger, borderColor: COLORS.danger }}>Confirm</button>
                </>
              ) : (
                <button onClick={() => setRejectingId(q.id)} style={{ ...secondaryBtnStyle, width: "auto", padding: "7px 16px", color: COLORS.danger, borderColor: COLORS.danger }}>Reject</button>
              )}
            </div>
          )}
        </div>
      ))}
      {queries.length === 0 && <div style={{ color: "#888" }}>No queries generated yet.</div>}
    </div>
  );
}

function EvidenceTab({ evidence }) {
  const classColors = { confirming: COLORS.success, contradicting: COLORS.danger, neutral: "#888" };
  return (
    <div>
      {evidence.map((ev) => (
        <div key={ev.id} style={{ background: "white", borderRadius: 8, padding: 20, marginBottom: 12, boxShadow: "0 1px 4px rgba(0,0,0,0.08)", borderLeft: `4px solid ${classColors[ev.classification] || "#ccc"}` }}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
            <span style={{ fontWeight: 600, color: COLORS.dark }}>{ev.data_source.toUpperCase()}</span>
            <div style={{ display: "flex", gap: 8 }}>
              <span style={{ background: classColors[ev.classification], color: "white", padding: "2px 8px", borderRadius: 10, fontSize: 12 }}>{ev.classification}</span>
              <span style={{ background: COLORS.bg, color: COLORS.dark, padding: "2px 8px", borderRadius: 10, fontSize: 12, fontWeight: 700 }}>{ev.confidence_score.toFixed(0)}%</span>
            </div>
          </div>
          <p style={{ color: COLORS.text, margin: "0 0 8px", fontSize: 14 }}>{ev.summary}</p>
          <p style={{ color: "#888", fontSize: 13, margin: "0 0 8px", fontStyle: "italic" }}>{ev.confidence_reasoning}</p>
          {ev.iocs_extracted?.length > 0 && (
            <div style={{ marginTop: 8 }}>
              <strong style={{ fontSize: 12, color: COLORS.mid }}>IOCs:</strong>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginTop: 4 }}>
                {ev.iocs_extracted.map((ioc, i) => (
                  <span key={i} style={{ background: COLORS.light, color: COLORS.mid, padding: "2px 6px", borderRadius: 4, fontSize: 11, fontFamily: "monospace" }}>
                    {ioc.type}: {ioc.value?.slice(0, 30)}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      ))}
      {evidence.length === 0 && <div style={{ color: "#888" }}>No evidence collected yet.</div>}
    </div>
  );
}

function ReportTab({ huntId, status }) {
  const api = useAPI();
  const { token } = useAuth();
  const [report, setReport] = useState(null);

  useEffect(() => {
    let interval;
    const fetchReport = () => {
      api.getReport(huntId).then((r) => {
        if (r) setReport(r);
      });
    };

    fetchReport();
    if (status === "reporting" || status === "executing" || status === "analyzing" || status === "completed") {
      interval = setInterval(fetchReport, 2000);
    }
    return () => clearInterval(interval);
  }, [huntId, status]);

  if (!report && status !== "completed") {
    return (
      <div style={{ background: "white", borderRadius: 8, padding: 30, textAlign: "center", boxShadow: "0 1px 4px rgba(0,0,0,0.08)" }}>
        <div style={{ fontSize: 16, fontWeight: 600, color: COLORS.mid, marginBottom: 8 }}>
          ⚡ AI Threat Report is being generated…
        </div>
        <p style={{ color: "#666", fontSize: 13, margin: 0 }}>
          Synthesizing evidence, mapping MITRE ATT&CK techniques, and compiling analyst recommendations.
        </p>
      </div>
    );
  }
  if (!report) return <div style={{ color: "#888", padding: 20 }}>Loading report…</div>;

  const verdictStr = report.verdict ? String(report.verdict) : "pending";
  const verdictColor = VERDICT_COLORS[verdictStr] || "#888";
  const confidenceVal = typeof report.final_confidence === "number" ? report.final_confidence : 0;

  return (
    <div>
      <div style={{ background: "white", borderRadius: 8, padding: 24, marginBottom: 16, boxShadow: "0 1px 4px rgba(0,0,0,0.08)", borderTop: `4px solid ${verdictColor}` }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
          <span style={{ background: verdictColor, color: "white", padding: "6px 16px", borderRadius: 16, fontWeight: 700, fontSize: 14 }}>
            {verdictStr.replace(/_/g, " ").toUpperCase()}
          </span>
          <span style={{ fontSize: 20, fontWeight: 700, color: verdictColor }}>{confidenceVal.toFixed(0)}% Confidence</span>
        </div>
        <h3 style={{ color: COLORS.dark, marginBottom: 8 }}>Executive Summary</h3>
        <p style={{ color: COLORS.text, lineHeight: 1.6 }}>{report.executive_summary || "Report generated."}</p>
      </div>

      {report.analyst_recommendations?.length > 0 && (
        <div style={{ background: "white", borderRadius: 8, padding: 24, marginBottom: 16, boxShadow: "0 1px 4px rgba(0,0,0,0.08)" }}>
          <h3 style={{ color: COLORS.dark, marginBottom: 12 }}>Recommendations</h3>
          {report.analyst_recommendations.map((rec, i) => (
            <div key={i} style={{ padding: 12, borderLeft: `3px solid ${rec.priority === "immediate" ? COLORS.danger : rec.priority === "short_term" ? COLORS.warning : COLORS.accent}`, marginBottom: 10, background: COLORS.bg, borderRadius: "0 6px 6px 0" }}>
              <span style={{ fontSize: 11, fontWeight: 700, textTransform: "uppercase", color: "#888" }}>{rec.priority}</span>
              <div style={{ fontWeight: 600, color: COLORS.dark, margin: "4px 0 2px" }}>{rec.action}</div>
              <div style={{ fontSize: 13, color: "#666" }}>{rec.rationale}</div>
            </div>
          ))}
        </div>
      )}

      <div style={{ display: "flex", gap: 12 }}>
        {["pdf", "json", "md"].map((fmt) => (
          <a key={fmt} href={`/api/v1/hunts/${huntId}/report/download?format=${fmt}&token=${token}`}
            style={{ ...secondaryBtnStyle, textDecoration: "none", display: "inline-block", textAlign: "center" }}>
            Download {fmt.toUpperCase()}
          </a>
        ))}
      </div>
    </div>
  );
}

// ── Approval Queue Page ───────────────────────────────────────────────────────

function ApprovalQueue() {
  const api = useAPI();
  const [hunts, setHunts] = useState([]);

  useEffect(() => {
    api.getHunts("?page=1&page_size=50").then((data) => {
      if (data) {
        setHunts((data.items || []).filter((h) => h.status === "awaiting_approval"));
      }
    });
  }, []);

  return (
    <div>
      <h1 style={{ color: COLORS.dark, marginBottom: 8 }}>Approval Queue</h1>
      <p style={{ color: "#666", marginBottom: 24 }}>Hunt sessions waiting for query approval</p>
      {hunts.length === 0 && <div style={{ color: "#888" }}>No hunts currently awaiting approval.</div>}
      {hunts.map((h) => (
        <div key={h.id} style={{ background: "white", borderRadius: 8, padding: 20, marginBottom: 12, boxShadow: "0 1px 4px rgba(0,0,0,0.08)", borderLeft: `4px solid ${COLORS.warning}` }}>
          <div style={{ fontWeight: 600, color: COLORS.dark }}>{h.title}</div>
          <div style={{ fontSize: 13, color: "#888", margin: "4px 0 12px" }}>{h.trigger_type}</div>
          <Link to={`/hunts/${h.id}?tab=queries`} style={{ ...primaryBtnStyle, textDecoration: "none", display: "inline-block", width: "auto", padding: "8px 16px" }}>
            Review Queries
          </Link>
        </div>
      ))}
    </div>
  );
}

// ── Shared component styles ───────────────────────────────────────────────────

const inputStyle = {
  width: "100%", padding: "10px 12px", border: `1px solid #d0d7e2`, borderRadius: 6,
  fontSize: 14, color: COLORS.text, background: "white", boxSizing: "border-box", outline: "none",
};
const primaryBtnStyle = {
  width: "100%", padding: "12px", background: COLORS.mid, color: "white", border: "none",
  borderRadius: 6, fontSize: 15, fontWeight: 600, cursor: "pointer", marginTop: 16,
};
const secondaryBtnStyle = {
  padding: "8px 16px", background: "white", color: COLORS.mid, border: `1px solid ${COLORS.mid}`,
  borderRadius: 6, fontSize: 14, cursor: "pointer",
};
const labelStyle = { display: "block", fontSize: 13, fontWeight: 600, color: "#555", marginBottom: 6 };

// ── Missing imports ───────────────────────────────────────────────────────────
import { useParams } from "react-router-dom";

// ── App Root ──────────────────────────────────────────────────────────────────

function ProtectedRoute({ children }) {
  const { user, token } = useAuth();
  if (!token) return <Navigate to="/login" replace />;
  return children;
}

export default function App() {
  return (
    <AuthProvider>
      <Router>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/" element={<ProtectedRoute><Layout><Dashboard /></Layout></ProtectedRoute>} />
          <Route path="/hunts" element={<ProtectedRoute><Layout><HuntList /></Layout></ProtectedRoute>} />
          <Route path="/hunts/new" element={<ProtectedRoute><Layout><NewHunt /></Layout></ProtectedRoute>} />
          <Route path="/hunts/:id" element={<ProtectedRoute><Layout><HuntDetail /></Layout></ProtectedRoute>} />
          <Route path="/approval" element={<ProtectedRoute><Layout><ApprovalQueue /></Layout></ProtectedRoute>} />
        </Routes>
      </Router>
    </AuthProvider>
  );
}
