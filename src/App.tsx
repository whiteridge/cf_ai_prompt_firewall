import {
  Clipboard,
  History,
  LoaderCircle,
  RotateCcw,
  SendHorizontal,
  ShieldCheck,
  ShieldQuestion,
  Sparkles,
  Trash2,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { FormEvent } from "react";
import type { AuditMode, AuditResponse, AuditSession, ChatMessage, PromptAudit } from "./shared/types";

const SESSION_STORAGE_KEY = "cf_ai_prompt_firewall_session";

const starterMessage: ChatMessage = {
  id: "starter",
  role: "assistant",
  content:
    "Paste a system prompt, app description, or agent policy. I will audit it for prompt-injection, data leakage, unsafe actions, unclear tool permissions, missing refusals, and privacy risks.",
  createdAt: new Date().toISOString(),
};

function App() {
  const [sessionId] = useState(getOrCreateSessionId);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [audits, setAudits] = useState<PromptAudit[]>([]);
  const [selectedAuditId, setSelectedAuditId] = useState<string | null>(null);
  const [input, setInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    const controller = new AbortController();

    fetch(`/api/session?sessionId=${encodeURIComponent(sessionId)}`, {
      signal: controller.signal,
    })
      .then((response) => {
        if (!response.ok) throw new Error("Could not load audit history");
        return response.json() as Promise<AuditSession>;
      })
      .then((session) => {
        setMessages(session.messages);
        setAudits(session.audits);
      })
      .catch((loadError: unknown) => {
        if (loadError instanceof DOMException && loadError.name === "AbortError") return;
        setError(loadError instanceof Error ? loadError.message : "Could not load audit history");
      });

    return () => controller.abort();
  }, [sessionId]);

  const latestAudit = audits.at(-1) ?? null;
  const selectedAudit = useMemo(
    () => audits.find((audit) => audit.id === selectedAuditId) ?? latestAudit,
    [audits, latestAudit, selectedAuditId],
  );
  const visibleMessages = messages.length ? messages : [starterMessage];

  async function submitAudit(mode: AuditMode) {
    const trimmed = input.trim();
    const message = mode === "improve" && !trimmed && latestAudit ? latestAudit.originalPrompt : trimmed;

    if (!message) {
      setError("Add a prompt or select an existing audit first.");
      return;
    }

    setIsLoading(true);
    setError(null);
    setCopied(false);

    try {
      const response = await fetch("/api/audit", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ sessionId, message, mode }),
      });
      const payload = (await response.json()) as AuditResponse | { error?: string };

      if (!response.ok) {
        throw new Error("error" in payload && payload.error ? payload.error : "Audit failed");
      }

      const auditResponse = payload as AuditResponse;
      setMessages(auditResponse.session.messages);
      setAudits(auditResponse.session.audits);
      setSelectedAuditId(auditResponse.audit.id);
      setInput("");
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : "Audit failed");
    } finally {
      setIsLoading(false);
    }
  }

  async function clearCurrentSession() {
    setIsLoading(true);
    setError(null);
    try {
      const response = await fetch(`/api/session?sessionId=${encodeURIComponent(sessionId)}`, {
        method: "DELETE",
      });
      if (!response.ok) throw new Error("Could not clear session");
      setMessages([]);
      setAudits([]);
      setSelectedAuditId(null);
    } catch (clearError) {
      setError(clearError instanceof Error ? clearError.message : "Could not clear session");
    } finally {
      setIsLoading(false);
    }
  }

  async function copyImprovedPrompt() {
    if (!selectedAudit?.improvedPrompt) return;
    await navigator.clipboard.writeText(selectedAudit.improvedPrompt);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1800);
  }

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void submitAudit("audit");
  }

  return (
    <div className="app-shell">
      <main className="audit-workspace">
        <section className="chat-panel" aria-label="Audit chat">
          <header className="topbar">
            <div>
              <p className="eyebrow">Cloudflare AI security tool</p>
              <h1>cf_ai_prompt_firewall</h1>
            </div>
            <div className="topbar-actions">
              <span className="session-pill" title={sessionId}>
                <ShieldQuestion size={16} />
                {shortSession(sessionId)}
              </span>
              <button className="icon-button" onClick={clearCurrentSession} type="button" title="Clear session">
                <Trash2 size={17} />
              </button>
            </div>
          </header>

          <div className="conversation" aria-live="polite">
            {visibleMessages.map((message) => (
              <article className={`message ${message.role}`} key={message.id}>
                <div className="message-meta">
                  <span>{message.role === "user" ? "You" : "Prompt Firewall"}</span>
                  {message.mode ? <span>{message.mode}</span> : null}
                </div>
                <p>{message.content}</p>
              </article>
            ))}

            {isLoading ? (
              <article className="message assistant loading-row">
                <LoaderCircle className="spin" size={18} />
                Running audit through the Worker coordinator...
              </article>
            ) : null}

            {selectedAudit ? <AuditResultCard audit={selectedAudit} /> : null}
          </div>

          <form className="composer" onSubmit={handleSubmit}>
            {error ? <div className="error-banner">{error}</div> : null}
            <textarea
              value={input}
              onChange={(event) => setInput(event.target.value)}
              placeholder="Paste a prompt, policy, or follow-up question..."
              rows={5}
            />
            <div className="composer-actions">
              <button className="primary-action" disabled={isLoading} type="submit">
                {isLoading ? <LoaderCircle className="spin" size={17} /> : <ShieldCheck size={17} />}
                Run Audit
              </button>
              <button
                className="secondary-action"
                disabled={isLoading || (!input.trim() && !latestAudit)}
                onClick={() => void submitAudit("improve")}
                type="button"
              >
                <Sparkles size={17} />
                Generate Safer Prompt
              </button>
              <button
                className="secondary-action"
                disabled={!selectedAudit?.improvedPrompt}
                onClick={() => void copyImprovedPrompt()}
                type="button"
              >
                <Clipboard size={17} />
                {copied ? "Copied" : "Copy Improved Prompt"}
              </button>
              <button
                className="icon-button"
                disabled={isLoading || !input.trim()}
                onClick={() => void submitAudit("followup")}
                type="button"
                title="Ask follow-up"
              >
                <SendHorizontal size={17} />
              </button>
            </div>
          </form>
        </section>

        <aside className="audit-sidebar" aria-label="Audit history">
          <section className="score-panel">
            <div className="score-header">
              <span>Latest score</span>
              <ShieldCheck size={18} />
            </div>
            <div className={`score-value ${latestAudit ? severityClass(latestAudit.severity) : ""}`}>
              {latestAudit ? latestAudit.score : "--"}
            </div>
            <p>{latestAudit ? latestAudit.severity : "No audit yet"}</p>
          </section>

          <section className="history-panel">
            <div className="panel-title">
              <History size={18} />
              Audit history
            </div>
            <div className="history-list">
              {audits.length ? (
                [...audits].reverse().map((audit) => (
                  <button
                    className={`history-item ${selectedAudit?.id === audit.id ? "active" : ""}`}
                    key={audit.id}
                    onClick={() => setSelectedAuditId(audit.id)}
                    type="button"
                  >
                    <span className="history-score">{audit.score}</span>
                    <span>
                      <strong>{audit.severity}</strong>
                      <small>{new Date(audit.createdAt).toLocaleString()}</small>
                    </span>
                  </button>
                ))
              ) : (
                <div className="empty-history">
                  <RotateCcw size={18} />
                  Session memory is ready.
                </div>
              )}
            </div>
          </section>
        </aside>
      </main>
    </div>
  );
}

function AuditResultCard({ audit }: { audit: PromptAudit }) {
  return (
    <article className="audit-card">
      <div className="audit-card-header">
        <div>
          <p className="eyebrow">Audit result</p>
          <h2>
            {audit.score}/100 <span className={severityClass(audit.severity)}>{audit.severity}</span>
          </h2>
        </div>
        <ShieldCheck size={28} />
      </div>

      <p className="summary">{audit.summary}</p>

      <div className="audit-grid">
        <section>
          <h3>Top risks</h3>
          <ul className="finding-list">
            {audit.findings.slice(0, 3).map((finding) => (
              <li key={finding.id}>
                <strong>{finding.title}</strong>
                <span>
                  {finding.category} · {finding.severity}
                </span>
              </li>
            ))}
          </ul>
        </section>

        <section>
          <h3>Generated attacks</h3>
          <ul className="attack-list">
            {audit.attacks.slice(0, 4).map((attack) => (
              <li key={attack.id}>
                <strong>{attack.name}</strong>
                <code>{attack.prompt}</code>
              </li>
            ))}
          </ul>
        </section>
      </div>

      <section>
        <h3>Categorized findings</h3>
        <div className="finding-table">
          {audit.findings.map((finding) => (
            <div className="finding-row" key={finding.id}>
              <span>{finding.category}</span>
              <strong>{finding.title}</strong>
              <p>{finding.recommendation}</p>
            </div>
          ))}
        </div>
      </section>

      <section>
        <h3>Recommended mitigations</h3>
        <ul className="policy-list">
          {audit.policyRules.map((rule) => (
            <li key={rule}>{rule}</li>
          ))}
        </ul>
      </section>

      <section>
        <h3>Improved prompt</h3>
        <pre className="improved-prompt">{audit.improvedPrompt}</pre>
      </section>
    </article>
  );
}

function getOrCreateSessionId() {
  const existing = localStorage.getItem(SESSION_STORAGE_KEY);
  if (existing) return existing;
  const sessionId = `session_${crypto.randomUUID()}`;
  localStorage.setItem(SESSION_STORAGE_KEY, sessionId);
  return sessionId;
}

function shortSession(sessionId: string) {
  return sessionId.replace("session_", "").slice(0, 8);
}

function severityClass(severity: PromptAudit["severity"]) {
  return `severity-${severity.toLowerCase()}`;
}

export default App;
