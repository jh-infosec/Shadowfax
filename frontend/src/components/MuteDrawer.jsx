import React, { useCallback, useEffect, useState } from "react";
import * as api from "../api.js";

// Muted alerts (v0.42): rules that hide a kind of alert from some agents or
// targets, for a reason, until a date.
//
// Muting hides, it never deletes. Muted alerts stay on each agent's timeline,
// "Show muted" brings them back into the table, and a rule that ends or runs
// out of time brings them back for everyone. Making or ending a rule is
// written into the ledger with who did it and why.
//
// Everything a rule or the server says is shown as plain text.

function reason(err) {
  const d = err.detail;
  if (d && Array.isArray(d.problems)) return d.problems.join(" ");
  return typeof d === "string" ? d : err.message;
}

function when(iso) {
  if (!iso) return "";
  return iso.replace("T", " ").slice(0, 16);
}

function counts(bySeverity) {
  const order = ["critical", "high", "medium", "low", "info"];
  const parts = order.filter((s) => bySeverity[s]).map((s) => `${bySeverity[s]} ${s}`);
  return parts.length ? parts.join(", ") : "nothing yet";
}

function RuleRow({ rule, canAnalyst, onChanged, onError }) {
  const [busy, setBusy] = useState(false);
  const [ending, setEnding] = useState(false);
  const [why, setWhy] = useState("");
  const end = async (e) => {
    e.preventDefault();
    setBusy(true);
    try {
      await api.endSuppression(rule.id, why.trim());
      onChanged();
    } catch (err) {
      onError(reason(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className={`mute-rule ${rule.state}`}>
      <div className="mute-rule-top">
        <div className="mute-rule-name">
          <span className="mono">{rule.category}</span>
          <span className="mute-state">{rule.state}</span>
        </div>
        {canAnalyst && rule.state === "active" && !ending && (
          <button className="btn" onClick={() => setEnding(true)}>End now</button>
        )}
      </div>
      <div className="mute-where">
        agents <span className="mono">{rule.actor}</span>, targets <span className="mono">{rule.target}</span>
      </div>
      <div className="mute-reason">{rule.reason}</div>
      {ending && (
        <form className="intel-row mute-end" onSubmit={end}>
          <input placeholder="Why end it? (optional)" value={why} onChange={(e) => setWhy(e.target.value)}
                 aria-label="Why end the rule" />
          <button className="btn primary" type="submit" disabled={busy}>End it</button>
          <button className="btn" type="button" onClick={() => setEnding(false)}>Keep</button>
        </form>
      )}
      <div className="mute-meta">
        by {rule.created_by}, {when(rule.created_at)}
        {rule.state === "active" && <> · ends {when(rule.expires_at)} · muting {counts(rule.muting)}</>}
        {rule.state === "expired" && <> · ran out {when(rule.expires_at)}</>}
        {rule.state === "ended" && (
          <> · ended by {rule.ended_by}, {when(rule.ended_at)}{rule.end_reason ? `: ${rule.end_reason}` : ""}</>
        )}
      </div>
    </div>
  );
}

function NewRule({ draft, maxDays, defaultDays, onMade, onError }) {
  const [form, setForm] = useState({
    category: draft?.category || "",
    actor: draft?.actor || "",
    target: draft?.target || "*",
    reason: "",
    days: defaultDays,
  });
  const [preview, setPreview] = useState(null);
  const [problem, setProblem] = useState(null);
  const [busy, setBusy] = useState(false);
  const set = (k) => (e) => {
    setForm({ ...form, [k]: k === "days" ? Number(e.target.value) : e.target.value });
    setPreview(null);
  };

  const look = async () => {
    setProblem(null);
    try {
      setPreview(await api.previewSuppression(form));
    } catch (e) {
      setProblem(reason(e));
    }
  };

  const make = async (e) => {
    e.preventDefault();
    setProblem(null);
    setBusy(true);
    try {
      await api.createSuppression(form);
      onMade();
    } catch (err) {
      setProblem(reason(err));
    } finally {
      setBusy(false);
    }
  };

  const days = [7, 30, maxDays].filter((d, i, a) => d <= maxDays && a.indexOf(d) === i);
  return (
    <form className="intel-add mute-new" onSubmit={make}>
      <div className="risk-label">Mute a false positive</div>
      <div className="intel-row">
        <input placeholder="Alert category" value={form.category} onChange={set("category")} required
               className="mono" aria-label="Alert category" />
      </div>
      <div className="intel-row">
        <input placeholder="Agents (* for any)" value={form.actor} onChange={set("actor")} required
               className="mono" aria-label="Agent pattern" />
        <input placeholder="Targets (* for any)" value={form.target} onChange={set("target")} required
               className="mono" aria-label="Target pattern" />
      </div>
      <div className="intel-note">Use * for "anything", like backup-agent-* or *.internal.</div>
      <textarea className="mute-why" placeholder="Why is this a false positive? Whoever reads it later will want to know."
                value={form.reason} onChange={set("reason")} required aria-label="Reason" />
      <select value={form.days} onChange={set("days")} aria-label="How long">
        {days.map((d) => <option key={d} value={d}>For {d} days</option>)}
      </select>
      {problem && <div className="intel-bad">{problem}</div>}
      {preview && (
        <div className="mute-preview">
          Right now this would mute {preview.total} alert{preview.total === 1 ? "" : "s"}
          {preview.total ? ` (${counts(preview.by_severity)}) from ${preview.agents} agent${preview.agents === 1 ? "" : "s"}` : ""}.
          {preview.examples.length > 0 && (
            <ul className="intel-hits">
              {preview.examples.map((x) => (
                <li key={x.id}><span className="mono">{x.actor_id}</span> on <span className="mono">{x.target}</span>: {x.message}</li>
              ))}
            </ul>
          )}
        </div>
      )}
      <div className="intel-actions">
        <button className="btn" type="button" onClick={look}>Preview</button>
        <button className="btn primary" type="submit" disabled={busy}>Mute</button>
      </div>
    </form>
  );
}

export default function MuteDrawer({ onClose, canAnalyst, draft, onChanged }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [formKey, setFormKey] = useState(0);

  const load = useCallback(() => {
    api.getSuppressions().then(setData).catch((e) => setError(reason(e)));
  }, []);
  useEffect(() => { load(); }, [load]);

  const changed = () => { setError(null); load(); onChanged(); };
  const active = data ? data.rules.filter((r) => r.state === "active") : [];
  const past = data ? data.rules.filter((r) => r.state !== "active") : [];

  return (
    <>
      <div className="drawer-overlay" onClick={onClose} />
      <div className="drawer intel-drawer mute-drawer">
        <div className="drawer-head">
          <div className="drawer-actor">Muted alerts</div>
          <button className="drawer-close" onClick={onClose} aria-label="Close">&times;</button>
        </div>
        <div className="lockout-rule">
          A rule hides one kind of alert from some agents or targets, for a reason, until a date. Muted
          alerts aren't deleted: they stay on each agent&apos;s timeline, and come back when the rule ends.
        </div>
        {error && <div className="error-banner">{error}</div>}
        {data === null && !error && <div className="empty-state">Loading…</div>}
        {data && (
          <div className="intel-body">
            {active.length === 0 && <div className="intel-empty">Nothing is muted.</div>}
            {active.map((r) => (
              <RuleRow key={r.id} rule={r} canAnalyst={canAnalyst} onChanged={changed} onError={setError} />
            ))}
            {canAnalyst && (
              <NewRule key={formKey} draft={draft} maxDays={data.max_days} defaultDays={data.default_days}
                       onMade={() => { setFormKey((k) => k + 1); changed(); }} onError={setError} />
            )}
            {past.length > 0 && (
              <>
                <div className="risk-label mute-past-label">Ended or run out</div>
                {past.map((r) => (
                  <RuleRow key={r.id} rule={r} canAnalyst={canAnalyst} onChanged={changed} onError={setError} />
                ))}
              </>
            )}
          </div>
        )}
      </div>
    </>
  );
}
