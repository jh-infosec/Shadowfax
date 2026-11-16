import React, { useCallback, useEffect, useState } from "react";
import * as api from "../api.js";

// Threat intel (v0.39): the feeds of known-bad addresses that every agent
// action is checked against, and the team's own watchlists.
//
// Anyone signed in can see which feeds are on and whether they're working.
// Analysts can look an address up. Only admins add, switch off, refresh or
// remove feeds, and every one of those changes goes into the ledger: switching
// a feed off makes its alerts disappear, so who did it matters.
//
// Everything a feed or a server says is shown as plain text.

function relative(iso) {
  if (!iso) return "never";
  const then = new Date(iso + (iso.endsWith("Z") ? "" : "Z"));
  const secs = Math.max(0, Math.round((Date.now() - then.getTime()) / 1000));
  if (secs < 60) return "just now";
  if (secs < 3600) return `${Math.round(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.round(secs / 3600)}h ago`;
  return `${Math.round(secs / 86400)}d ago`;
}

function reason(err) {
  return typeof err.detail === "string" ? err.detail : err.message;
}

function Watchlist({ feed, canAdmin, onSaved }) {
  const [text, setText] = useState(null);
  const [note, setNote] = useState(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.getIntelEntries(feed.id).then((rows) => setText(rows.map((r) => r.value).join("\n")))
      .catch((e) => setNote(reason(e)));
  }, [feed.id]);

  const save = async () => {
    setBusy(true);
    setNote(null);
    try {
      const values = text.split(/[\s,]+/).filter(Boolean);
      const r = await api.setIntelEntries(feed.id, values);
      setNote(`${r.listed} listed: ${r.added} added, ${r.retired} dropped.` +
        (r.rejected.length ? ` Not used: ${r.rejected.join(", ")}` : ""));
      onSaved();
    } catch (e) {
      setNote(reason(e));
    } finally {
      setBusy(false);
    }
  };

  if (text === null) return <div className="intel-note">{note || "Loading…"}</div>;
  return (
    <div className="intel-watchlist">
      <textarea
        className="intel-entries"
        value={text}
        readOnly={!canAdmin}
        spellCheck={false}
        placeholder="One per line: an address, a network like 203.0.113.0/24, a domain or a full URL"
        onChange={(e) => setText(e.target.value)}
        aria-label={`Entries in ${feed.name}`}
      />
      {canAdmin && (
        <button className="btn primary" disabled={busy} onClick={save}>Save entries</button>
      )}
      {note && <div className="intel-note">{note}</div>}
    </div>
  );
}

function FeedRow({ feed, canAdmin, onChanged, onError }) {
  const [busy, setBusy] = useState(null);
  const [confirm, setConfirm] = useState(false);
  const [open, setOpen] = useState(false);
  const [result, setResult] = useState(null);

  const run = async (what, fn) => {
    setBusy(what);
    try {
      const r = await fn();
      if (what === "refresh") {
        setResult(r.ok ? `${r.listed} listed: ${r.added} new, ${r.retired} dropped` : null);
      }
      onChanged();
    } catch (e) {
      onError(reason(e));
    } finally {
      setBusy(null);
    }
  };

  const status = feed.last_error
    ? <span className="intel-bad">Last refresh failed: {feed.last_error}</span>
    : feed.kind === "manual"
      ? <span>{feed.listed} listed{feed.retired ? ` · ${feed.retired} dropped` : ""}</span>
      : feed.last_success_at
        ? <span>{feed.listed.toLocaleString()} listed · {feed.retired.toLocaleString()} dropped · refreshed {relative(feed.last_success_at)}</span>
        : <span className="intel-muted">Not downloaded yet</span>;

  return (
    <div className={`intel-feed ${feed.enabled ? "" : "off"}`}>
      <div className="intel-feed-top">
        <div className="intel-feed-name">
          {feed.name}
          <span className="intel-kind">{feed.kind === "manual" ? "watchlist" : "feed"}</span>
          <span className={`intel-sev ${feed.severity}`}>{feed.severity}</span>
          {!feed.enabled && <span className="intel-kind">off</span>}
        </div>
        {canAdmin && (
          <div className="intel-actions">
            {feed.kind === "remote" && (
              <button className="btn" disabled={!!busy}
                      onClick={() => run("refresh", () => api.refreshIntelFeed(feed.id))}>
                {busy === "refresh" ? "Refreshing…" : "Refresh now"}
              </button>
            )}
            <button className="btn" disabled={!!busy}
                    onClick={() => run("toggle", () => api.updateIntelFeed(feed.id, { enabled: !feed.enabled }))}>
              {feed.enabled ? "Switch off" : "Switch on"}
            </button>
            {confirm ? (
              <button className="btn danger" disabled={!!busy}
                      onClick={() => run("remove", () => api.removeIntelFeed(feed.id))}>
                Remove for good
              </button>
            ) : (
              <button className="btn" disabled={!!busy} onClick={() => setConfirm(true)}>Remove</button>
            )}
          </div>
        )}
      </div>
      {feed.description && <div className="intel-desc">{feed.description}</div>}
      {feed.url && <div className="intel-url mono">{feed.url}</div>}
      <div className="intel-status">{status}{result && <span> · {result}</span>}</div>
      {feed.kind === "manual" && (
        <>
          <button className="btn intel-edit" onClick={() => setOpen(!open)}>
            {open ? "Hide entries" : canAdmin ? "Edit entries" : "Show entries"}
          </button>
          {open && <Watchlist feed={feed} canAdmin={canAdmin} onSaved={onChanged} />}
        </>
      )}
    </div>
  );
}

function AddFeed({ presets, existing, onAdded, onError }) {
  const [choice, setChoice] = useState("");
  const [form, setForm] = useState({ name: "", url: "", format: "text", field: "", severity: "high" });
  const [busy, setBusy] = useState(false);
  const taken = new Set(existing.map((f) => f.name));
  const available = presets.filter((p) => !taken.has(p.name));
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value });

  const add = async (e) => {
    e.preventDefault();
    setBusy(true);
    try {
      if (choice === "watchlist") {
        await api.addIntelFeed({ watchlist: true, name: form.name, severity: form.severity });
      } else if (choice === "custom") {
        await api.addIntelFeed({ name: form.name, url: form.url, format: form.format,
                                 field: form.field || null, severity: form.severity });
      } else {
        await api.addIntelFeed({ preset: choice });
      }
      setChoice("");
      setForm({ name: "", url: "", format: "text", field: "", severity: "high" });
      onAdded();
    } catch (err) {
      onError(reason(err));
    } finally {
      setBusy(false);
    }
  };

  const preset = presets.find((p) => p.key === choice);
  return (
    <form className="intel-add" onSubmit={add}>
      <div className="risk-label">Add</div>
      <select value={choice} onChange={(e) => setChoice(e.target.value)} aria-label="What to add">
        <option value="">Choose a feed or a watchlist…</option>
        {available.map((p) => <option key={p.key} value={p.key}>{p.name}</option>)}
        <option value="watchlist">A watchlist of your own</option>
        <option value="custom">Another feed, by its address</option>
      </select>
      {preset && <div className="intel-desc">{preset.description}</div>}
      {(choice === "watchlist" || choice === "custom") && (
        <input placeholder="Name" value={form.name} onChange={set("name")} required maxLength={80} />
      )}
      {choice === "custom" && (
        <>
          <input placeholder="https://… (a key goes in as {env:SHADOWFAX_INTEL_NAME})" value={form.url}
                 onChange={set("url")} required className="mono" />
          <div className="intel-row">
            <select value={form.format} onChange={set("format")} aria-label="Format">
              <option value="text">One entry per line</option>
              <option value="csv">CSV</option>
              <option value="json">JSON</option>
            </select>
            {form.format !== "text" && (
              <input placeholder={form.format === "csv" ? "Column name or number" : "Field name"}
                     value={form.field} onChange={set("field")} required={form.format === "json"} />
            )}
          </div>
        </>
      )}
      {(choice === "watchlist" || choice === "custom") && (
        <select value={form.severity} onChange={set("severity")} aria-label="Severity of a match">
          <option value="medium">A match is medium</option>
          <option value="high">A match is high</option>
          <option value="critical">A match is critical</option>
        </select>
      )}
      {choice && <button className="btn primary" type="submit" disabled={busy}>Add</button>}
    </form>
  );
}

function Lookup() {
  const [value, setValue] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const look = async (e) => {
    e.preventDefault();
    setError(null);
    try {
      setResult(await api.intelLookup(value.trim()));
    } catch (err) {
      setError(reason(err));
    }
  };

  return (
    <form className="intel-lookup" onSubmit={look}>
      <div className="risk-label">Is this on a list?</div>
      <div className="intel-row">
        <input value={value} onChange={(e) => setValue(e.target.value)} className="mono"
               placeholder="An address, domain or URL" aria-label="Look up" required />
        <button className="btn" type="submit">Look up</button>
      </div>
      {error && <div className="intel-bad">{error}</div>}
      {result && (result.listed.length === 0
        ? <div className="intel-note">Not on any feed or watchlist.</div>
        : (
          <ul className="intel-hits">
            {result.listed.map((h) => (
              <li key={`${h.feed_id}|${h.value}`}>
                <span className="mono">{h.value}</span> on {h.feed}
                {!h.enabled && " (switched off)"}
                {h.retired_at ? `, dropped ${relative(h.retired_at)}` : `, listed since ${relative(h.first_listed)}`}
              </li>
            ))}
          </ul>
        ))}
    </form>
  );
}

export default function IntelDrawer({ onClose, canAdmin, canAnalyst }) {
  const [data, setData] = useState(null);
  const [presets, setPresets] = useState([]);
  const [error, setError] = useState(null);

  const load = useCallback(() => {
    api.getIntelFeeds().then((d) => { setData(d); }).catch((e) => setError(reason(e)));
  }, []);

  useEffect(() => {
    load();
    api.getIntelPresets().then(setPresets).catch(() => {});
  }, [load]);

  return (
    <>
      <div className="drawer-overlay" onClick={onClose} />
      <div className="drawer intel-drawer">
        <div className="drawer-head">
          <div className="drawer-actor">Threat intel</div>
          <button className="drawer-close" onClick={onClose} aria-label="Close">&times;</button>
        </div>
        <div className="lockout-rule">
          Lists of known-bad addresses, domains and URLs. Everything an agent reaches is checked
          against them, including what it reached before an entry was added.
        </div>
        {error && <div className="error-banner">{error}</div>}
        {data === null && !error && <div className="empty-state">Loading…</div>}
        {data && (
          <div className="intel-body">
            {!data.fetching && (
              <div className="intel-note">Downloading feeds is switched off on this server; watchlists still work.</div>
            )}
            {data.feeds.length === 0 && (
              <div className="intel-empty">No feeds yet.{canAdmin ? " Add one below." : " An admin can add them."}</div>
            )}
            {data.feeds.map((f) => (
              <FeedRow key={f.id} feed={f} canAdmin={canAdmin} onChanged={load}
                       onError={(m) => setError(m)} />
            ))}
            {canAdmin && (
              <AddFeed presets={presets} existing={data.feeds} onAdded={() => { setError(null); load(); }}
                       onError={(m) => setError(m)} />
            )}
            {canAnalyst && <Lookup />}
          </div>
        )}
      </div>
    </>
  );
}
