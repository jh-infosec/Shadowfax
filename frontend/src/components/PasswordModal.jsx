import React, { useState } from "react";
import * as api from "../api.js";

// Change your own password (v0.19). In `forced` mode -- after an administrator
// reset it -- this is the whole screen: the server refuses everything else
// until it is done, so there is nothing behind it worth showing and no way to
// dismiss it except signing out.

const MIN_LENGTH = 12; // mirrors auth.PASSWORD_MIN_LENGTH; the server has the final say

export default function PasswordModal({ forced, user, onDone, onCancel, onLogout }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [again, setAgain] = useState("");
  const [problems, setProblems] = useState([]);
  const [saving, setSaving] = useState(false);
  const [done, setDone] = useState(null);

  const submit = async (e) => {
    e.preventDefault();
    // Cheap checks first, so a typo costs nothing -- but only as a courtesy.
    const local = [];
    if (next.length < MIN_LENGTH) local.push(`must be at least ${MIN_LENGTH} characters`);
    if (next !== again) local.push("the two new passwords do not match");
    if (local.length) {
      setProblems(local);
      return;
    }
    setSaving(true);
    setProblems([]);
    try {
      const result = await api.changePassword(current, next);
      setDone(result);
      setCurrent("");
      setNext("");
      setAgain("");
    } catch (err) {
      const listed = err.detail?.problems;
      if (Array.isArray(listed)) setProblems(listed);
      else if (err.status === 401) setProblems(["current password is incorrect"]);
      else if (err.status === 429) setProblems(["too many attempts -- wait a moment and try again"]);
      else setProblems([err.message]);
    } finally {
      setSaving(false);
    }
  };

  const overlay = forced ? "password-screen" : "policy-modal-overlay";

  if (done) {
    return (
      <div className={overlay} onClick={forced ? undefined : onDone}>
        <div className="policy-modal password-modal" onClick={(e) => e.stopPropagation()}>
          <div className="policy-modal-head">
            <div className="policy-modal-title">Password changed</div>
          </div>
          <div className="password-body">
            <p className="password-note">
              {done.other_sessions_ended
                ? `${done.other_sessions_ended} other session(s) were signed out.`
                : "No other sessions were signed in."}
            </p>
          </div>
          <div className="policy-modal-foot">
            <button className="btn primary" onClick={onDone}>Continue</button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className={overlay} onClick={forced ? undefined : onCancel}>
      <form className="policy-modal password-modal" onClick={(e) => e.stopPropagation()}
            onSubmit={submit}>
        <div className="policy-modal-head">
          <div className="policy-modal-title">
            {forced ? "Choose a new password" : "Change password"}
          </div>
          {!forced && <button type="button" className="drawer-close" onClick={onCancel}>&times;</button>}
        </div>
        <div className="password-body">
          {forced && (
            <p className="password-note forced">
              An administrator reset the password for <b>{user.username}</b>. Someone else
              has seen it, so it has to be replaced before you can continue.
            </p>
          )}
          <label>
            {forced ? "Password you were given" : "Current password"}
            <input type="password" autoComplete="current-password" value={current}
                   onChange={(e) => setCurrent(e.target.value)} required />
          </label>
          <label>
            New password <span className="password-hint">at least {MIN_LENGTH} characters</span>
            <input type="password" autoComplete="new-password" value={next}
                   onChange={(e) => setNext(e.target.value)} required />
          </label>
          <label>
            New password, again
            <input type="password" autoComplete="new-password" value={again}
                   onChange={(e) => setAgain(e.target.value)} required />
          </label>
          {problems.length > 0 && (
            <ul className="policy-problems password-problems">
              {problems.map((p) => <li key={p}>{p}</li>)}
            </ul>
          )}
          <p className="password-note">Your other signed-in sessions will be signed out.</p>
        </div>
        <div className="policy-modal-foot">
          {forced
            ? <button type="button" className="btn" onClick={onLogout}>Sign out</button>
            : <button type="button" className="btn" onClick={onCancel}>Cancel</button>}
          <button type="submit" className="btn primary" disabled={saving}>
            {saving ? "Saving…" : "Change password"}
          </button>
        </div>
      </form>
    </div>
  );
}
