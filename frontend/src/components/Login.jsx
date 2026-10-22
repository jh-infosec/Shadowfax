import React, { useState } from "react";
import * as api from "../api.js";

export default function Login({ onAuthenticated }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  // v0.25: the second step, for accounts with two-factor on. The password stays
  // in memory for the second request and is dropped with the component.
  const [needsCode, setNeedsCode] = useState(false);
  const [code, setCode] = useState("");
  const [useRecovery, setUseRecovery] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const second = !needsCode ? {}
      : useRecovery ? { recovery_code: code.trim() } : { totp_code: code.trim() };
    try {
      const user = await api.login(username.trim(), password, second);
      onAuthenticated(user);
    } catch (err) {
      if (err.status === 401 && err.detail?.mfa_required) {
        setNeedsCode(true);
      } else if (err.status === 429) {
        setError(typeof err.detail === "string" ? err.detail : "Too many attempts; wait and try again.");
      } else if (err.status === 401) {
        setError(needsCode ? (useRecovery ? "That recovery code did not work." : "That code did not work.")
          : "Invalid username or password.");
      } else if (err.status === 403 && typeof err.detail === "string") {
        setError(err.detail);
      } else {
        setError(err.message);
      }
      setCode("");
      setBusy(false);
    }
  };

  const startOver = () => {
    setNeedsCode(false);
    setPassword("");
    setCode("");
    setError(null);
  };

  return (
    <div className="login-screen">
      <form className="login-card" onSubmit={submit}>
        <div className="login-brand">
          <div className="radar">
            <div className="radar-ring" />
            <div className="radar-sweep" />
            <div className="radar-dot" />
          </div>
          <div>
            <div className="brand-name">SHADOWFAX</div>
            <div className="brand-sub">sign in to the console</div>
          </div>
        </div>

        {needsCode ? (
          <>
            <div className="login-step">
              Two-factor is on for <b>{username.trim()}</b>.{" "}
              {useRecovery ? "Enter one of your recovery codes." : "Enter the 6-digit code from your authenticator app."}
            </div>
            <label className="login-label">
              {useRecovery ? "Recovery code" : "Code"}
              <input
                className="login-input login-code"
                type="text"
                autoFocus
                inputMode={useRecovery ? "text" : "numeric"}
                autoComplete="one-time-code"
                value={code}
                onChange={(e) => setCode(e.target.value)}
              />
            </label>
            <div className="login-links">
              <button type="button" className="link-btn"
                      onClick={() => { setUseRecovery(!useRecovery); setCode(""); setError(null); }}>
                {useRecovery ? "Use the authenticator app" : "Use a recovery code"}
              </button>
              <button type="button" className="link-btn" onClick={startOver}>Start over</button>
            </div>
          </>
        ) : (
        <>
        <label className="login-label">
          Username
          <input
            className="login-input"
            type="text"
            autoFocus
            autoComplete="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
        </label>

        <label className="login-label">
          Password
          <input
            className="login-input"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </label>
        </>
        )}

        {error && <div className="login-error">{error}</div>}

        <button className="btn primary login-submit" type="submit" disabled={busy}>
          {busy ? "Signing in…" : needsCode ? "Verify" : "Sign in"}
        </button>
      </form>
    </div>
  );
}
