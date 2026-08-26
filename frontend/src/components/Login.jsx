import React, { useState } from "react";
import * as api from "../api.js";

export default function Login({ onAuthenticated }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const user = await api.login(username.trim(), password);
      onAuthenticated(user);
    } catch (err) {
      setError(err.status === 401 ? "Invalid username or password." : err.message);
      setBusy(false);
    }
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

        {error && <div className="login-error">{error}</div>}

        <button className="btn primary login-submit" type="submit" disabled={busy}>
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </div>
  );
}
