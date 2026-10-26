import React, { useEffect, useState } from "react";
import QRCode from "qrcode";
import * as api from "../api.js";

// Two-factor for your own account (v0.25).
//
// Turning it on is three steps, and nothing about sign-in changes until the
// last: the current password (a session left open is not enough), then the
// QR code or the key typed into an authenticator app, then a first code from
// the app. Only a code that matches proves the app has the right secret, so a
// mistyped key cannot lock anyone out. The recovery codes come back once, and
// the window will not close while they are shown.
//
// Turning it off takes the password and a current code (or a recovery code).
//
// v0.27: `forced` is the whole screen, for an admin on a server that requires
// two-factor for administrators -- the server refuses everything else until it
// is on, so there is nothing behind it to show and no way out but signing out.
// New recovery codes take the password and a current code.

export default function TwoFactorModal({ onClose, forced = false, onEnrolled, onLogout }) {
  const [status, setStatus] = useState(null);
  // status | password | scan | codes | disable | regen
  const [step, setStep] = useState(forced ? "password" : "status");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [setup, setSetup] = useState(null);
  const [qr, setQr] = useState(null);
  const [codes, setCodes] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  const load = () => api.getTotp().then(setStatus).catch((e) => setError(e.message));
  useEffect(() => { load(); }, []);

  useEffect(() => {
    if (!setup) { setQr(null); return; }
    QRCode.toDataURL(setup.uri, { margin: 1, width: 200 }).then(setQr).catch(() => setQr(null));
  }, [setup]);

  // Escape never closes this window (App.jsx leaves forms that hold typed
  // input alone); a click outside does, except while recovery codes are shown.
  const close = () => { if (!codes && !forced) onClose(); };

  const attempt = async (fn) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (err) {
      setError(typeof err.detail === "string" ? err.detail : err.message);
    } finally {
      setBusy(false);
    }
  };

  const begin = (e) => {
    e.preventDefault();
    attempt(async () => {
      const s = await api.startTotp(password);
      setPassword("");
      setSetup(s);
      setStep("scan");
    });
  };

  const confirm = (e) => {
    e.preventDefault();
    attempt(async () => {
      const r = await api.confirmTotp(code.replace(/\s/g, ""));
      setCode("");
      setSetup(null);
      setCodes(r.recovery_codes);
      setStep("codes");
      load();
    });
  };

  const regenerate = (e) => {
    e.preventDefault();
    attempt(async () => {
      const r = await api.newRecoveryCodes(password, code.replace(/\s/g, ""));
      setPassword("");
      setCode("");
      setCodes(r.recovery_codes);
      setStep("codes");
      load();
    });
  };

  const stored = () => {
    setCodes(null);
    if (forced && onEnrolled) onEnrolled();
    else setStep("status");
  };

  const turnOff = (e) => {
    e.preventDefault();
    attempt(async () => {
      await api.disableTotp(password, code.trim());
      setPassword("");
      setCode("");
      setStep("status");
      load();
    });
  };

  const formatKey = (k) => k.replace(/(.{4})/g, "$1 ").trim();

  return (
    <div className={forced ? "password-screen" : "policy-modal-overlay"} onClick={close}>
      <div className="policy-modal password-modal twofactor-modal" onClick={(e) => e.stopPropagation()}>
        <div className="policy-modal-head">
          <div className="policy-modal-title">Two-factor sign-in</div>
          {!forced && <button className="drawer-close" onClick={close} disabled={!!codes}>&times;</button>}
        </div>
        <div className="password-body">
          {error && <ul className="policy-problems password-problems"><li>{error}</li></ul>}

          {forced && step === "password" && (
            <p className="password-note forced tf-forced">
              This server requires two-factor sign-in for administrators. Turn it on to
              continue — it takes a minute and an authenticator app on your phone.
            </p>
          )}

          {step === "status" && status && (
            <>
              <p className="password-note">
                {status.enabled
                  ? <>Two-factor is <b className="tf-on">on</b>. Sign-in asks for a code from your
                      authenticator app. {status.recovery_codes_left} recovery code(s) left.</>
                  : <>Two-factor is <b>off</b>. With it on, a stolen password is not enough to
                      sign in as you.</>}
              </p>
              {status.enabled && status.required && (
                <p className="password-note">
                  Required for administrators on this server, so it cannot be turned off
                  here. To move it to a new phone, ask another admin to remove it, then
                  turn it on again.
                </p>
              )}
              <div className="policy-modal-foot tf-foot">
                {status.enabled && (
                  <button className="btn" onClick={() => { setStep("regen"); setError(null); }}>
                    New recovery codes
                  </button>
                )}
                {status.enabled
                  ? !status.required && (
                      <button className="btn" onClick={() => { setStep("disable"); setError(null); }}>Turn off</button>)
                  : <button className="btn primary" onClick={() => { setStep("password"); setError(null); }}>Turn on</button>}
              </div>
            </>
          )}

          {step === "password" && (
            <form onSubmit={begin}>
              <label>
                Current password
                <input type="password" autoComplete="current-password" autoFocus value={password}
                       onChange={(e) => setPassword(e.target.value)} required />
              </label>
              <div className="policy-modal-foot tf-foot">
                {forced
                  ? <button type="button" className="btn" onClick={onLogout}>Sign out</button>
                  : <button type="button" className="btn" onClick={() => setStep("status")}>Back</button>}
                <button type="submit" className="btn primary" disabled={busy}>Continue</button>
              </div>
            </form>
          )}

          {step === "scan" && setup && (
            <form onSubmit={confirm}>
              <p className="password-note">
                Scan this with an authenticator app (Google Authenticator, Microsoft
                Authenticator, 1Password, Aegis…), or type the key into it.
              </p>
              <div className="tf-scan">
                {qr ? <img className="tf-qr" src={qr} alt="QR code for your authenticator app" />
                    : <div className="tf-qr tf-qr-missing">QR unavailable — use the key</div>}
                <code className="secret-value tf-key">{formatKey(setup.secret)}</code>
              </div>
              <label>
                Then enter the 6-digit code it shows
                <input className="tf-code" type="text" inputMode="numeric" autoComplete="one-time-code"
                       autoFocus value={code} onChange={(e) => setCode(e.target.value)} required />
              </label>
              <div className="policy-modal-foot tf-foot">
                <button type="button" className="btn"
                        onClick={() => { setSetup(null); setStep(forced ? "password" : "status"); }}>Cancel</button>
                <button type="submit" className="btn primary" disabled={busy}>Turn on</button>
              </div>
            </form>
          )}

          {step === "codes" && codes && (
            <div className="secret-box" role="alert">
              <div className="secret-title">Two-factor is on. Your recovery codes:</div>
              <ul className="tf-recovery">
                {codes.map((c) => <li key={c}><code>{c}</code></li>)}
              </ul>
              <div className="secret-note">
                Shown once. Each works once, in place of a code, if you lose your phone. Keep
                them somewhere other than the phone.
              </div>
              <div className="secret-actions">
                <button className="btn" onClick={() => navigator.clipboard?.writeText(codes.join("\n"))}>Copy</button>
                <button className="btn primary" onClick={stored}>
                  I have stored them
                </button>
              </div>
            </div>
          )}

          {step === "regen" && (
            <form onSubmit={regenerate}>
              <p className="password-note">
                Replaces your recovery codes. Every old code stops working.
              </p>
              <label>
                Current password
                <input type="password" autoComplete="current-password" autoFocus value={password}
                       onChange={(e) => setPassword(e.target.value)} required />
              </label>
              <label>
                A current code from your app
                <input className="tf-code" type="text" inputMode="numeric" autoComplete="one-time-code"
                       value={code} onChange={(e) => setCode(e.target.value)} required />
              </label>
              <div className="policy-modal-foot tf-foot">
                <button type="button" className="btn" onClick={() => setStep("status")}>Back</button>
                <button type="submit" className="btn primary" disabled={busy}>Replace codes</button>
              </div>
            </form>
          )}

          {step === "disable" && (
            <form onSubmit={turnOff}>
              <label>
                Current password
                <input type="password" autoComplete="current-password" autoFocus value={password}
                       onChange={(e) => setPassword(e.target.value)} required />
              </label>
              <label>
                A current code, or a recovery code
                <input className="tf-code" type="text" autoComplete="one-time-code" value={code}
                       onChange={(e) => setCode(e.target.value)} required />
              </label>
              <div className="policy-modal-foot tf-foot">
                <button type="button" className="btn" onClick={() => setStep("status")}>Back</button>
                <button type="submit" className="btn danger" disabled={busy}>Turn off two-factor</button>
              </div>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}
