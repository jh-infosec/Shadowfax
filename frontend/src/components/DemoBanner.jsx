import React, { useEffect, useState } from "react";

// The public demo (v0.44): one line saying what this is and when the data
// resets, so nobody wonders why their view changed or why nothing is editable.
export default function DemoBanner({ demo }) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 30000);
    return () => clearInterval(t);
  }, []);
  const next = demo.next_reset_at ? Date.parse(demo.next_reset_at) : null;
  const mins = next ? Math.max(0, Math.round((next - now) / 60000)) : null;
  return (
    <div className="demo-banner">
      Public demo. Read-only for visitors. The data resets every {demo.reset_minutes} minutes
      {mins !== null ? `, next in ${mins === 0 ? "under a minute" : `${mins} min`}` : ""}, with a fresh
      run of the scripted attack.
    </div>
  );
}
