import { useEffect, useState } from "react";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { getUserProfile, listUsers } from "../api";
import type { UserPage, UserProfileData } from "../types";
import { Pager } from "./Badges";

interface Props { scanId: string; selectedUser: string | null; onSelect: (u: string | null) => void; onViewAlerts: (u: string) => void }
const pct = (n: number) => `${(n * 100).toFixed(1)}%`;

export default function UsersPanel({ scanId, selectedUser, onSelect, onViewAlerts }: Props) {
  const [q, setQ] = useState("");
  const [page, setPage] = useState(1);
  const [users, setUsers] = useState<UserPage | null>(null);
  const [profile, setProfile] = useState<UserProfileData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [usersLoading, setUsersLoading] = useState(true);
  const [profileLoading, setProfileLoading] = useState(false);

  useEffect(() => {
    setUsersLoading(true);
    listUsers(scanId, q, page, 12).then((d) => { setUsers(d); setError(null); }).catch((e: Error) => setError(e.message))
      .finally(() => setUsersLoading(false));
  }, [scanId, q, page]);

  useEffect(() => {
    if (!selectedUser) { setProfile(null); setProfileLoading(false); return; }
    let active = true;
    setProfile(null); setProfileLoading(true);
    getUserProfile(scanId, selectedUser).then((p) => { if (active) { setProfile(p); setError(null); } })
      .catch((e: Error) => { if (active) { setProfile(null); setError(e.message); } })
      .finally(() => { if (active) setProfileLoading(false); });
    return () => { active = false; };
  }, [scanId, selectedUser]);

  const hist = profile?.profile.hour_histogram.map((n, hour) => ({ hour, logins: n })) ?? [];

  return (
    <div className="grid2">
      <section className="card">
        <h2>Users</h2>
        <p className="muted small">
          Baselines use only each user's <b>earlier</b> events ({users?.uba_basis === "timestamp" ? "ordered by timestamp" : users?.uba_basis === "row_order" ? "file order assumed chronological" : "no username column"}).
          At least {users?.min_history ?? 10} earlier events are required before any deviation is reported.
        </p>
        <input type="search" aria-label="Search username" placeholder="Search username…" value={q} maxLength={100} onChange={(e) => { setQ(e.target.value); setPage(1); }} />
        {error && <div className="alert" role="alert">{error}</div>}
        {usersLoading && <p className="muted small" role="status">Loading users…</p>}
        <div className="scroll"><table>
          <thead><tr><th>User</th><th>Events</th><th>Flagged</th><th>Max score</th><th>With deviations</th></tr></thead>
          <tbody>
            {users?.items.map((u) => (
              <tr key={u.username} className={selectedUser === u.username ? "selected" : ""}>
                <td><button className="table-action" aria-label={`View profile for ${u.username}`} onClick={() => onSelect(u.username)}>{u.username}</button></td>
                <td>{u.events}</td><td>{u.flagged}</td><td>{u.max_score.toFixed(3)}</td><td>{u.deviation_events}</td>
              </tr>
            ))}
            {users && users.items.length === 0 && <tr><td colSpan={5} className="muted">{users.uba_basis === "none" ? "This file has no username column." : "No users match."}</td></tr>}
          </tbody>
        </table></div>
        {users && <Pager page={users.page} total={users.total} pageSize={users.page_size} onPage={setPage} />}
      </section>

      <section className="card">
        <h2>{profile ? `Profile: ${profile.username}` : "User profile"}</h2>
        {!profile && <p className="muted" role={profileLoading ? "status" : undefined}>{profileLoading ? "Loading user profile…" : "Select a user to see their typical behaviour and any deviations."}</p>}
        {profile && (<>
          {profile.notice && <div className="notice">{profile.notice}</div>}
          <div className="cards small-cards">
            {[["Events", profile.profile.events], ["Avg failed attempts", profile.profile.mean_failed_attempts],
              ["Max failed attempts", profile.profile.max_failed_attempts], ["Avg unique IPs", profile.profile.mean_unique_ips_24h],
              ["New-device rate", pct(profile.profile.new_device_rate)], ["Country-change rate", pct(profile.profile.country_changed_rate)]]
              .map(([l, v]) => <div className="card kpi" key={String(l)}><div className="kpi-value">{String(v)}</div><div className="muted small">{l}</div></div>)}
          </div>
          <p className="muted small">Whole-scan descriptive summary. Per-event deviations below never use this; they use only earlier events.</p>
          <div style={{ width: "100%", height: 200 }}>
            <ResponsiveContainer>
              <BarChart data={hist} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" opacity={0.3} />
                <XAxis dataKey="hour" tick={{ fontSize: 11 }} /><YAxis allowDecimals={false} tick={{ fontSize: 11 }} />
                <Tooltip /><Bar dataKey="logins" fill="#6b8cae" />
              </BarChart>
            </ResponsiveContainer>
          </div>
          <h3>Deviations from this user's own history</h3>
          {profile.deviation_events.length === 0 ? <p className="muted small">None reported.</p> : (
            <ul className="evidence">{profile.deviation_events.slice(0, 10).map((d) => (
              <li key={d.row}><b>Row {d.row}</b> (score {d.anomaly_score.toFixed(3)}, {d.n_prior} earlier events)
                <ul>{d.deviations.map((x) => <li key={x.detail}>{x.detail}</li>)}</ul></li>
            ))}</ul>
          )}
          <button className="secondary" onClick={() => onViewAlerts(profile.username)}>View this user's alerts</button>
        </>)}
      </section>
    </div>
  );
}
