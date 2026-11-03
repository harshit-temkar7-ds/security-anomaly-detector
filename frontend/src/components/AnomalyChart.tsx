import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { HourBucket } from "../types";

export default function AnomalyChart({ hourly }: { hourly: HourBucket[] }) {
  const data = hourly.map((h) => ({ hour: h.hour, normal: h.total - h.flagged, flagged: h.flagged }));
  return (
    <section className="card">
      <h2>Logins by hour</h2>
      <div style={{ width: "100%", height: 260 }}>
        <ResponsiveContainer>
          <BarChart data={data} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
            <CartesianGrid stroke="#8ba4ca" strokeDasharray="3 5" opacity={0.14} />
            <XAxis dataKey="hour" tick={{ fontSize: 11, fill: "#93a8c6" }} axisLine={{ stroke: "#526789" }} tickLine={false} />
            <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: "#93a8c6" }} axisLine={false} tickLine={false} />
            <Tooltip contentStyle={{ background: "rgba(5,15,38,.96)", border: "1px solid rgba(34,211,238,.45)", borderRadius: 8 }} />
            <Legend />
            <Bar dataKey="normal" name="Not flagged" stackId="a" fill="#2563eb" />
            <Bar dataKey="flagged" name="Flagged" stackId="a" fill="#ec4899" />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </section>
  );
}
