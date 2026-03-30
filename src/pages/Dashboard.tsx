import { useEffect, useState } from "react";
import {
  Users,
  Briefcase,
  FileText,
  AlertTriangle,
  Clock,
  CheckSquare,
  Activity,
  TrendingUp,
} from "lucide-react";
import { api, DashboardStats, Deadline, ActionItem } from "../lib/api";

function StatCard({
  icon: Icon,
  label,
  value,
  color,
}: {
  icon: React.ElementType;
  label: string;
  value: number | string;
  color: string;
}) {
  return (
    <div className="bg-zinc-900/60 border border-zinc-800 rounded-xl p-5 hover:border-zinc-700 transition-colors">
      <div className="flex items-center justify-between mb-3">
        <div className={`w-9 h-9 rounded-lg flex items-center justify-center ${color}`}>
          <Icon className="w-4.5 h-4.5" />
        </div>
        <span className="text-2xl font-bold text-zinc-100">{value}</span>
      </div>
      <p className="text-xs text-zinc-500 font-medium">{label}</p>
    </div>
  );
}

function StatusBar({ data, total }: { data: Record<string, number>; total: number }) {
  if (total === 0) return null;
  const colors: Record<string, string> = {
    open: "bg-blue-500",
    active: "bg-emerald-500",
    pending: "bg-amber-500",
    closed: "bg-zinc-600",
    analyzed: "bg-emerald-500",
    processing: "bg-amber-500",
    new: "bg-blue-500",
    review: "bg-purple-500",
  };

  return (
    <div className="flex h-2 rounded-full overflow-hidden bg-zinc-800 gap-px">
      {Object.entries(data).map(([status, count]) => (
        <div
          key={status}
          className={`${colors[status] ?? "bg-zinc-600"} transition-all`}
          style={{ width: `${(count / total) * 100}%` }}
          title={`${status}: ${count}`}
        />
      ))}
    </div>
  );
}

export default function Dashboard() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [deadlines, setDeadlines] = useState<Deadline[]>([]);
  const [actions, setActions] = useState<ActionItem[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      try {
        const [s, d, a] = await Promise.all([
          api.getDashboard(),
          api.listUpcomingDeadlines(14),
          api.listActionItems(),
        ]);
        setStats(s);
        setDeadlines(d);
        setActions(a.filter((i) => i.status !== "completed").slice(0, 8));
      } catch (e) {
        console.error("Dashboard load error:", e);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="animate-pulse text-zinc-500">Loading dashboard...</div>
      </div>
    );
  }

  if (!stats) {
    return (
      <div className="p-8 text-zinc-500">Failed to load dashboard data.</div>
    );
  }

  return (
    <div className="p-8 max-w-6xl mx-auto space-y-8">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Dashboard</h1>
        <p className="text-sm text-zinc-500 mt-1">Legal practice overview</p>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          icon={Users}
          label="Clients"
          value={stats.total_clients}
          color="bg-blue-600/20 text-blue-400"
        />
        <StatCard
          icon={Briefcase}
          label="Matters"
          value={stats.total_matters}
          color="bg-emerald-600/20 text-emerald-400"
        />
        <StatCard
          icon={FileText}
          label="Documents"
          value={stats.total_documents}
          color="bg-amber-600/20 text-amber-400"
        />
        <StatCard
          icon={AlertTriangle}
          label="Conflicts"
          value={stats.unresolved_conflicts}
          color="bg-red-600/20 text-red-400"
        />
      </div>

      {/* Matters & Documents Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-zinc-900/60 border border-zinc-800 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-4">
            <TrendingUp className="w-4 h-4 text-emerald-400" />
            <h3 className="text-sm font-medium">Matters by Status</h3>
          </div>
          <StatusBar data={stats.matters_by_status} total={stats.total_matters} />
          <div className="flex flex-wrap gap-3 mt-3">
            {Object.entries(stats.matters_by_status).map(([s, c]) => (
              <span key={s} className="text-xs text-zinc-400">
                <span className="font-medium text-zinc-300">{c}</span> {s}
              </span>
            ))}
          </div>
        </div>

        <div className="bg-zinc-900/60 border border-zinc-800 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-4">
            <Activity className="w-4 h-4 text-amber-400" />
            <h3 className="text-sm font-medium">Documents by Status</h3>
          </div>
          <StatusBar data={stats.documents_by_status} total={stats.total_documents} />
          <div className="flex flex-wrap gap-3 mt-3">
            {Object.entries(stats.documents_by_status).map(([s, c]) => (
              <span key={s} className="text-xs text-zinc-400">
                <span className="font-medium text-zinc-300">{c}</span> {s}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Deadlines & Action Items */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-zinc-900/60 border border-zinc-800 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-4">
            <Clock className="w-4 h-4 text-red-400" />
            <h3 className="text-sm font-medium">
              Upcoming Deadlines ({stats.upcoming_deadlines})
            </h3>
          </div>
          {deadlines.length === 0 ? (
            <p className="text-xs text-zinc-600">No upcoming deadlines</p>
          ) : (
            <div className="space-y-2">
              {deadlines.slice(0, 6).map((d) => (
                <div
                  key={d.id}
                  className="flex items-center justify-between py-2 border-b border-zinc-800/50 last:border-0"
                >
                  <div>
                    <p className="text-sm text-zinc-200">{d.title}</p>
                    <p className="text-xs text-zinc-500">{d.due_date}</p>
                  </div>
                  <span
                    className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${
                      d.priority === "urgent"
                        ? "bg-red-600/20 text-red-400"
                        : d.priority === "high"
                        ? "bg-amber-600/20 text-amber-400"
                        : "bg-zinc-700/50 text-zinc-400"
                    }`}
                  >
                    {d.priority}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="bg-zinc-900/60 border border-zinc-800 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-4">
            <CheckSquare className="w-4 h-4 text-purple-400" />
            <h3 className="text-sm font-medium">
              Open Action Items ({stats.open_action_items})
            </h3>
          </div>
          {actions.length === 0 ? (
            <p className="text-xs text-zinc-600">No open action items</p>
          ) : (
            <div className="space-y-2">
              {actions.map((a) => (
                <div
                  key={a.id}
                  className="flex items-center justify-between py-2 border-b border-zinc-800/50 last:border-0"
                >
                  <div>
                    <p className="text-sm text-zinc-200">{a.title}</p>
                    {a.assignee && (
                      <p className="text-xs text-zinc-500">{a.assignee}</p>
                    )}
                  </div>
                  <span
                    className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${
                      a.priority === "urgent"
                        ? "bg-red-600/20 text-red-400"
                        : a.priority === "high"
                        ? "bg-amber-600/20 text-amber-400"
                        : "bg-zinc-700/50 text-zinc-400"
                    }`}
                  >
                    {a.priority}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
