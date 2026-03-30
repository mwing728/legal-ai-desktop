import { useEffect, useState } from "react";
import { Plus, Briefcase, ChevronRight, X, Trash2 } from "lucide-react";
import { ask } from "@tauri-apps/plugin-dialog";
import { api, Matter, Client } from "../lib/api";

const statusColors: Record<string, string> = {
  open: "bg-blue-600/20 text-blue-400",
  active: "bg-emerald-600/20 text-emerald-400",
  pending: "bg-amber-600/20 text-amber-400",
  closed: "bg-zinc-700/50 text-zinc-400",
  archived: "bg-zinc-700/50 text-zinc-500",
};

const typeLabels: Record<string, string> = {
  family_law: "Family Law",
  criminal: "Criminal",
  immigration: "Immigration",
  real_estate: "Real Estate",
  estate: "Estate Planning",
  corporate: "Corporate",
  employment: "Employment",
  ip: "Intellectual Property",
  tax: "Tax",
  other: "Other",
};

export default function Matters() {
  const [matters, setMatters] = useState<Matter[]>([]);
  const [clients, setClients] = useState<Client[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [selected, setSelected] = useState<Matter | null>(null);
  const [filter, setFilter] = useState<string>("all");

  const [form, setForm] = useState({
    title: "",
    matter_type: "other",
    client_id: undefined as number | undefined,
    description: "",
  });

  useEffect(() => {
    load();
  }, []);

  async function load() {
    try {
      const [m, c] = await Promise.all([api.listMatters(), api.listClients()]);
      setMatters(m);
      setClients(c);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    try {
      await api.createMatter({
        title: form.title,
        matter_type: form.matter_type,
        client_id: form.client_id,
        description: form.description || undefined,
      });
      setShowForm(false);
      setForm({ title: "", matter_type: "other", client_id: undefined, description: "" });
      load();
    } catch (err) {
      console.error(err);
    }
  }

  async function handleDelete(id: number) {
    const confirmed = await ask(
      "Delete this matter? Related documents will be unlinked (not deleted). This cannot be undone.",
      { title: "Confirm Delete", kind: "warning" }
    );
    if (!confirmed) return;
    try {
      await api.deleteMatter(id);
      if (selected?.id === id) setSelected(null);
      load();
    } catch (e) {
      console.error(e);
    }
  }

  async function handleStatusChange(id: number, status: string) {
    await api.updateMatterStatus(id, status);
    load();
    if (selected?.id === id) {
      const updated = await api.getMatter(id);
      setSelected(updated);
    }
  }

  const filtered =
    filter === "all" ? matters : matters.filter((m) => m.status === filter);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="animate-pulse text-zinc-500">Loading matters...</div>
      </div>
    );
  }

  return (
    <div className="p-8 max-w-6xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Matters</h1>
          <p className="text-sm text-zinc-500 mt-1">
            {matters.length} total matters
          </p>
        </div>
        <button
          onClick={() => setShowForm(true)}
          className="flex items-center gap-2 px-4 py-2 bg-amber-600 hover:bg-amber-500 text-white rounded-lg text-sm font-medium transition-colors"
        >
          <Plus className="w-4 h-4" />
          New Matter
        </button>
      </div>

      {/* Filters */}
      <div className="flex gap-2">
        {["all", "open", "active", "pending", "closed"].map((s) => (
          <button
            key={s}
            onClick={() => setFilter(s)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
              filter === s
                ? "bg-amber-600/20 text-amber-400"
                : "bg-zinc-800/50 text-zinc-400 hover:text-zinc-200"
            }`}
          >
            {s.charAt(0).toUpperCase() + s.slice(1)}
          </button>
        ))}
      </div>

      {/* Matters List */}
      <div className="space-y-2">
        {filtered.map((m) => (
          <button
            key={m.id}
            onClick={() => setSelected(m)}
            className={`w-full text-left flex items-center gap-4 p-4 rounded-xl border transition-colors ${
              selected?.id === m.id
                ? "bg-zinc-800/80 border-amber-600/30"
                : "bg-zinc-900/60 border-zinc-800 hover:border-zinc-700"
            }`}
          >
            <div className="w-9 h-9 rounded-lg bg-zinc-800 flex items-center justify-center shrink-0">
              <Briefcase className="w-4 h-4 text-zinc-400" />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-zinc-200 truncate">{m.title}</p>
              <p className="text-xs text-zinc-500">
                {typeLabels[m.matter_type] ?? m.matter_type}
                {m.client_id && ` · Client #${m.client_id}`}
              </p>
            </div>
            <span
              className={`text-[10px] px-2 py-0.5 rounded-full font-medium shrink-0 ${
                statusColors[m.status] ?? "bg-zinc-700/50 text-zinc-400"
              }`}
            >
              {m.status}
            </span>
            <ChevronRight className="w-4 h-4 text-zinc-600 shrink-0" />
          </button>
        ))}
        {filtered.length === 0 && (
          <p className="text-sm text-zinc-600 text-center py-12">No matters found.</p>
        )}
      </div>

      {/* Detail Panel */}
      {selected && (
        <div className="fixed inset-y-0 right-0 w-96 bg-zinc-900 border-l border-zinc-800 p-6 overflow-y-auto z-50">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-lg font-semibold">Matter Detail</h2>
            <button onClick={() => setSelected(null)} className="text-zinc-500 hover:text-zinc-300">
              <X className="w-5 h-5" />
            </button>
          </div>
          <div className="space-y-4">
            <div>
              <label className="text-xs text-zinc-500">Title</label>
              <p className="text-sm text-zinc-200">{selected.title}</p>
            </div>
            <div>
              <label className="text-xs text-zinc-500">Type</label>
              <p className="text-sm text-zinc-200">
                {typeLabels[selected.matter_type] ?? selected.matter_type}
              </p>
            </div>
            <div>
              <label className="text-xs text-zinc-500">Status</label>
              <select
                value={selected.status}
                onChange={(e) => handleStatusChange(selected.id, e.target.value)}
                className="mt-1 block w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:ring-1 focus:ring-amber-600"
              >
                {["open", "active", "pending", "closed", "archived"].map((s) => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </select>
            </div>
            {selected.description && (
              <div>
                <label className="text-xs text-zinc-500">Description</label>
                <p className="text-sm text-zinc-300">{selected.description}</p>
              </div>
            )}
            <div>
              <label className="text-xs text-zinc-500">Opened</label>
              <p className="text-sm text-zinc-400">{selected.opened_at}</p>
            </div>
            <button
              onClick={() => handleDelete(selected.id)}
              className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-red-600/10 hover:bg-red-600/20 text-red-400 rounded-lg text-sm font-medium transition-colors border border-red-600/20 mt-4"
            >
              <Trash2 className="w-4 h-4" />
              Delete Matter
            </button>
          </div>
        </div>
      )}

      {/* Create Modal */}
      {showForm && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <form
            onSubmit={handleCreate}
            className="bg-zinc-900 border border-zinc-800 rounded-2xl p-6 w-full max-w-md space-y-4"
          >
            <h2 className="text-lg font-semibold">New Matter</h2>
            <div>
              <label className="text-xs text-zinc-500">Title</label>
              <input
                required
                value={form.title}
                onChange={(e) => setForm({ ...form, title: e.target.value })}
                className="mt-1 w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:ring-1 focus:ring-amber-600"
              />
            </div>
            <div>
              <label className="text-xs text-zinc-500">Type</label>
              <select
                value={form.matter_type}
                onChange={(e) => setForm({ ...form, matter_type: e.target.value })}
                className="mt-1 w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:ring-1 focus:ring-amber-600"
              >
                {Object.entries(typeLabels).map(([k, v]) => (
                  <option key={k} value={k}>{v}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-xs text-zinc-500">Client (optional)</label>
              <select
                value={form.client_id ?? ""}
                onChange={(e) =>
                  setForm({
                    ...form,
                    client_id: e.target.value ? Number(e.target.value) : undefined,
                  })
                }
                className="mt-1 w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:ring-1 focus:ring-amber-600"
              >
                <option value="">None</option>
                {clients.map((c) => (
                  <option key={c.id} value={c.id}>{c.name}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-xs text-zinc-500">Description</label>
              <textarea
                value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
                rows={3}
                className="mt-1 w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:ring-1 focus:ring-amber-600 resize-none"
              />
            </div>
            <div className="flex gap-3 pt-2">
              <button
                type="button"
                onClick={() => setShowForm(false)}
                className="flex-1 px-4 py-2 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded-lg text-sm transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="flex-1 px-4 py-2 bg-amber-600 hover:bg-amber-500 text-white rounded-lg text-sm font-medium transition-colors"
              >
                Create
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}
