import { useEffect, useState } from "react";
import { Plus, Users, Search, X, Pencil, Trash2 } from "lucide-react";
import { ask } from "@tauri-apps/plugin-dialog";
import { api, Client } from "../lib/api";

export default function Clients() {
  const [clients, setClients] = useState<Client[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [showForm, setShowForm] = useState(false);
  const [editing, setEditing] = useState<Client | null>(null);

  const [form, setForm] = useState({
    name: "",
    email: "",
    phone: "",
    address: "",
    notes: "",
  });

  useEffect(() => {
    load();
  }, []);

  async function load() {
    try {
      const c = await api.listClients();
      setClients(c);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }

  async function handleSearch(q: string) {
    setSearch(q);
    if (q.trim().length > 0) {
      const results = await api.searchClients(q);
      setClients(results);
    } else {
      load();
    }
  }

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    try {
      await api.createClient({
        name: form.name,
        email: form.email || undefined,
        phone: form.phone || undefined,
        address: form.address || undefined,
        notes: form.notes || undefined,
      });
      closeForm();
      load();
    } catch (err) {
      console.error(err);
    }
  }

  async function handleUpdate(e: React.FormEvent) {
    e.preventDefault();
    if (!editing) return;
    try {
      await api.updateClient({
        id: editing.id,
        name: form.name || undefined,
        email: form.email || undefined,
        phone: form.phone || undefined,
        address: form.address || undefined,
        notes: form.notes || undefined,
      });
      closeForm();
      load();
    } catch (err) {
      console.error(err);
    }
  }

  function openEdit(client: Client) {
    setEditing(client);
    setForm({
      name: client.name,
      email: client.email ?? "",
      phone: client.phone ?? "",
      address: client.address ?? "",
      notes: client.notes ?? "",
    });
    setShowForm(true);
  }

  async function handleDelete(client: Client) {
    const confirmed = await ask(
      `Delete "${client.name}"? This will also delete all their matters and unlink related documents. This cannot be undone.`,
      { title: "Confirm Delete", kind: "warning" }
    );
    if (!confirmed) return;
    try {
      await api.deleteClient(client.id);
      load();
    } catch (e) {
      console.error(e);
    }
  }

  function closeForm() {
    setShowForm(false);
    setEditing(null);
    setForm({ name: "", email: "", phone: "", address: "", notes: "" });
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="animate-pulse text-zinc-500">Loading clients...</div>
      </div>
    );
  }

  return (
    <div className="p-8 max-w-6xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Clients</h1>
          <p className="text-sm text-zinc-500 mt-1">{clients.length} clients</p>
        </div>
        <button
          onClick={() => {
            setEditing(null);
            setForm({ name: "", email: "", phone: "", address: "", notes: "" });
            setShowForm(true);
          }}
          className="flex items-center gap-2 px-4 py-2 bg-amber-600 hover:bg-amber-500 text-white rounded-lg text-sm font-medium transition-colors"
        >
          <Plus className="w-4 h-4" />
          New Client
        </button>
      </div>

      {/* Search */}
      <div className="relative max-w-sm">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500" />
        <input
          value={search}
          onChange={(e) => handleSearch(e.target.value)}
          placeholder="Search clients..."
          className="w-full pl-10 pr-4 py-2 bg-zinc-800/80 border border-zinc-700 rounded-lg text-sm text-zinc-200 placeholder-zinc-500 focus:outline-none focus:ring-1 focus:ring-amber-600"
        />
      </div>

      {/* Client Table */}
      <div className="bg-zinc-900/60 border border-zinc-800 rounded-xl overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-zinc-800">
              <th className="text-left text-xs text-zinc-500 font-medium px-5 py-3">Name</th>
              <th className="text-left text-xs text-zinc-500 font-medium px-5 py-3">Email</th>
              <th className="text-left text-xs text-zinc-500 font-medium px-5 py-3">Phone</th>
              <th className="text-left text-xs text-zinc-500 font-medium px-5 py-3">Created</th>
              <th className="w-10"></th>
            </tr>
          </thead>
          <tbody>
            {clients.map((c) => (
              <tr
                key={c.id}
                className="border-b border-zinc-800/50 hover:bg-zinc-800/30 transition-colors"
              >
                <td className="px-5 py-3">
                  <div className="flex items-center gap-3">
                    <div className="w-8 h-8 rounded-full bg-zinc-800 flex items-center justify-center">
                      <Users className="w-3.5 h-3.5 text-zinc-400" />
                    </div>
                    <span className="text-sm text-zinc-200 font-medium">{c.name}</span>
                  </div>
                </td>
                <td className="px-5 py-3 text-sm text-zinc-400">{c.email ?? "—"}</td>
                <td className="px-5 py-3 text-sm text-zinc-400">{c.phone ?? "—"}</td>
                <td className="px-5 py-3 text-xs text-zinc-500">
                  {new Date(c.created_at).toLocaleDateString()}
                </td>
                <td className="px-3">
                  <div className="flex items-center gap-1">
                    <button
                      onClick={() => openEdit(c)}
                      className="p-1.5 rounded-lg hover:bg-zinc-700/50 text-zinc-500 hover:text-zinc-300 transition-colors"
                    >
                      <Pencil className="w-3.5 h-3.5" />
                    </button>
                    <button
                      onClick={() => handleDelete(c)}
                      className="p-1.5 rounded-lg hover:bg-red-600/15 text-zinc-600 hover:text-red-400 transition-colors"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
            {clients.length === 0 && (
              <tr>
                <td colSpan={5} className="text-center py-12 text-sm text-zinc-600">
                  No clients yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Create/Edit Modal */}
      {showForm && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <form
            onSubmit={editing ? handleUpdate : handleCreate}
            className="bg-zinc-900 border border-zinc-800 rounded-2xl p-6 w-full max-w-md space-y-4"
          >
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold">
                {editing ? "Edit Client" : "New Client"}
              </h2>
              <button type="button" onClick={closeForm} className="text-zinc-500 hover:text-zinc-300">
                <X className="w-5 h-5" />
              </button>
            </div>
            {[
              { key: "name", label: "Name", required: true },
              { key: "email", label: "Email" },
              { key: "phone", label: "Phone" },
              { key: "address", label: "Address" },
            ].map(({ key, label, required }) => (
              <div key={key}>
                <label className="text-xs text-zinc-500">{label}</label>
                <input
                  required={required}
                  value={form[key as keyof typeof form]}
                  onChange={(e) => setForm({ ...form, [key]: e.target.value })}
                  className="mt-1 w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:ring-1 focus:ring-amber-600"
                />
              </div>
            ))}
            <div>
              <label className="text-xs text-zinc-500">Notes</label>
              <textarea
                value={form.notes}
                onChange={(e) => setForm({ ...form, notes: e.target.value })}
                rows={3}
                className="mt-1 w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:ring-1 focus:ring-amber-600 resize-none"
              />
            </div>
            <div className="flex gap-3 pt-2">
              <button
                type="button"
                onClick={closeForm}
                className="flex-1 px-4 py-2 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded-lg text-sm transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="flex-1 px-4 py-2 bg-amber-600 hover:bg-amber-500 text-white rounded-lg text-sm font-medium transition-colors"
              >
                {editing ? "Save" : "Create"}
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}
