import { useState } from "react";
import { Settings, Server, Brain, FolderOpen, Shield, Trash2, AlertTriangle } from "lucide-react";
import { api } from "../lib/api";

export default function SettingsPage() {
  const [serverUrl, setServerUrl] = useState("http://127.0.0.1:11435");
  const [model, setModel] = useState("bonsai-8b");
  const [contextSize, setContextSize] = useState("4096");
  const [inboxPath, setInboxPath] = useState("~/.ironclaw/inbox");
  const [dbPath, setDbPath] = useState("~/.ironclaw/legal.db");

  return (
    <div className="p-8 max-w-3xl mx-auto space-y-8">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Settings</h1>
        <p className="text-sm text-zinc-500 mt-1">
          Configure your Legal AI Assistant
        </p>
      </div>

      {/* Model Configuration */}
      <section className="bg-zinc-900/60 border border-zinc-800 rounded-xl p-6 space-y-5">
        <div className="flex items-center gap-2 mb-2">
          <Brain className="w-4 h-4 text-amber-400" />
          <h2 className="text-sm font-semibold">AI Model</h2>
        </div>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="text-xs text-zinc-500">Model Name</label>
            <input
              value={model}
              onChange={(e) => setModel(e.target.value)}
              className="mt-1 w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:ring-1 focus:ring-amber-600"
            />
          </div>
          <div>
            <label className="text-xs text-zinc-500">Context Window</label>
            <input
              value={contextSize}
              onChange={(e) => setContextSize(e.target.value)}
              className="mt-1 w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:ring-1 focus:ring-amber-600"
            />
          </div>
        </div>
      </section>

      {/* Ollama Configuration */}
      <section className="bg-zinc-900/60 border border-zinc-800 rounded-xl p-6 space-y-5">
        <div className="flex items-center gap-2 mb-2">
          <Server className="w-4 h-4 text-blue-400" />
          <h2 className="text-sm font-semibold">LLM Server</h2>
        </div>
        <div>
          <label className="text-xs text-zinc-500">Base URL</label>
          <input
            value={serverUrl}
            onChange={(e) => setServerUrl(e.target.value)}
            className="mt-1 w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:ring-1 focus:ring-amber-600"
          />
        </div>
      </section>

      {/* Paths */}
      <section className="bg-zinc-900/60 border border-zinc-800 rounded-xl p-6 space-y-5">
        <div className="flex items-center gap-2 mb-2">
          <FolderOpen className="w-4 h-4 text-emerald-400" />
          <h2 className="text-sm font-semibold">Paths</h2>
        </div>
        <div>
          <label className="text-xs text-zinc-500">Inbox Directory</label>
          <input
            value={inboxPath}
            onChange={(e) => setInboxPath(e.target.value)}
            className="mt-1 w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:ring-1 focus:ring-amber-600"
          />
          <p className="text-[10px] text-zinc-600 mt-1">
            Documents placed here are automatically processed
          </p>
        </div>
        <div>
          <label className="text-xs text-zinc-500">Database Path</label>
          <input
            value={dbPath}
            onChange={(e) => setDbPath(e.target.value)}
            className="mt-1 w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:ring-1 focus:ring-amber-600"
          />
        </div>
      </section>

      {/* Security Info */}
      <section className="bg-zinc-900/60 border border-zinc-800 rounded-xl p-6">
        <div className="flex items-center gap-2 mb-4">
          <Shield className="w-4 h-4 text-red-400" />
          <h2 className="text-sm font-semibold">Security</h2>
        </div>
        <div className="space-y-2 text-xs text-zinc-400">
          <p>
            <span className="text-zinc-300 font-medium">Zero Trust Architecture</span>{" "}
            — All tool executions pass through IronClaw&apos;s 13-step security pipeline.
          </p>
          <p>
            <span className="text-zinc-300 font-medium">Local Processing</span>{" "}
            — All AI inference runs locally via Bonsai 8B. No data leaves your machine.
          </p>
          <p>
            <span className="text-zinc-300 font-medium">Audit Trail</span>{" "}
            — All document operations are logged in the audit table.
          </p>
          <p>
            <span className="text-zinc-300 font-medium">DLP Protection</span>{" "}
            — IronClaw&apos;s Data Loss Prevention monitors for sensitive data exposure.
          </p>
        </div>
      </section>

      {/* Data Management */}
      <section className="bg-zinc-900/60 border border-red-900/30 rounded-xl p-6">
        <div className="flex items-center gap-2 mb-4">
          <Trash2 className="w-4 h-4 text-red-400" />
          <h2 className="text-sm font-semibold">Data Management</h2>
        </div>
        <p className="text-xs text-zinc-400 mb-4">
          Delete all application data including the AI model (~1.2 GB), database,
          documents, and settings. This cannot be undone.
        </p>
        <DeleteDataButton />
      </section>

      <div className="flex justify-end">
        <button className="px-6 py-2.5 bg-amber-600 hover:bg-amber-500 text-white rounded-lg text-sm font-medium transition-colors">
          Save Settings
        </button>
      </div>
    </div>
  );
}

function DeleteDataButton() {
  const [confirming, setConfirming] = useState(false);
  const [deleted, setDeleted] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleDelete() {
    try {
      await api.deleteAllAppData();
      setDeleted(true);
      setConfirming(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  if (deleted) {
    return (
      <div className="bg-emerald-950/50 border border-emerald-900/50 rounded-lg px-4 py-3 space-y-2">
        <p className="text-xs text-emerald-300">
          All data has been deleted. You can now safely uninstall the application.
        </p>
        <p className="text-[10px] text-emerald-500">
          Restart the app to re-initialize, or close it and uninstall.
        </p>
      </div>
    );
  }

  if (confirming) {
    return (
      <div className="space-y-3">
        <div className="bg-red-950/50 border border-red-900/50 rounded-lg px-4 py-3 flex items-start gap-2">
          <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
          <div>
            <p className="text-xs text-red-300 font-medium">
              Are you sure? This will permanently delete:
            </p>
            <ul className="text-[10px] text-red-400 mt-1 space-y-0.5 list-disc list-inside">
              <li>AI model files (~1.2 GB)</li>
              <li>All clients, matters, and documents</li>
              <li>Audit logs and settings</li>
            </ul>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleDelete}
            className="px-4 py-2 bg-red-600 hover:bg-red-500 text-white rounded-lg text-xs font-medium transition-colors"
          >
            Yes, Delete Everything
          </button>
          <button
            onClick={() => setConfirming(false)}
            className="px-4 py-2 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded-lg text-xs transition-colors"
          >
            Cancel
          </button>
        </div>
        {error && (
          <p className="text-xs text-red-400">{error}</p>
        )}
      </div>
    );
  }

  return (
    <button
      onClick={() => setConfirming(true)}
      className="flex items-center gap-2 px-4 py-2 bg-red-950/50 hover:bg-red-900/50 border border-red-900/30 text-red-400 hover:text-red-300 rounded-lg text-xs font-medium transition-colors"
    >
      <Trash2 className="w-3.5 h-3.5" />
      Delete All Data
    </button>
  );
}
