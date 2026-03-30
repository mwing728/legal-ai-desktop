import { useState, useEffect, useCallback } from "react";
import { Scale, Shield, Loader2, Download, CheckCircle, AlertCircle, RefreshCw } from "lucide-react";
import { api } from "../lib/api";

interface Props {
  onReady: () => void;
}

export default function Setup({ onReady }: Props) {
  const [state, setState] = useState("starting");
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const poll = useCallback(async () => {
    try {
      const status = await api.getOllamaStatus();
      setState(status.state);
      setProgress(status.progress);
      setError(status.error);
      if (status.state === "ready") {
        onReady();
      }
    } catch {
      // Tauri command not ready yet, keep polling
    }
  }, [onReady]);

  useEffect(() => {
    const interval = setInterval(poll, 500);
    poll();
    return () => clearInterval(interval);
  }, [poll]);

  const statusLabel = () => {
    switch (state) {
      case "starting":
        return "Starting AI engine...";
      case "checking_model":
        return "Checking AI model...";
      case "pulling_model":
        return "Downloading AI model (first time only)...";
      case "ready":
        return "Ready!";
      case "error":
        return "Setup error";
      default:
        return "Initializing...";
    }
  };

  const retry = () => {
    setError(null);
    setState("starting");
    setProgress(0);
    poll();
  };

  return (
    <div className="flex items-center justify-center h-screen bg-zinc-950 text-zinc-100">
      <div className="flex flex-col items-center gap-8 max-w-md text-center px-8">
        <div className="w-20 h-20 rounded-2xl bg-amber-600 flex items-center justify-center">
          <Scale className="w-10 h-10 text-white" />
        </div>

        <div>
          <h1 className="text-2xl font-bold tracking-tight">Legal AI Assistant</h1>
          <p className="text-xs text-zinc-500 flex items-center justify-center gap-1 mt-1">
            <Shield className="w-3 h-3" /> IronClaw Secured
          </p>
        </div>

        <div className="w-full space-y-4">
          <div className="flex items-center justify-center gap-2">
            {state === "error" ? (
              <AlertCircle className="w-5 h-5 text-red-400" />
            ) : state === "ready" ? (
              <CheckCircle className="w-5 h-5 text-emerald-400" />
            ) : state === "pulling_model" ? (
              <Download className="w-5 h-5 text-amber-400 animate-pulse" />
            ) : (
              <Loader2 className="w-5 h-5 text-amber-400 animate-spin" />
            )}
            <span className="text-sm text-zinc-300">{statusLabel()}</span>
          </div>

          {(state === "starting" || state === "pulling_model" || state === "checking_model") && (
            <div className="w-full bg-zinc-800 rounded-full h-2 overflow-hidden">
              <div
                className="h-full bg-amber-600 rounded-full transition-all duration-300"
                style={{ width: `${Math.max(progress, state === "starting" ? 5 : 0)}%` }}
              />
            </div>
          )}

          {state === "pulling_model" && (
            <p className="text-xs text-zinc-500">
              Downloading phi4-mini ({progress.toFixed(0)}%) — this only happens once
            </p>
          )}

          {error && (
            <div className="space-y-3">
              <div className="bg-red-950/50 border border-red-900/50 rounded-lg px-4 py-3">
                <p className="text-xs text-red-300">{error}</p>
              </div>
              <button
                onClick={retry}
                className="flex items-center gap-2 mx-auto px-4 py-2 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded-lg text-sm transition-colors"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                Retry
              </button>
            </div>
          )}
        </div>

        <p className="text-[10px] text-zinc-600">
          All AI processing runs locally. Your data never leaves this computer.
        </p>
      </div>
    </div>
  );
}
