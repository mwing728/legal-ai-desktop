import { useState, useEffect, useCallback } from "react";
import {
  Upload,
  FileText,
  FolderOpen,
  CheckCircle,
  AlertCircle,
  Loader2,
  Clock,
  Timer,
  X,
} from "lucide-react";
import { api, ProcessResult } from "../lib/api";
import { open } from "@tauri-apps/plugin-dialog";
import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow";

const LEGAL_EXTENSIONS = [
  "pdf", "txt", "md", "docx", "doc", "rtf",
  "jpg", "jpeg", "png", "tiff", "tif", "bmp",
];

interface QueueItem {
  filePath: string;
  fileName: string;
  status: "pending" | "processing" | "done" | "error";
  result?: ProcessResult;
  error?: string;
}

interface BatchStats {
  totalDocs: number;
  totalChunks: number;
  totalMs: number;
}

function isLegalDoc(path: string): boolean {
  const ext = path.split(".").pop()?.toLowerCase() ?? "";
  return LEGAL_EXTENSIONS.includes(ext);
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  const secs = ms / 1000;
  if (secs < 60) return `${secs.toFixed(1)}s`;
  const mins = Math.floor(secs / 60);
  const remainSecs = (secs % 60).toFixed(0);
  return `${mins}m ${remainSecs}s`;
}

export default function InboxPage() {
  const [queue, setQueue] = useState<QueueItem[]>([]);
  const [processing, setProcessing] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const [batchStats, setBatchStats] = useState<BatchStats | null>(null);

  const addPaths = useCallback((paths: string[]) => {
    const legal = paths.filter(isLegalDoc);
    if (legal.length === 0) return;

    const newItems: QueueItem[] = legal.map((p) => ({
      filePath: p,
      fileName: p.split("/").pop() ?? p,
      status: "pending" as const,
    }));

    setQueue((prev) => {
      const existing = new Set(prev.map((q) => q.filePath));
      const unique = newItems.filter((n) => !existing.has(n.filePath));
      return [...prev, ...unique];
    });
    setBatchStats(null);
  }, []);

  useEffect(() => {
    const webview = getCurrentWebviewWindow();
    const unlisten = webview.onDragDropEvent((event) => {
      if (event.payload.type === "over") {
        setIsDragging(true);
      } else if (event.payload.type === "drop") {
        setIsDragging(false);
        const paths = event.payload.paths;
        (async () => {
          const filePaths: string[] = [];
          for (const p of paths) {
            if (isLegalDoc(p)) {
              filePaths.push(p);
            } else {
              try {
                const scanned = await api.scanFolder(p);
                filePaths.push(...scanned);
              } catch {
                // Not a folder or scan failed
              }
            }
          }
          addPaths(filePaths);
        })();
      } else if (event.payload.type === "leave") {
        setIsDragging(false);
      }
    });

    return () => {
      unlisten.then((fn) => fn());
    };
  }, [addPaths]);

  async function handleSelectFiles() {
    try {
      const selected = await open({
        multiple: true,
        filters: [
          {
            name: "Legal Documents",
            extensions: LEGAL_EXTENSIONS,
          },
        ],
      });

      if (!selected) return;
      const paths = Array.isArray(selected) ? selected : [selected];
      addPaths(paths);
    } catch (e) {
      console.error("File dialog error:", e);
    }
  }

  async function handleSelectFolder() {
    try {
      const selected = await open({
        directory: true,
        multiple: false,
      });

      if (!selected) return;
      const folder = Array.isArray(selected) ? selected[0] : selected;
      const files = await api.scanFolder(folder);
      addPaths(files);
    } catch (e) {
      console.error("Folder dialog error:", e);
    }
  }

  async function handleProcessAll() {
    setProcessing(true);
    setBatchStats(null);
    const batchStart = Date.now();
    const pending = queue.filter((q) => q.status === "pending");
    let totalChunks = 0;
    let successCount = 0;

    for (const item of pending) {
      setQueue((prev) =>
        prev.map((q) =>
          q.filePath === item.filePath ? { ...q, status: "processing" } : q
        )
      );

      try {
        const result = await api.processDocument(item.filePath);
        totalChunks += result.chunks_processed;
        successCount++;
        setQueue((prev) =>
          prev.map((q) =>
            q.filePath === item.filePath ? { ...q, status: "done", result } : q
          )
        );
      } catch (e) {
        setQueue((prev) =>
          prev.map((q) =>
            q.filePath === item.filePath
              ? { ...q, status: "error", error: String(e) }
              : q
          )
        );
      }
    }

    const totalMs = Date.now() - batchStart;
    if (successCount > 0) {
      setBatchStats({
        totalDocs: successCount,
        totalChunks,
        totalMs,
      });
    }
    setProcessing(false);
  }

  function handleRemoveItem(filePath: string) {
    setQueue((prev) => prev.filter((q) => q.filePath !== filePath));
  }

  function handleClearDone() {
    setQueue((prev) => prev.filter((q) => q.status !== "done" && q.status !== "error"));
    setBatchStats(null);
  }

  const pendingCount = queue.filter((q) => q.status === "pending").length;
  const doneCount = queue.filter((q) => q.status === "done").length;

  return (
    <div className="p-8 max-w-4xl mx-auto space-y-8">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Inbox</h1>
        <p className="text-sm text-zinc-500 mt-1">
          Upload and process legal documents
        </p>
      </div>

      {/* Batch Stats Banner */}
      {batchStats && (
        <div className="bg-emerald-600/10 border border-emerald-600/20 rounded-xl px-5 py-4 flex items-center gap-4">
          <div className="w-9 h-9 rounded-lg bg-emerald-600/15 flex items-center justify-center shrink-0">
            <Timer className="w-4.5 h-4.5 text-emerald-400" />
          </div>
          <div className="flex-1">
            <p className="text-sm font-medium text-emerald-300">
              Processed {batchStats.totalDocs} document{batchStats.totalDocs !== 1 ? "s" : ""} in{" "}
              {formatDuration(batchStats.totalMs)}
            </p>
            <p className="text-xs text-emerald-400/70">
              {batchStats.totalChunks} chunk{batchStats.totalChunks !== 1 ? "s" : ""} analyzed
              {batchStats.totalDocs > 0 &&
                ` · ${formatDuration(Math.round(batchStats.totalMs / batchStats.totalDocs))} avg per document`}
            </p>
          </div>
        </div>
      )}

      {/* Drop Zone */}
      <div
        className={`border-2 border-dashed rounded-2xl p-12 text-center transition-colors ${
          isDragging
            ? "border-amber-500 bg-amber-600/5"
            : "border-zinc-700 hover:border-zinc-600"
        }`}
      >
        <div
          className={`w-14 h-14 rounded-2xl flex items-center justify-center mx-auto mb-4 transition-colors ${
            isDragging ? "bg-amber-600/15" : "bg-zinc-800"
          }`}
        >
          <Upload
            className={`w-6 h-6 transition-colors ${
              isDragging ? "text-amber-400" : "text-zinc-500"
            }`}
          />
        </div>

        {isDragging ? (
          <p className="text-sm text-amber-400 font-medium">
            Drop files or folders here
          </p>
        ) : (
          <>
            <p className="text-sm text-zinc-300 font-medium mb-1">
              Drag files or folders here, or use the buttons below
            </p>
            <p className="text-xs text-zinc-500 mb-5">
              PDF, TXT, MD, DOCX, DOC, RTF supported
            </p>

            <div className="flex items-center justify-center gap-3">
              <button
                onClick={handleSelectFiles}
                className="flex items-center gap-2 px-4 py-2 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 rounded-lg text-sm font-medium transition-colors border border-zinc-700"
              >
                <FileText className="w-4 h-4" />
                Select Files
              </button>
              <button
                onClick={handleSelectFolder}
                className="flex items-center gap-2 px-4 py-2 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 rounded-lg text-sm font-medium transition-colors border border-zinc-700"
              >
                <FolderOpen className="w-4 h-4" />
                Select Folder
              </button>
            </div>
          </>
        )}
      </div>

      {/* Queue */}
      {queue.length > 0 && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-sm text-zinc-400">
              {doneCount} of {queue.length} processed
              {pendingCount > 0 && ` · ${pendingCount} pending`}
            </p>
            <div className="flex gap-2">
              {doneCount > 0 && (
                <button
                  onClick={handleClearDone}
                  className="px-3 py-1.5 text-xs text-zinc-500 hover:text-zinc-300 hover:bg-zinc-800/50 rounded-lg transition-colors"
                >
                  Clear finished
                </button>
              )}
              {pendingCount > 0 && (
                <button
                  onClick={handleProcessAll}
                  disabled={processing}
                  className="flex items-center gap-2 px-4 py-2 bg-amber-600 hover:bg-amber-500 disabled:bg-zinc-800 disabled:text-zinc-600 text-white rounded-lg text-sm font-medium transition-colors"
                >
                  {processing && <Loader2 className="w-4 h-4 animate-spin" />}
                  Process All
                </button>
              )}
            </div>
          </div>

          <div className="space-y-2">
            {queue.map((item) => (
              <div
                key={item.filePath}
                className="flex items-center gap-4 bg-zinc-900/60 border border-zinc-800 rounded-xl px-5 py-4"
              >
                <div
                  className={`w-9 h-9 rounded-lg flex items-center justify-center shrink-0 ${
                    item.status === "done"
                      ? "bg-emerald-600/15"
                      : item.status === "error"
                      ? "bg-red-600/15"
                      : item.status === "processing"
                      ? "bg-amber-600/15"
                      : "bg-zinc-800"
                  }`}
                >
                  {item.status === "done" ? (
                    <CheckCircle className="w-4 h-4 text-emerald-400" />
                  ) : item.status === "error" ? (
                    <AlertCircle className="w-4 h-4 text-red-400" />
                  ) : item.status === "processing" ? (
                    <Loader2 className="w-4 h-4 text-amber-400 animate-spin" />
                  ) : (
                    <FileText className="w-4 h-4 text-zinc-400" />
                  )}
                </div>

                <div className="flex-1 min-w-0">
                  <p className="text-sm text-zinc-200 truncate">{item.fileName}</p>
                  {item.status === "done" && item.result && (
                    <div>
                      <p className="text-xs text-zinc-500">
                        {item.result.doc_type.replace(/_/g, " ")} ·{" "}
                        {item.result.category} · Doc #{item.result.document_id}
                      </p>
                      <p className="text-[10px] text-zinc-600">
                        {item.result.client_id && `Client #${item.result.client_id}`}
                        {item.result.matter_id && ` · Matter #${item.result.matter_id}`}
                        {item.result.conflicts_found > 0 && (
                          <span className="text-amber-400 ml-1">
                            ⚠ {item.result.conflicts_found} conflict{item.result.conflicts_found !== 1 ? "s" : ""}
                          </span>
                        )}
                        {(item.result.action_items_created > 0 || item.result.deadlines_created > 0) && (
                          <span className="text-emerald-400 ml-1">
                            {item.result.action_items_created} actions · {item.result.deadlines_created} deadlines
                          </span>
                        )}
                      </p>
                    </div>
                  )}
                  {item.status === "error" && (
                    <p className="text-xs text-red-400 truncate">{item.error}</p>
                  )}
                  {item.status === "processing" && (
                    <p className="text-xs text-amber-400">Extracting & analyzing...</p>
                  )}
                </div>

                {/* Per-document timing */}
                {item.status === "done" && item.result && (
                  <div className="text-right shrink-0">
                    <span className="flex items-center gap-1 text-[10px] text-zinc-500">
                      <Clock className="w-3 h-3" />
                      {formatDuration(item.result.elapsed_ms)}
                    </span>
                    {item.result.chunks_processed > 1 && (
                      <span className="text-[10px] text-zinc-600">
                        {item.result.chunks_processed} chunks
                      </span>
                    )}
                  </div>
                )}

                <span
                  className={`text-[10px] px-2 py-0.5 rounded-full font-medium shrink-0 ${
                    item.status === "done"
                      ? "bg-emerald-600/20 text-emerald-400"
                      : item.status === "error"
                      ? "bg-red-600/20 text-red-400"
                      : item.status === "processing"
                      ? "bg-amber-600/20 text-amber-400"
                      : "bg-zinc-700/50 text-zinc-400"
                  }`}
                >
                  {item.status}
                </span>

                {(item.status === "pending" || item.status === "error") && (
                  <button
                    onClick={() => handleRemoveItem(item.filePath)}
                    className="p-1 rounded-lg hover:bg-zinc-700/50 text-zinc-600 hover:text-zinc-300 transition-colors shrink-0"
                    title="Remove from queue"
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
