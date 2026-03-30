import { useEffect, useState } from "react";
import { FileText, Eye, ChevronDown, X, Link2, Trash2, FileEdit, ClipboardList, Loader2, AlertTriangle, CheckCircle2 } from "lucide-react";
import { ask } from "@tauri-apps/plugin-dialog";
import { api, Document, Matter, ConflictHit, Client } from "../lib/api";

const statusColors: Record<string, string> = {
  new: "bg-blue-600/20 text-blue-400",
  processing: "bg-amber-600/20 text-amber-400",
  analyzed: "bg-emerald-600/20 text-emerald-400",
  review: "bg-purple-600/20 text-purple-400",
  archived: "bg-zinc-700/50 text-zinc-500",
};

const categoryLabels: Record<string, string> = {
  family_law: "Family Law",
  criminal: "Criminal",
  immigration: "Immigration",
  real_estate: "Real Estate",
  estate: "Estate Planning",
  corporate: "Corporate",
  employment: "Employment",
  ip: "IP",
  tax: "Tax",
  general: "General",
};

export default function Documents() {
  const [docs, setDocs] = useState<Document[]>([]);
  const [matters, setMatters] = useState<Matter[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<Document | null>(null);
  const [filterCategory, setFilterCategory] = useState("all");
  const [filterStatus, setFilterStatus] = useState("all");
  const [draftType, setDraftType] = useState("");
  const [draftContent, setDraftContent] = useState("");
  const [draftLoading, setDraftLoading] = useState(false);
  const [packetContent, setPacketContent] = useState("");
  const [packetLoading, setPacketLoading] = useState(false);
  const [conflicts, setConflicts] = useState<ConflictHit[]>([]);
  const [conflictClients, setConflictClients] = useState<Record<number, string>>({});
  const [resolveNote, setResolveNote] = useState("");
  const [resolvingId, setResolvingId] = useState<number | null>(null);

  function selectDocument(doc: Document | null) {
    setSelected(doc);
    setDraftContent("");
    setPacketContent("");
    setDraftType("");
    setConflicts([]);
    setConflictClients({});
    setResolveNote("");
    setResolvingId(null);
  }

  useEffect(() => {
    load();
  }, []);

  useEffect(() => {
    if (!selected) return;
    api.getConflictsForDocument(selected.id).then(async (hits) => {
      setConflicts(hits);
      const clientIds = [...new Set(hits.map((h) => h.matched_client_id).filter(Boolean))] as number[];
      const names: Record<number, string> = {};
      await Promise.all(
        clientIds.map(async (cid) => {
          const client = await api.getClient(cid);
          if (client) names[cid] = client.name;
        })
      );
      setConflictClients(names);
    }).catch(console.error);
  }, [selected?.id]);

  async function load() {
    try {
      const [d, m] = await Promise.all([api.listDocuments(), api.listMatters()]);
      setDocs(d);
      setMatters(m);
      setSelected((prev) => prev ? d.find((x) => x.id === prev.id) ?? null : null);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }

  async function handleLinkMatter(docId: number, matterId: number) {
    await api.updateDocumentMatter(docId, matterId);
    load();
  }

  async function handleDelete(docId: number) {
    const confirmed = await ask("Delete this document? This cannot be undone.", {
      title: "Confirm Delete",
      kind: "warning",
    });
    if (!confirmed) return;
    try {
      await api.deleteDocument(docId);
      if (selected?.id === docId) selectDocument(null);
      load();
    } catch (e) {
      console.error(e);
    }
  }

  async function handleDraft(doc: Document, type: string) {
    setDraftLoading(true);
    setDraftContent("");
    setDraftType(type);
    try {
      const context = doc.analysis_json ?? doc.extracted_text ?? doc.filename;
      const result = await api.draftDocument(type, context);
      setDraftContent(result.content);
    } catch (e) {
      setDraftContent(`Error generating draft: ${e}`);
    } finally {
      setDraftLoading(false);
    }
  }

  async function handleResolveConflict(conflictId: number) {
    if (!resolveNote.trim()) return;
    try {
      await api.resolveConflict(conflictId, resolveNote.trim());
      setConflicts((prev) =>
        prev.map((c) =>
          c.id === conflictId ? { ...c, resolved: true, resolution_note: resolveNote.trim() } : c
        )
      );
      setResolveNote("");
      setResolvingId(null);
    } catch (e) {
      console.error(e);
    }
  }

  async function handleReviewPacket(docId: number) {
    setPacketLoading(true);
    setPacketContent("");
    try {
      const result = await api.generateReviewPacket(docId);
      setPacketContent(result.packet);
    } catch (e) {
      setPacketContent(`Error generating review packet: ${e}`);
    } finally {
      setPacketLoading(false);
    }
  }

  const filtered = docs.filter((d) => {
    if (filterCategory !== "all" && d.category !== filterCategory) return false;
    if (filterStatus !== "all" && d.status !== filterStatus) return false;
    return true;
  });

  function getAnalysis(doc: Document): Record<string, unknown> | null {
    if (!doc.analysis_json) return null;
    try {
      return JSON.parse(doc.analysis_json);
    } catch {
      return null;
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="animate-pulse text-zinc-500">Loading documents...</div>
      </div>
    );
  }

  return (
    <div className="p-8 max-w-6xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Documents</h1>
        <p className="text-sm text-zinc-500 mt-1">
          {docs.length} documents processed
        </p>
      </div>

      {/* Filters */}
      <div className="flex gap-4 flex-wrap">
        <div className="relative">
          <select
            value={filterCategory}
            onChange={(e) => setFilterCategory(e.target.value)}
            className="appearance-none bg-zinc-800/80 border border-zinc-700 rounded-lg pl-3 pr-8 py-1.5 text-xs text-zinc-300 focus:outline-none focus:ring-1 focus:ring-amber-600"
          >
            <option value="all">All Categories</option>
            {Object.entries(categoryLabels).map(([k, v]) => (
              <option key={k} value={k}>{v}</option>
            ))}
          </select>
          <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-3 h-3 text-zinc-500 pointer-events-none" />
        </div>
        <div className="relative">
          <select
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value)}
            className="appearance-none bg-zinc-800/80 border border-zinc-700 rounded-lg pl-3 pr-8 py-1.5 text-xs text-zinc-300 focus:outline-none focus:ring-1 focus:ring-amber-600"
          >
            <option value="all">All Statuses</option>
            <option value="new">New</option>
            <option value="processing">Processing</option>
            <option value="analyzed">Analyzed</option>
            <option value="review">Review</option>
          </select>
          <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-3 h-3 text-zinc-500 pointer-events-none" />
        </div>
      </div>

      {/* Document Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {filtered.map((doc) => {
          const analysis = getAnalysis(doc);
          return (
            <div
              key={doc.id}
              className="bg-zinc-900/60 border border-zinc-800 rounded-xl p-4 hover:border-zinc-700 transition-colors cursor-pointer"
              onClick={() => selectDocument(doc)}
            >
              <div className="flex items-start justify-between mb-3">
                <div className="w-9 h-9 rounded-lg bg-zinc-800 flex items-center justify-center shrink-0">
                  <FileText className="w-4 h-4 text-zinc-400" />
                </div>
                <div className="flex items-center gap-1.5">
                  <span
                    className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${
                      statusColors[doc.status] ?? "bg-zinc-700/50 text-zinc-400"
                    }`}
                  >
                    {doc.status}
                  </span>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      handleDelete(doc.id);
                    }}
                    className="p-1 rounded-lg hover:bg-red-600/15 text-zinc-600 hover:text-red-400 transition-colors"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
              <p className="text-sm font-medium text-zinc-200 truncate mb-1">
                {doc.filename}
              </p>
              <p className="text-xs text-zinc-500 mb-2">
                {doc.doc_type !== "unknown" ? doc.doc_type.replace(/_/g, " ") : "Unclassified"}
                {" · "}
                {categoryLabels[doc.category] ?? doc.category}
              </p>
              {analysis?.summary != null && (
                <p className="text-xs text-zinc-400 line-clamp-2">
                  {String(analysis.summary)}
                </p>
              )}
            </div>
          );
        })}
        {filtered.length === 0 && (
          <p className="text-sm text-zinc-600 col-span-full text-center py-12">
            No documents found.
          </p>
        )}
      </div>

      {/* Detail Panel */}
      {selected && (
        <div className="fixed inset-y-0 right-0 w-[480px] bg-zinc-900 border-l border-zinc-800 overflow-y-auto z-50">
          <div className="sticky top-0 bg-zinc-900 border-b border-zinc-800 p-5 flex items-center justify-between">
            <h2 className="text-lg font-semibold">Document Detail</h2>
            <button onClick={() => selectDocument(null)} className="text-zinc-500 hover:text-zinc-300">
              <X className="w-5 h-5" />
            </button>
          </div>
          <div className="p-5 space-y-5">
            <div>
              <label className="text-xs text-zinc-500">Filename</label>
              <p className="text-sm text-zinc-200">{selected.filename}</p>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-xs text-zinc-500">Type</label>
                <p className="text-sm text-zinc-200">{selected.doc_type.replace(/_/g, " ")}</p>
              </div>
              <div>
                <label className="text-xs text-zinc-500">Category</label>
                <p className="text-sm text-zinc-200">
                  {categoryLabels[selected.category] ?? selected.category}
                </p>
              </div>
            </div>
            <div>
              <label className="text-xs text-zinc-500">Status</label>
              <span
                className={`ml-2 text-[10px] px-2 py-0.5 rounded-full font-medium ${
                  statusColors[selected.status] ?? "bg-zinc-700/50 text-zinc-400"
                }`}
              >
                {selected.status}
              </span>
            </div>

            {/* Link to Matter */}
            <div>
              <label className="text-xs text-zinc-500 flex items-center gap-1">
                <Link2 className="w-3 h-3" /> Link to Matter
              </label>
              <select
                value={selected.matter_id ?? ""}
                onChange={(e) => {
                  if (e.target.value) {
                    handleLinkMatter(selected.id, Number(e.target.value));
                  }
                }}
                className="mt-1 w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:ring-1 focus:ring-amber-600"
              >
                <option value="">Unlinked</option>
                {matters.map((m) => (
                  <option key={m.id} value={m.id}>{m.title}</option>
                ))}
              </select>
            </div>

            {/* Analysis */}
            {(() => {
              const analysis = getAnalysis(selected);
              if (!analysis) return null;
              return (
                <div className="space-y-3">
                  <div className="flex items-center gap-1.5">
                    <Eye className="w-3.5 h-3.5 text-amber-400" />
                    <label className="text-xs text-zinc-500 font-medium">AI Analysis</label>
                  </div>
                  {analysis.summary != null && (
                    <div>
                      <label className="text-xs text-zinc-600">Summary</label>
                      <p className="text-sm text-zinc-300">{String(analysis.summary)}</p>
                    </div>
                  )}
                  {Array.isArray(analysis.parties) && analysis.parties.length > 0 && (
                    <div>
                      <label className="text-xs text-zinc-600">Parties</label>
                      <div className="flex flex-wrap gap-1.5 mt-1">
                        {(analysis.parties as string[]).map((p, i) => (
                          <span key={i} className="text-xs bg-zinc-800 px-2 py-0.5 rounded text-zinc-300">
                            {p}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                  {Array.isArray(analysis.key_dates) && analysis.key_dates.length > 0 && (
                    <div>
                      <label className="text-xs text-zinc-600">Key Dates</label>
                      <div className="flex flex-wrap gap-1.5 mt-1">
                        {(analysis.key_dates as string[]).map((d, i) => (
                          <span key={i} className="text-xs bg-zinc-800 px-2 py-0.5 rounded text-zinc-300">
                            {d}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                  {Array.isArray(analysis.risk_flags) && analysis.risk_flags.length > 0 && (
                    <div>
                      <label className="text-xs text-zinc-600">Risk Flags</label>
                      <div className="flex flex-wrap gap-1.5 mt-1">
                        {(analysis.risk_flags as string[]).map((r, i) => (
                          <span key={i} className="text-xs bg-red-900/30 text-red-400 px-2 py-0.5 rounded">
                            {r}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              );
            })()}

            {/* Conflicts */}
            {selected.status !== "new" && selected.status !== "processing" && (
              <div className="space-y-3">
                <div className="flex items-center gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5 text-orange-400" />
                  <label className="text-xs text-zinc-500 font-medium">
                    Conflicts ({conflicts.filter((c) => !c.resolved).length} unresolved)
                  </label>
                </div>
                {conflicts.length === 0 ? (
                  <p className="text-xs text-zinc-600">No conflicts detected.</p>
                ) : (
                  <div className="space-y-2">
                    {conflicts.map((hit) => (
                      <div
                        key={hit.id}
                        className={`rounded-lg border p-3 text-xs ${
                          hit.resolved
                            ? "border-zinc-800 bg-zinc-900/40"
                            : "border-orange-700/30 bg-orange-950/20"
                        }`}
                      >
                        <div className="flex items-start justify-between gap-2">
                          <div className="space-y-1 flex-1">
                            <p className="text-zinc-200 font-medium">
                              Party: <span className="text-orange-300">{hit.matched_name}</span>
                            </p>
                            <p className="text-zinc-400">
                              Matches client:{" "}
                              <span className="text-zinc-200">
                                {hit.matched_client_id
                                  ? conflictClients[hit.matched_client_id] ?? `#${hit.matched_client_id}`
                                  : "Unknown"}
                              </span>
                            </p>
                            <div className="flex items-center gap-2 text-zinc-500">
                              <span className="capitalize">{hit.conflict_type.replace(/_/g, " ")}</span>
                              <span>·</span>
                              <span>{Math.round(hit.confidence * 100)}% confidence</span>
                            </div>
                          </div>
                          {hit.resolved && (
                            <CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0 mt-0.5" />
                          )}
                        </div>

                        {hit.resolved && hit.resolution_note && (
                          <p className="mt-2 text-emerald-400/80 text-[11px] italic">
                            Resolved: {hit.resolution_note}
                          </p>
                        )}

                        {!hit.resolved && (
                          <div className="mt-2">
                            {resolvingId === hit.id ? (
                              <div className="flex gap-2">
                                <input
                                  type="text"
                                  value={resolveNote}
                                  onChange={(e) => setResolveNote(e.target.value)}
                                  onKeyDown={(e) => e.key === "Enter" && handleResolveConflict(hit.id)}
                                  placeholder="Resolution note..."
                                  className="flex-1 bg-zinc-800 border border-zinc-700 rounded px-2 py-1 text-xs text-zinc-200 focus:outline-none focus:ring-1 focus:ring-amber-600"
                                  autoFocus
                                />
                                <button
                                  onClick={() => handleResolveConflict(hit.id)}
                                  className="px-2 py-1 bg-emerald-600/20 text-emerald-400 rounded text-[11px] hover:bg-emerald-600/30 transition-colors"
                                >
                                  Resolve
                                </button>
                                <button
                                  onClick={() => { setResolvingId(null); setResolveNote(""); }}
                                  className="px-2 py-1 bg-zinc-800 text-zinc-400 rounded text-[11px] hover:bg-zinc-700 transition-colors"
                                >
                                  Cancel
                                </button>
                              </div>
                            ) : (
                              <button
                                onClick={() => setResolvingId(hit.id)}
                                className="text-[11px] text-amber-400 hover:text-amber-300 transition-colors"
                              >
                                Mark as resolved...
                              </button>
                            )}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* IronClaw Tools */}
            {selected.status !== "new" && selected.status !== "processing" && (
              <div className="space-y-3">
                <div className="flex items-center gap-1.5">
                  <FileEdit className="w-3.5 h-3.5 text-amber-400" />
                  <label className="text-xs text-zinc-500 font-medium">IronClaw Tools</label>
                </div>

                <div className="grid grid-cols-2 gap-2">
                  {[
                    { type: "retainer", label: "Retainer Letter" },
                    { type: "non_engagement", label: "Non-Engagement" },
                    { type: "response_outline", label: "Response Outline" },
                    { type: "checklist", label: "Checklist" },
                    { type: "summary_memo", label: "Summary Memo" },
                  ].map((d) => (
                    <button
                      key={d.type}
                      onClick={() => handleDraft(selected, d.type)}
                      disabled={draftLoading}
                      className="px-3 py-1.5 text-xs bg-zinc-800 hover:bg-zinc-700 disabled:opacity-50 text-zinc-300 rounded-lg transition-colors border border-zinc-700"
                    >
                      {draftLoading && draftType === d.type ? (
                        <Loader2 className="w-3 h-3 animate-spin inline mr-1" />
                      ) : null}
                      {d.label}
                    </button>
                  ))}
                </div>

                <button
                  onClick={() => handleReviewPacket(selected.id)}
                  disabled={packetLoading}
                  className="w-full flex items-center justify-center gap-2 px-3 py-2 text-xs bg-amber-600/10 hover:bg-amber-600/20 text-amber-400 rounded-lg transition-colors border border-amber-600/20 disabled:opacity-50"
                >
                  {packetLoading ? <Loader2 className="w-3 h-3 animate-spin" /> : <ClipboardList className="w-3.5 h-3.5" />}
                  Generate Review Packet
                </button>

                {draftContent && (
                  <div>
                    <label className="text-xs text-zinc-500">
                      Draft: {draftType.replace(/_/g, " ")}
                    </label>
                    <pre className="mt-1 text-xs text-zinc-300 bg-zinc-800/50 rounded-lg p-3 max-h-64 overflow-y-auto whitespace-pre-wrap font-mono">
                      {draftContent}
                    </pre>
                  </div>
                )}

                {packetContent && (
                  <div>
                    <label className="text-xs text-zinc-500">Review Packet</label>
                    <pre className="mt-1 text-xs text-zinc-300 bg-zinc-800/50 rounded-lg p-3 max-h-64 overflow-y-auto whitespace-pre-wrap font-mono">
                      {packetContent}
                    </pre>
                  </div>
                )}
              </div>
            )}

            {/* Delete */}
            <button
              onClick={() => handleDelete(selected.id)}
              className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-red-600/10 hover:bg-red-600/20 text-red-400 rounded-lg text-sm font-medium transition-colors border border-red-600/20"
            >
              <Trash2 className="w-4 h-4" />
              Delete Document
            </button>

            {/* Extracted Text Preview */}
            {selected.extracted_text && (
              <div>
                <label className="text-xs text-zinc-500">Extracted Text (preview)</label>
                <pre className="mt-1 text-xs text-zinc-400 bg-zinc-800/50 rounded-lg p-3 max-h-48 overflow-y-auto whitespace-pre-wrap font-mono">
                  {selected.extracted_text.substring(0, 2000)}
                  {selected.extracted_text.length > 2000 && "\n\n... (truncated)"}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
