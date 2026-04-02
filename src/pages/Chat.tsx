import { useState, useRef, useEffect, useCallback } from "react";
import {
  Send,
  Bot,
  User,
  Loader2,
  Trash2,
  FileText,
  ChevronLeft,
  ChevronRight,
  Check,
  AlertTriangle,
  RefreshCw,
} from "lucide-react";
import { api, ChatMessage, Document } from "../lib/api";

interface Message {
  role: "user" | "assistant" | "system";
  content: string;
}

const MAX_DOCS = 3;

export default function Chat() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [docs, setDocs] = useState<Document[]>([]);
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set());
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const bottomRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const refreshDocs = useCallback(() => {
    api.listDocuments().then((d) => {
      setDocs(d.filter((doc) => doc.status === "analyzed" || doc.status === "filed"));
    });
  }, []);

  useEffect(() => {
    refreshDocs();
  }, [refreshDocs]);

  function toggleDoc(id: number) {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        if (next.size >= MAX_DOCS) return prev;
        next.add(id);
      }
      return next;
    });
  }

  async function handleSend() {
    const text = input.trim();
    if (!text || loading) return;

    const userMsg: Message = { role: "user", content: text };
    const newMessages = [...messages, userMsg];
    setMessages(newMessages);
    setInput("");
    setLoading(true);

    try {
      const chatHistory: ChatMessage[] = newMessages.map((m) => ({
        role: m.role,
        content: m.content,
      }));
      const response = await api.chatSend(
        chatHistory,
        Array.from(selectedIds)
      );
      setMessages([
        ...newMessages,
        { role: "assistant", content: response.content },
      ]);
    } catch (e) {
      setMessages([
        ...newMessages,
        {
          role: "assistant",
          content: `Error: ${e instanceof Error ? e.message : String(e)}`,
        },
      ]);
    } finally {
      setLoading(false);
      inputRef.current?.focus();
    }
  }

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  }

  const selectedDocs = docs.filter((d) => selectedIds.has(d.id));

  return (
    <div className="flex h-full">
      {/* Document Sidebar */}
      <div
        className={`border-r border-zinc-800 flex flex-col bg-zinc-950/60 transition-all duration-200 shrink-0 ${
          sidebarOpen ? "w-64" : "w-0 overflow-hidden"
        }`}
      >
        <div className="p-3 border-b border-zinc-800 flex items-center justify-between">
          <span className="text-xs font-medium text-zinc-400">
            Documents{" "}
            {selectedIds.size > 0 && (
              <span className="ml-1 px-1.5 py-0.5 rounded-full bg-amber-600/20 text-amber-400 text-[10px]">
                {selectedIds.size}/{MAX_DOCS}
              </span>
            )}
          </span>
          <div className="flex items-center gap-1">
            <button
              onClick={refreshDocs}
              className="p-1 rounded hover:bg-zinc-800 text-zinc-500 hover:text-zinc-300 transition-colors"
              title="Refresh documents"
            >
              <RefreshCw className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => setSidebarOpen(false)}
              className="p-1 rounded hover:bg-zinc-800 text-zinc-500 hover:text-zinc-300 transition-colors"
            >
              <ChevronLeft className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {selectedIds.size >= MAX_DOCS && (
          <div className="px-3 py-2 bg-amber-600/5 border-b border-amber-600/10 flex items-center gap-1.5">
            <AlertTriangle className="w-3 h-3 text-amber-500 shrink-0" />
            <span className="text-[10px] text-amber-400">
              Max {MAX_DOCS} docs for context window
            </span>
          </div>
        )}

        <div className="flex-1 overflow-y-auto p-2 space-y-1">
          {docs.length === 0 && (
            <p className="text-xs text-zinc-600 text-center py-6">
              No analyzed documents yet. Process documents in the Inbox first.
            </p>
          )}
          {docs.map((doc) => {
            const isSelected = selectedIds.has(doc.id);
            const isDisabled = !isSelected && selectedIds.size >= MAX_DOCS;
            return (
              <button
                key={doc.id}
                onClick={() => !isDisabled && toggleDoc(doc.id)}
                disabled={isDisabled}
                className={`w-full text-left flex items-start gap-2.5 px-2.5 py-2 rounded-lg text-xs transition-colors ${
                  isSelected
                    ? "bg-amber-600/10 border border-amber-600/20"
                    : isDisabled
                    ? "opacity-40 cursor-not-allowed border border-transparent"
                    : "hover:bg-zinc-800/50 border border-transparent"
                }`}
              >
                <div
                  className={`w-4 h-4 rounded border flex items-center justify-center shrink-0 mt-0.5 transition-colors ${
                    isSelected
                      ? "bg-amber-600 border-amber-600"
                      : "border-zinc-600"
                  }`}
                >
                  {isSelected && <Check className="w-2.5 h-2.5 text-white" />}
                </div>
                <div className="min-w-0 flex-1">
                  <p className="text-zinc-200 truncate leading-tight">
                    {doc.filename}
                  </p>
                  <p className="text-zinc-500 mt-0.5">
                    {doc.doc_type !== "unknown"
                      ? doc.doc_type.replace(/_/g, " ")
                      : doc.category}
                  </p>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Main Chat Area */}
      <div className="flex flex-col flex-1 min-w-0">
        {/* Header */}
        <div className="border-b border-zinc-800 px-6 py-4 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-3">
            {!sidebarOpen && (
              <button
                onClick={() => setSidebarOpen(true)}
                className="p-1.5 rounded-lg hover:bg-zinc-800 text-zinc-500 hover:text-zinc-300 transition-colors"
                title="Show documents"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            )}
            <div>
              <h1 className="text-lg font-semibold tracking-tight">
                AI Assistant
              </h1>
              <p className="text-xs text-zinc-500">
                {selectedIds.size > 0
                  ? `${selectedIds.size} document${selectedIds.size !== 1 ? "s" : ""} selected for context`
                  : "Legal analysis powered by Bonsai 8B"}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {selectedIds.size > 0 && (
              <button
                onClick={() => setSelectedIds(new Set())}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-zinc-500 hover:text-zinc-300 hover:bg-zinc-800/50 rounded-lg transition-colors"
              >
                Deselect all
              </button>
            )}
            {messages.length > 0 && (
              <button
                onClick={() => setMessages([])}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-zinc-500 hover:text-zinc-300 hover:bg-zinc-800/50 rounded-lg transition-colors"
              >
                <Trash2 className="w-3.5 h-3.5" />
                Clear
              </button>
            )}
          </div>
        </div>

        {/* Selected docs pills */}
        {selectedDocs.length > 0 && (
          <div className="px-6 py-2 border-b border-zinc-800/50 flex items-center gap-2 flex-wrap">
            <FileText className="w-3.5 h-3.5 text-zinc-500 shrink-0" />
            {selectedDocs.map((doc) => (
              <span
                key={doc.id}
                className="inline-flex items-center gap-1 px-2 py-0.5 bg-amber-600/10 text-amber-400 rounded-md text-[10px] font-medium"
              >
                {doc.filename}
                <button
                  onClick={() => toggleDoc(doc.id)}
                  className="hover:text-amber-200 ml-0.5"
                >
                  ×
                </button>
              </span>
            ))}
          </div>
        )}

        {/* Messages */}
        <div className="flex-1 overflow-y-auto px-6 py-6 space-y-6">
          {messages.length === 0 && (
            <div className="flex flex-col items-center justify-center h-full text-center">
              <div className="w-14 h-14 rounded-2xl bg-amber-600/10 flex items-center justify-center mb-4">
                <Bot className="w-7 h-7 text-amber-500" />
              </div>
              <h2 className="text-lg font-semibold text-zinc-300 mb-2">
                Legal AI Assistant
              </h2>
              <p className="text-sm text-zinc-500 max-w-sm">
                {selectedIds.size > 0
                  ? "Ask me anything about your selected documents. I can analyze, summarize, compare, or answer specific questions."
                  : "Select documents from the sidebar to ask about them, or ask any general legal question."}
              </p>
              <div className="grid grid-cols-2 gap-2 mt-6 max-w-md">
                {(selectedIds.size > 0
                  ? [
                      "What are the key risks in these documents?",
                      "Summarize the main obligations and deadlines",
                      "Who are the parties involved and what are their roles?",
                      "What should I do next with these documents?",
                    ]
                  : [
                      "Analyze the key risks in a lease agreement",
                      "What are the steps for filing a divorce petition?",
                      "Draft a cease and desist letter outline",
                      "Explain the probate process for estates",
                    ]
                ).map((q) => (
                  <button
                    key={q}
                    onClick={() => {
                      setInput(q);
                      inputRef.current?.focus();
                    }}
                    className="text-left text-xs text-zinc-400 bg-zinc-800/50 hover:bg-zinc-800 border border-zinc-800 hover:border-zinc-700 rounded-lg px-3 py-2.5 transition-colors"
                  >
                    {q}
                  </button>
                ))}
              </div>
            </div>
          )}

          {messages.map((msg, i) => (
            <div
              key={i}
              className={`flex gap-3 ${msg.role === "user" ? "justify-end" : ""}`}
            >
              {msg.role === "assistant" && (
                <div className="w-8 h-8 rounded-lg bg-amber-600/15 flex items-center justify-center shrink-0 mt-0.5">
                  <Bot className="w-4 h-4 text-amber-400" />
                </div>
              )}
              <div
                className={`max-w-[70%] rounded-2xl px-4 py-3 text-sm leading-relaxed ${
                  msg.role === "user"
                    ? "bg-amber-600 text-white"
                    : "bg-zinc-800/80 text-zinc-200"
                }`}
              >
                <p className="whitespace-pre-wrap">{msg.content}</p>
              </div>
              {msg.role === "user" && (
                <div className="w-8 h-8 rounded-lg bg-zinc-700/50 flex items-center justify-center shrink-0 mt-0.5">
                  <User className="w-4 h-4 text-zinc-300" />
                </div>
              )}
            </div>
          ))}

          {loading && (
            <div className="flex gap-3">
              <div className="w-8 h-8 rounded-lg bg-amber-600/15 flex items-center justify-center shrink-0">
                <Loader2 className="w-4 h-4 text-amber-400 animate-spin" />
              </div>
              <div className="bg-zinc-800/80 rounded-2xl px-4 py-3">
                <div className="flex gap-1.5">
                  <div className="w-1.5 h-1.5 bg-zinc-500 rounded-full animate-bounce" />
                  <div className="w-1.5 h-1.5 bg-zinc-500 rounded-full animate-bounce [animation-delay:150ms]" />
                  <div className="w-1.5 h-1.5 bg-zinc-500 rounded-full animate-bounce [animation-delay:300ms]" />
                </div>
              </div>
            </div>
          )}
          <div ref={bottomRef} />
        </div>

        {/* Input */}
        <div className="border-t border-zinc-800 p-4 shrink-0">
          <div className="flex items-end gap-3 max-w-3xl mx-auto">
            <textarea
              ref={inputRef}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder={
                selectedIds.size > 0
                  ? "Ask about your selected documents..."
                  : "Ask a legal question..."
              }
              rows={1}
              className="flex-1 bg-zinc-800/80 border border-zinc-700 rounded-xl px-4 py-3 text-sm text-zinc-200 placeholder-zinc-500 resize-none focus:outline-none focus:ring-1 focus:ring-amber-600 max-h-32"
              style={{ minHeight: "44px" }}
            />
            <button
              onClick={handleSend}
              disabled={loading || !input.trim()}
              className="w-11 h-11 flex items-center justify-center bg-amber-600 hover:bg-amber-500 disabled:bg-zinc-800 disabled:text-zinc-600 text-white rounded-xl transition-colors shrink-0"
            >
              <Send className="w-4.5 h-4.5" />
            </button>
          </div>
          <p className="text-[10px] text-zinc-600 text-center mt-2">
            AI responses should be reviewed by a licensed attorney. Not legal
            advice.
          </p>
        </div>
      </div>
    </div>
  );
}
