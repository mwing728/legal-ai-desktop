import { invoke } from "@tauri-apps/api/core";

// ── Types ───────────────────────────────────────────────────────────

export interface Client {
  id: number;
  name: string;
  email: string | null;
  phone: string | null;
  address: string | null;
  notes: string | null;
  created_at: string;
  updated_at: string;
}

export interface Matter {
  id: number;
  client_id: number | null;
  title: string;
  matter_type: string;
  status: string;
  description: string | null;
  priority: string;
  assigned_to: string | null;
  opened_at: string;
  closed_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface Document {
  id: number;
  matter_id: number | null;
  filename: string;
  file_path: string;
  doc_type: string;
  category: string;
  extracted_text: string | null;
  analysis_json: string | null;
  status: string;
  created_at: string;
  updated_at: string;
}

export interface ConflictHit {
  id: number;
  document_id: number | null;
  matter_id: number | null;
  matched_name: string;
  matched_client_id: number | null;
  conflict_type: string;
  confidence: number;
  resolved: boolean;
  resolution_note: string | null;
  created_at: string;
}

export interface Deadline {
  id: number;
  matter_id: number | null;
  document_id: number | null;
  title: string;
  description: string | null;
  due_date: string;
  priority: string;
  status: string;
  created_at: string;
}

export interface ActionItem {
  id: number;
  matter_id: number | null;
  document_id: number | null;
  title: string;
  description: string | null;
  assignee: string | null;
  priority: string;
  status: string;
  created_at: string;
  completed_at: string | null;
}

export interface DashboardStats {
  total_clients: number;
  total_matters: number;
  matters_by_status: Record<string, number>;
  total_documents: number;
  documents_by_status: Record<string, number>;
  upcoming_deadlines: number;
  open_action_items: number;
  unresolved_conflicts: number;
}

export interface ProcessResult {
  document_id: number;
  doc_type: string;
  category: string;
  analysis: Record<string, unknown>;
  chunks_processed: number;
  elapsed_ms: number;
  client_id: number | null;
  matter_id: number | null;
  conflicts_found: number;
  action_items_created: number;
  deadlines_created: number;
}

export interface ChatMessage {
  role: string;
  content: string;
}

export interface ChatResponse {
  content: string;
}

export interface DraftResult {
  draft_type: string;
  content: string;
}

export interface ReviewPacketResult {
  document_id: number;
  packet: string;
}

export interface LlmStatus {
  state: string;
  progress: number;
  error: string | null;
}

// ── API Functions ───────────────────────────────────────────────────

export const api = {
  getDashboard: () => invoke<DashboardStats>("get_dashboard"),

  listClients: () => invoke<Client[]>("list_clients"),
  getClient: (id: number) => invoke<Client | null>("get_client", { id }),
  createClient: (payload: {
    name: string;
    email?: string;
    phone?: string;
    address?: string;
    notes?: string;
  }) => invoke<number>("create_client", { payload }),
  updateClient: (payload: {
    id: number;
    name?: string;
    email?: string;
    phone?: string;
    address?: string;
    notes?: string;
  }) => invoke<void>("update_client", { payload }),
  searchClients: (query: string) => invoke<Client[]>("search_clients", { query }),

  listMatters: () => invoke<Matter[]>("list_matters"),
  getMatter: (id: number) => invoke<Matter | null>("get_matter", { id }),
  listMattersByClient: (clientId: number) =>
    invoke<Matter[]>("list_matters_by_client", { clientId }),
  createMatter: (payload: {
    client_id?: number;
    title: string;
    matter_type: string;
    description?: string;
  }) => invoke<number>("create_matter", { payload }),
  updateMatterStatus: (id: number, status: string) =>
    invoke<void>("update_matter_status", { id, status }),

  listDocuments: () => invoke<Document[]>("list_documents"),
  getDocument: (id: number) => invoke<Document | null>("get_document", { id }),
  listDocumentsByMatter: (matterId: number) =>
    invoke<Document[]>("list_documents_by_matter", { matterId }),
  updateDocumentMatter: (id: number, matterId: number) =>
    invoke<void>("update_document_matter", { id, matterId }),
  processDocument: (filePath: string) =>
    invoke<ProcessResult>("process_document", { filePath }),

  listDeadlines: () => invoke<Deadline[]>("list_deadlines"),
  listUpcomingDeadlines: (days: number) =>
    invoke<Deadline[]>("list_upcoming_deadlines", { days }),
  updateDeadlineStatus: (id: number, status: string) =>
    invoke<void>("update_deadline_status", { id, status }),

  listActionItems: () => invoke<ActionItem[]>("list_action_items"),
  listActionItemsByMatter: (matterId: number) =>
    invoke<ActionItem[]>("list_action_items_by_matter", { matterId }),
  updateActionItemStatus: (id: number, status: string) =>
    invoke<void>("update_action_item_status", { id, status }),

  getConflictsForDocument: (documentId: number) =>
    invoke<ConflictHit[]>("get_conflicts_for_document", { documentId }),
  resolveConflict: (id: number, note: string) =>
    invoke<void>("resolve_conflict", { id, note }),

  chatSend: (messages: ChatMessage[], docIds: number[] = []) =>
    invoke<ChatResponse>("chat_send", { messages, docIds }),

  scanFolder: (folderPath: string) =>
    invoke<string[]>("scan_folder", { folderPath }),

  deleteDocument: (id: number) => invoke<void>("delete_document", { id }),
  deleteClient: (id: number) => invoke<void>("delete_client", { id }),
  deleteMatter: (id: number) => invoke<void>("delete_matter", { id }),

  draftDocument: (draftType: string, context: string) =>
    invoke<DraftResult>("draft_document", { draftType, context }),
  generateReviewPacket: (documentId: number) =>
    invoke<ReviewPacketResult>("generate_review_packet", { documentId }),

  getLlmStatus: () => invoke<LlmStatus>("get_llm_status"),
  retryLlmSetup: () => invoke<void>("retry_llm_setup"),
  deleteAllAppData: () => invoke<string>("delete_all_app_data"),
};
