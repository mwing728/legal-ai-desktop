use ironclaw::tools::db::{
    ActionItem, Client, ConflictHit, DashboardStats, Deadline, Document, LegalDatabase, Matter,
};
use ironclaw::core::types::{Message, MessageRole, ToolCall};
use ironclaw::workflow::{
    RetryPolicy, StepAction, Trigger, Workflow, WorkflowEngine, WorkflowStep,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tauri::{Manager, State};

const LLAMA_SERVER_HOST: &str = "127.0.0.1";
const LLAMA_SERVER_PORT: &str = "11435";
const LLAMA_SERVER_ADDR: &str = "127.0.0.1:11435";
const LLAMA_CHAT_URL: &str = "http://127.0.0.1:11435/v1/chat/completions";
const LLAMA_HEALTH_URL: &str = "http://127.0.0.1:11435/health";
const PHI4_MODEL: &str = "phi-4-mini";
const PHI4_GGUF: &str = "phi-4-mini-instruct-q4_k_m.gguf";
const PHI4_MODEL_URL: &str = "https://huggingface.co/bartowski/microsoft_Phi-4-mini-instruct-GGUF/resolve/main/microsoft_Phi-4-mini-instruct-Q4_K_M.gguf";

#[derive(Clone, Serialize)]
struct LlmStatus {
    state: String,
    progress: f64,
    error: Option<String>,
}

struct LlmManager {
    status: Arc<tokio::sync::RwLock<LlmStatus>>,
    child_pid: Arc<tokio::sync::Mutex<Option<u32>>>,
}

fn find_llama_server_binary() -> Option<std::path::PathBuf> {
    let exe_dir = std::env::current_exe().ok()?.parent()?.to_path_buf();

    let search_dirs = vec![
        exe_dir.join("llama-server"),
        exe_dir.clone(),
        exe_dir.join("resources").join("llama-server"),
        exe_dir.join("../Resources").join("llama-server"),
        exe_dir.join("../Resources"),
    ];

    let candidate_names = [
        "llama-server.exe",
        "llama-server",
    ];

    for dir in &search_dirs {
        for name in &candidate_names {
            let p = dir.join(name);
            if p.exists() {
                return Some(p);
            }
        }
    }

    if let Ok(path) = which::which("llama-server") {
        return Some(path);
    }

    None
}

fn find_model_file() -> Option<std::path::PathBuf> {
    let exe_dir = std::env::current_exe().ok()?.parent()?.to_path_buf();
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_string());
    let ironclaw_models = std::path::PathBuf::from(&home).join(".ironclaw").join("models");

    let search_dirs = vec![
        ironclaw_models,
        exe_dir.join("llama-server"),
        exe_dir.join("models"),
        exe_dir.join("resources").join("llama-server"),
        exe_dir.join("resources").join("models"),
        exe_dir.join("../Resources").join("llama-server"),
        exe_dir.join("../Resources").join("models"),
        exe_dir.clone(),
    ];

    for dir in &search_dirs {
        let p = dir.join(PHI4_GGUF);
        if p.exists() {
            return Some(p);
        }
    }

    None
}

impl LlmManager {
    fn new() -> Self {
        Self {
            status: Arc::new(tokio::sync::RwLock::new(LlmStatus {
                state: "starting".to_string(),
                progress: 0.0,
                error: None,
            })),
            child_pid: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    async fn set_state(&self, state: &str, progress: f64, error: Option<String>) {
        let mut s = self.status.write().await;
        s.state = state.to_string();
        s.progress = progress;
        s.error = error;
    }

    async fn spawn_and_wait(&self) {
        let server_bin = match find_llama_server_binary() {
            Some(p) => p,
            None => {
                self.set_state(
                    "error",
                    0.0,
                    Some("llama-server binary not found in application directory".to_string()),
                )
                .await;
                return;
            }
        };

        let model_file = match find_model_file() {
            Some(p) => p,
            None => {
                match self.download_model().await {
                    Ok(p) => p,
                    Err(e) => {
                        self.set_state(
                            "error",
                            0.0,
                            Some(format!("Failed to download model: {}", e)),
                        )
                        .await;
                        return;
                    }
                }
            }
        };

        eprintln!("[llm] Using server: {}", server_bin.display());
        eprintln!("[llm] Using model: {}", model_file.display());

        let server_dir = server_bin.parent().unwrap_or(std::path::Path::new("."));

        let mut cmd = tokio::process::Command::new(&server_bin);
        cmd.args([
                "-m", &model_file.to_string_lossy(),
                "--host", LLAMA_SERVER_HOST,
                "--port", LLAMA_SERVER_PORT,
                "--ctx-size", "2048",
                "-t", "8",
                "--batch-size", "512",
            ])
            .current_dir(server_dir)
            .env("LD_LIBRARY_PATH", server_dir)
            .env("DYLD_LIBRARY_PATH", server_dir)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
        }

        match cmd.spawn() {
            Ok(child) => {
                let pid = child.id();
                {
                    let mut stored_pid = self.child_pid.lock().await;
                    *stored_pid = pid;
                }
                eprintln!("[llm] Spawned with PID: {:?}", pid);

                tokio::spawn(async move {
                    let output = child.wait_with_output().await;
                    match output {
                        Ok(o) => {
                            if !o.stderr.is_empty() {
                                eprintln!(
                                    "[llm] stderr: {}",
                                    String::from_utf8_lossy(&o.stderr)
                                );
                            }
                            eprintln!("[llm] Process exited: {}", o.status);
                        }
                        Err(e) => eprintln!("[llm] Wait error: {}", e),
                    }
                });

                if self.wait_for_ready().await {
                    self.set_state("ready", 100.0, None).await;
                }
            }
            Err(e) => {
                self.set_state(
                    "error",
                    0.0,
                    Some(format!("Failed to start llama-server: {}", e)),
                )
                .await;
            }
        }
    }

    async fn download_model(&self) -> anyhow::Result<std::path::PathBuf> {
        use tokio::io::AsyncWriteExt;

        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".to_string());
        let models_dir = std::path::PathBuf::from(&home).join(".ironclaw").join("models");
        std::fs::create_dir_all(&models_dir)?;
        let dest = models_dir.join(PHI4_GGUF);

        if dest.exists() {
            return Ok(dest);
        }

        eprintln!("[llm] Downloading model from {}", PHI4_MODEL_URL);
        self.set_state("downloading", 0.0, None).await;

        let client = reqwest::Client::new();
        let resp = client.get(PHI4_MODEL_URL).send().await?;

        if !resp.status().is_success() {
            anyhow::bail!("HTTP {} from model download", resp.status());
        }

        let total_size = resp.content_length().unwrap_or(0);
        let mut downloaded: u64 = 0;

        let tmp_path = dest.with_extension("gguf.tmp");
        let mut file = tokio::fs::File::create(&tmp_path).await?;
        let mut stream = resp.bytes_stream();

        use futures_util::StreamExt;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            file.write_all(&chunk).await?;
            downloaded += chunk.len() as u64;

            if total_size > 0 {
                let pct = (downloaded as f64 / total_size as f64) * 80.0;
                self.set_state("downloading", pct, None).await;
            }
        }
        file.flush().await?;
        drop(file);

        tokio::fs::rename(&tmp_path, &dest).await?;
        self.set_state("downloading", 80.0, None).await;
        eprintln!("[llm] Model downloaded to {}", dest.display());

        Ok(dest)
    }

    async fn wait_for_ready(&self) -> bool {
        let client = reqwest::Client::new();
        for i in 0..90 {
            match client.get(LLAMA_HEALTH_URL).send().await {
                Ok(resp) if resp.status().is_success() => {
                    self.set_state("ready", 100.0, None).await;
                    return true;
                }
                _ => {
                    let progress = (i as f64 / 90.0) * 80.0;
                    self.set_state("starting", progress, None).await;
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
        self.set_state(
            "error",
            0.0,
            Some("llama-server failed to start within 90 seconds".to_string()),
        )
        .await;
        false
    }

    async fn kill(&self) {
        let pid = self.child_pid.lock().await;
        if let Some(pid) = *pid {
            #[cfg(unix)]
            {
                unsafe {
                    libc::kill(pid as i32, libc::SIGTERM);
                }
            }
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                let _ = std::process::Command::new("taskkill")
                    .args(["/F", "/T", "/PID", &pid.to_string()])
                    .creation_flags(0x08000000) // CREATE_NO_WINDOW
                    .output();
            }
        }
    }
}

#[tauri::command]
async fn get_llm_status(
    mgr: State<'_, LlmManager>,
) -> Result<LlmStatus, String> {
    Ok(mgr.status.read().await.clone())
}

#[tauri::command]
async fn retry_llm_setup(mgr: State<'_, LlmManager>) -> Result<(), String> {
    mgr.kill().await;
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    mgr.set_state("starting", 0.0, None).await;
    let status = Arc::clone(&mgr.status);
    let child_pid = Arc::clone(&mgr.child_pid);
    let spawner = LlmManager { status, child_pid };
    tauri::async_runtime::spawn(async move {
        spawner.spawn_and_wait().await;
    });
    Ok(())
}

struct AppState {
    db: Arc<LegalDatabase>,
    http: reqwest::Client,
    engine: Arc<ironclaw::core::Engine>,
    workflows: Arc<tokio::sync::Mutex<WorkflowEngine>>,
    ocr_tools_dir: Option<std::path::PathBuf>,
}

fn find_ocr_tools_dir() -> Option<std::path::PathBuf> {
    let exe_dir = std::env::current_exe().ok()?.parent()?.to_path_buf();

    let candidates = [
        exe_dir.join("ocr-tools"),
        exe_dir.join("resources").join("ocr-tools"),
        exe_dir.join("_up_").join("Resources").join("ocr-tools"), // macOS .app bundle
    ];

    for c in &candidates {
        if c.exists() {
            return Some(c.clone());
        }
    }
    None
}

fn resolve_ocr_tool(ocr_dir: &Option<std::path::PathBuf>, tool: &str) -> std::path::PathBuf {
    if let Some(dir) = ocr_dir {
        let candidate = if cfg!(target_os = "windows") {
            dir.join(format!("{}.exe", tool))
        } else {
            dir.join(tool)
        };
        if candidate.exists() {
            return candidate;
        }
    }
    std::path::PathBuf::from(tool)
}

fn resolve_tessdata_dir(ocr_dir: &Option<std::path::PathBuf>) -> Option<std::path::PathBuf> {
    if let Some(dir) = ocr_dir {
        let candidate = dir.join("tessdata");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

// ── Dashboard ───────────────────────────────────────────────────────

#[tauri::command]
fn get_dashboard(state: State<AppState>) -> Result<DashboardStats, String> {
    state.db.get_dashboard_stats().map_err(|e| e.to_string())
}

// ── Clients ─────────────────────────────────────────────────────────

#[tauri::command]
fn list_clients(state: State<AppState>) -> Result<Vec<Client>, String> {
    state.db.list_clients().map_err(|e| e.to_string())
}

#[tauri::command]
fn get_client(state: State<AppState>, id: i64) -> Result<Option<Client>, String> {
    state.db.get_client(id).map_err(|e| e.to_string())
}

#[derive(Deserialize)]
pub struct CreateClientPayload {
    name: String,
    email: Option<String>,
    phone: Option<String>,
    address: Option<String>,
    notes: Option<String>,
}

#[tauri::command]
fn create_client(state: State<AppState>, payload: CreateClientPayload) -> Result<i64, String> {
    state
        .db
        .create_client(
            &payload.name,
            payload.email.as_deref(),
            payload.phone.as_deref(),
            payload.address.as_deref(),
            payload.notes.as_deref(),
        )
        .map_err(|e| e.to_string())
}

#[derive(Deserialize)]
pub struct UpdateClientPayload {
    id: i64,
    name: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    address: Option<String>,
    notes: Option<String>,
}

#[tauri::command]
fn update_client(state: State<AppState>, payload: UpdateClientPayload) -> Result<(), String> {
    state
        .db
        .update_client(
            payload.id,
            payload.name.as_deref(),
            payload.email.as_deref(),
            payload.phone.as_deref(),
            payload.address.as_deref(),
            payload.notes.as_deref(),
        )
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn search_clients(state: State<AppState>, query: String) -> Result<Vec<Client>, String> {
    state.db.search_clients(&query).map_err(|e| e.to_string())
}

// ── Matters ─────────────────────────────────────────────────────────

#[tauri::command]
fn list_matters(state: State<AppState>) -> Result<Vec<Matter>, String> {
    state.db.list_matters().map_err(|e| e.to_string())
}

#[tauri::command]
fn get_matter(state: State<AppState>, id: i64) -> Result<Option<Matter>, String> {
    state.db.get_matter(id).map_err(|e| e.to_string())
}

#[tauri::command]
fn list_matters_by_client(state: State<AppState>, client_id: i64) -> Result<Vec<Matter>, String> {
    state
        .db
        .list_matters_by_client(client_id)
        .map_err(|e| e.to_string())
}

#[derive(Deserialize)]
pub struct CreateMatterPayload {
    client_id: Option<i64>,
    title: String,
    matter_type: String,
    description: Option<String>,
}

#[tauri::command]
fn create_matter(state: State<AppState>, payload: CreateMatterPayload) -> Result<i64, String> {
    state
        .db
        .create_matter(
            payload.client_id,
            &payload.title,
            &payload.matter_type,
            payload.description.as_deref(),
        )
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn update_matter_status(state: State<AppState>, id: i64, status: String) -> Result<(), String> {
    state
        .db
        .update_matter_status(id, &status)
        .map_err(|e| e.to_string())
}

// ── Documents ───────────────────────────────────────────────────────

#[tauri::command]
fn list_documents(state: State<AppState>) -> Result<Vec<Document>, String> {
    state.db.list_documents().map_err(|e| e.to_string())
}

#[tauri::command]
fn get_document(state: State<AppState>, id: i64) -> Result<Option<Document>, String> {
    state.db.get_document(id).map_err(|e| e.to_string())
}

#[tauri::command]
fn list_documents_by_matter(
    state: State<AppState>,
    matter_id: i64,
) -> Result<Vec<Document>, String> {
    state
        .db
        .list_documents_by_matter(matter_id)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn update_document_matter(
    state: State<AppState>,
    id: i64,
    matter_id: i64,
) -> Result<(), String> {
    state
        .db
        .update_document_matter(id, matter_id)
        .map_err(|e| e.to_string())
}

// ── Deadlines ───────────────────────────────────────────────────────

#[tauri::command]
fn list_deadlines(state: State<AppState>) -> Result<Vec<Deadline>, String> {
    state.db.list_deadlines().map_err(|e| e.to_string())
}

#[tauri::command]
fn list_upcoming_deadlines(state: State<AppState>, days: i64) -> Result<Vec<Deadline>, String> {
    state
        .db
        .list_upcoming_deadlines(days)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn update_deadline_status(state: State<AppState>, id: i64, status: String) -> Result<(), String> {
    state
        .db
        .update_deadline_status(id, &status)
        .map_err(|e| e.to_string())
}

// ── Action Items ────────────────────────────────────────────────────

#[tauri::command]
fn list_action_items(state: State<AppState>) -> Result<Vec<ActionItem>, String> {
    state.db.list_action_items().map_err(|e| e.to_string())
}

#[tauri::command]
fn list_action_items_by_matter(
    state: State<AppState>,
    matter_id: i64,
) -> Result<Vec<ActionItem>, String> {
    state
        .db
        .list_action_items_by_matter(matter_id)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn update_action_item_status(
    state: State<AppState>,
    id: i64,
    status: String,
) -> Result<(), String> {
    state
        .db
        .update_action_item_status(id, &status)
        .map_err(|e| e.to_string())
}

// ── Conflicts ───────────────────────────────────────────────────────

#[tauri::command]
fn get_conflicts_for_document(
    state: State<AppState>,
    document_id: i64,
) -> Result<Vec<ConflictHit>, String> {
    state
        .db
        .get_conflicts_for_document(document_id)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn resolve_conflict(state: State<AppState>, id: i64, note: String) -> Result<(), String> {
    state
        .db
        .resolve_conflict(id, &note)
        .map_err(|e| e.to_string())
}

// ── Document Processing (extract + chunked analyze via LLM) ─────────

#[derive(Serialize)]
pub struct ProcessResult {
    document_id: i64,
    doc_type: String,
    category: String,
    analysis: serde_json::Value,
    chunks_processed: usize,
    elapsed_ms: u64,
    client_id: Option<i64>,
    matter_id: Option<i64>,
    conflicts_found: usize,
    action_items_created: usize,
    deadlines_created: usize,
}

#[tauri::command]
async fn process_document(
    state: State<'_, AppState>,
    file_path: String,
) -> Result<ProcessResult, String> {
    let start = std::time::Instant::now();
    let path = std::path::Path::new(&file_path);
    let filename = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let text = extract_text_from_file(path, &state.ocr_tools_dir).map_err(|e| e.to_string())?;

    let doc_id = state
        .db
        .insert_document(&filename, &file_path, Some(&text))
        .map_err(|e| e.to_string())?;

    state
        .db
        .update_document_status(doc_id, "processing")
        .map_err(|e| e.to_string())?;

    let (analysis, chunks_processed) = call_llm_analyze(&state.http, &text)
        .await
        .map_err(|e| e.to_string())?;

    let doc_type = analysis["document_type"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    let category = analysis["category"]
        .as_str()
        .unwrap_or("general")
        .to_string();
    let title = analysis["title"]
        .as_str()
        .unwrap_or(&filename)
        .to_string();

    state
        .db
        .update_document_analysis(doc_id, &doc_type, &category, &analysis.to_string())
        .map_err(|e| e.to_string())?;
    state
        .db
        .update_document_status(doc_id, "analyzed")
        .map_err(|e| e.to_string())?;

    // ── Auto-triage via IronClaw Workflow Engine ──────────────────────

    let parties: Vec<String> = analysis["parties"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    let client_id = if let Some(primary_party) = parties.first() {
        resolve_client(&state.engine, primary_party).await
    } else {
        None
    };

    let workflow_id = match category.as_str() {
        "criminal" => "criminal_intake",
        "family_law" => "family_intake",
        "estate" => "estate_intake",
        "immigration" => "immigration_intake",
        "real_estate" => "real_estate_intake",
        _ => "default_intake",
    };

    let matter_title = format!("{} - {}", category.replace('_', " "), title);
    let wf_vars = HashMap::from([
        ("doc_id".to_string(), doc_id.to_string()),
        ("category".to_string(), category.clone()),
        ("title".to_string(), title.clone()),
        ("matter_title".to_string(), matter_title),
        ("parties_json".to_string(), serde_json::to_string(&parties).unwrap_or_default()),
        ("analysis_json".to_string(), analysis.to_string()),
        ("primary_party".to_string(), parties.first().cloned().unwrap_or_default()),
        ("resolved_client_id".to_string(), client_id.map(|id| id.to_string()).unwrap_or_default()),
        ("resolved_matter_id".to_string(), String::new()),
    ]);

    let triage = run_intake_workflow(&state, workflow_id, wf_vars).await;

    if triage.matter_id.is_some() {
        let _ = state.db.update_document_status(doc_id, "filed");
    }

    state
        .db
        .log_audit_event(
            "document_processed",
            Some("document"),
            Some(doc_id),
            Some(&serde_json::json!({
                "filename": filename,
                "chunks": chunks_processed,
                "workflow": workflow_id,
                "client_id": triage.client_id,
                "matter_id": triage.matter_id,
                "conflicts": triage.conflicts_found,
            }).to_string()),
        )
        .map_err(|e| e.to_string())?;

    let elapsed_ms = start.elapsed().as_millis() as u64;

    Ok(ProcessResult {
        document_id: doc_id,
        doc_type,
        category,
        analysis,
        chunks_processed,
        elapsed_ms,
        client_id: triage.client_id,
        matter_id: triage.matter_id,
        conflicts_found: triage.conflicts_found,
        action_items_created: triage.action_items_created,
        deadlines_created: triage.deadlines_created,
    })
}


// ── IronClaw DocDraftTool ───────────────────────────────────────────

#[derive(Serialize)]
pub struct DraftResult {
    draft_type: String,
    content: String,
}

#[tauri::command]
async fn draft_document(
    state: State<'_, AppState>,
    draft_type: String,
    context: String,
) -> Result<DraftResult, String> {
    let result = state.engine.execute_tool_call(&make_tool_call(
        "legal_doc_draft",
        serde_json::json!({"draft_type": draft_type, "context": context}),
    )).await.map_err(|e| e.to_string())?;

    if !result.success {
        return Err(result.error.unwrap_or_else(|| "Draft generation failed".to_string()));
    }

    Ok(DraftResult { draft_type, content: result.output })
}

// ── IronClaw ReviewPacketTool ───────────────────────────────────────

#[derive(Serialize)]
pub struct ReviewPacketResult {
    document_id: i64,
    packet: String,
}

#[tauri::command]
async fn generate_review_packet(
    state: State<'_, AppState>,
    document_id: i64,
) -> Result<ReviewPacketResult, String> {
    let result = state.engine.execute_tool_call(&make_tool_call(
        "legal_review_packet",
        serde_json::json!({"document_id": document_id}),
    )).await.map_err(|e| e.to_string())?;

    if !result.success {
        return Err(result.error.unwrap_or_else(|| "Review packet generation failed".to_string()));
    }

    Ok(ReviewPacketResult { document_id, packet: result.output })
}

// ── AI Chat (agentic via IronClaw Engine) ────────────────────────────

#[derive(Deserialize)]
pub struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Serialize)]
pub struct ChatResponse {
    content: String,
}

#[tauri::command]
async fn chat_send(
    state: State<'_, AppState>,
    messages: Vec<ChatMessage>,
    doc_ids: Vec<i64>,
) -> Result<ChatResponse, String> {
    let base_prompt = "You are a private local legal AI assistant. You help attorneys and paralegals process, analyze, and organize legal documents of all types including family law, criminal law, immigration, real estate, estate planning, corporate law, employment law, intellectual property, and tax law. Provide clear, actionable advice and analysis. Always note that you are an AI and that your analysis should be reviewed by a licensed attorney. You have tools available to look up documents, check conflicts, draft legal documents, generate review packets, manage clients and matters, and more. Use them when appropriate.";

    let system_content = if doc_ids.is_empty() {
        base_prompt.to_string()
    } else {
        let mut doc_context = String::from("\n\nThe user has selected the following documents for this conversation. Use them to answer questions:\n\n");
        let max_text_per_doc = 6000 / doc_ids.len().max(1);

        for (i, &id) in doc_ids.iter().take(3).enumerate() {
            if let Ok(Some(doc)) = state.db.get_document(id) {
                doc_context.push_str(&format!("--- DOCUMENT {} ---\n", i + 1));
                doc_context.push_str(&format!("ID: {}\n", doc.id));
                doc_context.push_str(&format!("Filename: {}\n", doc.filename));
                doc_context.push_str(&format!("Type: {}\n", doc.doc_type));
                doc_context.push_str(&format!("Category: {}\n", doc.category));
                doc_context.push_str(&format!("Status: {}\n", doc.status));

                if let Some(ref analysis_str) = doc.analysis_json {
                    if let Ok(analysis) = serde_json::from_str::<serde_json::Value>(analysis_str) {
                        if let Some(summary) = analysis["summary"].as_str() {
                            doc_context.push_str(&format!("AI Summary: {}\n", summary));
                        }
                        if let Some(parties) = analysis["parties"].as_array() {
                            let names: Vec<&str> = parties.iter().filter_map(|p| p.as_str()).collect();
                            if !names.is_empty() {
                                doc_context.push_str(&format!("Parties: {}\n", names.join(", ")));
                            }
                        }
                        if let Some(dates) = analysis["key_dates"].as_array() {
                            let vals: Vec<&str> = dates.iter().filter_map(|d| d.as_str()).collect();
                            if !vals.is_empty() {
                                doc_context.push_str(&format!("Key Dates: {}\n", vals.join(", ")));
                            }
                        }
                        if let Some(terms) = analysis["key_terms"].as_array() {
                            let vals: Vec<&str> = terms.iter().filter_map(|t| t.as_str()).collect();
                            if !vals.is_empty() {
                                doc_context.push_str(&format!("Key Terms: {}\n", vals.join(", ")));
                            }
                        }
                        if let Some(risks) = analysis["risk_flags"].as_array() {
                            let vals: Vec<&str> = risks.iter().filter_map(|r| r.as_str()).collect();
                            if !vals.is_empty() {
                                doc_context.push_str(&format!("Risk Flags: {}\n", vals.join(", ")));
                            }
                        }
                        if let Some(jurisdiction) = analysis["jurisdiction"].as_str() {
                            if !jurisdiction.is_empty() {
                                doc_context.push_str(&format!("Jurisdiction: {}\n", jurisdiction));
                            }
                        }
                    }
                }

                if let Some(ref text) = doc.extracted_text {
                    let truncated: String = text.chars().take(max_text_per_doc).collect();
                    doc_context.push_str(&format!("\nExtracted Text (excerpt):\n{}\n", truncated));
                    if text.len() > max_text_per_doc {
                        doc_context.push_str("... [text truncated]\n");
                    }
                }
                doc_context.push('\n');
            }
        }

        format!("{}\n{}", base_prompt, doc_context)
    };

    let now = chrono::Utc::now();
    let mut conversation: Vec<Message> = vec![Message {
        role: MessageRole::System,
        content: system_content,
        tool_calls: Vec::new(),
        tool_results: Vec::new(),
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: now,
        content_blocks: Vec::new(),
    }];

    for msg in &messages {
        let role = match msg.role.as_str() {
            "user" => MessageRole::User,
            "assistant" => MessageRole::Assistant,
            _ => MessageRole::User,
        };
        conversation.push(Message {
            role,
            content: msg.content.clone(),
            tool_calls: Vec::new(),
            tool_results: Vec::new(),
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: now,
            content_blocks: Vec::new(),
        });
    }

    const MAX_TOOL_ROUNDS: usize = 5;
    let mut final_content = String::new();

    for _ in 0..MAX_TOOL_ROUNDS {
        let response = state.engine.process_message(&mut conversation)
            .await
            .map_err(|e| e.to_string())?;

        final_content = response.content.clone();

        if response.tool_calls.is_empty() {
            break;
        }

        conversation.push(response);
    }

    Ok(ChatResponse { content: final_content })
}

// ── Delete Commands ─────────────────────────────────────────────────

#[tauri::command]
fn delete_document(state: State<'_, AppState>, id: i64) -> Result<(), String> {
    state.db.delete_document(id).map_err(|e| e.to_string())?;
    state
        .db
        .log_audit_event("document_deleted", Some("document"), Some(id), None)
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn delete_client(state: State<'_, AppState>, id: i64) -> Result<(), String> {
    state.db.delete_client(id).map_err(|e| e.to_string())?;
    state
        .db
        .log_audit_event("client_deleted", Some("client"), Some(id), None)
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn delete_matter(state: State<'_, AppState>, id: i64) -> Result<(), String> {
    state.db.delete_matter(id).map_err(|e| e.to_string())?;
    state
        .db
        .log_audit_event("matter_deleted", Some("matter"), Some(id), None)
        .map_err(|e| e.to_string())?;
    Ok(())
}

// ── Data Management ─────────────────────────────────────────────────

#[tauri::command]
async fn delete_all_app_data() -> Result<String, String> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|e| e.to_string())?;
    let data_dir = std::path::PathBuf::from(home).join(".ironclaw");
    if data_dir.exists() {
        std::fs::remove_dir_all(&data_dir).map_err(|e| e.to_string())?;
    }
    Ok("All application data has been deleted.".to_string())
}

// ── Helpers ─────────────────────────────────────────────────────────

fn make_tool_call(name: &str, args_value: serde_json::Value) -> ToolCall {
    let arguments = args_value.as_object()
        .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default();
    ToolCall {
        id: uuid::Uuid::new_v4().to_string(),
        name: name.to_string(),
        arguments,
    }
}

fn has_meaningful_text(text: &str) -> bool {
    text.chars().filter(|c| c.is_alphanumeric()).count() > 100
}

fn ocr_image(path: &std::path::Path, ocr_dir: &Option<std::path::PathBuf>) -> anyhow::Result<String> {
    let tesseract = resolve_ocr_tool(ocr_dir, "tesseract");
    let mut cmd = std::process::Command::new(&tesseract);
    cmd.arg(path)
        .arg("stdout")
        .arg("--oem")
        .arg("1")
        .arg("-l")
        .arg("eng");

    if let Some(tessdata) = resolve_tessdata_dir(ocr_dir) {
        cmd.env("TESSDATA_PREFIX", tessdata);
    }

    let output = cmd.output().map_err(|e| anyhow::anyhow!(
        "Failed to run tesseract at '{}': {}", tesseract.display(), e
    ))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Tesseract failed: {}", stderr);
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn ocr_pdf(path: &std::path::Path, ocr_dir: &Option<std::path::PathBuf>) -> anyhow::Result<String> {
    let tmp_dir = std::env::temp_dir().join(format!("legal-ai-ocr-{}", std::process::id()));
    std::fs::create_dir_all(&tmp_dir)?;

    let result = (|| -> anyhow::Result<String> {
        let pdftoppm = resolve_ocr_tool(ocr_dir, "pdftoppm");
        let status = std::process::Command::new(&pdftoppm)
            .arg("-png")
            .arg("-r")
            .arg("200")
            .arg(path)
            .arg(tmp_dir.join("page"))
            .status()
            .map_err(|e| anyhow::anyhow!(
                "Failed to run pdftoppm at '{}': {}", pdftoppm.display(), e
            ))?;

        if !status.success() {
            anyhow::bail!("pdftoppm failed with exit code: {:?}", status.code());
        }

        let mut pages: Vec<std::path::PathBuf> = std::fs::read_dir(&tmp_dir)?
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("png"))
            .collect();
        pages.sort();

        let mut full_text = String::new();
        for page_img in &pages {
            match ocr_image(page_img, ocr_dir) {
                Ok(page_text) => {
                    full_text.push_str(&page_text);
                    full_text.push('\n');
                }
                Err(e) => {
                    eprintln!("OCR warning: failed on {:?}: {}", page_img, e);
                }
            }
        }

        Ok(full_text)
    })();

    let _ = std::fs::remove_dir_all(&tmp_dir);
    result
}

fn extract_text_from_file(path: &std::path::Path, ocr_dir: &Option<std::path::PathBuf>) -> anyhow::Result<String> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    match ext.as_str() {
        "pdf" => {
            let bytes = std::fs::read(path)?;
            let text_layer = pdf_extract::extract_text_from_mem(&bytes)
                .unwrap_or_default();
            let ocr_text = ocr_pdf(path, ocr_dir).unwrap_or_default();

            if ocr_text.len() > text_layer.len() {
                Ok(ocr_text)
            } else if has_meaningful_text(&text_layer) {
                Ok(text_layer)
            } else {
                Ok(ocr_text)
            }
        }
        "txt" | "md" | "rtf" => Ok(std::fs::read_to_string(path)?),
        "docx" => {
            let data = std::fs::read(path)?;
            let doc = docx_rs::read_docx(&data)
                .map_err(|e| anyhow::anyhow!("DOCX read error: {}", e))?;
            let mut text = String::new();
            for child in doc.document.children {
                if let docx_rs::DocumentChild::Paragraph(p) = child {
                    for pc in &p.children {
                        if let docx_rs::ParagraphChild::Run(run) = pc {
                            for rc in &run.children {
                                if let docx_rs::RunChild::Text(t) = rc {
                                    text.push_str(&t.text);
                                }
                            }
                        }
                    }
                    text.push('\n');
                }
            }
            Ok(text)
        }
        "jpg" | "jpeg" | "png" | "tiff" | "tif" | "bmp" => ocr_image(path, ocr_dir),
        _ => Err(anyhow::anyhow!("Unsupported file type: {}", ext)),
    }
}

const CHUNK_SIZE: usize = 50_000;

fn chunk_text(text: &str) -> Vec<String> {
    if text.len() <= CHUNK_SIZE {
        return vec![text.to_string()];
    }

    let mut chunks = Vec::new();
    let mut start = 0;

    while start < text.len() {
        let end = std::cmp::min(start + CHUNK_SIZE, text.len());

        if end == text.len() {
            chunks.push(text[start..end].to_string());
            break;
        }

        // Try to break at a paragraph boundary
        let slice = &text[start..end];
        let break_at = slice
            .rfind("\n\n")
            .or_else(|| slice.rfind('\n'))
            .or_else(|| slice.rfind(". "))
            .map(|pos| pos + 1)
            .unwrap_or(slice.len());

        chunks.push(text[start..start + break_at].to_string());
        start += break_at;
    }

    chunks
}

async fn call_llm_analyze_chunk(
    client: &reqwest::Client,
    chunk: &str,
    chunk_index: usize,
    total_chunks: usize,
) -> anyhow::Result<serde_json::Value> {
    let context_hint = if total_chunks == 1 {
        String::new()
    } else {
        format!(
            "\n\nNOTE: This is section {} of {} of the document. Analyze only the content shown.\n",
            chunk_index + 1,
            total_chunks
        )
    };

    let prompt = format!(
        r#"Analyze this legal document section and respond with ONLY valid JSON (no markdown):
{{
  "document_type": "<specific type e.g. lease_agreement, divorce_petition, will, deed>",
  "category": "<broad category e.g. real_estate, family_law, estate, criminal, immigration, corporate, employment, ip, tax>",
  "title": "<document title or summary>",
  "parties": ["<list of parties/names mentioned>"],
  "key_dates": ["<important dates found>"],
  "key_terms": ["<important legal terms or clauses>"],
  "jurisdiction": "<jurisdiction if mentioned>",
  "summary": "<detailed 7-10 sentence summary describing what the document is, its purpose, the key facts, parties involved, obligations, important dates, and legal implications>",
  "risk_flags": ["<any concerns or issues noted>"]
}}{context_hint}
Document text:
{chunk}"#
    );

    let body = serde_json::json!({
        "model": PHI4_MODEL,
        "messages": [
            {"role": "system", "content": "You are a legal document analyst. Respond ONLY with valid JSON, no other text."},
            {"role": "user", "content": prompt}
        ],
        "max_tokens": 768,
        "temperature": 0.5,
        "stream": false,
    });

    let resp = client
        .post(LLAMA_CHAT_URL)
        .json(&body)
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let error_body = resp.text().await.unwrap_or_default();
        anyhow::bail!("LLM error {}: {}", status, error_body);
    }

    let json: serde_json::Value = resp.json().await?;
    let content = json["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or("{}")
        .to_string();

    let cleaned = content
        .trim()
        .trim_start_matches("```json")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim();

    serde_json::from_str(cleaned)
        .or_else(|_| Ok(serde_json::json!({"raw_response": content})))
}

fn merge_chunk_analyses(results: &[serde_json::Value]) -> (serde_json::Value, String) {
    if results.len() == 1 {
        return (results[0].clone(), String::new());
    }

    // Take doc_type, category, title, jurisdiction from the first chunk
    // (document headers are almost always in the first section)
    let first = &results[0];
    let doc_type = first["document_type"].as_str().unwrap_or("unknown");
    let category = first["category"].as_str().unwrap_or("general");
    let title = first["title"].as_str().unwrap_or("");
    let jurisdiction = results
        .iter()
        .find_map(|r| r["jurisdiction"].as_str().filter(|s| !s.is_empty()))
        .unwrap_or("");

    // Merge array fields with deduplication
    fn collect_strings(results: &[serde_json::Value], field: &str) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for r in results {
            if let Some(arr) = r[field].as_array() {
                for v in arr {
                    if let Some(s) = v.as_str() {
                        let lower = s.to_lowercase();
                        if !s.is_empty() && seen.insert(lower) {
                            out.push(s.to_string());
                        }
                    }
                }
            }
        }
        out
    }

    let parties = collect_strings(results, "parties");
    let key_dates = collect_strings(results, "key_dates");
    let key_terms = collect_strings(results, "key_terms");
    let risk_flags = collect_strings(results, "risk_flags");

    let summaries: Vec<&str> = results
        .iter()
        .filter_map(|r| r["summary"].as_str().filter(|s| !s.is_empty()))
        .collect();
    let summary = summaries.join(" ");

    (serde_json::json!({
        "document_type": doc_type,
        "category": category,
        "title": title,
        "parties": parties,
        "key_dates": key_dates,
        "key_terms": key_terms,
        "jurisdiction": jurisdiction,
        "summary": summary,
        "risk_flags": risk_flags,
        "chunks_analyzed": results.len(),
    }), summary)
}

async fn synthesize_final_summary(
    client: &reqwest::Client,
    chunk_summaries: &str,
    doc_type: &str,
) -> anyhow::Result<String> {
    let prompt = format!(
        r#"Below are section-by-section summaries of a legal document (type: {doc_type}). Write a single cohesive summary paragraph (8-12 sentences) that covers the entire document's purpose, key parties, obligations, important dates, and any risks or concerns. Respond with ONLY the summary text, no JSON, no markdown.

Section summaries:
{chunk_summaries}"#
    );

    let body = serde_json::json!({
        "model": PHI4_MODEL,
        "messages": [
            {"role": "system", "content": "You are a legal document analyst. Write clear, detailed summaries."},
            {"role": "user", "content": prompt}
        ],
        "max_tokens": 512,
        "temperature": 0.5,
        "stream": false,
    });

    let resp = client
        .post(LLAMA_CHAT_URL)
        .json(&body)
        .send()
        .await?;

    if !resp.status().is_success() {
        anyhow::bail!("LLM summary merge error: {}", resp.status());
    }

    let json: serde_json::Value = resp.json().await?;
    Ok(json["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or("")
        .trim()
        .to_string())
}

async fn call_llm_analyze(
    client: &reqwest::Client,
    text: &str,
) -> anyhow::Result<(serde_json::Value, usize)> {
    let chunks = chunk_text(text);
    let total = chunks.len();
    let mut results = Vec::with_capacity(total);

    for (i, chunk) in chunks.iter().enumerate() {
        let result = call_llm_analyze_chunk(client, chunk, i, total).await?;
        results.push(result);
    }

    let (mut merged, concatenated_summaries) = merge_chunk_analyses(&results);

    if total > 1 && !concatenated_summaries.is_empty() {
        let doc_type = merged["document_type"].as_str().unwrap_or("legal document");
        if let Ok(final_summary) = synthesize_final_summary(client, &concatenated_summaries, doc_type).await {
            if !final_summary.is_empty() {
                merged["summary"] = serde_json::Value::String(final_summary);
            }
        }
    }

    Ok((merged, total))
}

// ── Folder Scanning ─────────────────────────────────────────────────

const LEGAL_EXTENSIONS: &[&str] = &[
    "pdf", "txt", "md", "docx", "doc", "rtf",
    "jpg", "jpeg", "png", "tiff", "tif", "bmp",
];

#[tauri::command]
fn scan_folder(folder_path: String) -> Result<Vec<String>, String> {
    let root = std::path::Path::new(&folder_path);
    if !root.is_dir() {
        return Err(format!("Not a directory: {}", folder_path));
    }

    let mut results = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).map_err(|e| format!("Read dir error: {}", e))?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if LEGAL_EXTENSIONS.contains(&ext.to_lowercase().as_str()) {
                    if let Some(s) = path.to_str() {
                        results.push(s.to_string());
                    }
                }
            }
        }
    }

    results.sort();
    Ok(results)
}

// ── Workflow Definitions ─────────────────────────────────────────────

fn common_prefix_steps() -> Vec<WorkflowStep> {
    vec![
        WorkflowStep {
            id: "create_matter".to_string(),
            name: "Create matter".to_string(),
            action: StepAction::ToolExec {
                tool_name: "legal_matter_manager".to_string(),
                arguments: HashMap::from([
                    ("action".into(), serde_json::json!("create")),
                    ("title".into(), serde_json::json!("{{matter_title}}")),
                    ("matter_type".into(), serde_json::json!("{{category}}")),
                    ("description".into(), serde_json::json!("{{title}}")),
                    ("client_id".into(), serde_json::json!("{{resolved_client_id}}")),
                ]),
                output_var: "matter_result".to_string(),
            },
            depends_on: vec![],
            condition: None,
            retry: RetryPolicy::default(),
            timeout_secs: None,
        },
        WorkflowStep {
            id: "organize_doc".to_string(),
            name: "Link document to matter".to_string(),
            action: StepAction::ToolExec {
                tool_name: "legal_doc_organize".to_string(),
                arguments: HashMap::from([
                    ("document_id".into(), serde_json::json!("{{doc_id}}")),
                    ("matter_id".into(), serde_json::json!("{{resolved_matter_id}}")),
                ]),
                output_var: "organize_result".to_string(),
            },
            depends_on: vec!["create_matter".to_string()],
            condition: None,
            retry: RetryPolicy::default(),
            timeout_secs: None,
        },
        WorkflowStep {
            id: "conflict_check".to_string(),
            name: "Check for conflicts".to_string(),
            action: StepAction::ToolExec {
                tool_name: "legal_conflict_check".to_string(),
                arguments: HashMap::from([
                    ("document_id".into(), serde_json::json!("{{doc_id}}")),
                    ("parties".into(), serde_json::json!("{{parties_json}}")),
                ]),
                output_var: "conflict_result".to_string(),
            },
            depends_on: vec!["organize_doc".to_string()],
            condition: None,
            retry: RetryPolicy::default(),
            timeout_secs: None,
        },
    ]
}

fn build_intake_workflow(
    id: &str,
    name: &str,
    description: &str,
    extra_steps: Vec<WorkflowStep>,
    next_steps_depends: &str,
) -> Workflow {
    let mut steps = common_prefix_steps();
    steps.extend(extra_steps);
    steps.push(WorkflowStep {
        id: "next_steps".to_string(),
        name: "Generate next steps".to_string(),
        action: StepAction::ToolExec {
            tool_name: "legal_next_steps".to_string(),
            arguments: HashMap::from([
                ("document_id".into(), serde_json::json!("{{doc_id}}")),
                ("analysis_json".into(), serde_json::json!("{{analysis_json}}")),
            ]),
            output_var: "next_steps_result".to_string(),
        },
        depends_on: vec![next_steps_depends.to_string()],
        condition: None,
        retry: RetryPolicy::default(),
        timeout_secs: None,
    });

    Workflow {
        id: id.to_string(),
        name: name.to_string(),
        description: description.to_string(),
        steps,
        triggers: vec![Trigger::Manual],
        variables: HashMap::new(),
        enabled: true,
        max_retries: 0,
        timeout_secs: 600,
    }
}

fn register_all_workflows(wf_engine: &mut WorkflowEngine) {
    let default_wf = build_intake_workflow(
        "default_intake",
        "Default Intake",
        "Standard intake for corporate, employment, IP, tax, and general documents",
        vec![],
        "conflict_check",
    );

    let criminal_wf = build_intake_workflow(
        "criminal_intake",
        "Criminal Intake",
        "Enhanced intake for criminal cases with deep conflict analysis",
        vec![WorkflowStep {
            id: "criminal_analysis".to_string(),
            name: "Enhanced criminal conflict analysis".to_string(),
            action: StepAction::LlmCall {
                prompt_template: concat!(
                    "You are a criminal defense legal analyst. Analyze this criminal case for:\n",
                    "1. Co-defendant conflicts of interest\n",
                    "2. Witness conflicts (current/former clients as witnesses)\n",
                    "3. Victim advocacy conflicts\n",
                    "4. Any potential Brady material obligations\n",
                    "5. Speedy trial deadline calculations\n\n",
                    "Case analysis: {{analysis_json}}\n",
                    "Parties: {{parties_json}}\n\n",
                    "Provide a structured analysis with specific flagged issues and recommended deadlines. ",
                    "Return as JSON with keys: flagged_issues (array), brady_obligations (array), ",
                    "speedy_trial_deadline (string), recommended_actions (array)."
                ).to_string(),
                provider: None,
                model: None,
                output_var: "criminal_extra".to_string(),
            },
            depends_on: vec!["conflict_check".to_string()],
            condition: None,
            retry: RetryPolicy::default(),
            timeout_secs: None,
        }],
        "criminal_analysis",
    );

    let family_wf = build_intake_workflow(
        "family_intake",
        "Family Law Intake",
        "Family law intake with custody and support checklist",
        vec![WorkflowStep {
            id: "family_analysis".to_string(),
            name: "Custody and support checklist".to_string(),
            action: StepAction::LlmCall {
                prompt_template: concat!(
                    "You are a family law legal analyst. Review this case and create a comprehensive checklist:\n",
                    "1. Custody arrangement analysis (sole, joint, visitation schedules)\n",
                    "2. Child support calculation factors\n",
                    "3. Spousal support/alimony considerations\n",
                    "4. Property division inventory\n",
                    "5. Key hearing dates and mediation deadlines\n",
                    "6. Financial disclosure requirements\n\n",
                    "Case analysis: {{analysis_json}}\n",
                    "Parties: {{parties_json}}\n\n",
                    "Return as JSON with keys: custody_issues (array), support_factors (array), ",
                    "property_items (array), deadlines (array with date and description), ",
                    "financial_disclosures_needed (array)."
                ).to_string(),
                provider: None,
                model: None,
                output_var: "family_extra".to_string(),
            },
            depends_on: vec!["conflict_check".to_string()],
            condition: None,
            retry: RetryPolicy::default(),
            timeout_secs: None,
        }],
        "family_analysis",
    );

    let estate_wf = build_intake_workflow(
        "estate_intake",
        "Estate Intake",
        "Estate planning intake with beneficiary and asset tracking",
        vec![WorkflowStep {
            id: "estate_analysis".to_string(),
            name: "Beneficiary and asset tracking".to_string(),
            action: StepAction::LlmCall {
                prompt_template: concat!(
                    "You are an estate planning legal analyst. Analyze this document for:\n",
                    "1. All beneficiaries, trustees, and fiduciary roles\n",
                    "2. Potential undue influence or capacity concerns\n",
                    "3. Assets that require retitling or transfer\n",
                    "4. Probate filing deadlines\n",
                    "5. Trust funding requirements\n",
                    "6. Beneficiary notification obligations\n\n",
                    "Document analysis: {{analysis_json}}\n",
                    "Parties: {{parties_json}}\n\n",
                    "Return as JSON with keys: beneficiaries (array with name and role), ",
                    "fiduciaries (array), capacity_concerns (array), assets_to_retitle (array), ",
                    "probate_deadlines (array), trust_funding_items (array), notifications_required (array)."
                ).to_string(),
                provider: None,
                model: None,
                output_var: "estate_extra".to_string(),
            },
            depends_on: vec!["conflict_check".to_string()],
            condition: None,
            retry: RetryPolicy::default(),
            timeout_secs: None,
        }],
        "estate_analysis",
    );

    let immigration_wf = build_intake_workflow(
        "immigration_intake",
        "Immigration Intake",
        "Immigration intake with form identification and deadline calculation",
        vec![WorkflowStep {
            id: "immigration_analysis".to_string(),
            name: "Form identification and eligibility".to_string(),
            action: StepAction::LlmCall {
                prompt_template: concat!(
                    "You are an immigration legal analyst. Analyze this case for:\n",
                    "1. Immigration form type identification (I-130, I-485, I-751, N-400, etc.)\n",
                    "2. Eligibility category and basis\n",
                    "3. Priority date if applicable\n",
                    "4. Bars to admissibility or removal risks\n",
                    "5. Filing deadlines and processing times\n",
                    "6. Biometrics appointment requirements\n\n",
                    "Case analysis: {{analysis_json}}\n",
                    "Parties: {{parties_json}}\n\n",
                    "Return as JSON with keys: form_type (string), eligibility_category (string), ",
                    "priority_date (string or null), admissibility_bars (array), removal_risks (array), ",
                    "filing_deadlines (array with date and description), biometrics_required (boolean), ",
                    "estimated_processing_months (number)."
                ).to_string(),
                provider: None,
                model: None,
                output_var: "immigration_extra".to_string(),
            },
            depends_on: vec!["conflict_check".to_string()],
            condition: None,
            retry: RetryPolicy::default(),
            timeout_secs: None,
        }],
        "immigration_analysis",
    );

    let real_estate_wf = build_intake_workflow(
        "real_estate_intake",
        "Real Estate Intake",
        "Real estate intake with title chain and encumbrance analysis",
        vec![WorkflowStep {
            id: "real_estate_analysis".to_string(),
            name: "Title chain and encumbrance check".to_string(),
            action: StepAction::LlmCall {
                prompt_template: concat!(
                    "You are a real estate legal analyst. Analyze this document for:\n",
                    "1. Title chain of ownership\n",
                    "2. Existing encumbrances, liens, and easements\n",
                    "3. Closing date and timeline requirements\n",
                    "4. Inspection deadlines and contingencies\n",
                    "5. Recording requirements\n",
                    "6. Title insurance issues\n\n",
                    "Document analysis: {{analysis_json}}\n",
                    "Parties: {{parties_json}}\n\n",
                    "Return as JSON with keys: title_chain (array of owners), encumbrances (array), ",
                    "liens (array), easements (array), closing_date (string or null), ",
                    "inspection_deadline (string or null), recording_requirements (array), ",
                    "title_insurance_issues (array)."
                ).to_string(),
                provider: None,
                model: None,
                output_var: "real_estate_extra".to_string(),
            },
            depends_on: vec!["conflict_check".to_string()],
            condition: None,
            retry: RetryPolicy::default(),
            timeout_secs: None,
        }],
        "real_estate_analysis",
    );

    for wf in [default_wf, criminal_wf, family_wf, estate_wf, immigration_wf, real_estate_wf] {
        wf_engine.register(wf).expect("Failed to register intake workflow");
    }
}

// ── App Setup ───────────────────────────────────────────────────────

struct TriageResult {
    client_id: Option<i64>,
    matter_id: Option<i64>,
    conflicts_found: usize,
    action_items_created: usize,
    deadlines_created: usize,
}

async fn resolve_client(engine: &ironclaw::core::Engine, primary_party: &str) -> Option<i64> {
    let search_result = engine
        .execute_tool_call(&make_tool_call(
            "legal_client_manager",
            serde_json::json!({"action": "search", "name": primary_party}),
        ))
        .await;

    let existing_id = search_result.ok().and_then(|r| {
        if r.success {
            serde_json::from_str::<serde_json::Value>(&r.output)
                .ok()
                .and_then(|arr| {
                    arr.as_array()
                        .and_then(|a| a.first().and_then(|c| c["id"].as_i64()))
                })
        } else {
            None
        }
    });

    if let Some(id) = existing_id {
        return Some(id);
    }

    engine
        .execute_tool_call(&make_tool_call(
            "legal_client_manager",
            serde_json::json!({"action": "create", "name": primary_party}),
        ))
        .await
        .ok()
        .and_then(|r| {
            if r.success {
                serde_json::from_str::<serde_json::Value>(&r.output)
                    .ok()
                    .and_then(|v| v["id"].as_i64())
            } else {
                None
            }
        })
}

fn extract_id_from_tool_output(output: &str) -> Option<i64> {
    serde_json::from_str::<serde_json::Value>(output)
        .ok()
        .and_then(|v| v["id"].as_i64())
}

async fn run_intake_workflow(
    state: &AppState,
    workflow_id: &str,
    vars: HashMap<String, String>,
) -> TriageResult {
    let empty = TriageResult {
        client_id: None,
        matter_id: None,
        conflicts_found: 0,
        action_items_created: 0,
        deadlines_created: 0,
    };

    let mut wf = state.workflows.lock().await;
    let exec_id = match wf.start_execution_with_vars(workflow_id, vars) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("Failed to start workflow {}: {}", workflow_id, e);
            return empty;
        }
    };

    loop {
        match wf.execute_next_step(&exec_id).await {
            Ok(Some(step_id)) => {
                if step_id == "create_matter" {
                    let mid = wf
                        .get_execution(&exec_id)
                        .and_then(|e| e.variables.get("matter_result"))
                        .and_then(|o| extract_id_from_tool_output(o));
                    if let Some(id) = mid {
                        wf.set_execution_variable(
                            &exec_id,
                            "resolved_matter_id".to_string(),
                            id.to_string(),
                        );
                    }
                }
            }
            Ok(None) => break,
            Err(e) => {
                eprintln!("Workflow step failed: {}", e);
                break;
            }
        }
    }

    let exec = match wf.get_execution(&exec_id) {
        Some(e) => e,
        None => return empty,
    };

    let mut result = TriageResult {
        client_id: exec.variables.get("resolved_client_id").and_then(|s| s.parse::<i64>().ok()),
        matter_id: None,
        conflicts_found: 0,
        action_items_created: 0,
        deadlines_created: 0,
    };

    if let Some(matter_output) = exec.variables.get("matter_result") {
        result.matter_id = extract_id_from_tool_output(matter_output);
    }

    if let Some(conflict_output) = exec.variables.get("conflict_result") {
        result.conflicts_found = serde_json::from_str::<serde_json::Value>(conflict_output)
            .ok()
            .and_then(|v| v["conflicts_found"].as_u64())
            .map(|n| n as usize)
            .unwrap_or(0);
    }

    if let Some(ns_output) = exec.variables.get("next_steps_result") {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(ns_output) {
            result.action_items_created =
                v["action_items"].as_array().map(|a| a.len()).unwrap_or(0);
            result.deadlines_created =
                v["deadlines"].as_array().map(|a| a.len()).unwrap_or(0);
        }
    }

    result
}

const EMBEDDED_CONFIG: &str = include_str!("../ironclaw-embedded.toml");

pub fn run() {
    let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");

    let (db, http, engine, workflows) = rt.block_on(async {
        let config = ironclaw::core::config::Config::from_toml(EMBEDDED_CONFIG)
            .expect("Failed to parse embedded IronClaw config");

        let policy = ironclaw::rbac::Policy::from_config(&config.permissions)
            .expect("Failed to init RBAC policy");
        let guardian = ironclaw::guardian::CommandGuardian::new(&config.guardian)
            .expect("Failed to init Command Guardian");
        let audit = ironclaw::observability::AuditLog::new(&config.audit)
            .expect("Failed to init Audit Log");
        let anti_stealer = ironclaw::antitheft::AntiStealer::new(config.antitheft.enforce)
            .expect("Failed to init AntiStealer");
        let ssrf_guard = ironclaw::network::SsrfGuard::new(
            config.permissions.network.block_private,
            config.permissions.network.block_domains.clone(),
            config.permissions.network.allow_domains.clone(),
        );
        let dlp_engine = ironclaw::dlp::DlpEngine::new(config.dlp.enabled, ironclaw::dlp::DlpAction::Redact)
            .expect("Failed to init DLP engine");
        let cost_tracker = ironclaw::core::cost::CostTracker::new(
            "~/.ironclaw/costs.db",
            ironclaw::core::cost::BudgetConfig {
                daily_limit_usd: ironclaw::core::cost::cents_to_usd(config.agent.max_daily_cost_cents),
                monthly_limit_usd: ironclaw::core::cost::cents_to_usd(config.agent.max_daily_cost_cents * 30),
                alert_threshold: 0.8,
            },
        ).ok();
        let skill_scanner = ironclaw::skills::scanner::SkillScanner::new().ok();

        let engine = ironclaw::core::Engine::new(ironclaw::core::EngineConfig {
            config,
            policy,
            guardian,
            audit,
            anti_stealer,
            ssrf_guard,
            dlp_engine,
            cost_tracker,
            skill_scanner,
            provider_name: "openai".to_string(),
            model: Some(PHI4_MODEL.to_string()),
            ui_sender: None,
            channel_manager: None,
            session_auth: None,
        }).await.expect("Failed to initialize IronClaw Engine");

        let db = LegalDatabase::new("~/.ironclaw/legal.db")
            .expect("Failed to open legal database");
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(300))
            .build()
            .expect("Failed to create HTTP client");

        let engine = Arc::new(engine);

        let mut wf_engine = WorkflowEngine::new(8);
        wf_engine.set_engine(Arc::clone(&engine));
        register_all_workflows(&mut wf_engine);

        (db, http, engine, wf_engine)
    });

    let llm_manager = LlmManager::new();
    let llm_for_shutdown = LlmManager {
        status: Arc::clone(&llm_manager.status),
        child_pid: Arc::clone(&llm_manager.child_pid),
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_shell::init())
        .manage(AppState {
            db: Arc::new(db),
            http,
            engine,
            workflows: Arc::new(tokio::sync::Mutex::new(workflows)),
            ocr_tools_dir: find_ocr_tools_dir(),
        })
        .manage(llm_manager)
        .setup(|app| {
            let mgr = app.state::<LlmManager>();
            let status = Arc::clone(&mgr.status);
            let child_pid = Arc::clone(&mgr.child_pid);
            let spawner = LlmManager { status, child_pid };
            tauri::async_runtime::spawn(async move {
                spawner.spawn_and_wait().await;
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_dashboard,
            list_clients,
            get_client,
            create_client,
            update_client,
            search_clients,
            list_matters,
            get_matter,
            list_matters_by_client,
            create_matter,
            update_matter_status,
            list_documents,
            get_document,
            list_documents_by_matter,
            update_document_matter,
            process_document,
            list_deadlines,
            list_upcoming_deadlines,
            update_deadline_status,
            list_action_items,
            list_action_items_by_matter,
            update_action_item_status,
            get_conflicts_for_document,
            resolve_conflict,
            chat_send,
            scan_folder,
            delete_document,
            delete_client,
            delete_matter,
            draft_document,
            generate_review_packet,
            get_llm_status,
            retry_llm_setup,
            delete_all_app_data,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(move |_app_handle, event| {
            match event {
                tauri::RunEvent::Exit | tauri::RunEvent::ExitRequested { .. } => {
                    let rt = tokio::runtime::Runtime::new().unwrap();
                    rt.block_on(llm_for_shutdown.kill());
                }
                _ => {}
            }
        });
}
