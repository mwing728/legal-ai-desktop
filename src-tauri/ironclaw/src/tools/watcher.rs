use anyhow::Result;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::tools::db::LegalDatabase;

pub struct InboxWatcher {
    watch_dir: PathBuf,
    db: Arc<LegalDatabase>,
}

impl InboxWatcher {
    pub fn new(watch_dir: &str, db: Arc<LegalDatabase>) -> Self {
        let expanded = shellexpand::tilde(watch_dir).to_string();
        Self {
            watch_dir: PathBuf::from(expanded),
            db,
        }
    }

    pub async fn start(self) -> Result<()> {
        std::fs::create_dir_all(&self.watch_dir)?;
        info!(dir = %self.watch_dir.display(), "Starting inbox watcher");

        let (tx, mut rx) = mpsc::channel::<PathBuf>(256);

        let watch_dir = self.watch_dir.clone();
        std::thread::spawn(move || {
            let rt_tx = tx.clone();
            let mut watcher = RecommendedWatcher::new(
                move |res: Result<Event, notify::Error>| {
                    if let Ok(event) = res {
                        if matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
                            for path in event.paths {
                                if is_legal_document(&path) {
                                    let _ = rt_tx.blocking_send(path);
                                }
                            }
                        }
                    }
                },
                Config::default(),
            )
            .expect("Failed to create file watcher");

            watcher
                .watch(&watch_dir, RecursiveMode::Recursive)
                .expect("Failed to watch directory");

            // Keep the watcher alive
            loop {
                std::thread::sleep(std::time::Duration::from_secs(60));
            }
        });

        let db = self.db.clone();
        tokio::spawn(async move {
            while let Some(path) = rx.recv().await {
                info!(file = %path.display(), "New document detected");
                if let Err(e) = process_incoming_document(&path, &db).await {
                    error!(file = %path.display(), error = %e, "Failed to process document");
                }
            }
        });

        Ok(())
    }
}

fn is_legal_document(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("pdf" | "txt" | "md" | "docx" | "doc" | "rtf")
    )
}

async fn process_incoming_document(path: &Path, db: &LegalDatabase) -> Result<()> {
    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();
    let file_path = path.to_string_lossy().to_string();

    // Stage 1: Extract text
    let text = extract_text(path)?;
    if text.trim().is_empty() {
        warn!(file = %filename, "No text extracted, skipping");
        return Ok(());
    }

    // Stage 2: Insert document record
    let doc_id = db.insert_document(&filename, &file_path, Some(&text))?;
    db.update_document_status(doc_id, "processing")?;
    info!(doc_id = doc_id, file = %filename, "Document inserted, running analysis");

    // Stage 3: Call Ollama for analysis
    let analysis = analyze_document(&text).await?;

    // Stage 4: Parse and store analysis
    let doc_type = analysis["doc_type"].as_str().unwrap_or("unknown");
    let category = analysis["category"].as_str().unwrap_or("general");
    let analysis_str = serde_json::to_string_pretty(&analysis)?;
    db.update_document_analysis(doc_id, doc_type, category, &analysis_str)?;

    // Stage 5: Conflict check
    if let Some(parties) = analysis["parties"].as_array() {
        for party in parties {
            if let Some(name) = party.as_str() {
                let matches = db.search_clients(name)?;
                for client in &matches {
                    db.insert_conflict_hit(
                        Some(doc_id),
                        None,
                        name,
                        Some(client.id),
                        "name_match",
                        0.8,
                    )?;
                    info!(doc_id = doc_id, party = name, client = %client.name, "Conflict hit found");
                }
            }
        }
    }

    // Stage 6: Generate next steps
    if let Ok(steps) = generate_next_steps(&analysis_str, &filename).await {
        if let Some(deadlines) = steps["deadlines"].as_array() {
            for dl in deadlines {
                let title = dl["title"].as_str().unwrap_or("Untitled deadline");
                let due_date = dl["due_date"].as_str().unwrap_or("2025-12-31");
                let priority = dl["priority"].as_str().unwrap_or("normal");
                db.insert_deadline(None, Some(doc_id), title, dl["description"].as_str(), due_date, priority)?;
            }
        }
        if let Some(actions) = steps["action_items"].as_array() {
            for ai in actions {
                let title = ai["title"].as_str().unwrap_or("Untitled action");
                let priority = ai["priority"].as_str().unwrap_or("normal");
                db.insert_action_item(None, Some(doc_id), title, ai["description"].as_str(), ai["assignee"].as_str(), priority)?;
            }
        }
    }

    db.update_document_status(doc_id, "analyzed")?;
    db.log_audit_event(
        "document_processed",
        Some("document"),
        Some(doc_id),
        Some(&format!("{{\"filename\":\"{}\",\"doc_type\":\"{}\",\"category\":\"{}\"}}", filename, doc_type, category)),
    )?;

    info!(doc_id = doc_id, file = %filename, doc_type = doc_type, "Document processing complete");
    Ok(())
}

fn extract_text(path: &Path) -> Result<String> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    match ext.as_str() {
        "pdf" => {
            let bytes = std::fs::read(path)?;
            pdf_extract::extract_text_from_mem(&bytes)
                .map_err(|e| anyhow::anyhow!("PDF extraction failed: {}", e))
        }
        "txt" | "md" | "rtf" => Ok(std::fs::read_to_string(path)?),
        "docx" => extract_docx_text(path),
        _ => anyhow::bail!("Unsupported file type: {}", ext),
    }
}

fn extract_docx_text(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path)?;
    let docx = docx_rs::read_docx(&bytes)
        .map_err(|e| anyhow::anyhow!("DOCX parse failed: {:?}", e))?;
    let mut text = String::new();
    for child in &docx.document.children {
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

async fn analyze_document(text: &str) -> Result<serde_json::Value> {
    let truncated = if text.len() > 8000 { &text[..8000] } else { text };
    let system_prompt = r#"You are a legal document analyzer. Analyze the provided document and return a JSON object with these fields:
- "doc_type": specific document type (e.g. "complaint", "contract", "will", "deed", "petition", "motion", "letter", "agreement", "order", "subpoena")
- "category": broad legal category (one of: "family_law", "criminal", "immigration", "real_estate", "estate", "corporate", "employment", "ip", "tax", "general")
- "parties": array of all person/entity names mentioned
- "key_dates": array of objects with {"date": "...", "description": "..."}
- "summary": 2-3 sentence summary of the document
- "key_terms": array of important legal terms or clauses found
- "jurisdiction": jurisdiction if identifiable, or "unknown"
- "recommended_actions": array of recommended next steps

Return ONLY valid JSON, no markdown or explanation."#;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(300))
        .build()?;
    let body = serde_json::json!({
        "model": "phi-4-mini",
        "messages": [
            { "role": "system", "content": system_prompt },
            { "role": "user", "content": format!("Analyze this legal document:\n\n{}", truncated) }
        ],
        "max_tokens": 768,
        "temperature": 0.5,
        "stream": false,
    });

    let resp = client
        .post("http://127.0.0.1:11435/v1/chat/completions")
        .json(&body)
        .send()
        .await?;

    if !resp.status().is_success() {
        anyhow::bail!("LLM error: {}", resp.status());
    }

    let json: serde_json::Value = resp.json().await?;
    let content = json["choices"][0]["message"]["content"].as_str().unwrap_or("{}");

    // Try to parse the LLM response as JSON, stripping any markdown fences
    let cleaned = content
        .trim()
        .trim_start_matches("```json")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim();

    serde_json::from_str(cleaned).or_else(|_| {
        Ok(serde_json::json!({
            "doc_type": "unknown",
            "category": "general",
            "parties": [],
            "key_dates": [],
            "summary": content,
            "key_terms": [],
            "jurisdiction": "unknown",
            "recommended_actions": []
        }))
    })
}

async fn generate_next_steps(analysis_json: &str, filename: &str) -> Result<serde_json::Value> {
    let system_prompt = r#"Based on the legal document analysis provided, generate actionable next steps. Return a JSON object with:
- "next_steps": array of strings describing what should be done
- "deadlines": array of objects with {"title": "...", "description": "...", "due_date": "YYYY-MM-DD", "priority": "normal|high|urgent"}
- "action_items": array of objects with {"title": "...", "description": "...", "assignee": "attorney|paralegal|client", "priority": "normal|high|urgent"}

Return ONLY valid JSON."#;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(300))
        .build()?;
    let body = serde_json::json!({
        "model": "phi-4-mini",
        "messages": [
            { "role": "system", "content": system_prompt },
            { "role": "user", "content": format!("Document: {}\nAnalysis:\n{}", filename, analysis_json) }
        ],
        "max_tokens": 512,
        "temperature": 0.5,
        "stream": false,
    });

    let resp = client
        .post("http://127.0.0.1:11435/v1/chat/completions")
        .json(&body)
        .send()
        .await?;

    if !resp.status().is_success() {
        anyhow::bail!("LLM error: {}", resp.status());
    }

    let json: serde_json::Value = resp.json().await?;
    let content = json["choices"][0]["message"]["content"].as_str().unwrap_or("{}");
    let cleaned = content
        .trim()
        .trim_start_matches("```json")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim();

    serde_json::from_str(cleaned).map_err(|e| anyhow::anyhow!("Failed to parse next steps: {}", e))
}
