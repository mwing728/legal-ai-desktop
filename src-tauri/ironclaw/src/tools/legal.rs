use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use crate::core::tool::Tool;
use crate::core::types::{RiskLevel, SecurityContext, ToolResult, ToolResultMetadata};
use crate::tools::db::LegalDatabase;

fn make_result(tool_name: &str, success: bool, output: String) -> ToolResult {
    let now = chrono::Utc::now();
    ToolResult {
        success,
        output,
        error: None,
        metadata: ToolResultMetadata {
            tool_name: tool_name.to_string(),
            duration_ms: 0,
            sandboxed: false,
            risk_level: RiskLevel::Low,
            execution_id: uuid::Uuid::new_v4().to_string(),
            started_at: now,
            completed_at: now,
            exit_code: None,
            bytes_read: 0,
            bytes_written: 0,
            truncated: false,
            provider_usage: None,
        },
    }
}

fn make_err(tool_name: &str, msg: String) -> ToolResult {
    let mut r = make_result(tool_name, false, String::new());
    r.error = Some(msg);
    r
}

async fn call_llm(system_prompt: &str, user_message: &str) -> Result<String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(300))
        .build()?;
    let body = serde_json::json!({
        "model": "phi-4-mini",
        "messages": [
            { "role": "system", "content": system_prompt },
            { "role": "user", "content": user_message }
        ],
        "max_tokens": 768,
        "temperature": 0.5,
        "stream": false,
    });
    let resp = client.post("http://127.0.0.1:11435/v1/chat/completions").json(&body).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("LLM error: {}", resp.status());
    }
    let json: Value = resp.json().await?;
    Ok(json["choices"][0]["message"]["content"].as_str().unwrap_or("").to_string())
}

fn parse_llm_json(raw: &str) -> Value {
    let cleaned = raw.trim()
        .trim_start_matches("```json")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim();
    serde_json::from_str(cleaned).unwrap_or_else(|_| serde_json::json!({"raw_response": raw}))
}

fn str_arg<'a>(args: &'a HashMap<String, Value>, key: &str) -> Option<&'a str> {
    args.get(key).and_then(|v| v.as_str())
}

fn int_arg(args: &HashMap<String, Value>, key: &str) -> Option<i64> {
    args.get(key).and_then(|v| v.as_i64())
}

// ---------------------------------------------------------------------------
// 1. DocExtractTool
// ---------------------------------------------------------------------------

pub struct DocExtractTool { pub db: Arc<LegalDatabase> }

#[async_trait]
impl Tool for DocExtractTool {
    fn name(&self) -> &str { "legal_doc_extract" }
    fn description(&self) -> &str { "Extract text from legal documents (PDF, TXT, MD, DOCX)" }
    fn parameters_schema(&self) -> Value {
        serde_json::json!({"type":"object","properties":{"file_path":{"type":"string"}},"required":["file_path"]})
    }
    fn risk_level(&self) -> RiskLevel { RiskLevel::Low }
    fn required_permissions(&self) -> Vec<String> { vec![] }

    async fn execute(&self, args: &HashMap<String, Value>, _ctx: &SecurityContext) -> Result<ToolResult> {
        let file_path = match str_arg(args, "file_path") {
            Some(p) => p,
            None => return Ok(make_err(self.name(), "Missing file_path".into())),
        };
        let path = std::path::Path::new(file_path);
        if !path.exists() {
            return Ok(make_err(self.name(), format!("File not found: {file_path}")));
        }
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
        let text = match ext.as_str() {
            "pdf" => {
                let bytes = std::fs::read(path)?;
                pdf_extract::extract_text_from_mem(&bytes)
                    .map_err(|e| anyhow::anyhow!("PDF extraction failed: {}", e))?
            }
            "txt" | "md" | "rtf" => std::fs::read_to_string(path)?,
            "docx" => extract_docx_text(path)?,
            _ => return Ok(make_err(self.name(), format!("Unsupported file type: .{ext}"))),
        };
        Ok(make_result(self.name(), true, text))
    }
}

fn extract_docx_text(path: &std::path::Path) -> Result<String> {
    let bytes = std::fs::read(path)?;
    let docx = docx_rs::read_docx(&bytes).map_err(|e| anyhow::anyhow!("DOCX parse failed: {:?}", e))?;
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

// ---------------------------------------------------------------------------
// 2. DocAnalyzeTool
// ---------------------------------------------------------------------------

pub struct DocAnalyzeTool { pub db: Arc<LegalDatabase> }

#[async_trait]
impl Tool for DocAnalyzeTool {
    fn name(&self) -> &str { "legal_doc_analyze" }
    fn description(&self) -> &str { "Analyze a legal document using AI to classify type, extract parties, dates, key terms" }
    fn parameters_schema(&self) -> Value {
        serde_json::json!({"type":"object","properties":{"document_id":{"type":"integer"},"text":{"type":"string"}},"required":["document_id","text"]})
    }
    fn risk_level(&self) -> RiskLevel { RiskLevel::Low }
    fn required_permissions(&self) -> Vec<String> { vec![] }

    async fn execute(&self, args: &HashMap<String, Value>, _ctx: &SecurityContext) -> Result<ToolResult> {
        let document_id = match int_arg(args, "document_id") {
            Some(id) => id,
            None => return Ok(make_err(self.name(), "Missing document_id".into())),
        };
        let text = match str_arg(args, "text") {
            Some(t) => t,
            None => return Ok(make_err(self.name(), "Missing text".into())),
        };
        let truncated = if text.len() > 12000 { &text[..12000] } else { text };

        let system_prompt = r#"You are a legal document analyzer. Return ONLY valid JSON:
{"doc_type":"string","category":"string (family_law|criminal|immigration|real_estate|estate|corporate|employment|ip|tax|general)","parties":["names"],"key_dates":[{"date":"...","description":"..."}],"summary":"2-3 sentences","key_terms":["terms"],"jurisdiction":"string or unknown","recommended_actions":["actions"]}"#;

        let response = match call_llm(system_prompt, truncated).await {
            Ok(r) => r,
            Err(e) => return Ok(make_err(self.name(), format!("LLM call failed: {e}"))),
        };

        let analysis = parse_llm_json(&response);
        let doc_type = analysis["doc_type"].as_str().unwrap_or("unknown");
        let category = analysis["category"].as_str().unwrap_or("general");
        let analysis_str = serde_json::to_string_pretty(&analysis)?;

        if let Err(e) = self.db.update_document_analysis(document_id, doc_type, category, &analysis_str) {
            tracing::warn!("Failed to store analysis for doc {document_id}: {e}");
        }

        Ok(make_result(self.name(), true, analysis_str))
    }
}

// ---------------------------------------------------------------------------
// 3. ConflictCheckTool
// ---------------------------------------------------------------------------

pub struct ConflictCheckTool { pub db: Arc<LegalDatabase> }

#[async_trait]
impl Tool for ConflictCheckTool {
    fn name(&self) -> &str { "legal_conflict_check" }
    fn description(&self) -> &str { "Check for conflicts of interest by searching existing clients against document parties" }
    fn parameters_schema(&self) -> Value {
        serde_json::json!({"type":"object","properties":{"document_id":{"type":"integer"},"parties":{"type":"array","items":{"type":"string"}}},"required":["document_id","parties"]})
    }
    fn risk_level(&self) -> RiskLevel { RiskLevel::Low }
    fn required_permissions(&self) -> Vec<String> { vec![] }

    async fn execute(&self, args: &HashMap<String, Value>, _ctx: &SecurityContext) -> Result<ToolResult> {
        let document_id = match int_arg(args, "document_id") {
            Some(id) => id,
            None => return Ok(make_err(self.name(), "Missing document_id".into())),
        };
        let parties: Vec<String> = match args.get("parties").and_then(|v| v.as_array()) {
            Some(arr) => arr.iter().filter_map(|v| v.as_str().map(String::from)).collect(),
            None => return Ok(make_err(self.name(), "Missing parties array".into())),
        };

        let mut conflicts = Vec::new();
        for party in &parties {
            match self.db.search_clients(party) {
                Ok(matches) => {
                    for client in &matches {
                        let _ = self.db.insert_conflict_hit(
                            Some(document_id), None, party, Some(client.id), "name_match", 0.8,
                        );
                        conflicts.push(serde_json::json!({
                            "party": party,
                            "matched_client_id": client.id,
                            "matched_client_name": client.name,
                        }));
                    }
                }
                Err(e) => tracing::warn!("Client search failed for '{party}': {e}"),
            }
        }

        let output = serde_json::to_string_pretty(&serde_json::json!({
            "document_id": document_id,
            "conflicts_found": conflicts.len(),
            "conflicts": conflicts,
        }))?;
        Ok(make_result(self.name(), true, output))
    }
}

// ---------------------------------------------------------------------------
// 4. DocDraftTool
// ---------------------------------------------------------------------------

pub struct DocDraftTool { pub db: Arc<LegalDatabase> }

#[async_trait]
impl Tool for DocDraftTool {
    fn name(&self) -> &str { "legal_doc_draft" }
    fn description(&self) -> &str { "Generate legal document drafts (retainer, non-engagement, response outline, checklist, memo)" }
    fn parameters_schema(&self) -> Value {
        serde_json::json!({"type":"object","properties":{"draft_type":{"type":"string","enum":["retainer","non_engagement","response_outline","checklist","summary_memo"]},"context":{"type":"string"}},"required":["draft_type","context"]})
    }
    fn risk_level(&self) -> RiskLevel { RiskLevel::Medium }
    fn required_permissions(&self) -> Vec<String> { vec![] }

    async fn execute(&self, args: &HashMap<String, Value>, _ctx: &SecurityContext) -> Result<ToolResult> {
        let draft_type = match str_arg(args, "draft_type") {
            Some(t) => t,
            None => return Ok(make_err(self.name(), "Missing draft_type".into())),
        };
        let context = match str_arg(args, "context") {
            Some(c) => c,
            None => return Ok(make_err(self.name(), "Missing context".into())),
        };

        let system_prompt = match draft_type {
            "retainer" => "Generate a professional retainer/engagement letter. Include scope, fees, obligations.",
            "non_engagement" => "Generate a non-engagement/declination letter. Advise seeking other counsel. Note any statutes of limitation.",
            "response_outline" => "Generate a response outline: factual background, legal issues, applicable law, arguments, evidence needs, timeline.",
            "checklist" => "Generate a numbered legal checklist: intake steps, documents needed, deadlines, discovery, follow-ups.",
            "summary_memo" => "Generate an internal summary memo: executive summary, key facts, analysis, risks, strategy.",
            _ => return Ok(make_err(self.name(), format!("Unknown draft_type: {draft_type}"))),
        };

        let draft = match call_llm(system_prompt, context).await {
            Ok(d) => d,
            Err(e) => return Ok(make_err(self.name(), format!("LLM call failed: {e}"))),
        };
        Ok(make_result(self.name(), true, draft))
    }
}

// ---------------------------------------------------------------------------
// 5. ReviewPacketTool
// ---------------------------------------------------------------------------

pub struct ReviewPacketTool { pub db: Arc<LegalDatabase> }

#[async_trait]
impl Tool for ReviewPacketTool {
    fn name(&self) -> &str { "legal_review_packet" }
    fn description(&self) -> &str { "Generate a comprehensive review packet for a document" }
    fn parameters_schema(&self) -> Value {
        serde_json::json!({"type":"object","properties":{"document_id":{"type":"integer"}},"required":["document_id"]})
    }
    fn risk_level(&self) -> RiskLevel { RiskLevel::Low }
    fn required_permissions(&self) -> Vec<String> { vec![] }

    async fn execute(&self, args: &HashMap<String, Value>, _ctx: &SecurityContext) -> Result<ToolResult> {
        let document_id = match int_arg(args, "document_id") {
            Some(id) => id,
            None => return Ok(make_err(self.name(), "Missing document_id".into())),
        };

        let doc = match self.db.get_document(document_id) {
            Ok(Some(d)) => d,
            Ok(None) => return Ok(make_err(self.name(), "Document not found".into())),
            Err(e) => return Ok(make_err(self.name(), format!("DB error: {e}"))),
        };

        let analysis = doc.analysis_json.as_deref().unwrap_or("No analysis available");
        let conflicts = self.db.get_conflicts_for_document(document_id).unwrap_or_default();
        let conflicts_str = serde_json::to_string_pretty(&conflicts).unwrap_or_default();

        let system_prompt = "Compile a review packet with sections: 1) DOCUMENT SUMMARY 2) KEY FINDINGS 3) PARTIES & CONFLICTS 4) RECOMMENDED ACTIONS 5) DEADLINES 6) RISK ASSESSMENT";
        let user_msg = format!("Document: {}\nAnalysis:\n{}\n\nConflicts:\n{}", doc.filename, analysis, conflicts_str);

        let packet = match call_llm(system_prompt, &user_msg).await {
            Ok(p) => p,
            Err(e) => return Ok(make_err(self.name(), format!("LLM call failed: {e}"))),
        };
        Ok(make_result(self.name(), true, packet))
    }
}

// ---------------------------------------------------------------------------
// 6. NextStepsTool
// ---------------------------------------------------------------------------

pub struct NextStepsTool { pub db: Arc<LegalDatabase> }

#[async_trait]
impl Tool for NextStepsTool {
    fn name(&self) -> &str { "legal_next_steps" }
    fn description(&self) -> &str { "Generate actionable next steps, deadlines, and action items from a document analysis" }
    fn parameters_schema(&self) -> Value {
        serde_json::json!({"type":"object","properties":{"document_id":{"type":"integer"},"analysis_json":{"type":"string"}},"required":["document_id","analysis_json"]})
    }
    fn risk_level(&self) -> RiskLevel { RiskLevel::Low }
    fn required_permissions(&self) -> Vec<String> { vec![] }

    async fn execute(&self, args: &HashMap<String, Value>, _ctx: &SecurityContext) -> Result<ToolResult> {
        let document_id = match int_arg(args, "document_id") {
            Some(id) => id,
            None => return Ok(make_err(self.name(), "Missing document_id".into())),
        };
        let analysis_json = match str_arg(args, "analysis_json") {
            Some(a) => a,
            None => return Ok(make_err(self.name(), "Missing analysis_json".into())),
        };

        let system_prompt = r#"Return ONLY valid JSON: {"next_steps":["strings"],"deadlines":[{"title":"...","due_date":"YYYY-MM-DD","priority":"normal|high|urgent","description":"..."}],"action_items":[{"title":"...","priority":"normal|high|urgent","assignee":"attorney|paralegal|client","description":"..."}]}"#;

        let response = match call_llm(system_prompt, analysis_json).await {
            Ok(r) => r,
            Err(e) => return Ok(make_err(self.name(), format!("LLM call failed: {e}"))),
        };

        let parsed = parse_llm_json(&response);

        if let Some(deadlines) = parsed["deadlines"].as_array() {
            for dl in deadlines {
                let title = dl["title"].as_str().unwrap_or("Deadline");
                let due_date = dl["due_date"].as_str().unwrap_or("2026-12-31");
                let priority = dl["priority"].as_str().unwrap_or("normal");
                let _ = self.db.insert_deadline(None, Some(document_id), title, dl["description"].as_str(), due_date, priority);
            }
        }
        if let Some(items) = parsed["action_items"].as_array() {
            for ai in items {
                let title = ai["title"].as_str().unwrap_or("Action item");
                let priority = ai["priority"].as_str().unwrap_or("normal");
                let _ = self.db.insert_action_item(None, Some(document_id), title, ai["description"].as_str(), ai["assignee"].as_str(), priority);
            }
        }

        let output = serde_json::to_string_pretty(&parsed)?;
        Ok(make_result(self.name(), true, output))
    }
}

// ---------------------------------------------------------------------------
// 7. ClientManagerTool
// ---------------------------------------------------------------------------

pub struct ClientManagerTool { pub db: Arc<LegalDatabase> }

#[async_trait]
impl Tool for ClientManagerTool {
    fn name(&self) -> &str { "legal_client_manager" }
    fn description(&self) -> &str { "Manage clients: create, get, list, update, or search" }
    fn parameters_schema(&self) -> Value {
        serde_json::json!({"type":"object","properties":{"action":{"type":"string","enum":["create","get","list","update","search"]},"client_id":{"type":"integer"},"name":{"type":"string"},"email":{"type":"string"},"phone":{"type":"string"},"address":{"type":"string"},"notes":{"type":"string"}},"required":["action"]})
    }
    fn risk_level(&self) -> RiskLevel { RiskLevel::Low }
    fn required_permissions(&self) -> Vec<String> { vec![] }

    async fn execute(&self, args: &HashMap<String, Value>, _ctx: &SecurityContext) -> Result<ToolResult> {
        let action = match str_arg(args, "action") {
            Some(a) => a.to_string(),
            None => return Ok(make_err(self.name(), "Missing action".into())),
        };

        match action.as_str() {
            "create" => {
                let name = match str_arg(args, "name") {
                    Some(n) => n,
                    None => return Ok(make_err(self.name(), "Missing name".into())),
                };
                match self.db.create_client(name, str_arg(args, "email"), str_arg(args, "phone"), str_arg(args, "address"), str_arg(args, "notes")) {
                    Ok(id) => Ok(make_result(self.name(), true, serde_json::json!({"id": id, "status": "created"}).to_string())),
                    Err(e) => Ok(make_err(self.name(), e.to_string())),
                }
            }
            "get" => {
                let id = match int_arg(args, "client_id") {
                    Some(id) => id,
                    None => return Ok(make_err(self.name(), "Missing client_id".into())),
                };
                match self.db.get_client(id) {
                    Ok(Some(c)) => Ok(make_result(self.name(), true, serde_json::to_string_pretty(&c)?)),
                    Ok(None) => Ok(make_err(self.name(), "Client not found".into())),
                    Err(e) => Ok(make_err(self.name(), e.to_string())),
                }
            }
            "list" => {
                match self.db.list_clients() {
                    Ok(clients) => Ok(make_result(self.name(), true, serde_json::to_string_pretty(&clients)?)),
                    Err(e) => Ok(make_err(self.name(), e.to_string())),
                }
            }
            "update" => {
                let id = match int_arg(args, "client_id") {
                    Some(id) => id,
                    None => return Ok(make_err(self.name(), "Missing client_id".into())),
                };
                match self.db.update_client(id, str_arg(args, "name"), str_arg(args, "email"), str_arg(args, "phone"), str_arg(args, "address"), str_arg(args, "notes")) {
                    Ok(()) => Ok(make_result(self.name(), true, serde_json::json!({"status": "updated"}).to_string())),
                    Err(e) => Ok(make_err(self.name(), e.to_string())),
                }
            }
            "search" => {
                let query = match str_arg(args, "name") {
                    Some(q) => q,
                    None => return Ok(make_err(self.name(), "Missing name for search".into())),
                };
                match self.db.search_clients(query) {
                    Ok(clients) => Ok(make_result(self.name(), true, serde_json::to_string_pretty(&clients)?)),
                    Err(e) => Ok(make_err(self.name(), e.to_string())),
                }
            }
            _ => Ok(make_err(self.name(), format!("Unknown action: {action}"))),
        }
    }
}

// ---------------------------------------------------------------------------
// 8. MatterManagerTool
// ---------------------------------------------------------------------------

pub struct MatterManagerTool { pub db: Arc<LegalDatabase> }

#[async_trait]
impl Tool for MatterManagerTool {
    fn name(&self) -> &str { "legal_matter_manager" }
    fn description(&self) -> &str { "Manage legal matters: create, get, list, list by client, update status" }
    fn parameters_schema(&self) -> Value {
        serde_json::json!({"type":"object","properties":{"action":{"type":"string","enum":["create","get","list","list_by_client","update_status"]},"matter_id":{"type":"integer"},"client_id":{"type":"integer"},"title":{"type":"string"},"matter_type":{"type":"string"},"status":{"type":"string"},"description":{"type":"string"}},"required":["action"]})
    }
    fn risk_level(&self) -> RiskLevel { RiskLevel::Low }
    fn required_permissions(&self) -> Vec<String> { vec![] }

    async fn execute(&self, args: &HashMap<String, Value>, _ctx: &SecurityContext) -> Result<ToolResult> {
        let action = match str_arg(args, "action") {
            Some(a) => a.to_string(),
            None => return Ok(make_err(self.name(), "Missing action".into())),
        };

        match action.as_str() {
            "create" => {
                let title = match str_arg(args, "title") {
                    Some(t) => t,
                    None => return Ok(make_err(self.name(), "Missing title".into())),
                };
                let matter_type = str_arg(args, "matter_type").unwrap_or("general");
                let client_id = int_arg(args, "client_id");
                match self.db.create_matter(client_id, title, matter_type, str_arg(args, "description")) {
                    Ok(id) => Ok(make_result(self.name(), true, serde_json::json!({"id": id, "status": "created"}).to_string())),
                    Err(e) => Ok(make_err(self.name(), e.to_string())),
                }
            }
            "get" => {
                let id = match int_arg(args, "matter_id") {
                    Some(id) => id,
                    None => return Ok(make_err(self.name(), "Missing matter_id".into())),
                };
                match self.db.get_matter(id) {
                    Ok(Some(m)) => Ok(make_result(self.name(), true, serde_json::to_string_pretty(&m)?)),
                    Ok(None) => Ok(make_err(self.name(), "Matter not found".into())),
                    Err(e) => Ok(make_err(self.name(), e.to_string())),
                }
            }
            "list" => {
                match self.db.list_matters() {
                    Ok(matters) => Ok(make_result(self.name(), true, serde_json::to_string_pretty(&matters)?)),
                    Err(e) => Ok(make_err(self.name(), e.to_string())),
                }
            }
            "list_by_client" => {
                let client_id = match int_arg(args, "client_id") {
                    Some(id) => id,
                    None => return Ok(make_err(self.name(), "Missing client_id".into())),
                };
                match self.db.list_matters_by_client(client_id) {
                    Ok(matters) => Ok(make_result(self.name(), true, serde_json::to_string_pretty(&matters)?)),
                    Err(e) => Ok(make_err(self.name(), e.to_string())),
                }
            }
            "update_status" => {
                let id = match int_arg(args, "matter_id") {
                    Some(id) => id,
                    None => return Ok(make_err(self.name(), "Missing matter_id".into())),
                };
                let status = match str_arg(args, "status") {
                    Some(s) => s,
                    None => return Ok(make_err(self.name(), "Missing status".into())),
                };
                match self.db.update_matter_status(id, status) {
                    Ok(()) => Ok(make_result(self.name(), true, serde_json::json!({"status": "updated"}).to_string())),
                    Err(e) => Ok(make_err(self.name(), e.to_string())),
                }
            }
            _ => Ok(make_err(self.name(), format!("Unknown action: {action}"))),
        }
    }
}

// ---------------------------------------------------------------------------
// 9. DocOrganizeTool
// ---------------------------------------------------------------------------

pub struct DocOrganizeTool { pub db: Arc<LegalDatabase> }

#[async_trait]
impl Tool for DocOrganizeTool {
    fn name(&self) -> &str { "legal_doc_organize" }
    fn description(&self) -> &str { "Link a document to a matter; optionally auto-suggest the best matter via AI" }
    fn parameters_schema(&self) -> Value {
        serde_json::json!({"type":"object","properties":{"document_id":{"type":"integer"},"matter_id":{"type":"integer"}},"required":["document_id"]})
    }
    fn risk_level(&self) -> RiskLevel { RiskLevel::Low }
    fn required_permissions(&self) -> Vec<String> { vec![] }

    async fn execute(&self, args: &HashMap<String, Value>, _ctx: &SecurityContext) -> Result<ToolResult> {
        let document_id = match int_arg(args, "document_id") {
            Some(id) => id,
            None => return Ok(make_err(self.name(), "Missing document_id".into())),
        };

        let matter_id = match int_arg(args, "matter_id") {
            Some(id) => id,
            None => {
                let doc = match self.db.get_document(document_id) {
                    Ok(Some(d)) => d,
                    _ => return Ok(make_err(self.name(), "Document not found".into())),
                };
                let matters = self.db.list_matters().unwrap_or_default();
                let analysis = doc.analysis_json.as_deref().unwrap_or("No analysis");

                let system_prompt = "Given a document analysis and list of matters, return ONLY JSON: {\"matter_id\": <int or null>, \"reason\": \"...\"}";
                let user_msg = format!("Analysis:\n{}\n\nMatters:\n{}", analysis, serde_json::to_string_pretty(&matters)?);

                match call_llm(system_prompt, &user_msg).await {
                    Ok(resp) => {
                        let suggestion = parse_llm_json(&resp);
                        match suggestion["matter_id"].as_i64() {
                            Some(id) => id,
                            None => return Ok(make_result(self.name(), true, serde_json::json!({"status":"no_match","suggestion":suggestion}).to_string())),
                        }
                    }
                    Err(e) => return Ok(make_err(self.name(), format!("LLM call failed: {e}"))),
                }
            }
        };

        if let Err(e) = self.db.update_document_matter(document_id, matter_id) {
            return Ok(make_err(self.name(), format!("Failed to link: {e}")));
        }
        let _ = self.db.update_document_status(document_id, "filed");

        Ok(make_result(self.name(), true, serde_json::json!({"document_id":document_id,"matter_id":matter_id,"status":"filed"}).to_string()))
    }
}

// ---------------------------------------------------------------------------
// 10. DashboardTool
// ---------------------------------------------------------------------------

pub struct DashboardTool { pub db: Arc<LegalDatabase> }

#[async_trait]
impl Tool for DashboardTool {
    fn name(&self) -> &str { "legal_dashboard" }
    fn description(&self) -> &str { "Retrieve dashboard statistics" }
    fn parameters_schema(&self) -> Value {
        serde_json::json!({"type":"object","properties":{}})
    }
    fn risk_level(&self) -> RiskLevel { RiskLevel::Low }
    fn required_permissions(&self) -> Vec<String> { vec![] }

    async fn execute(&self, _args: &HashMap<String, Value>, _ctx: &SecurityContext) -> Result<ToolResult> {
        match self.db.get_dashboard_stats() {
            Ok(stats) => Ok(make_result(self.name(), true, serde_json::to_string_pretty(&stats)?)),
            Err(e) => Ok(make_err(self.name(), format!("Failed to get stats: {e}"))),
        }
    }
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

pub fn register_legal_tools(registry: &mut crate::core::tool::ToolRegistry, db: Arc<LegalDatabase>) -> anyhow::Result<()> {
    registry.register(Box::new(DocExtractTool { db: db.clone() }))?;
    registry.register(Box::new(DocAnalyzeTool { db: db.clone() }))?;
    registry.register(Box::new(ConflictCheckTool { db: db.clone() }))?;
    registry.register(Box::new(DocDraftTool { db: db.clone() }))?;
    registry.register(Box::new(ReviewPacketTool { db: db.clone() }))?;
    registry.register(Box::new(NextStepsTool { db: db.clone() }))?;
    registry.register(Box::new(ClientManagerTool { db: db.clone() }))?;
    registry.register(Box::new(MatterManagerTool { db: db.clone() }))?;
    registry.register(Box::new(DocOrganizeTool { db: db.clone() }))?;
    registry.register(Box::new(DashboardTool { db }))?;
    Ok(())
}
