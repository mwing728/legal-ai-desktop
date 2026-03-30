use anyhow::Result;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

pub struct LegalDatabase {
    conn: Mutex<Connection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
    pub id: i64,
    pub name: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub address: Option<String>,
    pub notes: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Matter {
    pub id: i64,
    pub client_id: Option<i64>,
    pub title: String,
    pub matter_type: String,
    pub status: String,
    pub description: Option<String>,
    pub priority: String,
    pub assigned_to: Option<String>,
    pub opened_at: String,
    pub closed_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Document {
    pub id: i64,
    pub matter_id: Option<i64>,
    pub filename: String,
    pub file_path: String,
    pub doc_type: String,
    pub category: String,
    pub extracted_text: Option<String>,
    pub analysis_json: Option<String>,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictHit {
    pub id: i64,
    pub document_id: Option<i64>,
    pub matter_id: Option<i64>,
    pub matched_name: String,
    pub matched_client_id: Option<i64>,
    pub conflict_type: String,
    pub confidence: f64,
    pub resolved: bool,
    pub resolution_note: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Deadline {
    pub id: i64,
    pub matter_id: Option<i64>,
    pub document_id: Option<i64>,
    pub title: String,
    pub description: Option<String>,
    pub due_date: String,
    pub priority: String,
    pub status: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionItem {
    pub id: i64,
    pub matter_id: Option<i64>,
    pub document_id: Option<i64>,
    pub title: String,
    pub description: Option<String>,
    pub assignee: Option<String>,
    pub priority: String,
    pub status: String,
    pub created_at: String,
    pub completed_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: i64,
    pub event_type: String,
    pub entity_type: Option<String>,
    pub entity_id: Option<i64>,
    pub details_json: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardStats {
    pub total_clients: i64,
    pub total_matters: i64,
    pub matters_by_status: std::collections::HashMap<String, i64>,
    pub total_documents: i64,
    pub documents_by_status: std::collections::HashMap<String, i64>,
    pub upcoming_deadlines: i64,
    pub open_action_items: i64,
    pub unresolved_conflicts: i64,
}

impl LegalDatabase {
    pub fn new(path: &str) -> Result<Self> {
        let expanded = shellexpand::tilde(path).to_string();
        if let Some(parent) = std::path::Path::new(&expanded).parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(&expanded)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        let db = Self { conn: Mutex::new(conn) };
        db.init_schema()?;
        Ok(db)
    }

    fn init_schema(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT,
                phone TEXT,
                address TEXT,
                notes TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS matters (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id INTEGER REFERENCES clients(id),
                title TEXT NOT NULL,
                matter_type TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'intake',
                description TEXT,
                priority TEXT DEFAULT 'normal',
                assigned_to TEXT,
                opened_at TEXT NOT NULL DEFAULT (datetime('now')),
                closed_at TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                matter_id INTEGER REFERENCES matters(id),
                filename TEXT NOT NULL,
                file_path TEXT NOT NULL,
                doc_type TEXT NOT NULL DEFAULT 'unknown',
                category TEXT NOT NULL DEFAULT 'general',
                extracted_text TEXT,
                analysis_json TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS conflict_hits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                document_id INTEGER REFERENCES documents(id),
                matter_id INTEGER REFERENCES matters(id),
                matched_name TEXT NOT NULL,
                matched_client_id INTEGER REFERENCES clients(id),
                conflict_type TEXT NOT NULL,
                confidence REAL NOT NULL,
                resolved INTEGER NOT NULL DEFAULT 0,
                resolution_note TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS deadlines (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                matter_id INTEGER REFERENCES matters(id),
                document_id INTEGER REFERENCES documents(id),
                title TEXT NOT NULL,
                description TEXT,
                due_date TEXT NOT NULL,
                priority TEXT DEFAULT 'normal',
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS action_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                matter_id INTEGER REFERENCES matters(id),
                document_id INTEGER REFERENCES documents(id),
                title TEXT NOT NULL,
                description TEXT,
                assignee TEXT,
                priority TEXT DEFAULT 'normal',
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                completed_at TEXT
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                entity_type TEXT,
                entity_id INTEGER,
                details_json TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            ",
        )?;
        Ok(())
    }

    // --- Clients ---

    pub fn create_client(&self, name: &str, email: Option<&str>, phone: Option<&str>, address: Option<&str>, notes: Option<&str>) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO clients (name, email, phone, address, notes) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![name, email, phone, address, notes],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn get_client(&self, id: i64) -> Result<Option<Client>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT id, name, email, phone, address, notes, created_at, updated_at FROM clients WHERE id = ?1")?;
        let mut rows = stmt.query_map(params![id], |row| {
            Ok(Client {
                id: row.get(0)?,
                name: row.get(1)?,
                email: row.get(2)?,
                phone: row.get(3)?,
                address: row.get(4)?,
                notes: row.get(5)?,
                created_at: row.get(6)?,
                updated_at: row.get(7)?,
            })
        })?;
        match rows.next() {
            Some(Ok(c)) => Ok(Some(c)),
            _ => Ok(None),
        }
    }

    pub fn list_clients(&self) -> Result<Vec<Client>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT id, name, email, phone, address, notes, created_at, updated_at FROM clients ORDER BY name")?;
        let rows = stmt.query_map([], |row| {
            Ok(Client {
                id: row.get(0)?,
                name: row.get(1)?,
                email: row.get(2)?,
                phone: row.get(3)?,
                address: row.get(4)?,
                notes: row.get(5)?,
                created_at: row.get(6)?,
                updated_at: row.get(7)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn update_client(&self, id: i64, name: Option<&str>, email: Option<&str>, phone: Option<&str>, address: Option<&str>, notes: Option<&str>) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        if let Some(n) = name {
            conn.execute("UPDATE clients SET name = ?1, updated_at = datetime('now') WHERE id = ?2", params![n, id])?;
        }
        if let Some(e) = email {
            conn.execute("UPDATE clients SET email = ?1, updated_at = datetime('now') WHERE id = ?2", params![e, id])?;
        }
        if let Some(p) = phone {
            conn.execute("UPDATE clients SET phone = ?1, updated_at = datetime('now') WHERE id = ?2", params![p, id])?;
        }
        if let Some(a) = address {
            conn.execute("UPDATE clients SET address = ?1, updated_at = datetime('now') WHERE id = ?2", params![a, id])?;
        }
        if let Some(n) = notes {
            conn.execute("UPDATE clients SET notes = ?1, updated_at = datetime('now') WHERE id = ?2", params![n, id])?;
        }
        Ok(())
    }

    pub fn search_clients(&self, query: &str) -> Result<Vec<Client>> {
        let conn = self.conn.lock().unwrap();
        let pattern = format!("%{}%", query);
        let mut stmt = conn.prepare(
            "SELECT id, name, email, phone, address, notes, created_at, updated_at FROM clients WHERE name LIKE ?1 OR email LIKE ?1 ORDER BY name"
        )?;
        let rows = stmt.query_map(params![pattern], |row| {
            Ok(Client {
                id: row.get(0)?,
                name: row.get(1)?,
                email: row.get(2)?,
                phone: row.get(3)?,
                address: row.get(4)?,
                notes: row.get(5)?,
                created_at: row.get(6)?,
                updated_at: row.get(7)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    // --- Matters ---

    pub fn create_matter(&self, client_id: Option<i64>, title: &str, matter_type: &str, description: Option<&str>) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO matters (client_id, title, matter_type, description) VALUES (?1, ?2, ?3, ?4)",
            params![client_id, title, matter_type, description],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn get_matter(&self, id: i64) -> Result<Option<Matter>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, client_id, title, matter_type, status, description, priority, assigned_to, opened_at, closed_at, created_at, updated_at FROM matters WHERE id = ?1"
        )?;
        let mut rows = stmt.query_map(params![id], |row| {
            Ok(Matter {
                id: row.get(0)?,
                client_id: row.get(1)?,
                title: row.get(2)?,
                matter_type: row.get(3)?,
                status: row.get(4)?,
                description: row.get(5)?,
                priority: row.get(6)?,
                assigned_to: row.get(7)?,
                opened_at: row.get(8)?,
                closed_at: row.get(9)?,
                created_at: row.get(10)?,
                updated_at: row.get(11)?,
            })
        })?;
        match rows.next() {
            Some(Ok(m)) => Ok(Some(m)),
            _ => Ok(None),
        }
    }

    pub fn list_matters(&self) -> Result<Vec<Matter>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, client_id, title, matter_type, status, description, priority, assigned_to, opened_at, closed_at, created_at, updated_at FROM matters ORDER BY created_at DESC"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(Matter {
                id: row.get(0)?,
                client_id: row.get(1)?,
                title: row.get(2)?,
                matter_type: row.get(3)?,
                status: row.get(4)?,
                description: row.get(5)?,
                priority: row.get(6)?,
                assigned_to: row.get(7)?,
                opened_at: row.get(8)?,
                closed_at: row.get(9)?,
                created_at: row.get(10)?,
                updated_at: row.get(11)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn list_matters_by_client(&self, client_id: i64) -> Result<Vec<Matter>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, client_id, title, matter_type, status, description, priority, assigned_to, opened_at, closed_at, created_at, updated_at FROM matters WHERE client_id = ?1 ORDER BY created_at DESC"
        )?;
        let rows = stmt.query_map(params![client_id], |row| {
            Ok(Matter {
                id: row.get(0)?,
                client_id: row.get(1)?,
                title: row.get(2)?,
                matter_type: row.get(3)?,
                status: row.get(4)?,
                description: row.get(5)?,
                priority: row.get(6)?,
                assigned_to: row.get(7)?,
                opened_at: row.get(8)?,
                closed_at: row.get(9)?,
                created_at: row.get(10)?,
                updated_at: row.get(11)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn update_matter_status(&self, id: i64, status: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE matters SET status = ?1, updated_at = datetime('now') WHERE id = ?2",
            params![status, id],
        )?;
        Ok(())
    }

    // --- Documents ---

    pub fn insert_document(&self, filename: &str, file_path: &str, extracted_text: Option<&str>) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO documents (filename, file_path, extracted_text) VALUES (?1, ?2, ?3)",
            params![filename, file_path, extracted_text],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn get_document(&self, id: i64) -> Result<Option<Document>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, matter_id, filename, file_path, doc_type, category, extracted_text, analysis_json, status, created_at, updated_at FROM documents WHERE id = ?1"
        )?;
        let mut rows = stmt.query_map(params![id], |row| {
            Ok(Document {
                id: row.get(0)?,
                matter_id: row.get(1)?,
                filename: row.get(2)?,
                file_path: row.get(3)?,
                doc_type: row.get(4)?,
                category: row.get(5)?,
                extracted_text: row.get(6)?,
                analysis_json: row.get(7)?,
                status: row.get(8)?,
                created_at: row.get(9)?,
                updated_at: row.get(10)?,
            })
        })?;
        match rows.next() {
            Some(Ok(d)) => Ok(Some(d)),
            _ => Ok(None),
        }
    }

    pub fn list_documents(&self) -> Result<Vec<Document>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, matter_id, filename, file_path, doc_type, category, extracted_text, analysis_json, status, created_at, updated_at FROM documents ORDER BY created_at DESC"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(Document {
                id: row.get(0)?,
                matter_id: row.get(1)?,
                filename: row.get(2)?,
                file_path: row.get(3)?,
                doc_type: row.get(4)?,
                category: row.get(5)?,
                extracted_text: row.get(6)?,
                analysis_json: row.get(7)?,
                status: row.get(8)?,
                created_at: row.get(9)?,
                updated_at: row.get(10)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn list_documents_by_matter(&self, matter_id: i64) -> Result<Vec<Document>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, matter_id, filename, file_path, doc_type, category, extracted_text, analysis_json, status, created_at, updated_at FROM documents WHERE matter_id = ?1 ORDER BY created_at DESC"
        )?;
        let rows = stmt.query_map(params![matter_id], |row| {
            Ok(Document {
                id: row.get(0)?,
                matter_id: row.get(1)?,
                filename: row.get(2)?,
                file_path: row.get(3)?,
                doc_type: row.get(4)?,
                category: row.get(5)?,
                extracted_text: row.get(6)?,
                analysis_json: row.get(7)?,
                status: row.get(8)?,
                created_at: row.get(9)?,
                updated_at: row.get(10)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn update_document_status(&self, id: i64, status: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE documents SET status = ?1, updated_at = datetime('now') WHERE id = ?2",
            params![status, id],
        )?;
        Ok(())
    }

    pub fn update_document_analysis(&self, id: i64, doc_type: &str, category: &str, analysis_json: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE documents SET doc_type = ?1, category = ?2, analysis_json = ?3, status = 'analyzed', updated_at = datetime('now') WHERE id = ?4",
            params![doc_type, category, analysis_json, id],
        )?;
        Ok(())
    }

    pub fn update_document_matter(&self, id: i64, matter_id: i64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE documents SET matter_id = ?1, updated_at = datetime('now') WHERE id = ?2",
            params![matter_id, id],
        )?;
        Ok(())
    }

    // --- Conflict Hits ---

    pub fn insert_conflict_hit(&self, document_id: Option<i64>, matter_id: Option<i64>, matched_name: &str, matched_client_id: Option<i64>, conflict_type: &str, confidence: f64) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO conflict_hits (document_id, matter_id, matched_name, matched_client_id, conflict_type, confidence) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![document_id, matter_id, matched_name, matched_client_id, conflict_type, confidence],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn get_conflicts_for_document(&self, document_id: i64) -> Result<Vec<ConflictHit>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, document_id, matter_id, matched_name, matched_client_id, conflict_type, confidence, resolved, resolution_note, created_at FROM conflict_hits WHERE document_id = ?1"
        )?;
        let rows = stmt.query_map(params![document_id], |row| {
            Ok(ConflictHit {
                id: row.get(0)?,
                document_id: row.get(1)?,
                matter_id: row.get(2)?,
                matched_name: row.get(3)?,
                matched_client_id: row.get(4)?,
                conflict_type: row.get(5)?,
                confidence: row.get(6)?,
                resolved: row.get::<_, i32>(7)? != 0,
                resolution_note: row.get(8)?,
                created_at: row.get(9)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn resolve_conflict(&self, id: i64, note: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE conflict_hits SET resolved = 1, resolution_note = ?1 WHERE id = ?2",
            params![note, id],
        )?;
        Ok(())
    }

    // --- Deadlines ---

    pub fn insert_deadline(&self, matter_id: Option<i64>, document_id: Option<i64>, title: &str, description: Option<&str>, due_date: &str, priority: &str) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO deadlines (matter_id, document_id, title, description, due_date, priority) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![matter_id, document_id, title, description, due_date, priority],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn list_deadlines(&self) -> Result<Vec<Deadline>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, matter_id, document_id, title, description, due_date, priority, status, created_at FROM deadlines ORDER BY due_date ASC"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(Deadline {
                id: row.get(0)?,
                matter_id: row.get(1)?,
                document_id: row.get(2)?,
                title: row.get(3)?,
                description: row.get(4)?,
                due_date: row.get(5)?,
                priority: row.get(6)?,
                status: row.get(7)?,
                created_at: row.get(8)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn list_upcoming_deadlines(&self, days: i64) -> Result<Vec<Deadline>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, matter_id, document_id, title, description, due_date, priority, status, created_at FROM deadlines WHERE status = 'pending' AND due_date <= datetime('now', ?1) ORDER BY due_date ASC"
        )?;
        let offset = format!("+{} days", days);
        let rows = stmt.query_map(params![offset], |row| {
            Ok(Deadline {
                id: row.get(0)?,
                matter_id: row.get(1)?,
                document_id: row.get(2)?,
                title: row.get(3)?,
                description: row.get(4)?,
                due_date: row.get(5)?,
                priority: row.get(6)?,
                status: row.get(7)?,
                created_at: row.get(8)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn update_deadline_status(&self, id: i64, status: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("UPDATE deadlines SET status = ?1 WHERE id = ?2", params![status, id])?;
        Ok(())
    }

    // --- Action Items ---

    pub fn insert_action_item(&self, matter_id: Option<i64>, document_id: Option<i64>, title: &str, description: Option<&str>, assignee: Option<&str>, priority: &str) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO action_items (matter_id, document_id, title, description, assignee, priority) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![matter_id, document_id, title, description, assignee, priority],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn list_action_items(&self) -> Result<Vec<ActionItem>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, matter_id, document_id, title, description, assignee, priority, status, created_at, completed_at FROM action_items ORDER BY created_at DESC"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(ActionItem {
                id: row.get(0)?,
                matter_id: row.get(1)?,
                document_id: row.get(2)?,
                title: row.get(3)?,
                description: row.get(4)?,
                assignee: row.get(5)?,
                priority: row.get(6)?,
                status: row.get(7)?,
                created_at: row.get(8)?,
                completed_at: row.get(9)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn list_action_items_by_matter(&self, matter_id: i64) -> Result<Vec<ActionItem>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, matter_id, document_id, title, description, assignee, priority, status, created_at, completed_at FROM action_items WHERE matter_id = ?1 ORDER BY created_at DESC"
        )?;
        let rows = stmt.query_map(params![matter_id], |row| {
            Ok(ActionItem {
                id: row.get(0)?,
                matter_id: row.get(1)?,
                document_id: row.get(2)?,
                title: row.get(3)?,
                description: row.get(4)?,
                assignee: row.get(5)?,
                priority: row.get(6)?,
                status: row.get(7)?,
                created_at: row.get(8)?,
                completed_at: row.get(9)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn update_action_item_status(&self, id: i64, status: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        if status == "completed" {
            conn.execute(
                "UPDATE action_items SET status = ?1, completed_at = datetime('now') WHERE id = ?2",
                params![status, id],
            )?;
        } else {
            conn.execute("UPDATE action_items SET status = ?1 WHERE id = ?2", params![status, id])?;
        }
        Ok(())
    }

    // --- Deletes ---

    pub fn delete_document(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM conflict_hits WHERE document_id = ?1", params![id])?;
        conn.execute("DELETE FROM deadlines WHERE document_id = ?1", params![id])?;
        conn.execute("DELETE FROM action_items WHERE document_id = ?1", params![id])?;
        conn.execute("DELETE FROM documents WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn delete_matter(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("UPDATE documents SET matter_id = NULL WHERE matter_id = ?1", params![id])?;
        conn.execute("DELETE FROM conflict_hits WHERE matter_id = ?1", params![id])?;
        conn.execute("DELETE FROM deadlines WHERE matter_id = ?1", params![id])?;
        conn.execute("DELETE FROM action_items WHERE matter_id = ?1", params![id])?;
        conn.execute("DELETE FROM matters WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn delete_client(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT id FROM matters WHERE client_id = ?1")?;
        let matter_ids: Vec<i64> = stmt
            .query_map(params![id], |row| row.get(0))?
            .filter_map(|r| r.ok())
            .collect();
        drop(stmt);

        for mid in &matter_ids {
            conn.execute("UPDATE documents SET matter_id = NULL WHERE matter_id = ?1", params![mid])?;
            conn.execute("DELETE FROM conflict_hits WHERE matter_id = ?1", params![mid])?;
            conn.execute("DELETE FROM deadlines WHERE matter_id = ?1", params![mid])?;
            conn.execute("DELETE FROM action_items WHERE matter_id = ?1", params![mid])?;
        }
        conn.execute("DELETE FROM matters WHERE client_id = ?1", params![id])?;
        conn.execute("DELETE FROM clients WHERE id = ?1", params![id])?;
        Ok(())
    }

    // --- Audit Log ---

    pub fn log_audit_event(&self, event_type: &str, entity_type: Option<&str>, entity_id: Option<i64>, details_json: Option<&str>) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO audit_log (event_type, entity_type, entity_id, details_json) VALUES (?1, ?2, ?3, ?4)",
            params![event_type, entity_type, entity_id, details_json],
        )?;
        Ok(())
    }

    // --- Dashboard ---

    pub fn get_dashboard_stats(&self) -> Result<DashboardStats> {
        let conn = self.conn.lock().unwrap();

        let total_clients: i64 = conn.query_row("SELECT COUNT(*) FROM clients", [], |r| r.get(0))?;
        let total_matters: i64 = conn.query_row("SELECT COUNT(*) FROM matters", [], |r| r.get(0))?;
        let total_documents: i64 = conn.query_row("SELECT COUNT(*) FROM documents", [], |r| r.get(0))?;
        let upcoming_deadlines: i64 = conn.query_row(
            "SELECT COUNT(*) FROM deadlines WHERE status = 'pending' AND due_date <= datetime('now', '+30 days')",
            [], |r| r.get(0),
        )?;
        let open_action_items: i64 = conn.query_row(
            "SELECT COUNT(*) FROM action_items WHERE status IN ('pending', 'in_progress')",
            [], |r| r.get(0),
        )?;
        let unresolved_conflicts: i64 = conn.query_row(
            "SELECT COUNT(*) FROM conflict_hits WHERE resolved = 0",
            [], |r| r.get(0),
        )?;

        let mut matters_by_status = std::collections::HashMap::new();
        {
            let mut stmt = conn.prepare("SELECT status, COUNT(*) FROM matters GROUP BY status")?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?;
            for row in rows.flatten() {
                matters_by_status.insert(row.0, row.1);
            }
        }

        let mut documents_by_status = std::collections::HashMap::new();
        {
            let mut stmt = conn.prepare("SELECT status, COUNT(*) FROM documents GROUP BY status")?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?;
            for row in rows.flatten() {
                documents_by_status.insert(row.0, row.1);
            }
        }

        Ok(DashboardStats {
            total_clients,
            total_matters,
            matters_by_status,
            total_documents,
            documents_by_status,
            upcoming_deadlines,
            open_action_items,
            unresolved_conflicts,
        })
    }
}
