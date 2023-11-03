use parking_lot::Mutex;
use rusqlite::{params, params_from_iter, Connection, Result};
use std::collections::HashMap;

use super::IStore;

pub struct SQLiteStore {
    db: Mutex<Connection>,
}

impl IStore for SQLiteStore {
    fn get(&self, key: &str) -> Result<Option<String>> {
        let binding = self.db.lock();
        let mut stmt = binding.prepare("SELECT value FROM store WHERE key = ?")?;

        let mut rows = stmt.query(params![key])?;

        if let Some(row) = rows.next()? {
            Ok(Some(row.get(0)?))
        } else {
            Ok(None)
        }
    }

    fn get_many(&self, keys: Vec<&str>) -> Result<HashMap<String, String>> {
        let mut map = HashMap::new();

        // Create the placeholders string.
        let placeholders: Vec<String> = vec!["?".to_string(); keys.len()];
        let placeholders_str = placeholders.join(", ");
        // Prepare the statement.
        let query = format!(
            "SELECT key, value FROM store WHERE key IN ({})",
            placeholders_str
        );
        let binding = self.db.lock();
        let mut stmt = binding.prepare(&query)?;
        let mut rows = stmt.query(params_from_iter(keys.iter()))?;

        while let Some(row) = rows.next()? {
            map.insert(row.get(0)?, row.get(1)?);
        }

        Ok(map)
    }

    fn set(&self, key: &str, value: &str) -> Result<()> {
        self.db.lock().execute(
            "INSERT OR REPLACE INTO store (key, value) VALUES (?, ?)",
            params![key, value],
        )?;
        Ok(())
    }

    fn set_many(&self, entries: HashMap<String, String>) -> Result<()> {
        let mut binding = self.db.lock();
        let tx = binding.transaction()?;
        for (key, value) in entries.iter() {
            tx.execute(
                "INSERT OR REPLACE INTO store (key, value) VALUES (?, ?)",
                params![key, value],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<()> {
        self.db
            .lock()
            .execute("DELETE FROM store WHERE key = ?", params![key])?;
        Ok(())
    }

    fn delete_many(&self, keys: Vec<&str>) -> Result<()> {
        // Create the placeholders string.
        let placeholders: Vec<String> = vec!["?".to_string(); keys.len()];
        let placeholders_str = placeholders.join(", ");

        // Prepare the statement.
        let query = format!("DELETE FROM store WHERE key IN ({})", placeholders_str);

        // Bind the parameters and execute the query.
        self.db
            .lock()
            .execute(&query, params_from_iter(keys.iter()))?;

        Ok(())
    }
}

impl SQLiteStore {
    pub fn new(path: &str) -> Result<Self> {
        let db = Mutex::new(Connection::open(path)?);
        Ok(SQLiteStore { db })
    }

    pub fn init(&self) -> Result<()> {
        self.db.lock().execute(
            "CREATE TABLE IF NOT EXISTS store (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );",
            [],
        )?;
        Ok(())
    }
}
