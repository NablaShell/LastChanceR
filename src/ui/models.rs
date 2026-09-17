// src/ui/models.rs
use chrono::{DateTime, Utc};
use slint::{ModelRc, SharedString, VecModel};

use crate::ContactItem;
use crate::MessageItem;

pub fn truncate_hash(hash: &str, len: usize) -> String {
    if hash.is_empty() {
        return String::new();
    }
    if hash.len() <= len * 2 {
        hash.to_string()
    } else {
        format!("{}...{}", &hash[..len], &hash[hash.len() - len..])
    }
}

pub fn contacts_to_model(contacts: &[crate::storage::Contact]) -> ModelRc<ContactItem> {
    let items: Vec<ContactItem> = contacts
        .iter()
        .map(|c| ContactItem {
            hash: SharedString::from(&c.hash),
            nickname: SharedString::from(&c.nickname),
            truncated_hash: SharedString::from(truncate_hash(&c.hash, 4)),
            avatar_url: SharedString::from(format!(
                "https://api.dicebear.com/7.x/avataaars/svg?seed={}",
                c.hash
            )),
            unread: 0,
        })
        .collect();
    ModelRc::new(VecModel::from(items))
}

pub fn message_to_item(
    id: &str,
    text: &str,
    is_own: bool,
    timestamp: DateTime<Utc>,
    file_info: Option<(String, String, Option<String>)>,
) -> MessageItem {
    let (is_file, file_name, file_hash, file_size) = match file_info {
        Some((n, h, s)) => (
            true,
            SharedString::from(n),
            SharedString::from(h),
            SharedString::from(s.unwrap_or_default()),
        ),
        None => (
            false,
            SharedString::default(),
            SharedString::default(),
            SharedString::default(),
        ),
    };

    MessageItem {
        id: SharedString::from(id),
        text: SharedString::from(text),
        is_own,
        time: SharedString::from(timestamp.format("%H:%M").to_string()),
        is_file,
        file_name,
        file_hash: file_hash.clone(),
        file_hash_truncated: SharedString::from(truncate_hash(&file_hash, 6)),
        file_size,
    }
}

/// Парсит `📎 File: name\nSize: size\nHash: hash`.
pub fn parse_file_message(content: &str) -> Option<(String, String, Option<String>)> {
    if !content.starts_with("📎 File:") {
        return None;
    }

    let mut name = String::new();
    let mut size: Option<String> = None;
    let mut hash = String::new();

    for line in content.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("📎 File:") {
            name = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("Size:") {
            size = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("Hash:") {
            hash = rest.trim().to_string();
        }
    }

    if name.is_empty() || hash.is_empty() {
        None
    } else {
        Some((name, hash, size))
    }
}

pub fn humanize_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}
