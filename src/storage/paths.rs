// src/storage/paths.rs
use anyhow::{anyhow, Result};
use std::fs;
use std::path::{Component, Path, PathBuf};

pub struct SafeFSOps {
    root: PathBuf,
}

impl SafeFSOps {
    pub fn new(root: &str) -> Result<Self> {
        let clean_root = PathBuf::from(root)
            .canonicalize()
            .map_err(|e| anyhow!("cannot access storage root: {}", e))?;

        if !clean_root.is_dir() {
            return Err(anyhow!("storage root is not a directory: {:?}", clean_root));
        }

        Ok(Self { root: clean_root })
    }

    pub fn resolve_path(&self, user_path: &str) -> Result<PathBuf> {
        // Пустой путь или "." → сам корень
        let trimmed = user_path.trim();
        if trimmed.is_empty() || trimmed == "." {
            return Ok(self.root.clone());
        }

        let clean_path = Path::new(trimmed);
        let abs_path = self.root.join(clean_path);

        // Нормализуем компоненты без обращения к ФС:
        // убираем "." и разрешаем ".." только в пределах root.
        let normalized = normalize_path(&abs_path);

        // Проверяем, что нормализованный путь начинается с root.
        if !normalized.starts_with(&self.root) {
            return Err(anyhow!("path traversal detected: {}", user_path));
        }

        Ok(normalized)
    }

    pub fn safe_open_file(&self, user_path: &str) -> Result<std::fs::File> {
        let safe_path = self.resolve_path(user_path)?;
        std::fs::File::open(&safe_path).map_err(|e| anyhow!("cannot open {:?}: {}", safe_path, e))
    }

    pub fn safe_write_file(&self, user_path: &str, data: &[u8], perm: u32) -> Result<()> {
        let safe_path = self.resolve_path(user_path)?;

        if let Some(parent) = safe_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| anyhow!("cannot create directory {:?}: {}", parent, e))?;
        }

        use std::os::unix::fs::PermissionsExt;
        let permissions = fs::Permissions::from_mode(perm);

        fs::write(&safe_path, data)
            .map_err(|e| anyhow!("cannot write file {:?}: {}", safe_path, e))?;

        fs::set_permissions(&safe_path, permissions)
            .map_err(|e| anyhow!("cannot set permissions {:?}: {}", safe_path, e))?;

        Ok(())
    }

    pub fn safe_read_file(&self, user_path: &str) -> Result<Vec<u8>> {
        let safe_path = self.resolve_path(user_path)?;
        fs::read(&safe_path).map_err(|e| anyhow!("cannot read file {:?}: {}", safe_path, e))
    }

    pub fn safe_stat(&self, user_path: &str) -> Result<fs::Metadata> {
        let safe_path = self.resolve_path(user_path)?;
        fs::metadata(&safe_path).map_err(|e| anyhow!("cannot stat file {:?}: {}", safe_path, e))
    }

    pub fn ensure_dir(&self, dir_path: &str) -> Result<()> {
        let safe_path = self.resolve_path(dir_path)?;
        fs::create_dir_all(&safe_path)
            .map_err(|e| anyhow!("cannot create directory {:?}: {}", safe_path, e))
    }
}

/// Нормализует путь: убирает `.`, обрабатывает `..`, не обращаясь к ФС.
fn normalize_path(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::Prefix(p) => out.push(p.as_os_str()),
            Component::RootDir => out.push(Component::RootDir.as_os_str()),
            Component::CurDir => { /* skip "." */ }
            Component::ParentDir => {
                // Пытаемся подняться, но не выше корня
                if !out.pop() {
                    out.push("..");
                }
            }
            Component::Normal(c) => out.push(c),
        }
    }
    out
}

pub fn get_base_dir() -> Result<String> {
    use std::env;

    let exec_path =
        env::current_exe().map_err(|e| anyhow!("unable to get executable path: {}", e))?;
    let exec_dir = exec_path
        .parent()
        .ok_or_else(|| anyhow!("no parent directory"))?;

    let portable_flag = exec_dir.join(".portable");
    if portable_flag.exists() {
        let base_dir = exec_dir.join("data");
        fs::create_dir_all(&base_dir)
            .map_err(|e| anyhow!("failed to create portable data directory: {}", e))?;
        return Ok(base_dir.to_string_lossy().to_string());
    }

    let data_home = if cfg!(target_os = "windows") {
        env::var("LOCALAPPDATA").unwrap_or_else(|_| {
            dirs::home_dir()
                .unwrap_or_default()
                .join("AppData")
                .join("Local")
                .to_string_lossy()
                .to_string()
        })
    } else {
        env::var("XDG_DATA_HOME").unwrap_or_else(|_| {
            dirs::home_dir()
                .unwrap_or_default()
                .join(".local")
                .join("share")
                .to_string_lossy()
                .to_string()
        })
    };

    let base_dir = PathBuf::from(data_home).join("lastchance");
    fs::create_dir_all(&base_dir)
        .map_err(|e| anyhow!("failed to create app data directory: {}", e))?;

    Ok(base_dir.to_string_lossy().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_resolve_path() {
        let temp_dir = std::env::temp_dir().join("test_safe_fs");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let safe_fs = SafeFSOps::new(temp_dir.to_str().unwrap()).unwrap();

        // Нормальный путь
        let path = safe_fs.resolve_path("test.txt").unwrap();
        assert!(path.starts_with(&temp_dir));

        // Точка → корень
        let root = safe_fs.resolve_path(".").unwrap();
        assert_eq!(root, temp_dir.canonicalize().unwrap());

        // Пустая строка → корень
        let root2 = safe_fs.resolve_path("").unwrap();
        assert_eq!(root2, temp_dir.canonicalize().unwrap());

        // Path traversal
        let result = safe_fs.resolve_path("../escape.txt");
        assert!(result.is_err());

        fs::remove_dir_all(&temp_dir).unwrap();
    }
}
