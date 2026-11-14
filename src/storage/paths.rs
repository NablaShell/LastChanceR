// src/storage/paths.rs
use anyhow::{anyhow, Result};
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

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

        // Атомарная замена: пишем во временный файл рядом с целевым и
        // переименовываем. Читатель видит либо старую, либо новую версию,
        // но никогда — половину записи.
        let file_name = safe_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| anyhow!("invalid file name: {:?}", safe_path))?;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        let tmp_path = safe_path.with_file_name(format!(
            ".{}.tmp-{}-{}",
            file_name,
            std::process::id(),
            nanos
        ));

        let result = write_and_replace(&tmp_path, &safe_path, data, perm);
        if result.is_err() {
            let _ = fs::remove_file(&tmp_path);
        }
        result
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

/// Записывает данные во временный файл и атомарно заменяет им целевой.
fn write_and_replace(tmp_path: &Path, target: &Path, data: &[u8], perm: u32) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);

    // На Unix права выставляются уже при создании файла, чтобы данные ни
    // мгновения не были доступны другим пользователям.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(perm);
    }

    let mut file = options
        .open(tmp_path)
        .map_err(|e| anyhow!("cannot create temp file {:?}: {}", tmp_path, e))?;
    file.write_all(data)
        .map_err(|e| anyhow!("cannot write {:?}: {}", tmp_path, e))?;
    file.sync_all()
        .map_err(|e| anyhow!("cannot flush {:?}: {}", tmp_path, e))?;
    drop(file);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = fs::Permissions::from_mode(perm);
        fs::set_permissions(tmp_path, permissions)
            .map_err(|e| anyhow!("cannot set permissions {:?}: {}", tmp_path, e))?;
    }

    // Windows не поддерживает POSIX-права. Безопасная заглушка:
    // если владелец лишён права записи, помечаем файл как readonly.
    #[cfg(not(unix))]
    {
        if perm & 0o200 == 0 {
            let mut permissions = fs::metadata(tmp_path)
                .map_err(|e| anyhow!("cannot stat file {:?}: {}", tmp_path, e))?
                .permissions();
            permissions.set_readonly(true);
            fs::set_permissions(tmp_path, permissions)
                .map_err(|e| anyhow!("cannot set permissions {:?}: {}", tmp_path, e))?;
        }
    }

    if let Err(err) = fs::rename(tmp_path, target) {
        // `rename` на Windows не перезаписывает существующий файл.
        #[cfg(windows)]
        {
            if target.exists() {
                fs::remove_file(target)
                    .map_err(|e| anyhow!("cannot replace {:?}: {}", target, e))?;
                fs::rename(tmp_path, target)
                    .map_err(|e| anyhow!("cannot replace {:?}: {}", target, e))?;
            } else {
                return Err(anyhow!("cannot replace {:?}: {}", target, err));
            }
        }
        #[cfg(not(windows))]
        {
            return Err(anyhow!("cannot replace {:?}: {}", target, err));
        }
    }

    // Фиксируем на диске и саму переименованную запись каталога.
    #[cfg(unix)]
    if let Some(parent) = target.parent() {
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }

    Ok(())
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

/// Имя каталога профиля внутри системной конфигурационной директории.
pub const PROFILE_DIR_NAME: &str = "lastchance";

/// Стандартный каталог профиля: `<config_dir>/lastchance`.
///
/// Linux/Unix: `~/.config/lastchance` (или `$XDG_CONFIG_HOME/lastchance`),
/// macOS: `~/Library/Application Support/lastchance`,
/// Windows: `%APPDATA%\lastchance`.
pub fn default_profile_dir() -> Result<PathBuf> {
    let base = dirs::config_dir()
        .or_else(|| dirs::home_dir().map(|home| home.join(".config")))
        .ok_or_else(|| anyhow!("cannot determine the user configuration directory"))?;
    Ok(base.join(PROFILE_DIR_NAME))
}

/// Старое расположение профиля (`dirs::data_local_dir()/lastchance`):
/// `~/.local/share/lastchance` на Linux, `%LOCALAPPDATA%\lastchance` на Windows.
fn legacy_profile_dir() -> Option<PathBuf> {
    dirs::data_local_dir().map(|base| base.join(PROFILE_DIR_NAME))
}

/// Источник выбранного каталога профиля (для сообщений и тестов).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProfileSource {
    Cli,
    Env,
    Portable,
    Default,
}

impl ProfileSource {
    fn label(self) -> &'static str {
        match self {
            Self::Cli => "--profile-dir",
            Self::Env => "LASTCHANCE_DIR",
            Self::Portable => "portable mode",
            Self::Default => "system default",
        }
    }
}

/// Выбирает путь профиля с приоритетом:
/// 1. `--profile-dir` / `--data-dir` из CLI;
/// 2. переменная окружения `LASTCHANCE_DIR`;
/// 3. переносимый режим (файл `.portable` рядом с бинарником);
/// 4. системная конфигурационная директория.
fn select_profile_path(
    cli_override: Option<&str>,
    env_override: Option<&std::ffi::OsStr>,
    portable_dir: Option<PathBuf>,
    default_dir: PathBuf,
) -> Result<(PathBuf, ProfileSource)> {
    if let Some(path) = cli_override {
        let path = path.trim();
        if path.is_empty() {
            return Err(anyhow!("--profile-dir: путь не должен быть пустым"));
        }
        return Ok((PathBuf::from(path), ProfileSource::Cli));
    }

    if let Some(dir) = env_override {
        if !dir.is_empty() {
            return Ok((PathBuf::from(dir), ProfileSource::Env));
        }
    }

    if let Some(dir) = portable_dir {
        return Ok((dir, ProfileSource::Portable));
    }

    Ok((default_dir, ProfileSource::Default))
}

/// Определяет переносимый режим: рядом с бинарником лежит `.portable`.
fn detect_portable_dir() -> Result<Option<PathBuf>> {
    let exec_path = std::env::current_exe()
        .map_err(|e| anyhow!("unable to get executable path: {}", e))?;
    let exec_dir = exec_path
        .parent()
        .ok_or_else(|| anyhow!("no parent directory"))?;

    if exec_dir.join(".portable").exists() {
        Ok(Some(exec_dir.join("data")))
    } else {
        Ok(None)
    }
}

/// Возвращает базовую директорию с приоритетом:
/// 1. явный аргумент `--profile-dir` (передаётся из CLI);
/// 2. переменная окружения `LASTCHANCE_DIR`;
/// 3. переносимый режим (файл `.portable` рядом с бинарником);
/// 4. стандартный конфигурационный путь (`~/.config/lastchance`).
///
/// Для стандартного пути при первом запуске выполняется безопасная
/// автомиграция из старой data-директории. Директория создаётся через
/// `create_dir_all`, если её ещё нет.
pub fn get_base_dir() -> Result<String> {
    get_base_dir_with_override(None)
}

pub fn get_base_dir_with_override(cli_override: Option<&str>) -> Result<String> {
    use std::env;

    let portable_dir = detect_portable_dir()?;
    let default_dir = default_profile_dir()?;
    let env_dir = env::var_os("LASTCHANCE_DIR");
    let (path, source) = select_profile_path(
        cli_override,
        env_dir.as_deref(),
        portable_dir,
        default_dir,
    )?;

    // Автомиграция имеет смысл только для стандартного пути: явно заданный
    // профиль не трогаем.
    if source == ProfileSource::Default {
        if let Some(legacy) = legacy_profile_dir() {
            if legacy != path {
                match migrate_legacy_profile(&path, &legacy) {
                    Ok(true) => log::info!(
                        "Migrated profile from {:?} to {:?}",
                        legacy,
                        path
                    ),
                    Ok(false) => {}
                    Err(e) => log::warn!(
                        "Profile migration from {:?} failed: {:#}",
                        legacy,
                        e
                    ),
                }
            }
        }
    }

    ensure_base_dir(path, source.label())
}

/// Копирует непустой старый профиль в новую директорию и выставляет
/// строгие права (0700 на каталоги, 0600 на файлы).
///
/// Копирование идёт во временную директорию рядом с целевой и только затем
/// атомарно переименовывается: прерванная миграция не оставит «полупрофиль».
/// Исходная директория сохраняется — данные никогда не удаляются.
fn migrate_legacy_profile(new_dir: &Path, old_dir: &Path) -> Result<bool> {
    if new_dir.exists() || !old_dir.is_dir() {
        return Ok(false);
    }

    let mut entries = fs::read_dir(old_dir)
        .map_err(|e| anyhow!("cannot read legacy profile {:?}: {}", old_dir, e))?;
    if entries.next().is_none() {
        return Ok(false);
    }
    drop(entries);

    let parent = new_dir
        .parent()
        .ok_or_else(|| anyhow!("profile directory has no parent: {:?}", new_dir))?;
    fs::create_dir_all(parent)
        .map_err(|e| anyhow!("cannot create directory {:?}: {}", parent, e))?;

    let tmp = parent.join(format!(
        ".{}.migrate-{}",
        new_dir
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("profile"),
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&tmp);

    let result = (|| -> Result<bool> {
        copy_dir_recursive(old_dir, &tmp)?;
        harden_tree(&tmp)?;

        // Пока копировали, другой процесс мог уже создать профиль.
        if new_dir.exists() {
            let _ = fs::remove_dir_all(&tmp);
            return Ok(false);
        }

        fs::rename(&tmp, new_dir).map_err(|e| {
            anyhow!("cannot finalize profile migration to {:?}: {}", new_dir, e)
        })?;
        Ok(true)
    })();

    if result.is_err() {
        let _ = fs::remove_dir_all(&tmp);
    }
    result
}

/// Рекурсивно копирует обычные файлы и каталоги. Симлинки и специальные
/// файлы пропускаются, чтобы не вынести данные за пределы профиля.
fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst)
        .map_err(|e| anyhow!("cannot create directory {:?}: {}", dst, e))?;

    let entries = fs::read_dir(src)
        .map_err(|e| anyhow!("cannot read directory {:?}: {}", src, e))?;

    for entry in entries {
        let entry =
            entry.map_err(|e| anyhow!("cannot read directory entry in {:?}: {}", src, e))?;
        let file_type = entry
            .file_type()
            .map_err(|e| anyhow!("cannot stat {:?}: {}", entry.path(), e))?;
        let target = dst.join(entry.file_name());

        if file_type.is_dir() {
            copy_dir_recursive(&entry.path(), &target)?;
        } else if file_type.is_file() {
            fs::copy(entry.path(), &target).map_err(|e| {
                anyhow!(
                    "cannot copy {:?} to {:?}: {}",
                    entry.path(),
                    target,
                    e
                )
            })?;
        }
    }

    Ok(())
}

/// Выставляет 0700 на каталоги и 0600 на файлы внутри скопированного профиля.
#[cfg(unix)]
fn harden_tree(root: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(root, fs::Permissions::from_mode(0o700))
        .map_err(|e| anyhow!("cannot set permissions on {:?}: {}", root, e))?;

    let entries = fs::read_dir(root)
        .map_err(|e| anyhow!("cannot read directory {:?}: {}", root, e))?;

    for entry in entries {
        let entry =
            entry.map_err(|e| anyhow!("cannot read directory entry in {:?}: {}", root, e))?;
        let file_type = entry
            .file_type()
            .map_err(|e| anyhow!("cannot stat {:?}: {}", entry.path(), e))?;

        if file_type.is_dir() {
            harden_tree(&entry.path())?;
        } else if file_type.is_file() {
            fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o600))
                .map_err(|e| {
                    anyhow!("cannot set permissions on {:?}: {}", entry.path(), e)
                })?;
        }
    }

    Ok(())
}

#[cfg(not(unix))]
fn harden_tree(_root: &Path) -> Result<()> {
    Ok(())
}

fn ensure_base_dir(path: PathBuf, source: &str) -> Result<String> {
    fs::create_dir_all(&path).map_err(|e| {
        anyhow!(
            "failed to create profile directory from {} ({:?}): {}",
            source,
            path,
            e
        )
    })?;

    Ok(path.to_string_lossy().to_string())
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

    #[test]
    fn profile_path_priority_is_cli_env_then_default() {
        use std::ffi::OsStr;

        let default = PathBuf::from("/tmp/lastchance-default");

        let (path, source) = select_profile_path(
            Some("/tmp/bot-profile"),
            Some(OsStr::new("/tmp/env-profile")),
            Some(PathBuf::from("/tmp/portable")),
            default.clone(),
        )
        .unwrap();
        assert_eq!(path, PathBuf::from("/tmp/bot-profile"));
        assert_eq!(source, ProfileSource::Cli);

        let (path, source) = select_profile_path(
            None,
            Some(OsStr::new("/tmp/env-profile")),
            Some(PathBuf::from("/tmp/portable")),
            default.clone(),
        )
        .unwrap();
        assert_eq!(path, PathBuf::from("/tmp/env-profile"));
        assert_eq!(source, ProfileSource::Env);

        let (path, source) = select_profile_path(
            None,
            None,
            Some(PathBuf::from("/tmp/portable")),
            default.clone(),
        )
        .unwrap();
        assert_eq!(path, PathBuf::from("/tmp/portable"));
        assert_eq!(source, ProfileSource::Portable);

        let (path, source) =
            select_profile_path(None, None, None, default.clone()).unwrap();
        assert_eq!(path, default);
        assert_eq!(source, ProfileSource::Default);
    }

    #[test]
    fn empty_cli_profile_path_is_rejected() {
        let result = select_profile_path(Some("   "), None, None, PathBuf::from("/tmp"));
        assert!(result.is_err());
    }

    #[test]
    fn default_profile_dir_lives_under_config_dir() {
        let dir = default_profile_dir().unwrap();
        let config = dirs::config_dir().unwrap();

        assert_eq!(dir, config.join(PROFILE_DIR_NAME));
        assert_eq!(
            dir.file_name().and_then(|name| name.to_str()),
            Some(PROFILE_DIR_NAME)
        );
    }

    #[test]
    fn migrates_non_empty_legacy_profile_with_strict_permissions() {
        let temp = tempfile::tempdir().unwrap();
        let old = temp.path().join("old-profile");
        let new = temp.path().join("new-profile");

        fs::create_dir_all(old.join("nested")).unwrap();
        fs::write(old.join("global.conf"), b"sealed-config").unwrap();
        fs::write(old.join("nested").join("user.db"), b"database").unwrap();

        assert!(migrate_legacy_profile(&new, &old).unwrap());

        assert_eq!(
            fs::read(new.join("global.conf")).unwrap(),
            b"sealed-config"
        );
        assert_eq!(
            fs::read(new.join("nested").join("user.db")).unwrap(),
            b"database"
        );
        // Исходный профиль не удаляется.
        assert!(old.join("global.conf").exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mode = |path: &Path| {
                fs::metadata(path).unwrap().permissions().mode() & 0o777
            };

            assert_eq!(mode(&new), 0o700);
            assert_eq!(mode(&new.join("nested")), 0o700);
            assert_eq!(mode(&new.join("global.conf")), 0o600);
            assert_eq!(mode(&new.join("nested").join("user.db")), 0o600);
        }
    }

    #[test]
    fn migration_skips_existing_or_empty_targets() {
        let temp = tempfile::tempdir().unwrap();
        let old = temp.path().join("old-profile");
        let new = temp.path().join("new-profile");

        // Пустой старый профиль мигрировать не нужно.
        fs::create_dir_all(&old).unwrap();
        assert!(!migrate_legacy_profile(&new, &old).unwrap());
        assert!(!new.exists());

        // Непустой старый профиль, но новая директория уже существует.
        fs::write(old.join("global.conf"), b"old").unwrap();
        fs::create_dir_all(&new).unwrap();
        fs::write(new.join("keep.txt"), b"new").unwrap();

        assert!(!migrate_legacy_profile(&new, &old).unwrap());
        assert!(!new.join("global.conf").exists());
        assert_eq!(fs::read(new.join("keep.txt")).unwrap(), b"new");
    }
}
