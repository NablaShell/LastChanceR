//! CI-проверка гигиены секретов (M-5).
//!
//! Тест сканирует продакшн-код и падает, если в нём снова появляются
//! неявные копии секретов или старый API, возвращавший корневой ключ по
//! значению. Это дешёвая замена `#[deny(...)]`, которую нельзя выразить
//! стандартными лints.

use std::fs;
use std::path::{Path, PathBuf};

/// Паттерны, запрещённые в `src/`.
///
/// Комментарии тоже сканируются: упоминание паттерна в комментарии — повод
/// явно объяснить его в ревью, а не оставить случайно.
const BANNED_PATTERNS: [&str; 6] = [
    ".private_key.clone()",
    ".seed_phrase.clone()",
    ".ed25519_private_key.clone()",
    ".private_key.to_vec()",
    ".ed25519_private_key.to_vec()",
    "current_root_key",
];

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir).unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()));

    for entry in entries {
        let entry = entry.unwrap_or_else(|e| panic!("cannot read entry in {}: {e}", dir.display()));
        let path = entry.path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn production_code_does_not_leak_secret_copies() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_sources(&src, &mut files);

    assert!(!files.is_empty(), "no Rust sources found under {}", src.display());

    let mut violations = Vec::new();
    for path in files {
        let content = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));

        for (index, line) in content.lines().enumerate() {
            for pattern in BANNED_PATTERNS {
                if line.contains(pattern) {
                    violations.push(format!(
                        "{}:{}: `{}` in: {}",
                        path.display(),
                        index + 1,
                        pattern,
                        line.trim()
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "secret hygiene violations:\n{}",
        violations.join("\n")
    );
}
