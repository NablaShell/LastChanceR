//! CI-проверки wire-format v3 (M-3, M-4, M-7).
//!
//! Дешёвые source-сканы не дают вернуть удалённый legacy-путь или открытый
//! `X-File-Name`. Интеграционные проверки подтверждают fail-closed для
//! пакетов v1/v2 через публичный API.

use std::fs;
use std::path::{Path, PathBuf};

use lastchance::crypto::ratchet::{RatchetError, RatchetState, Role};

/// Паттерны, которых не должно быть в продакшн-коде.
const BANNED_PATTERNS: [&str; 5] = [
    "decrypt_message",
    "encrypt_message",
    "X-File-Name",
    "x-file-name",
    "fn decrypt_file(",
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
fn legacy_decrypt_and_plaintext_file_name_are_gone() {
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
        "wire-format violations:\n{}",
        violations.join("\n")
    );
}

#[test]
fn v1_and_v2_packets_are_rejected_fail_closed() {
    let shared = [7u8; 32];
    for version in [1u8, 2u8] {
        let mut packet = vec![0u8; 256];
        packet[0] = version;
        let mut state = RatchetState::new(&shared, Role::Initiator).unwrap();
        let error = state.decrypt(&packet, &shared).unwrap_err();
        assert_eq!(
            error.downcast_ref::<RatchetError>(),
            Some(&RatchetError::UnsupportedVersion(version)),
            "version {} must be rejected without panic",
            version
        );
    }
}
