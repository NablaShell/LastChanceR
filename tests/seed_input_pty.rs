//! L-6: seed-фраза не должна эхоиться в реальном терминале.
//!
//! Тест запускает бинарник под псевдотерминалом (PTY), дожидается, пока
//! приложение выключит ECHO в termios, вводит одну и ту же BIP-39 фразу
//! дважды и проверяет, что ни один байт фразы не попал в вывод терминала.
//! Это дополняет юнит-тест `apply_secret_key` из `src/main.rs`.
#![cfg(target_os = "linux")]

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

const PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const SEED_PROMPT: &str = "Мнемоническая фраза BIP-39";
const CONFIRM_PROMPT: &str = "Повторите фразу";
const PASSWORD_PROMPT: &str = "Новый мастер-пароль";
const TIMEOUT: Duration = Duration::from_secs(15);

fn open_pty() -> (OwnedFd, OwnedFd) {
    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;

    // SAFETY: `openpty` заполняет переданные указатели валидными fd.
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    assert_eq!(rc, 0, "openpty failed: {}", std::io::Error::last_os_error());

    // SAFETY: fd только что созданы `openpty` и никем больше не закрываются.
    unsafe {
        (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave))
    }
}

fn duplicate(fd: &OwnedFd) -> File {
    // SAFETY: `dup` возвращает новый fd или -1; -1 проверяется.
    let duplicated = unsafe { libc::dup(fd.as_raw_fd()) };
    assert!(duplicated >= 0, "dup failed: {}", std::io::Error::last_os_error());
    // SAFETY: `duplicated` — свежий fd, принадлежащий этому `File`.
    unsafe { File::from_raw_fd(duplicated) }
}

/// Ждёт, пока приложение выставит termios без ECHO.
///
/// Проверка идёт по master-fd PTY: атрибуты общие для обеих сторон.
/// Так тест не зависит от гонки «напечатали prompt, но ещё не включили
/// raw mode».
fn wait_echo_off(fd: RawFd, deadline: Instant) {
    loop {
        let mut termios = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: `tcgetattr` пишет в валидный указатель при успехе.
        let rc = unsafe { libc::tcgetattr(fd, termios.as_mut_ptr()) };
        if rc == 0 {
            // SAFETY: rc == 0 означает, что структура инициализирована.
            let termios = unsafe { termios.assume_init() };
            if termios.c_lflag & libc::ECHO == 0 {
                return;
            }
        }

        assert!(
            Instant::now() < deadline,
            "terminal echo was not disabled by the recovery prompt"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

/// Убивает дочерний процесс даже при панике в тесте.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn seed_phrase_is_not_echoed_by_a_real_terminal() {
    let profile = tempfile::tempdir().expect("temp profile");
    let (master, slave) = open_pty();

    let child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_lastchance"))
            .arg("--profile-dir")
            .arg(profile.path())
            .arg("--recovery")
            .env_remove("LASTCHANCE_PASS")
            .env_remove("LASTCHANCE_PASS_FILE")
            .stdin(Stdio::from(duplicate(&slave)))
            .stdout(Stdio::from(duplicate(&slave)))
            .stderr(Stdio::from(duplicate(&slave)))
            .spawn()
            .expect("spawn lastchance"),
    );

    drop(slave);

    let mut writer = File::from(master);
    let mut reader = writer.try_clone().expect("clone pty master");
    let (chunk_tx, chunk_rx) = mpsc::channel::<Vec<u8>>();

    let reader_thread = thread::spawn(move || {
        let mut buffer = [0u8; 1024];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    if chunk_tx.send(buffer[..read].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });

    let deadline = Instant::now() + TIMEOUT;
    let mut output = Vec::new();

    let wait_for = |needle: &str, output: &mut Vec<u8>| {
        while !String::from_utf8_lossy(output).contains(needle) {
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {needle:?}; terminal output so far:\n{}",
                String::from_utf8_lossy(output)
            );
            match chunk_rx.recv_timeout(Duration::from_millis(100)) {
                Ok(chunk) => output.extend_from_slice(&chunk),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => panic!(
                    "terminal closed while waiting for {needle:?}; output:\n{}",
                    String::from_utf8_lossy(output)
                ),
            }
        }
    };

    wait_for(SEED_PROMPT, &mut output);
    wait_echo_off(writer.as_raw_fd(), deadline);

    // Enter в raw mode — это CR, а не LF.
    write!(writer, "{PHRASE}\r{PHRASE}\r").expect("write seed phrase");
    writer.flush().expect("flush seed phrase");

    // После подтверждения фразы run_recovery спрашивает новый мастер-пароль.
    wait_for(PASSWORD_PROMPT, &mut output);
    assert!(
        String::from_utf8_lossy(&output).contains(CONFIRM_PROMPT),
        "confirmation prompt was not shown:\n{}",
        String::from_utf8_lossy(&output)
    );

    drop(child);
    let _ = reader_thread.join();

    let output = String::from_utf8_lossy(&output);
    assert!(
        !output.contains("abandon"),
        "seed phrase leaked to the terminal:\n{output}"
    );
}
