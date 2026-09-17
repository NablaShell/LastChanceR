// src/file_dialog.rs
use anyhow::{anyhow, Result};
use std::process::Command;

pub struct FileDialog;

impl FileDialog {
    pub fn open_file_dialog(title: &str) -> Result<Option<String>> {
        // For now, we'll use a simple approach with zenity on Linux
        // In the future, this will be replaced with GPUI's native dialogs
        #[cfg(target_os = "linux")]
        {
            let output = Command::new("zenity")
                .arg("--file-selection")
                .arg("--title")
                .arg(title)
                .output()
                .map_err(|e| anyhow!("failed to open file dialog: {}", e))?;
            
            if output.status.success() {
                let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if path.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(path))
                }
            } else {
                Ok(None)
            }
        }
        
        #[cfg(target_os = "macos")]
        {
            // Use osascript for macOS
            let script = format!(
                "tell application \"System Events\" to choose file with prompt \"{}\"",
                title
            );
            
            let output = Command::new("osascript")
                .arg("-e")
                .arg(script)
                .output()
                .map_err(|e| anyhow!("failed to open file dialog: {}", e))?;
            
            if output.status.success() {
                let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if path.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(path))
                }
            } else {
                Ok(None)
            }
        }
        
        #[cfg(target_os = "windows")]
        {
            // For Windows, we'll need to implement this later
            Ok(None)
        }
    }
    
    pub fn save_file_dialog(title: &str, default_filename: &str) -> Result<Option<String>> {
        #[cfg(target_os = "linux")]
        {
            let output = Command::new("zenity")
                .arg("--file-selection")
                .arg("--save")
                .arg("--title")
                .arg(title)
                .arg("--filename")
                .arg(default_filename)
                .output()
                .map_err(|e| anyhow!("failed to open save dialog: {}", e))?;
            
            if output.status.success() {
                let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if path.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(path))
                }
            } else {
                Ok(None)
            }
        }
        
        #[cfg(target_os = "macos")]
        {
            let script = format!(
                "tell application \"System Events\" to choose file name with prompt \"{}\" default name \"{}\"",
                title, default_filename
            );
            
            let output = Command::new("osascript")
                .arg("-e")
                .arg(script)
                .output()
                .map_err(|e| anyhow!("failed to open save dialog: {}", e))?;
            
            if output.status.success() {
                let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if path.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(path))
                }
            } else {
                Ok(None)
            }
        }
        
        #[cfg(target_os = "windows")]
        {
            Ok(None)
        }
    }
}
