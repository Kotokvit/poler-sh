//! Causal Nexus IPC Bridge for poler-sh
//!
//! Перехват намерений команд (AST NOP-annihilation и Collision Protection)
//! через Event Plane Unix Domain Socket (/tmp/poler-event.sock).

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Instant;

pub fn check_causal_nexus(raw_cmd: &str) -> Option<(String, bool, i32)> {
    let t0 = Instant::now();
    let trimmed = raw_cmd.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut writes = Vec::new();
    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    let prog = parts.first().copied().unwrap_or("");

    // 1. Редиректы: `> target` или `>> target`
    if let Some(pos) = trimmed.find('>') {
        let after = trimmed[pos + 1..].trim_start_matches('>').trim();
        let target = after.split_whitespace().next().unwrap_or("");
        let clean_target = target.trim_matches(|c| c == '\'' || c == '"');
        if !clean_target.is_empty() {
            writes.push(clean_target.to_string());
        }
    }

    // 2. Команды touch, sed -i
    if prog == "touch" {
        for arg in &parts[1..] {
            if !arg.starts_with('-') {
                let clean_arg = arg.trim_matches(|c| c == '\'' || c == '"');
                if !clean_arg.is_empty() {
                    writes.push(clean_arg.to_string());
                }
            }
        }
    } else if prog == "sed" && parts.contains(&"-i") {
        if let Some(target) = parts.last() {
            if !target.starts_with('-') {
                let clean_target = target.trim_matches(|c| c == '\'' || c == '"');
                if !clean_target.is_empty() {
                    writes.push(clean_target.to_string());
                }
            }
        }
    }

    if writes.is_empty() {
        return None;
    }

    let cwd = std::env::current_dir().unwrap_or_default().to_string_lossy().to_string();
    let sock_path = "/tmp/poler-event.sock";
    let mut stream = UnixStream::connect(sock_path).ok()?;
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(25)));
    let _ = stream.set_write_timeout(Some(std::time::Duration::from_millis(25)));

    let mut reader = BufReader::new(stream.try_clone().ok()?);

    let mut ack_line = String::new();
    let _ = reader.read_line(&mut ack_line);

    let intent = serde_json::json!({
        "type": "cmd_intent",
        "id": 1,
        "cmd": raw_cmd,
        "argv": parts.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        "writes": writes,
        "cwd": cwd
    });
    let intent_str = intent.to_string() + "\n";
    let _ = stream.write_all(intent_str.as_bytes());
    let _ = stream.flush();

    let mut resp_line = String::new();
    if reader.read_line(&mut resp_line).is_ok() && !resp_line.trim().is_empty() {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&resp_line) {
            match val.get("type").and_then(|t| t.as_str()) {
                Some("noop_commit") => {
                    let reason = val.get("reason").and_then(|r| r.as_str()).unwrap_or("Identical state");
                    let us = t0.elapsed().as_micros();
                    return Some((
                        format!(
                            "⚡ [Causal Nexus NOP] {}\n✓ Системный вызов аннигилирован (код: 0, время: {} мкс)",
                            reason, us
                        ),
                        true,
                        0,
                    ));
                }
                Some("block") => {
                    let reason = val.get("reason").and_then(|r| r.as_str()).unwrap_or("Запись заблокирована");
                    return Some((
                        format!("🚫 [Causal Nexus Block] {}", reason),
                        false,
                        1,
                    ));
                }
                _ => {}
            }
        }
    }

    None
}
