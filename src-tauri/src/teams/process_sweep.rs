//! Best-effort same-uid sweep before a human-confirmed worker worktree reuse.
//! Process names are logged; command lines are intentionally never collected.

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Default)]
pub(crate) struct SweepReport {
    pub found: Vec<ProcessRecord>,
    pub killed: Vec<ProcessRecord>,
    pub remaining: Vec<ProcessRecord>,
    pub note: String,
}

#[derive(Clone, Debug)]
pub(crate) struct ProcessRecord {
    pub pid: u32,
    pub command: String,
}

impl SweepReport {
    pub fn counts(&self) -> (usize, usize, usize) {
        (self.found.len(), self.killed.len(), self.remaining.len())
    }
}

pub(crate) fn sweep(root: &Path) -> Result<SweepReport> {
    let root = root
        .canonicalize()
        .context("resolve reused worker worktree for process sweep")?;
    #[cfg(unix)]
    let protected = daemon_and_helpers()?;
    #[cfg(not(unix))]
    let protected = std::collections::HashSet::new();
    sweep_with_protected(&root, &protected)
}

fn sweep_with_protected(
    root: &Path,
    protected: &std::collections::HashSet<u32>,
) -> Result<SweepReport> {
    let root = root.canonicalize().context("resolve worker worktree for process sweep")?;
    #[cfg(target_os = "macos")]
    let mut processes = macos_processes_except(&root, protected)?;
    #[cfg(target_os = "linux")]
    let mut processes = linux_processes_except(&root, protected)?;
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let mut processes: Vec<ProcessRecord> = Vec::new();

    processes.sort_by_key(|p| p.pid);
    processes.dedup_by_key(|p| p.pid);
    let found = processes.clone();
    #[cfg(unix)]
    {
        for p in &found {
            unsafe {
                libc::kill(p.pid as i32, libc::SIGTERM);
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
        let mut remaining = matching_processes(&root, protected)?;
        for p in &remaining {
            unsafe {
                libc::kill(p.pid as i32, libc::SIGKILL);
            }
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            remaining = matching_processes(&root, protected)?;
            if remaining.is_empty() || std::time::Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let killed: Vec<_> = found
            .iter()
            .filter(|p| !remaining.iter().any(|r| r.pid == p.pid))
            .cloned()
            .collect();
        let report = SweepReport {
            found,
            killed,
            remaining,
            note: String::new(),
        };
        tracing::warn!(
            worktree=%root.display(),
            found=?report.found.iter().map(|p| (p.pid, p.command.as_str())).collect::<Vec<_>>(),
            killed=?report.killed.iter().map(|p| (p.pid, p.command.as_str())).collect::<Vec<_>>(),
            remaining=?report.remaining.iter().map(|p| (p.pid, p.command.as_str())).collect::<Vec<_>>(),
            "worker worktree process sweep completed"
        );
        return Ok(report);
    }
    #[cfg(not(unix))]
    {
        Ok(SweepReport {
            found,
            killed: Vec::new(),
            remaining: Vec::new(),
            note: "process sweep is not implemented on this platform".into(),
        })
    }
}

#[cfg(unix)]
fn daemon_and_helpers() -> Result<std::collections::HashSet<u32>> {
    let daemon = std::process::id();
    let output = std::process::Command::new("/bin/ps")
        .args(["-A", "-o", "pid=", "-o", "ppid="])
        .output()
        .context("list process parents for worker sweep")?;
    if !output.status.success() {
        bail!("process parent list failed: {}", output.status);
    }
    let mut protected = std::collections::HashSet::from([daemon]);
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let mut fields = line.split_whitespace();
        let (Some(pid), Some(ppid)) = (
            fields.next().and_then(|v| v.parse::<u32>().ok()),
            fields.next().and_then(|v| v.parse::<u32>().ok()),
        ) else {
            continue;
        };
        if ppid == daemon {
            protected.insert(pid);
        }
    }
    Ok(protected)
}

#[cfg(target_os = "macos")]
fn matching_processes(
    root: &Path,
    protected: &std::collections::HashSet<u32>,
) -> Result<Vec<ProcessRecord>> {
    macos_processes_except(root, protected)
}

#[cfg(target_os = "macos")]
fn macos_processes_except(
    root: &Path,
    protected: &std::collections::HashSet<u32>,
) -> Result<Vec<ProcessRecord>> {
    let uid = unsafe { libc::geteuid() };
    let uid_arg = uid.to_string();
    let output = std::process::Command::new("/usr/sbin/lsof")
        .args(["-nP", "-l", "-Fpcfn", "-u", &uid_arg])
        .output()
        .context("enumerate same-uid open files with lsof")?;
    // lsof returns 1 when it finds no open files. That is a complete empty result, unlike other
    // errors, which fail closed before the caller can launch a worker.
    if !output.status.success() && output.status.code() != Some(1) {
        bail!("lsof process sweep failed ({})", output.status);
    }
    let (mut pid, mut command) = (None, String::new());
    let mut matches = std::collections::BTreeMap::<u32, String>::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let Some((field, value)) = line.split_at_checked(1) else {
            continue;
        };
        match field {
            "p" => {
                pid = value.parse().ok();
                command.clear();
            }
            "c" => command = value.to_owned(),
            "n" => {
                if let Some(id) = pid.filter(|id| !protected.contains(id))
                    && path_inside(
                        Path::new(value.strip_suffix(" (deleted)").unwrap_or(value)),
                        root,
                    )
                {
                    matches.entry(id).or_insert_with(|| {
                        if command.is_empty() {
                            "unknown".into()
                        } else {
                            command.clone()
                        }
                    });
                }
            }
            _ => {}
        }
    }
    Ok(matches
        .into_iter()
        .map(|(pid, command)| ProcessRecord { pid, command })
        .collect())
}

#[cfg(target_os = "linux")]
fn matching_processes(
    root: &Path,
    protected: &std::collections::HashSet<u32>,
) -> Result<Vec<ProcessRecord>> {
    linux_processes_except(root, protected)
}

#[cfg(target_os = "linux")]
fn linux_processes_except(
    root: &Path,
    protected: &std::collections::HashSet<u32>,
) -> Result<Vec<ProcessRecord>> {
    let uid = unsafe { libc::geteuid() };
    let mut found = Vec::new();
    for entry in std::fs::read_dir("/proc").context("enumerate /proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        if protected.contains(&pid) {
            continue;
        }
        let proc = entry.path();
        let Ok(status) = std::fs::read_to_string(proc.join("status")) else {
            continue;
        };
        if status.lines().any(|line| {
            line.starts_with("State:")
                && (line.contains("zombie")
                    || line
                        .split_whitespace()
                        .nth(1)
                        .is_some_and(|s| s.starts_with('Z') || s.starts_with('X')))
        }) {
            continue;
        }
        let process_uid = status.lines().find_map(|line| {
            line.strip_prefix("Uid:")
                .and_then(|s| s.split_whitespace().next()?.parse::<u32>().ok())
        });
        if process_uid != Some(uid) {
            continue;
        }
        let command = std::fs::read_to_string(proc.join("comm"))
            .unwrap_or_else(|_| "unknown".into())
            .trim()
            .to_owned();
        let mut inside =
            std::fs::read_link(proc.join("cwd")).is_ok_and(|p| path_inside(&trim_deleted(p), root));
        if !inside && let Ok(fds) = std::fs::read_dir(proc.join("fd")) {
            inside = fds.flatten().any(|fd| {
                std::fs::read_link(fd.path()).is_ok_and(|p| path_inside(&trim_deleted(p), root))
            });
        }
        if inside {
            found.push(ProcessRecord { pid, command });
        }
    }
    Ok(found)
}

fn path_inside(candidate: &Path, root: &Path) -> bool {
    let candidate = candidate
        .canonicalize()
        .unwrap_or_else(|_| lexical_path(candidate));
    candidate.starts_with(root)
}

#[cfg(target_os = "linux")]
fn trim_deleted(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy();
    PathBuf::from(text.strip_suffix(" (deleted)").unwrap_or(&text))
}

fn lexical_path(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    fn tree() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("pb-sweep-{}", crate::db::new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn kills_same_uid_process_with_worktree_cwd() {
        let root = tree();
        let child = Command::new("/bin/sh")
            .args(["-c", "sleep 5"])
            .current_dir(&root)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let protected = std::collections::HashSet::from([std::process::id()]);
        let report = sweep_with_protected(&root, &protected).unwrap();
        assert!(
            report.found.iter().any(|p| p.pid == child.id()),
            "sweep missed planted worker cwd process: {report:?}"
        );
        assert!(
            report.killed.iter().any(|p| p.pid == child.id()),
            "sweep did not kill planted worker: {report:?}"
        );
        assert!(
            report.remaining.is_empty(),
            "sweep left processes: {report:?}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn leaves_daemon_helper_and_unrelated_process_alone() {
        let root = tree();
        let outside = tree();
        let helper = Command::new("/bin/sh")
            .args(["-c", "sleep 5"])
            .current_dir(&root)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let unrelated = Command::new("/bin/sh")
            .args(["-c", "sleep 30"])
            .current_dir(&outside)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let protected = std::collections::HashSet::from([std::process::id(), helper.id()]);
        let report = sweep_with_protected(&root, &protected).unwrap();
        assert!(
            !report.found.iter().any(|p| p.pid == helper.id()),
            "sweep selected daemon helper: {report:?}"
        );
        assert!(
            !report.found.iter().any(|p| p.pid == unrelated.id()),
            "sweep selected outside process: {report:?}"
        );
        unsafe {
            libc::kill(helper.id() as i32, libc::SIGKILL);
            libc::kill(unrelated.id() as i32, libc::SIGKILL);
        }
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(outside);
    }
}
