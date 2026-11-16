//! Same-uid process scan before a human-confirmed worker worktree reuse.
//! Logs contain process IDs and names, never worktree paths or command lines.

use anyhow::{Context, Result, bail};
use std::{
    collections::HashSet,
    io,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
#[cfg(test)]
use std::{collections::HashMap, sync::Mutex};

const TERM_GRACE: Duration = Duration::from_millis(250);
const KILL_WAIT: Duration = Duration::from_secs(2);
const SIGTERM_SIGNAL: i32 = 15;
const SIGKILL_SIGNAL: i32 = 9;

#[derive(Clone, Debug, Default)]
pub(crate) struct SweepReport {
    pub found: Vec<ProcessRecord>,
    pub killed: Vec<ProcessRecord>,
    pub remaining: Vec<ProcessRecord>,
    pub unknown: usize,
    pub complete: bool,
    pub wall_ms: u128,
    pub note: String,
}

impl SweepReport {
    pub fn counts(&self) -> (usize, usize, usize) {
        (self.found.len(), self.killed.len(), self.remaining.len())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProcessRecord {
    pub pid: u32,
    pub uid: u32,
    pub start_sec: u64,
    pub start_subsec: u64,
    pub parent: u32,
    pub pgid: u32,
    pub command: String,
    pub paths: Vec<PathBuf>,
    pub paths_complete: bool,
}

impl ProcessRecord {
    fn same_identity(&self, other: &Self) -> bool {
        self.pid == other.pid
            && self.uid == other.uid
            && self.start_sec == other.start_sec
            && self.start_subsec == other.start_subsec
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ScanSnapshot {
    pub processes: Vec<ProcessRecord>,
    /// Candidates whose cwd/open-file paths could not be resolved and checked.
    pub unknown: usize,
}

pub(crate) trait ProcessSource: Send + Sync {
    fn scan(&self) -> Result<ScanSnapshot>;
    fn inspect(&self, pid: u32) -> Result<Option<ProcessRecord>>;
    fn signal(&self, pid: u32, signal: i32) -> io::Result<()>;
}

#[derive(Default)]
pub(crate) struct SystemProcessSource;

pub(crate) fn sweep(root: &Path, daemon_pid: u32, worker_pgid: Option<u32>) -> Result<SweepReport> {
    sweep_with(root, daemon_pid, worker_pgid, &SystemProcessSource)
}

pub(crate) fn sweep_with(
    root: &Path,
    daemon_pid: u32,
    worker_pgid: Option<u32>,
    source: &dyn ProcessSource,
) -> Result<SweepReport> {
    let began = Instant::now();
    let root = root.canonicalize().context("resolve reused worker worktree for process sweep")?;
    let first = source.scan().context("scan same-uid processes before worker reuse")?;
    let protected = protected_descendants(&first.processes, daemon_pid, worker_pgid);
    let mut unknown = first.unknown;
    let mut found: Vec<_> = first
        .processes
        .into_iter()
        .filter(|p| !protected.contains(&p.pid))
        .filter_map(|p| match inside_status(&p, &root) {
            PathStatus::Inside => Some(p),
            PathStatus::Outside => None,
            PathStatus::Unknown => {
                unknown += 1;
                None
            }
        })
        .collect();
    found.sort_by_key(|p| p.pid);
    found.dedup_by_key(|p| p.pid);

    let mut unresolved = 0usize;
    for process in &found {
        let _ = revalidate_and_signal(source, &root, process, SIGTERM_SIGNAL, &mut unresolved)?;
    }
    unknown += unresolved;
    if !found.is_empty() { std::thread::sleep(TERM_GRACE); }

    let before_kill = source.scan().context("rescan before killing worktree processes")?;
    unknown += before_kill.unknown;
    let still_matching = match_found(&found, &before_kill.processes, &root, &mut unknown);
    for process in &still_matching {
        let _ = revalidate_and_signal(source, &root, process, SIGKILL_SIGNAL, &mut unknown)?;
    }

    let deadline = Instant::now() + KILL_WAIT;
    let (remaining, final_unknown) = loop {
        let snapshot = source.scan().context("verify worker process sweep completion")?;
        let mut scan_unknown = snapshot.unknown;
        let remaining = match_found(&found, &snapshot.processes, &root, &mut scan_unknown);
        if remaining.is_empty() || Instant::now() >= deadline {
            break (remaining, scan_unknown);
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    unknown += final_unknown;
    let killed: Vec<_> = found
        .iter()
        .filter(|p| !remaining.iter().any(|r| p.same_identity(r)))
        .cloned()
        .collect();
    let complete = unknown == 0 && remaining.is_empty();
    let note = if complete {
        "same-uid process scan complete".to_owned()
    } else {
        format!("sweep incomplete: {unknown} process/path checks unknown; {} processes remain", remaining.len())
    };
    let report = SweepReport {
        found,
        killed,
        remaining,
        unknown,
        complete,
        wall_ms: began.elapsed().as_millis(),
        note,
    };
    tracing::warn!(
        found=?report.found.iter().map(|p| (p.pid, p.command.as_str())).collect::<Vec<_>>(),
        killed=?report.killed.iter().map(|p| (p.pid, p.command.as_str())).collect::<Vec<_>>(),
        remaining=?report.remaining.iter().map(|p| (p.pid, p.command.as_str())).collect::<Vec<_>>(),
        unknown=report.unknown,
        complete=report.complete,
        wall_ms=report.wall_ms,
        "worker worktree process sweep completed"
    );
    Ok(report)
}

fn revalidate_and_signal(
    source: &dyn ProcessSource,
    root: &Path,
    expected: &ProcessRecord,
    signal: i32,
    unknown: &mut usize,
) -> Result<bool> {
    let Some(current) = source.inspect(expected.pid).context("revalidate process before signal")? else {
        return Ok(false);
    };
    if !expected.same_identity(&current) || current.uid != current_uid() {
        return Ok(false);
    }
    match inside_status(&current, root) {
        PathStatus::Inside => {}
        PathStatus::Outside => return Ok(false),
        PathStatus::Unknown => {
            *unknown += 1;
            return Ok(false);
        }
    }
    match source.signal(current.pid, signal) {
        Ok(()) => Ok(true),
        Err(e) if e.raw_os_error() == Some(libc::ESRCH) => Ok(false),
        Err(e) if e.raw_os_error() == Some(libc::EPERM) => {
            *unknown += 1;
            Ok(false)
        }
        Err(e) => Err(e).context("signal same-uid worktree process"),
    }
}

fn match_found(
    found: &[ProcessRecord],
    current: &[ProcessRecord],
    root: &Path,
    unknown: &mut usize,
) -> Vec<ProcessRecord> {
    found.iter().filter_map(|expected| {
        let Some(now) = current.iter().find(|p| p.pid == expected.pid) else { return None };
        if !expected.same_identity(now) || now.uid != current_uid() {
            return None;
        }
        match inside_status(now, root) {
            PathStatus::Inside => Some(now.clone()),
            PathStatus::Outside => None,
            PathStatus::Unknown => {
                *unknown += 1;
                None
            }
        }
    }).collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PathStatus { Inside, Outside, Unknown }

fn inside_status(process: &ProcessRecord, root: &Path) -> PathStatus {
    let mut unknown = false;
    for path in &process.paths {
        match path.canonicalize() {
            Ok(real) if real.starts_with(root) => return PathStatus::Inside,
            Ok(_) => {}
            Err(_) if unresolved_candidate_inside(path, root) => unknown = true,
            Err(_) => {}
        }
    }
    if unknown || !process.paths_complete { PathStatus::Unknown } else { PathStatus::Outside }
}

fn unresolved_candidate_inside(path: &Path, root: &Path) -> bool {
    let mut cursor = path;
    let mut suffix = Vec::new();
    loop {
        if let Ok(real_parent) = cursor.canonicalize() {
            let mut resolved = real_parent;
            for part in suffix.iter().rev() { resolved.push(part); }
            return resolved.starts_with(root);
        }
        let Some(name) = cursor.file_name() else { return false };
        suffix.push(name.to_os_string());
        let Some(parent) = cursor.parent() else { return false };
        cursor = parent;
    }
}

fn current_uid() -> u32 {
    #[cfg(unix)]
    { unsafe { libc::geteuid() } }
    #[cfg(not(unix))]
    { u32::MAX }
}

#[cfg(unix)]
fn process_probe_is_unknown(result: i32, error: Option<i32>) -> bool {
    result == 0 || error != Some(libc::ESRCH)
}

#[cfg(unix)]
fn pid_probe_is_unknown(pid: i32) -> bool {
    let result = unsafe { libc::kill(pid, 0) };
    let error = (result != 0).then(|| io::Error::last_os_error().raw_os_error()).flatten();
    process_probe_is_unknown(result, error)
}

pub(crate) fn protected_descendants(
    processes: &[ProcessRecord],
    daemon_pid: u32,
    worker_pgid: Option<u32>,
) -> HashSet<u32> {
    let mut daemon_tree = HashSet::from([daemon_pid]);
    let mut worker_tree = HashSet::new();
    if let Some(group) = worker_pgid.filter(|g| *g > 1) {
        worker_tree.extend(processes.iter().filter(|p| p.pgid == group).map(|p| p.pid));
    }
    let mut changed = true;
    while changed {
        changed = false;
        for p in processes {
            if daemon_tree.contains(&p.parent) && daemon_tree.insert(p.pid) { changed = true; }
            if worker_tree.contains(&p.parent) && worker_tree.insert(p.pid) { changed = true; }
        }
    }
    daemon_tree.retain(|pid| !worker_tree.contains(pid));
    // Keep the daemon itself protected even if the optional group value is malformed.
    daemon_tree.insert(daemon_pid);
    daemon_tree
}

impl ProcessSource for SystemProcessSource {
    fn scan(&self) -> Result<ScanSnapshot> {
        #[cfg(target_os = "macos")]
        { macos_scan() }
        #[cfg(target_os = "linux")]
        { linux_scan() }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        { bail!("process sweep is unsupported on this platform") }
    }

    fn inspect(&self, pid: u32) -> Result<Option<ProcessRecord>> {
        #[cfg(target_os = "macos")]
        { macos_process(pid) }
        #[cfg(target_os = "linux")]
        { linux_process(pid) }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        { let _ = pid; bail!("process sweep is unsupported on this platform") }
    }

    fn signal(&self, pid: u32, signal: i32) -> io::Result<()> {
        #[cfg(unix)]
        {
        let result = unsafe { libc::kill(pid as i32, signal) };
        if result == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
        }
        #[cfg(not(unix))]
        { let _ = (pid, signal); Err(io::Error::new(io::ErrorKind::Unsupported, "process sweep is unsupported")) }
    }
}

#[cfg(target_os = "macos")]
fn macos_scan() -> Result<ScanSnapshot> {
    let mut pids = vec![0i32; 65_536];
    let uid = unsafe { libc::geteuid() };
    let bytes = unsafe { libc::proc_listpids(4, uid, pids.as_mut_ptr().cast(), (pids.len() * std::mem::size_of::<i32>()) as i32) };
    if bytes < 0 || bytes as usize >= pids.len() * std::mem::size_of::<i32>() {
        bail!("libproc process list failed or was truncated");
    }
    pids.truncate(bytes as usize / std::mem::size_of::<i32>());
    let mut result = ScanSnapshot::default();
    for pid in pids.into_iter().filter(|p| *p > 0) {
        match macos_process(pid as u32)? {
            Some(p) if p.uid == uid => result.processes.push(p),
            Some(_) => {}
            None => {
                if pid_probe_is_unknown(pid) { result.unknown += 1; }
            }
        }
    }
    Ok(result)
}

#[cfg(target_os = "macos")]
fn macos_process(pid: u32) -> Result<Option<ProcessRecord>> {
    let mut info = unsafe { std::mem::zeroed::<libc::proc_bsdinfo>() };
    let size = std::mem::size_of_val(&info) as i32;
    let read = unsafe { libc::proc_pidinfo(pid as i32, libc::PROC_PIDTBSDINFO, 0, (&mut info as *mut libc::proc_bsdinfo).cast(), size) };
    if read != size { return Ok(None); }
    let mut paths = Vec::new();
    let mut paths_complete = true;
    let mut vnode = unsafe { std::mem::zeroed::<libc::proc_vnodepathinfo>() };
    let vnode_size = std::mem::size_of_val(&vnode) as i32;
    let got_vnode = unsafe { libc::proc_pidinfo(pid as i32, libc::PROC_PIDVNODEPATHINFO, 0, (&mut vnode as *mut libc::proc_vnodepathinfo).cast(), vnode_size) };
    if got_vnode == vnode_size {
        let cwd = flatten_path(&vnode.pvi_cdir.vip_path);
        if !cwd.as_os_str().is_empty() { paths.push(cwd); }
    } else {
        paths_complete = false;
    }
    let fd_size = libc::PROC_PIDLISTFD_SIZE as usize;
    let mut fds = vec![unsafe { std::mem::zeroed::<libc::proc_fdinfo>() }; info.pbi_nfiles as usize + 16];
    let fds_capacity = fds.len() * fd_size;
    let got_fds = unsafe { libc::proc_pidinfo(pid as i32, libc::PROC_PIDLISTFDS, 0, fds.as_mut_ptr().cast(), fds_capacity as i32) };
    if got_fds > 0 {
        if got_fds as usize >= fds_capacity { paths_complete = false; }
        fds.truncate((got_fds as usize / fd_size).min(fds.len()));
        for fd in fds.into_iter().filter(|f| f.proc_fdtype == libc::PROX_FDTYPE_VNODE as u32) {
            let mut path_info = unsafe { std::mem::zeroed::<VnodeFdInfoWithPath>() };
            let got = unsafe { libc::proc_pidfdinfo(pid as i32, fd.proc_fd, 2, (&mut path_info as *mut VnodeFdInfoWithPath).cast(), std::mem::size_of_val(&path_info) as i32) };
            if got == std::mem::size_of_val(&path_info) as i32 {
                let path = flatten_path(&path_info.path.vip_path);
                if !path.as_os_str().is_empty() { paths.push(path); }
            } else {
                paths_complete = false;
            }
        }
    } else if info.pbi_nfiles > 0 {
        paths_complete = false;
    }
    let command_bytes: Vec<u8> = info.pbi_comm.iter().take_while(|c| **c != 0).map(|c| *c as u8).collect();
    let command = String::from_utf8_lossy(&command_bytes).into_owned();
    Ok(Some(ProcessRecord {
        pid,
        uid: info.pbi_uid,
        start_sec: info.pbi_start_tvsec,
        start_subsec: info.pbi_start_tvusec,
        parent: info.pbi_ppid,
        pgid: info.pbi_pgid,
        command,
        paths,
        paths_complete,
    }))
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct VnodeFdInfoWithPath { fileinfo: [u64; 3], path: libc::vnode_info_path }

#[cfg(target_os = "macos")]
fn flatten_path(chars: &[[libc::c_char; 32]; 32]) -> PathBuf {
    let bytes: Vec<u8> = chars.iter().flat_map(|x| x.iter()).take_while(|c| **c != 0).map(|c| *c as u8).collect();
    PathBuf::from(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(target_os = "linux")]
fn linux_scan() -> Result<ScanSnapshot> {
    let mut result = ScanSnapshot::default();
    for entry in std::fs::read_dir("/proc").context("enumerate /proc")? {
        let entry = entry?;
        let Some(pid) = entry.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
        match linux_process(pid)? {
            Some(p) if p.uid == unsafe { libc::geteuid() } => result.processes.push(p),
            Some(_) => {}
            None => {
                if pid_probe_is_unknown(pid as i32) { result.unknown += 1; }
            }
        }
    }
    Ok(result)
}

#[cfg(target_os = "linux")]
fn linux_process(pid: u32) -> Result<Option<ProcessRecord>> {
    let proc = PathBuf::from(format!("/proc/{pid}"));
    let status = match std::fs::read_to_string(proc.join("status")) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).context("read process uid"),
    };
    let uid = status.lines().find_map(|line| line.strip_prefix("Uid:")?.split_whitespace().next()?.parse::<u32>().ok());
    let Some(uid) = uid else { return Ok(None) };
    let stat = std::fs::read_to_string(proc.join("stat")).context("read process identity")?;
    let close = stat.rfind(')').ok_or_else(|| anyhow::anyhow!("invalid /proc process stat"))?;
    let fields: Vec<_> = stat[close + 1..].split_whitespace().collect();
    if fields.len() < 20 { bail!("incomplete /proc process stat"); }
    let parent = fields[1].parse::<u32>().unwrap_or(0);
    let pgid = fields[2].parse::<u32>().unwrap_or(0);
    let start = fields[19].parse::<u64>().context("parse process start time")?;
    let command_start = stat.find('(').map(|i| i + 1).unwrap_or(0);
    let command_end = stat.rfind(')').unwrap_or(command_start);
    let command = stat[command_start..command_end].to_owned();
    let mut paths = Vec::new();
    match std::fs::read_link(proc.join("cwd")) {
        Ok(p) => paths.push(trim_deleted(p)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).context("read process cwd"),
    }
    let fds = std::fs::read_dir(proc.join("fd")).context("list process descriptors")?;
    for fd in fds {
        let fd = fd?;
        match std::fs::read_link(fd.path()) {
            Ok(p) => paths.push(trim_deleted(p)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).context("read open file path"),
        }
    }
    Ok(Some(ProcessRecord { pid, uid, start_sec: start, start_subsec: 0, parent, pgid, command, paths, paths_complete: true }))
}

#[cfg(target_os = "linux")]
fn trim_deleted(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy();
    PathBuf::from(text.strip_suffix(" (deleted)").unwrap_or(&text))
}

#[cfg(test)]
pub(crate) struct TestProcessSource {
    pub snapshot: Mutex<ScanSnapshot>,
    pub current: Mutex<HashMap<u32, ProcessRecord>>,
    pub signals: Mutex<Vec<(u32, i32)>>,
    pub fail_scan: bool,
    pub fail_first_scan: bool,
    pub scan_count: std::sync::atomic::AtomicUsize,
}

#[cfg(test)]
impl TestProcessSource {
    pub fn empty() -> Self {
        Self { snapshot: Mutex::new(ScanSnapshot::default()), current: Mutex::new(HashMap::new()), signals: Mutex::new(Vec::new()), fail_scan: false, fail_first_scan: false, scan_count: std::sync::atomic::AtomicUsize::new(0) }
    }
}

#[cfg(test)]
impl ProcessSource for TestProcessSource {
    fn scan(&self) -> Result<ScanSnapshot> {
        self.scan_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let scan_number = self.scan_count.load(std::sync::atomic::Ordering::SeqCst);
        if self.fail_scan || (self.fail_first_scan && scan_number == 1) { bail!("injected scan error"); }
        Ok(self.snapshot.lock().unwrap().clone())
    }
    fn inspect(&self, pid: u32) -> Result<Option<ProcessRecord>> { Ok(self.current.lock().unwrap().get(&pid).cloned()) }
    fn signal(&self, pid: u32, signal: i32) -> io::Result<()> { self.signals.lock().unwrap().push((pid, signal)); Ok(()) }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    fn tree() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("pb-sweep-{}", crate::db::new_id()));
        std::fs::create_dir_all(&dir).unwrap(); dir
    }
    fn record(pid: u32, parent: u32, pgid: u32, path: PathBuf) -> ProcessRecord {
        ProcessRecord { pid, uid: unsafe { libc::geteuid() }, start_sec: 10, start_subsec: 2, parent, pgid, command: "fixture".into(), paths: vec![path], paths_complete: true }
    }
    fn fake(record: ProcessRecord) -> TestProcessSource {
        let mut current = HashMap::new(); current.insert(record.pid, record.clone());
        TestProcessSource { snapshot: Mutex::new(ScanSnapshot { processes: vec![record], unknown: 0 }), current: Mutex::new(current), signals: Mutex::new(Vec::new()), fail_scan: false, fail_first_scan: false, scan_count: std::sync::atomic::AtomicUsize::new(0) }
    }

    #[test]
    fn injected_scan_error_fails_closed() {
        let root = tree();
        let source = TestProcessSource { snapshot: Mutex::new(ScanSnapshot::default()), current: Mutex::new(HashMap::new()), signals: Mutex::new(Vec::new()), fail_scan: false, fail_first_scan: true, scan_count: std::sync::atomic::AtomicUsize::new(0) };
        assert!(sweep_with(&root, u32::MAX, None, &source).is_err());
        assert!(source.signals.lock().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn denied_process_probe_is_unknown_but_esrch_is_not() {
        assert!(process_probe_is_unknown(0, None));
        assert!(process_probe_is_unknown(-1, Some(libc::EPERM)));
        assert!(!process_probe_is_unknown(-1, Some(libc::ESRCH)));
    }

    #[test]
    fn changed_pid_identity_is_never_signalled() {
        let root = tree();
        let canonical_root = root.canonicalize().unwrap();
        let initial = record(8123, 1, 8123, canonical_root.clone());
        let source = fake(initial.clone());
        let mut replacement = initial.clone(); replacement.start_sec += 1;
        source.current.lock().unwrap().insert(8123, replacement);
        let mut unknown = 0;
        assert!(!revalidate_and_signal(&source, &canonical_root, &initial, SIGTERM_SIGNAL, &mut unknown).unwrap());
        assert!(source.signals.lock().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn unresolved_candidate_path_is_unknown_and_not_signalled() {
        let root = tree();
        let missing = root.join("gone");
        let record = record(8124, 1, 8124, missing);
        let root = root.canonicalize().unwrap();
        assert_eq!(inside_status(&record, &root), PathStatus::Unknown);
        let source = fake(record.clone());
        let mut unknown = 0;
        assert!(!revalidate_and_signal(&source, &root, &record, SIGTERM_SIGNAL, &mut unknown).unwrap());
        assert_eq!(unknown, 1);
        assert!(source.signals.lock().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn unresolved_candidate_makes_the_sweep_confirmation_incomplete() {
        let root = tree();
        let record = record(8125, 1, 8125, root.join("gone"));
        let source = fake(record);
        let report = sweep_with(&root, u32::MAX, None, &source).unwrap();
        assert!(!report.complete);
        assert_eq!(report.unknown, 1);
        assert!(report.note.contains("incomplete"));
        assert!(source.signals.lock().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn daemon_tree_is_protected_except_the_stopped_worker_group() {
        let path = PathBuf::from("/tmp");
        let records = vec![record(10, 1, 10, path.clone()), record(11, 10, 11, path.clone()), record(12, 11, 12, path.clone()), record(13, 10, 13, path)];
        let protected = protected_descendants(&records, 10, Some(11));
        assert!(protected.contains(&10));
        assert!(protected.contains(&13));
        assert!(!protected.contains(&11));
        assert!(!protected.contains(&12));
    }

    #[test]
    fn kills_same_uid_process_with_worktree_cwd() {
        use std::os::unix::process::CommandExt;
        let root = tree();
        let child = Command::new("/bin/sh").args(["-c", "sleep 5"]).current_dir(&root).process_group(0).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        let report = sweep(&root, std::process::id(), Some(child.id())).unwrap();
        eprintln!("process sweep duration: {} ms", report.wall_ms);
        assert!(report.found.iter().any(|p| p.pid == child.id()), "sweep missed planted worker cwd process: {report:?}");
        assert!(report.killed.iter().any(|p| p.pid == child.id()), "sweep did not kill planted worker: {report:?}");
        assert!(report.remaining.is_empty(), "sweep left processes: {report:?}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn leaves_daemon_helper_and_unrelated_process_alone() {
        let root = tree(); let outside = tree();
        let helper = Command::new("/bin/sh").args(["-c", "sleep 5"]).current_dir(&root).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        let unrelated = Command::new("/bin/sh").args(["-c", "sleep 30"]).current_dir(&outside).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        let protected = HashSet::from([std::process::id(), helper.id()]);
        let report = sweep_with_protected_for_test(&root, &protected).unwrap();
        assert!(!report.found.iter().any(|p| p.pid == helper.id()), "sweep selected daemon helper: {report:?}");
        assert!(!report.found.iter().any(|p| p.pid == unrelated.id()), "sweep selected outside process: {report:?}");
        unsafe { libc::kill(helper.id() as i32, libc::SIGKILL); libc::kill(unrelated.id() as i32, libc::SIGKILL); }
        let _ = std::fs::remove_dir_all(root); let _ = std::fs::remove_dir_all(outside);
    }
}

#[cfg(test)]
fn sweep_with_protected_for_test(root: &Path, protected: &HashSet<u32>) -> Result<SweepReport> {
    let source = SystemProcessSource;
    let start = Instant::now();
    let root = root.canonicalize()?;
    let snapshot = source.scan()?;
    let candidates: Vec<_> = snapshot.processes.into_iter().filter(|p| !protected.contains(&p.pid)).filter(|p| inside_status(p, &root) == PathStatus::Inside).collect();
    let mut found = candidates.clone();
    found.sort_by_key(|p| p.pid);
    for p in &found { let mut unknown = 0; let _ = revalidate_and_signal(&source, &root, p, SIGTERM_SIGNAL, &mut unknown)?; }
    std::thread::sleep(TERM_GRACE);
    for p in &found { let mut unknown = 0; let _ = revalidate_and_signal(&source, &root, p, SIGKILL_SIGNAL, &mut unknown)?; }
    let remaining = Vec::new();
    Ok(SweepReport { found: found.clone(), killed: found, remaining, unknown: snapshot.unknown, complete: snapshot.unknown == 0, wall_ms: start.elapsed().as_millis(), note: String::new() })
}
