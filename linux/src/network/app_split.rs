//! Per-application socket marking for Linux split tunneling.
//!
//! A small cgroup/sock_create eBPF program applies a routing mark to sockets
//! created by selected processes. The daemon keeps a UID-and-process-name map
//! in sync with `/proc`, including descendants of matching app launchers.

#![allow(unsafe_code)]

use anyhow::{bail, Context, Result};
use shared::split_tunnel::SplitTunnelApp;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;
use tracing::{debug, info, warn};

mod process;

use process::{scan_processes, selected_processes};

pub(super) const SOCKET_MARK: u32 = 0x4d41;
const PROC_SCAN_INTERVAL: Duration = Duration::from_millis(50);
const BPF_MAP_CREATE: u32 = 0;
const BPF_MAP_UPDATE_ELEM: u32 = 2;
const BPF_MAP_DELETE_ELEM: u32 = 3;
const BPF_PROG_LOAD: u32 = 5;
const BPF_LINK_CREATE: u32 = 28;
const BPF_MAP_TYPE_HASH: u32 = 1;
const BPF_PROG_TYPE_CGROUP_SOCK: u32 = 9;
const BPF_CGROUP_INET_SOCK_CREATE: u32 = 2;
const BPF_ANY: u64 = 0;
const BPF_PSEUDO_MAP_FD: u8 = 1;
const BPF_FUNC_MAP_LOOKUP_ELEM: i32 = 1;
const BPF_FUNC_GET_CURRENT_UID_GID: i32 = 15;
const BPF_FUNC_GET_CURRENT_COMM: i32 = 16;
const TASK_COMM_LEN: usize = 16;

pub(super) struct AppSplitTunnel {
    stop: Arc<AtomicBool>,
    worker: Mutex<Option<JoinHandle<()>>>,
    link: Mutex<Option<OwnedFd>>,
    _program: OwnedFd,
    _app_map: Arc<BpfMap>,
}

impl AppSplitTunnel {
    pub(super) fn start(uid: u32, apps: &[SplitTunnelApp]) -> Result<Self> {
        if apps.is_empty() {
            bail!("Application split tunneling requires at least one selected application");
        }
        let app_map = Arc::new(BpfMap::create()?);
        let signatures = apps.iter().map(|app| app.exec.clone()).collect::<Vec<_>>();
        let seeds = seed_keys(uid, &signatures);
        for key in &seeds {
            app_map.insert(key)?;
        }
        let program = load_socket_marker(app_map.fd())?;
        let cgroup = File::open("/sys/fs/cgroup")
            .context("Linux application split tunneling requires a mounted cgroup filesystem")?;
        let link = create_cgroup_link(program.as_raw_fd(), cgroup.as_raw_fd())?;

        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let worker_map = app_map.clone();
        let worker = std::thread::Builder::new()
            .name("mavi-app-split".to_string())
            .spawn(move || monitor_processes(uid, signatures, seeds, worker_map, worker_stop))
            .context("Failed to start the application split-tunnel monitor")?;

        info!(
            uid,
            applications = apps.len(),
            "Linux application split tunneling enabled"
        );
        Ok(Self {
            stop,
            worker: Mutex::new(Some(worker)),
            link: Mutex::new(Some(link)),
            _program: program,
            _app_map: app_map,
        })
    }

    pub(super) fn stop(&self) {
        self.stop.store(true, Ordering::Release);
        if let Ok(mut worker) = self.worker.lock() {
            if let Some(worker) = worker.take() {
                if worker.join().is_err() {
                    warn!("Application split-tunnel monitor panicked during shutdown");
                }
            }
        }
        // Closing this BPF link detaches only Mavi's program. Taking it from
        // the option makes repeated cleanup calls harmless.
        if let Ok(mut link) = self.link.lock() {
            link.take();
        }
    }
}

impl Drop for AppSplitTunnel {
    fn drop(&mut self) {
        self.stop();
    }
}

fn monitor_processes(
    uid: u32,
    signatures: Vec<Vec<String>>,
    seeds: HashSet<AppKey>,
    app_map: Arc<BpfMap>,
    stop: Arc<AtomicBool>,
) {
    let mut marked = HashMap::<u32, (u64, AppKey)>::new();
    let mut references = seeds
        .into_iter()
        .map(|key| (key, 1usize))
        .collect::<HashMap<_, _>>();
    while !stop.load(Ordering::Acquire) {
        match scan_processes(uid) {
            Ok(processes) => sync_process_map(
                &processes,
                &signatures,
                &app_map,
                &mut marked,
                &mut references,
            ),
            Err(error) => warn!(%error, "Could not scan processes for split tunneling"),
        }
        std::thread::sleep(PROC_SCAN_INTERVAL);
    }
}

fn sync_process_map(
    processes: &[process::ProcessInfo],
    signatures: &[Vec<String>],
    app_map: &BpfMap,
    marked: &mut HashMap<u32, (u64, AppKey)>,
    references: &mut HashMap<AppKey, usize>,
) {
    let live = processes
        .iter()
        .map(|process| (process.pid, process.start_time))
        .collect::<HashMap<_, _>>();
    for (pid, (start_time, key)) in marked.clone() {
        if live.get(&pid) != Some(&start_time) {
            remove_reference(key, app_map, references);
            marked.remove(&pid);
        }
    }

    let selected = selected_processes(processes, signatures);
    for process in processes {
        if selected.contains(&process.pid)
            && marked.get(&process.pid).map(|entry| entry.0) != Some(process.start_time)
        {
            let key = AppKey::new(process.uid, &process.comm);
            match add_reference(key, app_map, references) {
                Ok(()) => {
                    marked.insert(process.pid, (process.start_time, key));
                    debug!(pid = process.pid, "Marked split-tunnel application process");
                }
                Err(error) => warn!(pid = process.pid, %error, "Failed to update BPF app map"),
            }
        }
    }
}

fn add_reference(key: AppKey, map: &BpfMap, references: &mut HashMap<AppKey, usize>) -> Result<()> {
    let count = references.entry(key).or_default();
    if *count == 0 {
        map.insert(&key)?;
    }
    *count += 1;
    Ok(())
}

fn remove_reference(key: AppKey, map: &BpfMap, references: &mut HashMap<AppKey, usize>) {
    let Some(count) = references.get_mut(&key) else {
        return;
    };
    *count -= 1;
    if *count == 0 {
        let _ = map.delete(&key);
        references.remove(&key);
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct AppKey([u8; 4 + TASK_COMM_LEN]);

impl AppKey {
    fn new(uid: u32, comm: &[u8]) -> Self {
        let mut key = [0; 4 + TASK_COMM_LEN];
        key[..4].copy_from_slice(&uid.to_ne_bytes());
        let length = comm.len().min(TASK_COMM_LEN - 1);
        key[4..4 + length].copy_from_slice(&comm[..length]);
        Self(key)
    }
}

fn seed_keys(uid: u32, signatures: &[Vec<String>]) -> HashSet<AppKey> {
    signatures
        .iter()
        .flat_map(|signature| {
            let executable = signature.first().and_then(|value| {
                std::path::Path::new(value)
                    .file_name()
                    .map(|name| name.as_encoded_bytes())
            });
            let wrapped = signature
                .iter()
                .find_map(|value| value.strip_prefix("--command="))
                .map(str::as_bytes);
            executable.into_iter().chain(wrapped)
        })
        .filter(|name| !name.is_empty())
        .map(|name| AppKey::new(uid, name))
        .collect()
}

struct BpfMap(OwnedFd);

impl BpfMap {
    fn create() -> Result<Self> {
        let mut attr = BpfAttr::default();
        attr.set_u32(0, BPF_MAP_TYPE_HASH);
        attr.set_u32(4, size_of::<AppKey>() as u32);
        attr.set_u32(8, size_of::<u32>() as u32);
        attr.set_u32(12, 65_536);
        let fd = bpf_fd(BPF_MAP_CREATE, &attr).context("Failed to create BPF app map")?;
        Ok(Self(fd))
    }

    fn fd(&self) -> i32 {
        self.0.as_raw_fd()
    }

    fn insert(&self, key: &AppKey) -> Result<()> {
        let value = 1u32;
        let mut attr = BpfAttr::default();
        attr.set_u32(0, self.fd() as u32);
        attr.set_u64(8, key.0.as_ptr().addr() as u64);
        attr.set_u64(16, (&raw const value).addr() as u64);
        attr.set_u64(24, BPF_ANY);
        bpf_call(BPF_MAP_UPDATE_ELEM, &attr)?;
        Ok(())
    }

    fn delete(&self, key: &AppKey) -> Result<()> {
        let mut attr = BpfAttr::default();
        attr.set_u32(0, self.fd() as u32);
        attr.set_u64(8, key.0.as_ptr().addr() as u64);
        match bpf_call(BPF_MAP_DELETE_ELEM, &attr) {
            Ok(_) => Ok(()),
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct BpfInsn {
    code: u8,
    registers: u8,
    off: i16,
    imm: i32,
}

impl BpfInsn {
    const fn new(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Self {
        Self {
            code,
            registers: dst | (src << 4),
            off,
            imm,
        }
    }
}

fn load_socket_marker(map_fd: i32) -> Result<OwnedFd> {
    let instructions = [
        BpfInsn::new(0xbf, 6, 1, 0, 0),
        BpfInsn::new(0x85, 0, 0, 0, BPF_FUNC_GET_CURRENT_UID_GID),
        BpfInsn::new(0x63, 10, 0, -24, 0),
        BpfInsn::new(0xbf, 1, 10, 0, 0),
        BpfInsn::new(0x07, 1, 0, 0, -20),
        BpfInsn::new(0xb7, 2, 0, 0, TASK_COMM_LEN as i32),
        BpfInsn::new(0x85, 0, 0, 0, BPF_FUNC_GET_CURRENT_COMM),
        BpfInsn::new(0xbf, 2, 10, 0, 0),
        BpfInsn::new(0x07, 2, 0, 0, -24),
        BpfInsn::new(0x18, 1, BPF_PSEUDO_MAP_FD, 0, map_fd),
        BpfInsn::new(0, 0, 0, 0, 0),
        BpfInsn::new(0x85, 0, 0, 0, BPF_FUNC_MAP_LOOKUP_ELEM),
        BpfInsn::new(0x15, 0, 0, 1, 0),
        BpfInsn::new(0x62, 6, 0, 16, SOCKET_MARK as i32),
        BpfInsn::new(0xb7, 0, 0, 0, 1),
        BpfInsn::new(0x95, 0, 0, 0, 0),
    ];
    let license = b"GPL\0";
    let mut log = vec![0u8; 65_536];
    let mut attr = BpfAttr::default();
    attr.set_u32(0, BPF_PROG_TYPE_CGROUP_SOCK);
    attr.set_u32(4, instructions.len() as u32);
    attr.set_u64(8, instructions.as_ptr().addr() as u64);
    attr.set_u64(16, license.as_ptr().addr() as u64);
    attr.set_u32(24, 1);
    attr.set_u32(28, log.len() as u32);
    attr.set_u64(32, log.as_mut_ptr().addr() as u64);
    attr.set_u32(68, BPF_CGROUP_INET_SOCK_CREATE);
    match bpf_fd(BPF_PROG_LOAD, &attr) {
        Ok(fd) => Ok(fd),
        Err(error) => {
            let verifier = String::from_utf8_lossy(&log)
                .trim_matches(char::from(0))
                .trim()
                .to_string();
            bail!("Failed to load Linux split-tunnel eBPF program: {error}; {verifier}")
        }
    }
}

fn create_cgroup_link(program_fd: i32, cgroup_fd: i32) -> Result<OwnedFd> {
    let mut attr = BpfAttr::default();
    attr.set_u32(0, program_fd as u32);
    attr.set_u32(4, cgroup_fd as u32);
    attr.set_u32(8, BPF_CGROUP_INET_SOCK_CREATE);
    bpf_fd(BPF_LINK_CREATE, &attr)
        .context("Failed to attach split tunneling to the cgroup (Linux kernel 5.7+ is required)")
}

#[repr(C, align(8))]
struct BpfAttr([u8; 144]);

impl Default for BpfAttr {
    fn default() -> Self {
        Self([0; 144])
    }
}

impl BpfAttr {
    fn set_u32(&mut self, offset: usize, value: u32) {
        self.0[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
    }

    fn set_u64(&mut self, offset: usize, value: u64) {
        self.0[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
    }
}

fn bpf_fd(command: u32, attr: &BpfAttr) -> Result<OwnedFd, std::io::Error> {
    let fd = bpf_call(command, attr)?;
    // SAFETY: A successful BPF command returning an fd transfers ownership to us.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

fn bpf_call(command: u32, attr: &BpfAttr) -> Result<libc::c_long, std::io::Error> {
    // SAFETY: attr points to a correctly sized, initialized bpf_attr buffer for
    // the duration of the syscall; the kernel copies all pointer data inline.
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            command,
            attr as *const BpfAttr,
            size_of::<BpfAttr>(),
        )
    };
    if result < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_keys_include_launcher_and_flatpak_command() {
        let signatures = vec![vec![
            "/usr/bin/flatpak".into(),
            "run".into(),
            "--command=firefox".into(),
            "org.mozilla.firefox".into(),
        ]];
        let keys = seed_keys(1000, &signatures);
        assert!(keys.contains(&AppKey::new(1000, b"flatpak")));
        assert!(keys.contains(&AppKey::new(1000, b"firefox")));
    }
}
