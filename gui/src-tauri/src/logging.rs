use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::fmt::MakeWriter;

const MAX_LOG_BYTES: u64 = 10 * 1024 * 1024;

#[derive(Clone)]
struct SharedLogFile {
    state: Arc<Mutex<SharedLogState>>,
}

struct SharedLogState {
    path: PathBuf,
    file: Option<File>,
}

struct SharedLogWriter {
    state: Arc<Mutex<SharedLogState>>,
}

impl<'a> MakeWriter<'a> for SharedLogFile {
    type Writer = SharedLogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        SharedLogWriter {
            state: Arc::clone(&self.state),
        }
    }
}

impl Write for SharedLogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("log file lock poisoned"))?;
        state.rotate_if_needed()?;
        state.file_mut()?.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("log file lock poisoned"))?;
        state.file_mut()?.flush()
    }
}

impl SharedLogState {
    fn file_mut(&mut self) -> io::Result<&mut File> {
        self.file
            .as_mut()
            .ok_or_else(|| io::Error::other("log file is temporarily unavailable"))
    }

    fn rotate_if_needed(&mut self) -> io::Result<()> {
        if self
            .file_mut()?
            .metadata()
            .is_ok_and(|metadata| metadata.len() < MAX_LOG_BYTES)
        {
            return Ok(());
        }

        if let Some(mut file) = self.file.take() {
            file.flush()?;
        }
        rotate_if_needed(&self.path)?;
        self.file = Some(open_append_file(&self.path)?);
        Ok(())
    }
}

pub(crate) fn init_gui_logging() -> Option<PathBuf> {
    let env_filter = default_env_filter();
    let log_path = gui_log_dir().join("mavi-vpn-gui.log");

    match open_log_file(&log_path) {
        Ok(file) => {
            let writer = SharedLogFile {
                state: Arc::new(Mutex::new(SharedLogState {
                    path: log_path.clone(),
                    file: Some(file),
                })),
            };
            if tracing_subscriber::fmt()
                .with_env_filter(env_filter)
                .with_ansi(false)
                .with_target(true)
                .with_thread_ids(true)
                .with_line_number(true)
                .with_writer(writer)
                .try_init()
                .is_ok()
            {
                Some(log_path)
            } else {
                None
            }
        }
        Err(error) => {
            eprintln!(
                "Failed to open GUI log file at {}: {error}",
                log_path.display()
            );
            let _ = tracing_subscriber::fmt()
                .with_env_filter(env_filter)
                .with_target(true)
                .with_thread_ids(true)
                .with_line_number(true)
                .try_init();
            None
        }
    }
}

fn default_env_filter() -> EnvFilter {
    std::env::var("RUST_LOG").map_or_else(
        |_| {
            EnvFilter::new(
                "info,mavi_vpn_gui_lib=debug,shared=debug,hyper=warn,h2=warn,reqwest=warn,rustls=warn",
            )
        },
        EnvFilter::new,
    )
}

fn gui_log_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
        return PathBuf::from(local_app_data).join("MaviVPN").join("logs");
    }

    if let Some(state_home) = std::env::var_os("XDG_STATE_HOME") {
        return PathBuf::from(state_home).join("mavi-vpn").join("logs");
    }

    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home)
            .join(".local")
            .join("state")
            .join("mavi-vpn")
            .join("logs");
    }

    std::env::temp_dir().join("mavi-vpn").join("logs")
}

fn open_log_file(path: &Path) -> io::Result<File> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    rotate_if_needed(path)?;
    open_append_file(path)
}

fn open_append_file(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

fn rotate_if_needed(path: &Path) -> io::Result<()> {
    if fs::metadata(path).is_ok_and(|metadata| metadata.len() >= MAX_LOG_BYTES) {
        let old_path = path.with_extension("log.old");
        let _ = fs::remove_file(&old_path);
        fs::rename(path, old_path)?;
    }
    Ok(())
}
