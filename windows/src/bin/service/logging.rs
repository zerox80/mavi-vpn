use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::util::SubscriberInitExt;

const MAX_LOG_BYTES: u64 = 10 * 1024 * 1024;

#[derive(Clone)]
struct SharedLogFile {
    file: Arc<Mutex<File>>,
}

struct SharedLogWriter {
    file: Arc<Mutex<File>>,
}

impl<'a> MakeWriter<'a> for SharedLogFile {
    type Writer = SharedLogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        SharedLogWriter {
            file: Arc::clone(&self.file),
        }
    }
}

impl Write for SharedLogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut file = self
            .file
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "log file lock poisoned"))?;
        file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut file = self
            .file
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "log file lock poisoned"))?;
        file.flush()
    }
}

pub fn init_service_logging() -> Option<PathBuf> {
    let env_filter = default_env_filter();
    let log_path = service_log_dir().join("mavi-vpn-service.log");

    match open_log_file(&log_path) {
        Ok(file) => {
            let writer = SharedLogFile {
                file: Arc::new(Mutex::new(file)),
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
                "Failed to open service log file at {}: {error}",
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
                "info,mavi_vpn_service=debug,windows_vpn=debug,shared=debug,wintun=off,hyper=warn,h2=warn,reqwest=warn,rustls=warn",
            )
        },
        EnvFilter::new,
    )
}

fn service_log_dir() -> PathBuf {
    std::env::var_os("PROGRAMDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("mavi-vpn")
        .join("logs")
}

fn open_log_file(path: &Path) -> io::Result<File> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    rotate_if_needed(path)?;
    OpenOptions::new().create(true).append(true).open(path)
}

fn rotate_if_needed(path: &Path) -> io::Result<()> {
    if fs::metadata(path).map_or(false, |metadata| metadata.len() >= MAX_LOG_BYTES) {
        let old_path = path.with_extension("log.old");
        let _ = fs::remove_file(&old_path);
        fs::rename(path, old_path)?;
    }
    Ok(())
}
