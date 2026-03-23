//! # Linux TUN Device
//!
//! Creates and manages a TUN device via the kernel's `/dev/net/tun` interface.
//! Provides both synchronous and async (tokio) I/O for the packet pump.

use anyhow::{Context, Result};
use std::ffi::CStr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use tokio::io::unix::AsyncFd;

// ioctl request code for TUNSETIFF
const TUNSETIFF: libc::c_ulong = 0x400454ca;
// TUN device (layer 3, raw IP packets)
const IFF_TUN: libc::c_short = 0x0001;
// No packet info header (we want raw IP, not prepended with flags+proto)
const IFF_NO_PI: libc::c_short = 0x1000;

/// A Linux TUN network device backed by `/dev/net/tun`.
pub struct TunDevice {
    fd: OwnedFd,
    name: String,
}

#[repr(C)]
struct IfReq {
    ifr_name: [libc::c_char; libc::IFNAMSIZ],
    ifr_flags: libc::c_short,
    _pad: [u8; 22], // padding to match kernel struct size
}

impl TunDevice {
    /// Creates a new TUN device with the given name (e.g. "mavi0").
    /// Requires CAP_NET_ADMIN or root privileges.
    pub fn create(name: &str) -> Result<Self> {
        // Open the TUN clone device
        let fd = unsafe { libc::open(b"/dev/net/tun\0".as_ptr() as *const _, libc::O_RDWR) };
        if fd < 0 {
            return Err(anyhow::anyhow!(
                "Failed to open /dev/net/tun: {}. Are you running as root?",
                std::io::Error::last_os_error()
            ));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };

        // Prepare the ioctl request
        let mut req = IfReq {
            ifr_name: [0; libc::IFNAMSIZ],
            ifr_flags: IFF_TUN | IFF_NO_PI,
            _pad: [0; 22],
        };

        // Copy device name (truncated to IFNAMSIZ - 1)
        let name_bytes = name.as_bytes();
        let copy_len = name_bytes.len().min(libc::IFNAMSIZ - 1);
        for (i, &b) in name_bytes[..copy_len].iter().enumerate() {
            req.ifr_name[i] = b as libc::c_char;
        }

        // Create the device
        let ret = unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF as _, &mut req as *mut _) };
        if ret < 0 {
            return Err(anyhow::anyhow!(
                "TUNSETIFF ioctl failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Read back the actual device name assigned by the kernel
        let actual_name = unsafe {
            CStr::from_ptr(req.ifr_name.as_ptr())
                .to_string_lossy()
                .into_owned()
        };

        // Set non-blocking for async I/O
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(anyhow::anyhow!("fcntl F_GETFL failed"));
        }
        let ret = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if ret < 0 {
            return Err(anyhow::anyhow!("fcntl F_SETFL O_NONBLOCK failed"));
        }

        tracing::info!("TUN device '{}' created (fd={})", actual_name, fd.as_raw_fd());

        Ok(Self {
            fd,
            name: actual_name,
        })
    }

    /// Returns the device name (e.g. "mavi0").
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the raw file descriptor for direct I/O.
    pub fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Wraps the TUN fd in tokio's `AsyncFd` for async read/write.
    pub fn into_async(self) -> Result<AsyncTun> {
        let async_fd =
            AsyncFd::new(self).context("Failed to register TUN fd with tokio epoll")?;
        Ok(AsyncTun { inner: async_fd })
    }
}

impl AsRawFd for TunDevice {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// Async wrapper around the TUN device using tokio's epoll-based `AsyncFd`.
pub struct AsyncTun {
    inner: AsyncFd<TunDevice>,
}

impl AsyncTun {
    /// Read a single IP packet from the TUN device.
    /// Returns the number of bytes read into `buf`.
    pub async fn read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let mut guard = self.inner.readable().await?;
            match guard.try_io(|inner| {
                let fd = inner.get_ref().raw_fd();
                let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len()) };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    /// Write a single IP packet to the TUN device.
    /// Returns the number of bytes written.
    pub async fn write(&self, buf: &[u8]) -> std::io::Result<usize> {
        loop {
            let mut guard = self.inner.writable().await?;
            match guard.try_io(|inner| {
                let fd = inner.get_ref().raw_fd();
                let n = unsafe { libc::write(fd, buf.as_ptr() as *const _, buf.len()) };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    /// Returns the device name.
    pub fn name(&self) -> &str {
        self.inner.get_ref().name()
    }
}
