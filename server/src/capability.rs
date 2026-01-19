use caps::{CapSet, Capability, CapsHashSet};
use rustix::process::{Gid, Uid, getgid, getuid};

// Wrapper functions using libc since rustix doesn't expose these
fn setuid(uid: Uid) -> Result<(), rustix::io::Errno> {
    let ret = unsafe { libc::setuid(uid.as_raw()) };
    if ret == 0 {
        Ok(())
    } else {
        Err(rustix::io::Errno::from_raw_os_error(
            std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EINVAL),
        ))
    }
}

fn setgid(gid: Gid) -> Result<(), rustix::io::Errno> {
    let ret = unsafe { libc::setgid(gid.as_raw()) };
    if ret == 0 {
        Ok(())
    } else {
        Err(rustix::io::Errno::from_raw_os_error(
            std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EINVAL),
        ))
    }
}

fn setgroups(groups: &[Gid]) -> Result<(), rustix::io::Errno> {
    let gids: Vec<libc::gid_t> = groups.iter().map(|g| g.as_raw()).collect();
    let ret = unsafe { libc::setgroups(gids.len(), gids.as_ptr()) };
    if ret == 0 {
        Ok(())
    } else {
        Err(rustix::io::Errno::from_raw_os_error(
            std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EINVAL),
        ))
    }
}

#[derive(Debug)]
pub enum Error {
    CapsRead(caps::errors::CapsError),
    CapsUpdate(caps::errors::CapsError),
    DropGroups(rustix::io::Errno),
    SetGid(rustix::io::Errno),
    SetUid(rustix::io::Errno),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CapsRead(e) => write!(f, "Failed to read process capabilities: {e}"),
            Self::CapsUpdate(e) => write!(f, "Failed updating process capabilities: {e}"),
            Self::DropGroups(e) => write!(f, "Failed to drop supplementary groups: {e}"),
            Self::SetGid(e) => write!(f, "Failed to setgid: {e}"),
            Self::SetUid(e) => write!(f, "Failed to setuid: {e}"),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Debug, PartialEq)]
enum CapabilityState {
    // We are either setuid root or the root user
    Full,
    // File system based capabilities
    Partial,
    None,
}

fn handle_full_capabilities() -> Result<(), Error> {
    // First, prepare the capability sets we want to end up with
    let mut ipc_lock_caps = CapsHashSet::new();
    ipc_lock_caps.insert(Capability::CAP_IPC_LOCK);

    // Clear all capabilities first, but DON'T touch bounding set yet
    let empty_caps = CapsHashSet::new();
    caps::set(None, CapSet::Effective, &empty_caps).map_err(Error::CapsUpdate)?;
    caps::set(None, CapSet::Permitted, &empty_caps).map_err(Error::CapsUpdate)?;

    // Set only CAP_IPC_LOCK in permitted and effective (before identity change)
    caps::set(None, CapSet::Permitted, &ipc_lock_caps).map_err(Error::CapsUpdate)?;
    caps::set(None, CapSet::Effective, &ipc_lock_caps).map_err(Error::CapsUpdate)?;

    // Drop supplementary groups first
    setgroups(&[]).map_err(Error::DropGroups)?;

    // Change to real GID
    setgid(getgid()).map_err(Error::SetGid)?;

    // Change to real UID (this should be done last)
    setuid(getuid()).map_err(Error::SetUid)?;

    // NOW we can safely clear the bounding set (after identity change)
    if let Err(err) = caps::set(None, CapSet::Bounding, &ipc_lock_caps) {
        tracing::debug!(
            "Could not clear bounding set (may not be supported): {}",
            err
        );
    }

    Ok(())
}

fn handle_partial_capabilities() -> Result<(), Error> {
    let effective_caps = caps::read(None, CapSet::Effective).map_err(Error::CapsRead)?;

    // Check if we have CAP_IPC_LOCK in effective set
    if !effective_caps.contains(&Capability::CAP_IPC_LOCK) {
        tracing::warn!("Insufficient process capabilities, insecure memory might get used");
    }

    // Check if we have CAP_SETPCAP for bounding set manipulation
    let has_setpcap =
        caps::has_cap(None, CapSet::Effective, Capability::CAP_SETPCAP).map_err(Error::CapsRead)?;

    // Clear all capabilities first
    let empty_caps = CapsHashSet::new();
    caps::set(None, CapSet::Effective, &empty_caps).map_err(Error::CapsUpdate)?;
    caps::set(None, CapSet::Permitted, &empty_caps).map_err(Error::CapsUpdate)?;

    // Only clear bounding set if we have CAP_SETPCAP
    if has_setpcap {
        if let Err(err) = caps::set(None, CapSet::Bounding, &empty_caps) {
            tracing::warn!("Failed to clear bounding set: {}", err);
        }
    }

    // Add only CAP_IPC_LOCK to effective and permitted sets
    let mut ipc_lock_caps = CapsHashSet::new();
    ipc_lock_caps.insert(Capability::CAP_IPC_LOCK);

    caps::set(None, CapSet::Effective, &ipc_lock_caps).map_err(Error::CapsUpdate)?;
    caps::set(None, CapSet::Permitted, &ipc_lock_caps).map_err(Error::CapsUpdate)?;

    // Only set bounding set if we have CAP_SETPCAP and cleared it successfully
    if has_setpcap {
        if let Err(err) = caps::set(None, CapSet::Bounding, &ipc_lock_caps) {
            tracing::warn!("Failed to set bounding set: {}", err);
        }
    }

    Ok(())
}

/// Determines the current capability state of the process
/// This mirrors the logic from libcap-ng's capng_have_capabilities()
fn determine_capability_state() -> Result<CapabilityState, Error> {
    let effective_caps = caps::read(None, CapSet::Effective).map_err(Error::CapsRead)?;
    let permitted_caps = caps::read(None, CapSet::Permitted).map_err(Error::CapsRead)?;
    let bounding_caps = caps::read(None, CapSet::Bounding).map_err(Error::CapsRead)?;

    // Check if we have no capabilities at all
    if permitted_caps.is_empty() && effective_caps.is_empty() {
        return Ok(CapabilityState::None);
    }

    // To match libcap-ng logic more closely, check if we have "most" capabilities
    // This is a heuristic - if we have a substantial number of capabilities,
    // we're likely in FULL state (setuid root or running as root)

    // Count total unique capabilities across all sets
    let mut all_caps = permitted_caps.clone();
    all_caps.extend(&effective_caps);
    all_caps.extend(&bounding_caps);

    // If we have 10+ capabilities total, likely FULL state
    // This matches libcap-ng's heuristic more closely than checking specific caps
    if all_caps.len() >= 10 {
        Ok(CapabilityState::Full)
    } else {
        // Otherwise, we have partial/filesystem-based capabilities
        Ok(CapabilityState::Partial)
    }
}

pub fn drop_unnecessary_capabilities() -> Result<(), Error> {
    // First, verify we can read capabilities at all (equivalent to CAPNG_FAIL
    // check)
    if let Err(e) = caps::read(None, CapSet::Effective) {
        // Critical error - cannot proceed safely, should abort like C version
        tracing::error!("Error getting process capabilities: {:?}, aborting", e);
        std::process::exit(1);
    }

    match determine_capability_state()? {
        CapabilityState::Full => {
            // We are either setuid root or the root user
            handle_full_capabilities()?;
        }
        CapabilityState::None => {
            tracing::warn!("No process capabilities, insecure memory might get used");
            return Ok(());
        }
        CapabilityState::Partial => {
            // File system based capabilities
            handle_partial_capabilities()?;
        }
    }

    Ok(())
}
