use caps::{CapSet, Capability, CapsHashSet};
use nix::unistd::{getgid, getuid, setgid, setgroups, setuid};

#[derive(Debug)]
pub enum Error {
    CapsReadError(caps::errors::CapsError),
    CapsUpdateError(caps::errors::CapsError),
    DropGroupsError(nix::Error),
    SetGidError(nix::Error),
    SetUidError(nix::Error),
    InsufficientCapabilities,
    NoCapabilities,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CapsReadError(e) => write!(f, "Failed to read process capabilities: {}", e),
            Self::CapsUpdateError(e) => write!(f, "Failed updating process capabilities: {}", e),
            Self::DropGroupsError(e) => write!(f, "Failed to drop supplementary groups: {}", e),
            Self::SetGidError(e) => write!(f, "Failed to setgid: {}", e),
            Self::SetUidError(e) => write!(f, "Failed to setuid: {}", e),
            Self::InsufficientCapabilities => write!(
                f,
                "Insufficient process capabilities, insecure memory might get used"
            ),
            Self::NoCapabilities => {
                write!(f, "No process capabilities, insecure memory might get used")
            }
        }
    }
}

impl std::error::Error for Error {}

pub fn drop_unnecessary_capabilities() -> Result<(), Error> {
    // Load current process capabilities
    let permitted_caps = caps::read(None, CapSet::Permitted).map_err(Error::CapsReadError)?;

    if permitted_caps.contains(&Capability::CAP_IPC_LOCK) {
        // Check if CAP_SETPCAP is available (needed to drop bounding set and groups)
        let has_setpcap = caps::has_cap(None, CapSet::Permitted, Capability::CAP_SETPCAP)
            .map_err(Error::CapsReadError)?;

        let mut drop_caps = CapsHashSet::new();
        drop_caps.insert(Capability::CAP_IPC_LOCK);

        // Clear other capabilities and apply only CAP_IPC_LOCK
        caps::set(None, CapSet::Effective, &drop_caps).map_err(Error::CapsUpdateError)?;
        caps::set(None, CapSet::Permitted, &drop_caps).map_err(Error::CapsUpdateError)?;

        // Drop supplementary groups and switch to real UID/GID.
        if has_setpcap {
            setgroups(&[]).map_err(Error::DropGroupsError)?;
            setgid(getgid()).map_err(Error::SetGidError)?;
            setuid(getuid()).map_err(Error::SetUidError)?;
        } else {
            return Err(Error::InsufficientCapabilities);
        }
    } else if permitted_caps.is_empty() {
        return Err(Error::NoCapabilities);
    } else {
        return Err(Error::InsufficientCapabilities);
    }

    Ok(())
}
