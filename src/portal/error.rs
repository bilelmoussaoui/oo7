use zbus::zvariant;

#[derive(Debug)]
pub enum Error {
    /// File header does not match `FILE_HEADER`
    FileHeaderMismatch(Option<String>),
    /// Version bytes do not match `MAJOR_VERSION` or `MINOR_VERSION`
    VersionMismatch(Option<Vec<u8>>),
    /// No data behind header and version bytes
    NoData,
    NoParentDir(String),
    /// Bytes don't have the expected GVariant format
    GVariantDeserialization(zvariant::Error),
    Io(std::io::Error),
    MacError,
    HashedAttributeMac(String),
    /// XDG_DATA_HOME required for reading from default location
    NoDataDir,
    TargetFileChanged(String),
    /// Portal DBus communication error.
    PortalBus(zbus::Error),
    CancelledPortalRequest,
}

impl From<zvariant::Error> for Error {
    fn from(value: zvariant::Error) -> Self {
        Self::GVariantDeserialization(value)
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<digest::MacError> for Error {
    fn from(_value: digest::MacError) -> Self {
        Self::MacError
    }
}

impl From<zbus::Error> for Error {
    fn from(value: zbus::Error) -> Self {
        Self::PortalBus(value)
    }
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::FileHeaderMismatch(e) => {
                write!(f, "File header doesn't match FILE_HEADER {:#?}", e)
            }
            Error::VersionMismatch(e) => write!(
                f,
                "Version doesn't match MAJOR_VERSION OR MICRO_VERSION {:#?}",
                e
            ),
            Error::NoData => write!(f, "No data behind header and version bytes"),
            Error::NoParentDir(e) => write!(f, "No Parent Directory {e}"),
            Error::GVariantDeserialization(e) => write!(f, "Failed to deserialize {e}"),
            Error::Io(e) => write!(f, "IO error {e}"),
            Error::MacError => write!(f, "Mac digest is not equal to the expected value"),
            Error::HashedAttributeMac(e) => write!(f, "Failed to validate hashed attribute {e}"),
            Error::NoDataDir => write!(f, "Couldn't retrieve XDG_DATA_DIR"),
            Error::TargetFileChanged(e) => write!(f, "The target file has changed {e}"),
            Error::PortalBus(e) => write!(f, "Portal communication failed {e}"),
            Error::CancelledPortalRequest => write!(f, "Portal request was cancelled"),
        }
    }
}
