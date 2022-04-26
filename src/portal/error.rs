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
    SecretPortal(crate::Error),
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

// TODO: This does not really make sense
impl From<crate::Error> for Error {
    fn from(value: crate::Error) -> Self {
        Self::SecretPortal(value)
    }
}
