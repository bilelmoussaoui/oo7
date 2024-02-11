use zbus::zvariant;

/// File backend specific errors.
#[derive(Debug)]
pub enum Error {
    /// File header does not match `FILE_HEADER`.
    FileHeaderMismatch(Option<String>),
    /// Version bytes do not match `MAJOR_VERSION` or `MINOR_VERSION`.
    VersionMismatch(Option<Vec<u8>>),
    /// No data behind header and version bytes.
    NoData,
    /// No Parent directory.
    NoParentDir(String),
    /// Bytes don't have the expected GVariant format.
    GVariantDeserialization(zvariant::Error),
    /// Mismatch between array length and length explicitly stored in keyring
    SaltSizeMismatch(usize, u32),
    /// Key for some reason too weak to trust it for writing
    WeakKey(WeakKeyError),
    /// Input/Output.
    Io(std::io::Error),
    /// Unexpected MAC digest value.
    MacError,
    /// Failure to validate the attributes.
    HashedAttributeMac(String),
    /// XDG_DATA_HOME required for reading from default location.
    NoDataDir,
    /// Target file has changed.
    TargetFileChanged(String),
    /// Portal DBus communication error.
    PortalBus(zbus::Error),
    /// Portal request has been cancelled.
    CancelledPortalRequest,
    /// If the portal is not available on the host.
    /// Can happen if the host has an old xdg-desktop-portal
    /// or no secret service is available to store the secret.
    PortalNotAvailable,
    /// The addressed index does not exist.
    InvalidItemIndex(usize),
}

impl From<zvariant::Error> for Error {
    fn from(value: zvariant::Error) -> Self {
        Self::GVariantDeserialization(value)
    }
}

impl From<WeakKeyError> for Error {
    fn from(value: WeakKeyError) -> Self {
        Self::WeakKey(value)
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
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
                write!(f, "File header doesn't match FILE_HEADER {e:#?}")
            }
            Error::VersionMismatch(e) => write!(
                f,
                "Version doesn't match MAJOR_VERSION OR MICRO_VERSION {e:#?}",
            ),
            Error::NoData => write!(f, "No data behind header and version bytes"),
            Error::NoParentDir(e) => write!(f, "No Parent Directory {e}"),
            Error::GVariantDeserialization(e) => write!(f, "Failed to deserialize {e}"),
            Error::SaltSizeMismatch(arr, explicit) => write!(
                f,
                "Salt size is not as expected. Array: {arr}, Explicit: {explicit}"
            ),
            Error::WeakKey(err) => write!(f, "{err}"),
            Error::Io(e) => write!(f, "IO error {e}"),
            Error::MacError => write!(f, "Mac digest is not equal to the expected value"),
            Error::HashedAttributeMac(e) => write!(f, "Failed to validate hashed attribute {e}"),
            Error::NoDataDir => write!(f, "Couldn't retrieve XDG_DATA_DIR"),
            Error::TargetFileChanged(e) => write!(f, "The target file has changed {e}"),
            Error::PortalBus(e) => write!(f, "Portal communication failed {e}"),
            Error::CancelledPortalRequest => write!(f, "Portal request was cancelled"),
            Error::PortalNotAvailable => write!(f, "xdg-desktop-portal is too old on the host or secret service not available to store the secret"),
            Error::InvalidItemIndex(index) => write!(f, "The addressed item index {index} does not exist"),
        }
    }
}

#[derive(Debug)]
/// All information that is available about an invalid (not decryptable)
/// [`Item`](super::Item)
pub struct InvalidItemError {
    error: Error,
    attribute_names: Vec<String>,
}

impl InvalidItemError {
    pub(super) fn new(error: Error, attribute_names: Vec<String>) -> Self {
        Self {
            error,
            attribute_names,
        }
    }
}

impl std::error::Error for InvalidItemError {}

impl std::fmt::Display for InvalidItemError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Invalid item: {:?}. Property names: {:?}",
            self.error, self.attribute_names
        )
    }
}

/// Details about why an encryption key is consider too weak for writing
#[derive(Debug, Copy, Clone)]
pub enum WeakKeyError {
    /// Avoid attack on existing files
    IterationCountTooLow(u32),
    /// Avoid attack on existing files
    SaltTooShort(usize),
    /// Just not secure enough to store password
    PasswordTooShort(usize),
    /// Should not occur
    ///
    /// Used by [`dbus`](crate::dbus) module that does not currently
    /// check key strength.
    StrengthUnknown,
}

impl std::error::Error for WeakKeyError {}

impl std::fmt::Display for WeakKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IterationCountTooLow(count) => write!(f, "Iteration count too low: {count}"),
            Self::SaltTooShort(length) => write!(f, "Salt too short: {length}"),
            Self::PasswordTooShort(length) => {
                write!(f, "Password (secret from portal) too short: {length}")
            }
            Self::StrengthUnknown => write!(f, "Strength unknown"),
        }
    }
}
