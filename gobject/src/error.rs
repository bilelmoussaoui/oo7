use gobject_ffi::{c_return_type, ffi_impl};

/// Error codes for the Oo7 error domain
#[derive(Debug, Clone, Copy, PartialEq, Eq, glib::Enum, glib::ErrorDomain)]
#[repr(i32)]
#[enum_type(name = "Oo7Error")]
#[error_domain(name = "oo7-error-quark")]
pub enum Error {
    // File backend errors
    FileHeaderMismatch = 1,
    VersionMismatch = 2,
    NoData = 3,
    NoParentDir = 4,
    GVariantDeserialization = 5,
    SaltSizeMismatch = 6,
    WeakKey = 7,
    Io = 8,
    MacError = 9,
    ChecksumMismatch = 10,
    HashedAttributeMac = 11,
    NoDataDir = 12,
    TargetFileChanged = 13,
    Portal = 14,
    InvalidItemIndex = 15,
    Utf8 = 16,
    AlgorithmMismatch = 17,
    IncorrectSecret = 18,
    PartiallyCorruptedKeyring = 19,
    Crypto = 20,
    Locked = 21,

    // DBus backend errors
    ZBus = 100,
    ServiceError = 101,
    Deleted = 102,
    Dismissed = 103,
    NotFound = 104,
    IsLocked = 105,
    NoSession = 106,
    NoSuchObject = 107,

    // Generic/unknown error
    #[enum_value(name = "Unknown", nick = "unknown")]
    Unknown = 999,
}

#[ffi_impl(prefix = "oo7", ty = "enum")]
impl Error {
    #[c_return_type(u32, transfer=primitive)]
    fn quark() -> glib::Quark {
        <Error as glib::prelude::ErrorDomain>::domain()
    }
}

/// Convert an oo7_rs::Error to a glib::Error with proper error codes and
/// messages
pub fn to_glib_error(error: oo7_rs::Error) -> glib::Error {
    match error {
        oo7_rs::Error::File(e) => file_error_to_glib(e),
        oo7_rs::Error::DBus(e) => dbus_error_to_glib(e),
    }
}

fn file_error_to_glib(error: oo7_rs::file::Error) -> glib::Error {
    let (code, message) = match error {
        oo7_rs::file::Error::FileHeaderMismatch(_) => {
            (Error::FileHeaderMismatch, error.to_string())
        }
        oo7_rs::file::Error::VersionMismatch(_) => (Error::VersionMismatch, error.to_string()),
        oo7_rs::file::Error::NoData => (Error::NoData, error.to_string()),
        oo7_rs::file::Error::NoParentDir(_) => (Error::NoParentDir, error.to_string()),
        oo7_rs::file::Error::GVariantDeserialization(_) => {
            (Error::GVariantDeserialization, error.to_string())
        }
        oo7_rs::file::Error::SaltSizeMismatch(_, _) => (Error::SaltSizeMismatch, error.to_string()),
        oo7_rs::file::Error::WeakKey(_) => (Error::WeakKey, error.to_string()),
        oo7_rs::file::Error::Io(_) => (Error::Io, error.to_string()),
        oo7_rs::file::Error::MacError => (Error::MacError, error.to_string()),
        oo7_rs::file::Error::ChecksumMismatch => (Error::ChecksumMismatch, error.to_string()),
        oo7_rs::file::Error::HashedAttributeMac(_) => {
            (Error::HashedAttributeMac, error.to_string())
        }
        oo7_rs::file::Error::NoDataDir => (Error::NoDataDir, error.to_string()),
        oo7_rs::file::Error::TargetFileChanged(_) => (Error::TargetFileChanged, error.to_string()),
        oo7_rs::file::Error::Portal(_) => (Error::Portal, error.to_string()),
        oo7_rs::file::Error::InvalidItemIndex(_) => (Error::InvalidItemIndex, error.to_string()),
        oo7_rs::file::Error::Utf8(_) => (Error::Utf8, error.to_string()),
        oo7_rs::file::Error::AlgorithmMismatch(_) => (Error::AlgorithmMismatch, error.to_string()),
        oo7_rs::file::Error::IncorrectSecret => (Error::IncorrectSecret, error.to_string()),
        oo7_rs::file::Error::PartiallyCorruptedKeyring { .. } => {
            (Error::PartiallyCorruptedKeyring, error.to_string())
        }
        oo7_rs::file::Error::Crypto(_) => (Error::Crypto, error.to_string()),
        oo7_rs::file::Error::Locked => (Error::Locked, error.to_string()),
    };

    glib::Error::new(code, &message)
}

fn dbus_error_to_glib(error: oo7_rs::dbus::Error) -> glib::Error {
    use oo7_rs::dbus::ServiceError;

    let (code, message) = match error {
        oo7_rs::dbus::Error::ZBus(_) => (Error::ZBus, error.to_string()),
        oo7_rs::dbus::Error::Service(ref service_err) => match service_err {
            ServiceError::ZBus(_) => (Error::ZBus, error.to_string()),
            ServiceError::IsLocked(_) => (Error::IsLocked, error.to_string()),
            ServiceError::NoSession(_) => (Error::NoSession, error.to_string()),
            ServiceError::NoSuchObject(_) => (Error::NoSuchObject, error.to_string()),
        },
        oo7_rs::dbus::Error::Deleted => (Error::Deleted, error.to_string()),
        oo7_rs::dbus::Error::Dismissed => (Error::Dismissed, error.to_string()),
        oo7_rs::dbus::Error::NotFound(_) => (Error::NotFound, error.to_string()),
        oo7_rs::dbus::Error::IO(_) => (Error::Io, error.to_string()),
        oo7_rs::dbus::Error::Crypto(_) => (Error::Crypto, error.to_string()),
    };

    glib::Error::new(code, &message)
}
