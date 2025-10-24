use std::os::raw::{c_char, c_int, c_void};

// PAM return codes
pub const PAM_SUCCESS: c_int = 0;
pub const PAM_SYSTEM_ERR: c_int = 4;

// PAM item types
pub const PAM_AUTHTOK: c_int = 5;

// Opaque PAM handle type
#[repr(C)]
pub struct pam_handle_t {
    _private: [u8; 0],
}

unsafe extern "C" {
    /// Get the username
    pub fn pam_get_user(
        pamh: *mut pam_handle_t,
        user: *mut *const c_char,
        prompt: *const c_char,
    ) -> c_int;

    /// Get a PAM item (like authentication token)
    pub fn pam_get_item(
        pamh: *const pam_handle_t,
        item_type: c_int,
        item: *mut *const c_void,
    ) -> c_int;
}
