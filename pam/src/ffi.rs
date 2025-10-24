use std::os::raw::{c_char, c_int, c_void};

// PAM return codes
pub const PAM_SUCCESS: c_int = 0;
pub const PAM_SYSTEM_ERR: c_int = 4;
pub const PAM_AUTHTOK_RECOVER_ERR: c_int = 20;

// PAM item types
pub const PAM_AUTHTOK: c_int = 6;

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

    /// Get a PAM item
    pub fn pam_get_item(
        pamh: *const pam_handle_t,
        item_type: c_int,
        item: *mut *const c_void,
    ) -> c_int;

    /// Store data in PAM context with a cleanup function
    pub fn pam_set_data(
        pamh: *mut pam_handle_t,
        module_data_name: *const c_char,
        data: *mut c_void,
        cleanup: Option<unsafe extern "C" fn(*mut pam_handle_t, *mut c_void, c_int)>,
    ) -> c_int;

    /// Retrieve data from PAM context
    pub fn pam_get_data(
        pamh: *const pam_handle_t,
        module_data_name: *const c_char,
        data: *mut *const c_void,
    ) -> c_int;
}
