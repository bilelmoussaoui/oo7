//! PAM module for oo7 Secret Service integration
//!
//! This module intercepts PAM authentication to capture and send user passwords
//! to the oo7 Secret Service daemon, enabling automatic keyring unlocking.

mod ffi;
mod protocol;
mod socket;

use std::{
    ffi::CStr,
    os::raw::{c_char, c_int},
};

use zeroize::Zeroizing;

use crate::{
    ffi::{PAM_AUTHTOK, PAM_SUCCESS, PAM_SYSTEM_ERR, pam_handle_t},
    protocol::PamMessage,
    socket::send_secret_to_daemon,
};

/// Get the username
unsafe fn get_user(pamh: *mut pam_handle_t) -> Result<String, c_int> {
    let mut user_ptr: *const c_char = std::ptr::null();
    let ret =
        unsafe { ffi::pam_get_user(pamh, &mut user_ptr as *mut *const c_char, std::ptr::null()) };

    if ret != PAM_SUCCESS {
        return Err(ret);
    }

    if user_ptr.is_null() {
        return Err(PAM_SYSTEM_ERR);
    }

    let user_cstr = unsafe { CStr::from_ptr(user_ptr) };
    Ok(user_cstr.to_string_lossy().into_owned())
}

/// Get the authentication token
unsafe fn get_auth_token(pamh: *mut pam_handle_t) -> Result<Zeroizing<Vec<u8>>, c_int> {
    let mut authtok_ptr: *const c_char = std::ptr::null();
    let ret = unsafe {
        ffi::pam_get_item(
            pamh,
            PAM_AUTHTOK,
            &mut authtok_ptr as *mut *const c_char as *mut *const std::os::raw::c_void,
        )
    };

    if ret != PAM_SUCCESS {
        return Err(ret);
    }

    if authtok_ptr.is_null() {
        return Err(PAM_SYSTEM_ERR);
    }

    let authtok_cstr = unsafe { CStr::from_ptr(authtok_ptr) };
    let authtok_bytes = authtok_cstr.to_bytes();

    Ok(Zeroizing::new(authtok_bytes.to_vec()))
}

/// PAM authentication entry point
#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *mut *const c_char,
) -> c_int {
    // Initialize tracing if not already done
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();

    unsafe {
        let username = match get_user(pamh) {
            Ok(user) => user,
            Err(ret) => {
                tracing::error!("Failed to get username from PAM");
                return ret;
            }
        };

        tracing::debug!("PAM authentication for user: {}", username);

        let password = match get_auth_token(pamh) {
            Ok(pass) => pass,
            Err(ret) => {
                tracing::error!("Failed to get auth token from PAM");
                return ret;
            }
        };

        tracing::debug!("Captured authentication token");

        let message = PamMessage {
            username: username.clone(),
            secret: password.to_vec(),
        };

        // Send the secret to the oo7 daemon
        std::thread::spawn(move || match send_secret_to_daemon(message) {
            Ok(_) => {
                tracing::info!(
                    "Successfully sent secret to oo7 daemon for user: {}",
                    username
                );
            }
            Err(e) => {
                tracing::error!("Failed to send secret to oo7 daemon: {}", e);
            }
        });

        // Always return success to not block authentication
        // if the daemon communication fails
        PAM_SUCCESS
    }
}

/// PAM credential setting entry point
#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_setcred(
    _pamh: *mut pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *mut *const c_char,
) -> c_int {
    PAM_SUCCESS
}

/// PAM account management entry point
#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_acct_mgmt(
    _pamh: *mut pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *mut *const c_char,
) -> c_int {
    PAM_SUCCESS
}

/// PAM session opening entry point
#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_open_session(
    _pamh: *mut pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *mut *const c_char,
) -> c_int {
    PAM_SUCCESS
}

/// PAM session closing entry point
#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_close_session(
    _pamh: *mut pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *mut *const c_char,
) -> c_int {
    PAM_SUCCESS
}

/// PAM password change entry point
#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_chauthtok(
    _pamh: *mut pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *mut *const c_char,
) -> c_int {
    PAM_SUCCESS
}
