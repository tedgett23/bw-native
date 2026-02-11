mod auth;
mod ui;

slint::include_modules!();

const SOFTWARE_FALLBACK_ENV: &str = "BW_NATIVE_SOFTWARE_FALLBACK";

fn main() -> Result<(), slint::PlatformError> {
    match std::panic::catch_unwind(ui::run) {
        Ok(run_result) => handle_run_result(run_result),
        Err(panic_payload) => {
            if should_retry_with_software_for_panic(&panic_payload) {
                return relaunch_with_software_renderer();
            }
            std::panic::resume_unwind(panic_payload);
        }
    }
}

fn handle_run_result(
    run_result: Result<(), slint::PlatformError>,
) -> Result<(), slint::PlatformError> {
    match run_result {
        Ok(()) => Ok(()),
        Err(error) if should_retry_with_software_for_error(&error) => {
            relaunch_with_software_renderer()
        }
        Err(error) => Err(error),
    }
}

fn should_retry_with_software_for_error(error: &slint::PlatformError) -> bool {
    if !can_retry_with_software() {
        return false;
    }

    is_gl_context_failure_message(&error.to_string())
}

fn should_retry_with_software_for_panic(panic_payload: &(dyn std::any::Any + Send)) -> bool {
    if !can_retry_with_software() {
        return false;
    }

    panic_message(panic_payload)
        .map(is_gl_context_failure_message)
        .unwrap_or(false)
}

fn can_retry_with_software() -> bool {
    std::env::var_os(SOFTWARE_FALLBACK_ENV).is_none() && std::env::var_os("SLINT_BACKEND").is_none()
}

fn is_gl_context_failure_message(message: &str) -> bool {
    let lowercase = message.to_ascii_lowercase();
    lowercase.contains("gl_version")
        || lowercase.contains("valid gl context")
        || lowercase.contains("opengl")
}

fn panic_message(panic_payload: &(dyn std::any::Any + Send)) -> Option<&str> {
    if let Some(message) = panic_payload.downcast_ref::<&str>() {
        return Some(message);
    }
    panic_payload.downcast_ref::<String>().map(String::as_str)
}

fn relaunch_with_software_renderer() -> Result<(), slint::PlatformError> {
    eprintln!("Retrying with Slint software renderer.");

    let current_exe = std::env::current_exe().map_err(|error| {
        slint::PlatformError::Other(format!("Failed to resolve current executable: {error}"))
    })?;

    let status = std::process::Command::new(current_exe)
        .args(std::env::args_os().skip(1))
        .env("SLINT_BACKEND", "software")
        .env(SOFTWARE_FALLBACK_ENV, "1")
        .status()
        .map_err(|error| {
            slint::PlatformError::Other(format!(
                "Failed to launch software fallback process: {error}"
            ))
        })?;

    std::process::exit(status.code().unwrap_or(1));
}
