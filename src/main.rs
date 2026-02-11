mod auth;
mod ui;

slint::include_modules!();

const SOFTWARE_FALLBACK_ENV: &str = "BW_NATIVE_SOFTWARE_FALLBACK";
const SOFTWARE_BACKEND_VALUE: &str = "winit-software";

fn main() -> Result<(), slint::PlatformError> {
    match std::panic::catch_unwind(ui::run) {
        Ok(run_result) => handle_run_result(run_result),
        Err(panic_payload) => {
            if should_retry_with_software_for_panic() {
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
        Err(error) if should_retry_with_software_for_error() => relaunch_with_software_renderer(),
        Err(error) => Err(error),
    }
}

fn should_retry_with_software_for_error() -> bool {
    can_retry_with_software() && !is_software_backend_requested()
}

fn should_retry_with_software_for_panic() -> bool {
    can_retry_with_software() && !is_software_backend_requested()
}

fn can_retry_with_software() -> bool {
    std::env::var_os(SOFTWARE_FALLBACK_ENV).is_none()
}

fn is_software_backend_requested() -> bool {
    let Some(value) = std::env::var_os("SLINT_BACKEND") else {
        return false;
    };

    let lowercase = value.to_string_lossy().to_ascii_lowercase();
    lowercase == "sw"
        || lowercase == "software"
        || lowercase.ends_with("-sw")
        || lowercase.ends_with("-software")
}

fn relaunch_with_software_renderer() -> Result<(), slint::PlatformError> {
    eprintln!("Retrying with Slint software renderer ({SOFTWARE_BACKEND_VALUE}).");

    let current_exe = std::env::current_exe().map_err(|error| {
        slint::PlatformError::Other(format!("Failed to resolve current executable: {error}"))
    })?;

    let status = std::process::Command::new(current_exe)
        .args(std::env::args_os().skip(1))
        .env("SLINT_BACKEND", SOFTWARE_BACKEND_VALUE)
        .env(SOFTWARE_FALLBACK_ENV, "1")
        .status()
        .map_err(|error| {
            slint::PlatformError::Other(format!(
                "Failed to launch software fallback process: {error}"
            ))
        })?;

    std::process::exit(status.code().unwrap_or(1));
}
