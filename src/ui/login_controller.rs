use std::thread;

use slint::ComponentHandle;

pub(super) fn attach_handlers(window: &crate::MainWindow) {
    let weak_window = window.as_weak();

    window.on_login_requested(move || {
        let Some(window) = weak_window.upgrade() else {
            return;
        };

        if window.get_is_logging_in() {
            return;
        }

        let server_url = window.get_server_url().to_string();
        let username = window.get_username().to_string();
        let password = window.get_password().to_string();

        window.set_status_is_error(false);
        window.set_status_text("Logging in...".into());
        window.set_is_logging_in(true);

        let weak_for_thread = weak_window.clone();
        thread::spawn(move || {
            let result = crate::auth::try_login(&server_url, &username, &password);

            let _ = slint::invoke_from_event_loop(move || {
                if let Some(window) = weak_for_thread.upgrade() {
                    window.set_is_logging_in(false);
                    match result {
                        Ok(()) => {
                            window.set_status_is_error(false);
                            window.set_status_text("Login successful.".into());
                            window.set_password("".into());
                        }
                        Err(error) => {
                            window.set_status_is_error(true);
                            window.set_status_text(error.into());
                        }
                    }
                }
            });
        });
    });
}
