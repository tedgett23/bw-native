mod login_controller;

use slint::ComponentHandle;

pub fn run() -> Result<(), slint::PlatformError> {
    let main_window = crate::MainWindow::new()?;
    login_controller::attach_handlers(&main_window);
    main_window.run()
}
