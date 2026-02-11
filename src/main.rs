mod auth;
mod ui;

slint::include_modules!();

fn main() -> Result<(), slint::PlatformError> {
    ui::run()
}
