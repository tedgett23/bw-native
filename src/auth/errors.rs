use super::models::TokenErrorResponse;

pub(super) fn extract_error_message(response_body: &str) -> String {
    if response_body.trim().is_empty() {
        return "No details returned by server.".to_string();
    }

    if let Ok(error_response) = serde_json::from_str::<TokenErrorResponse>(response_body) {
        if let Some(description) = error_response.error_description {
            if !description.trim().is_empty() {
                return description;
            }
        }
        if let Some(message) = error_response.message {
            if !message.trim().is_empty() {
                return message;
            }
        }
        if let Some(error) = error_response.error {
            if !error.trim().is_empty() {
                return error;
            }
        }
    }

    response_body
        .lines()
        .next()
        .unwrap_or("Unknown error")
        .to_string()
}
