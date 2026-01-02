use thiserror::Error;

#[async_trait::async_trait]
pub trait MessageDeliveryService: Send + Sync {
    async fn send_message(
        &self,
        recipient: &str,
        message: &str,
    ) -> Result<(), MessageDeliveryError>;
}

#[derive(Debug, Error)]
pub enum MessageDeliveryError {
    ServiceUnavailable,
    InvalidRecipient,
    MessageTooLong,
    Unknown,
}

impl std::fmt::Display for MessageDeliveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageDeliveryError::ServiceUnavailable => write!(f, "Service is unavailable"),
            MessageDeliveryError::InvalidRecipient => write!(f, "Invalid recipient"),
            MessageDeliveryError::MessageTooLong => write!(f, "Message is too long"),
            MessageDeliveryError::Unknown => write!(f, "Unknown error"),
        }
    }
}

const WHATSAPP_PHONE_ID: &str = "940408239151860";
const WHATSAPP_API_URL: &str = "https://graph.facebook.com/v24.0/";

pub struct WhatsAppMessageDeliveryService {
    http_client: reqwest::Client,
    api_key: String,
}

impl WhatsAppMessageDeliveryService {
    pub fn new(api_key: String) -> Self {
        Self {
            http_client: reqwest::Client::new(),
            api_key,
        }
    }
}

#[async_trait::async_trait]
impl MessageDeliveryService for WhatsAppMessageDeliveryService {
    async fn send_message(
        &self,
        recipient: &str,
        message: &str,
    ) -> Result<(), MessageDeliveryError> {
        // WhatsApp template payload as required
        let payload = serde_json::json!({
            "messaging_product": "whatsapp",
            "to": recipient,
            "type": "template",
            "template": {
                "name": "yral_auth",
                "language": {
                    "code": "en_IN"
                },
                "components": [
                    {
                        "type": "body",
                        "parameters": [
                            {
                                "type": "text",
                                "text": message
                            }
                        ]
                    },
                    {
                        "type": "button",
                        "sub_type": "url",
                        "index": "0",
                        "parameters": [
                            {
                                "type": "text",
                                "text": message
                            }
                        ]
                    }
                ]
            }
        });

        let url = format!("{}{}{}", WHATSAPP_API_URL, WHATSAPP_PHONE_ID, "/messages");
        let response = self
            .http_client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&payload)
            .send()
            .await
            .map_err(|_| MessageDeliveryError::ServiceUnavailable)?;

        if response.status().is_success() {
            Ok(())
        } else if response.status().as_u16() == 400 {
            Err(MessageDeliveryError::InvalidRecipient)
        } else if response.status().as_u16() == 413 {
            Err(MessageDeliveryError::MessageTooLong)
        } else {
            Err(MessageDeliveryError::Unknown)
        }
    }
}
