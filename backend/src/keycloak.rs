use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use anyhow::{Context, Result};
use tokio::sync::RwLock;
use tracing::{info, warn};

pub struct KeycloakValidator {
    url: String,
    realm: String,
    pub client_id: String,
    jwks: RwLock<Option<JwkSet>>,
}

impl KeycloakValidator {
    pub fn new(url: String, realm: String, client_id: String) -> Self {
        Self { url, realm, client_id, jwks: RwLock::new(None) }
    }

    pub async fn init_and_fetch(&self) -> Result<()> {
        let jwks_url = format!("{}/realms/{}/protocol/openid-connect/certs", self.url.trim_end_matches('/'), self.realm);
        info!("Fetching Keycloak JWKS from: {}", jwks_url);
        
        // Wait up to 5 seconds to fetch the JWKS on boot to prevent hanging forever
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()?;
            
        let res = client.get(&jwks_url).send().await.context("Failed to fetch JWKS")?;
        let jwks: JwkSet = res.json().await.context("Failed to parse JWKS JSON")?;
        
        *self.jwks.write().await = Some(jwks);
        info!("Successfully loaded Keycloak JWKS configuration");
        Ok(())
    }

    pub async fn validate_token(&self, token: &str) -> Result<bool> {
        let header = decode_header(token).context("Invalid JWT header")?;
        let kid = header.kid.ok_or_else(|| anyhow::anyhow!("JWT header without 'kid' block"))?;

        let jwks_read = self.jwks.read().await;
        let jwks = jwks_read.as_ref().ok_or_else(|| anyhow::anyhow!("JWKS not yet loaded from Keycloak Server"))?;

        let jwk = jwks.find(&kid).ok_or_else(|| anyhow::anyhow!("JWK not found for kid: {}", kid))?;

        let decoding_key = DecodingKey::from_jwk(jwk).context("Failed to create decoding key from JWK")?;
        
        let mut validation = Validation::new(Algorithm::RS256);
        
        // --- SECURITY FIX: Validate Audience and Issuer ---
        // 1. Set the expected Audience (the client_id used for this VPN service)
        validation.set_audience(&[&self.client_id]);
        validation.validate_aud = true;

        // 2. Set the expected Issuer (the Keycloak realm URL)
        let issuer = format!("{}/realms/{}", self.url.trim_end_matches('/'), self.realm);
        validation.set_issuer(&[&issuer]);

        match decode::<serde_json::Value>(token, &decoding_key, &validation) {
            Ok(_) => Ok(true),
            Err(e) => {
                warn!("JWT Validation failed: {}", e);
                Ok(false)
            }
        }
    }
}
