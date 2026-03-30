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

        let jwk = jwks.find(&kid).ok_or_else(|| {
            warn!("Token kid '{}' not found in cached JWKS. Available kids: {:?}",
                kid, jwks.keys.iter().filter_map(|k| k.common.key_id.as_ref()).collect::<Vec<_>>());
            anyhow::anyhow!("JWK not found for kid: {}", kid)
        })?;

        let decoding_key = DecodingKey::from_jwk(jwk).context("Failed to create decoding key from JWK")?;
        
        let mut validation = Validation::new(Algorithm::RS256);
        
        // Keycloak access tokens have aud:"account" by default, NOT the client_id.
        // The client_id is in the "azp" (authorized party) claim.
        // So we disable built-in audience validation and check azp manually below.
        validation.validate_aud = false;

        // Increased leeway to 300 seconds to compensate for any server/auth clock differences.
        validation.leeway = 300;

        // Validate the issuer (the Keycloak realm URL)
        let issuer = format!("{}/realms/{}", self.url.trim_end_matches('/'), self.realm);
        validation.set_issuer(&[&issuer]);

        // Robust Debug: Manually decode the second part of the JWT (the payload)
        // This is always valid Base64 JSON and doesn't require a key.
        let token_parts: Vec<&str> = token.split('.').collect();
        if token_parts.len() >= 2 {
            if let Ok(payload_bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(token_parts[1]) {
                if let Ok(claims) = serde_json::from_slice::<serde_json::Value>(&payload_bytes) {
                    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
                    let exp = claims.get("exp").and_then(|v| v.as_u64()).unwrap_or(0);
                    let iat = claims.get("iat").and_then(|v| v.as_u64()).unwrap_or(0);
                    info!("JWT Debug: now={}, iat={}, exp={}, expires_in={}s, diff_iat={}s, azp={}",
                        now, iat, exp,
                        if exp > now { (exp - now) as i64 } else { -((now - exp) as i64) },
                        (now as i64) - (iat as i64),
                        claims.get("azp").and_then(|v| v.as_str()).unwrap_or("?"),
                    );
                }
            }
        }

        match decode::<serde_json::Value>(token, &decoding_key, &validation) {
            Ok(token_data) => {
                // Manually validate "azp" (authorized party) = our client_id
                let claims = &token_data.claims;
                let azp = claims.get("azp").and_then(|v| v.as_str()).unwrap_or("");
                if azp != self.client_id {
                    warn!("JWT azp mismatch: expected '{}', got '{}'", self.client_id, azp);
                    return Ok(false);
                }

                info!("Keycloak JWT validated successfully (sub: {}, azp: {})",
                    claims.get("sub").and_then(|v| v.as_str()).unwrap_or("?"), azp);
                Ok(true)
            }
            Err(e) => {
                warn!("JWT validation failed: {}", e);
                Ok(false)
            }
        }
    }
}
