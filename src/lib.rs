pub mod client;
pub mod types;
pub mod error;

use crate::types::EnvConfig;
use crate::client::{ManageMentAccessToken, Jwks};
use crate::error::AuthError;

use std::sync::OnceLock;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};



static KEYS: OnceLock<Jwks> = OnceLock::new();
    
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct JWT(String);

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub iat: i32,
    pub exp: i32,
    pub gty: String,
    pub azp: String,
}

impl JWT {
    pub fn new(token: String) -> Self {
        Self(token)
    }

    pub fn access_token(&self) -> &str {
        &self.0
    }

    /// アクセストークンを検証
    pub fn validate(&self, secret: &EnvConfig) -> Result<Claims, AuthError> {
        let jwks = KEYS.get().ok_or(AuthError::NotFound("key".to_string()))?;
        let header = decode_header(self.access_token())?;
        let jwk = jwks.get_jwk(&header.kid.ok_or(AuthError::NotFound("kid".to_string()))?)?;
        let decoding_key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[&secret.aud]);
        validation.set_issuer(&[&secret.iss]);
        let token_data = decode::<Claims>(self.access_token(), &decoding_key, &validation)?;

        Ok(token_data.claims)
    }
}

/// Initialize the key
pub async fn key_init(secret: &EnvConfig) -> Result<(), AuthError> {
    // 管理APIアクセストークン取得
    let access_token = ManageMentAccessToken::get_access_token(
        secret.access_token_url.clone(), 
        secret.management_api_client_id.clone(), 
        secret.management_api_client_secret.clone(), 
        secret.management_api_audience.clone()
    ).await?;
    // JWKS取得
    let jwks = Jwks::new(
        secret.jwks_url.clone(), 
        access_token
    ).await?;

    KEYS.set(jwks).map_err(|_| AuthError::InvalidKeyset)
}
