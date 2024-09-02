use serde::{Serialize, Deserialize};

/// Auth0APIのアクセストークンのレスポンスを表現する構造体
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppAccessToken {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i32,
}

/// Auth0のJWKのレスポンスを表現する構造体
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Jwk {
    pub alg: String,
    pub kty: String,
    pub r#use: String,
    pub x5c: Vec<String>,
    pub n: String,
    pub e: String,
    pub kid: String,
    pub x5t: String,
}

/// Auth0のJWKSのレスポンスを表現する構造体
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

/// アクストークンのClaimsを表現する構造体
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub iat: i32,
    pub exp: i32,
    pub gty: String,
    pub azp: String,
}

/// 環境変数
#[derive(Debug, Deserialize)]
pub struct EnvConfig {
    pub access_token_url: String,
    pub management_api_client_id: String,
    pub management_api_client_secret: String,
    pub management_api_audience: String,
    pub app_api_client_id: String,
    pub app_api_client_secret: String,
    pub app_api_audience: String,
    pub jwks_url: String,
    pub aud: String,
    pub iss: String,
}
