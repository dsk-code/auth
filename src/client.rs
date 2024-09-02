use std::{collections::HashMap, time::Duration};

use reqwest::{header::CONTENT_TYPE, Client};
use serde::{Deserialize, Serialize};

use crate::error::AuthError;

/// Auth0管理APIのアクセストークンのレスポンスを表現する構造体
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManageMentAccessToken {
    pub access_token: String,
    pub expires_in: i32,
    pub scope: String,
    pub token_type: String,
}

impl ManageMentAccessToken {
    pub async fn get_access_token(url: String, client_id: String, client_secret: String, audience: String) -> Result<Self, reqwest::Error> {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("Failed to build client");

        let mut params = HashMap::new();
        params.insert("grant_type".to_string(), "client_credentials".to_string());
        params.insert("client_id".to_string(), client_id);
        params.insert("client_secret".to_string(), client_secret);
        params.insert("audience".to_string(), audience);

        let response = client
            .post(&url)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .form(&params)
            .send()
            .await?
            .json::<ManageMentAccessToken>()
            .await?;

        Ok(response)
    }
}

#[derive(Debug)]
pub struct AccessTokenClient {
    url: String,
    client: Client,
    params: HashMap<String, String>,
}

impl AccessTokenClient {
    pub fn new(url: String, client_id: String, client_secret: String, audience: String) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("Failed to build client");

        let mut params = HashMap::new();
        params.insert("grant_type".to_string(), "client_credentials".to_string());
        params.insert("client_id".to_string(), client_id);
        params.insert("client_secret".to_string(), client_secret);
        params.insert("audience".to_string(), audience);

        AccessTokenClient {
            url,
            client,
            params,
        }
    }

    pub async fn get<T: serde::de::DeserializeOwned>(&self) -> Result<T, reqwest::Error> {
        let response = self.client
            .post(&self.url)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .form(&self.params)
            .send()
            .await?
            .json::<T>()
            .await?;

        Ok(response)

    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

impl Jwks {
    pub async fn new(url: String, token: ManageMentAccessToken) -> Result<Self, reqwest::Error> {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("Failed to build client");

        let response = client
            .get(&url)
            .bearer_auth(&token.access_token)
            .send()
            .await?
            .json::<Jwks>()
            .await?;

        Ok(response)
    }

    /// kidに対応したJWKを返す
    pub fn get_jwk(&self, kid: &str) -> Result<Jwk, AuthError> {
        let jwk = self.keys
            .iter()
            .find(|key| &key.kid == kid)
            .cloned()
            .ok_or(AuthError::NotFound("JWK".to_string()));

        jwk
    }
}