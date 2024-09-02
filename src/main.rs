use auth::{key_init, JWT};
use auth::client::AccessTokenClient;
use auth::types::{
    EnvConfig,
    AppAccessToken,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv()?;
    let secret = envy::from_env::<EnvConfig>()?;

    let _set = key_init(&secret).await?;

    let app_api_client = AccessTokenClient::new(
            secret.access_token_url.clone(), 
            secret.app_api_client_id.clone(), 
            secret.app_api_client_secret.clone(), 
            secret.app_api_audience.clone()
        );
    let app_api_access_token: AppAccessToken = app_api_client
        .get()
        .await?;

    let access_token = JWT::new(app_api_access_token.access_token);
    let claims = access_token.validate(&secret);
    println!("claims = {:?}", claims.unwrap());
    
    Ok(())
}
