mod vault;
mod entropy;
mod cpu_entropy;
mod registration;
mod sessions;
mod trust_channel;
mod server_db;

use axum::{
    extract::{Path, State},
    Json, Router, http::StatusCode, response::IntoResponse, routing::{get, post},
};

use uuid::Uuid;
use serde_json::{json};
use sqlx::PgPool;
use std::env;
use dotenv::dotenv;

use crate::{registration::login_user, server_db::ServerDB};

#[derive(Debug)]
#[allow(unused)]
enum ApiError {
    NotFound,
    InvalidInput(String),
    InternalError,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let (status, error_message) = match self {
            ApiError::NotFound => (
                StatusCode::NOT_FOUND, "Data not found".to_string(),
            ),
            ApiError::InvalidInput(msg) => (
                StatusCode::BAD_REQUEST, msg,
            ),
            ApiError::InternalError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string()
            ),
        };
        
        let body = Json(json!({
            "error": error_message,
        }));

        (status, body).into_response()
    }
}

async fn health_check() -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "message": "Server is running",
    }))
}

async fn info() -> impl IntoResponse {
    Json(json!({
        "body": "This is syncronization server for Rust Password Manager project. Currently private.
                GITHUB: https://github.com/herabel
                Version: 0.0.1 (alpha)",
    }))
}

async fn list_users(_: State<ServerDB>) -> Result<Json<serde_json::Value>, ApiError> {
    Err(ApiError::InternalError)
}

async fn get_user(
    State(_ctx): State<ServerDB>,
    Path(uuid): Path<Uuid>
) -> Result<Json<serde_json::Value>, ApiError> {
    if !uuid.to_string().starts_with('1') {
        return Err(ApiError::NotFound);
    }

    Ok(Json(json!({"id": uuid, "name": "User"})))
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    let pool = PgPool::connect(&env::var("DATABASE_URL").expect("DATABASE_URL required"))
        .await
        .expect("Failed to connect to DB");

    let client_redis = redis::Client::open("redis://bice_cache/").expect("Couldn't create redis client");
    let con = client_redis.get_multiplexed_async_connection().await.expect("Couldn't open redis connection");

    let databases = ServerDB{
        db: pool,
        redis: con,
    };

    let app = Router::new()
        .route("/api/v1", get(info))
        .route("/api/v1/health", get(health_check))
        .route("/api/v1/users", get(list_users))
        .route("/api/v1/users/{id}", get(get_user))
        .route("/api/v1/users/register", post(registration::register))
        .route("/api/v1/users/login", get(login_user))
        .route("/api/v1/sync/handshake", post(trust_channel::secure_channel))
        .route("/api/v1/sync/", post(trust_channel::sync))
        .with_state(databases);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("failed to bind tcp listener");
    
    println!("Server running on http://0.0.0.0:3000");
    println!("Health: http://0.0.0.0:3000/health");
    println!("Register: POST http://0.0.0.0:3000/users/register");
    
    axum::serve(listener, app).await.unwrap();
}
