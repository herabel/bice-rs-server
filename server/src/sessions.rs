use sqlx::{PgPool};
use axum::{
    http::StatusCode,
};

use crate::registration::Session;

pub async fn verify_session(session: &Session, pool: &PgPool) -> Result<bool, StatusCode>{
    println!("session verify: session={} w id={}", session.session_token, session.session_id);

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sessions WHERE session_token = $1"
    ).bind(session.session_token).fetch_one(pool).await.map_err(|e| {
        println!("verify_session DB ERROR: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    println!("verify_session COUNT = {}", count);
    Ok(count > 0)
}