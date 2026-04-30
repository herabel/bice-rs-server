use std::str;

use axum::{
    extract::{Json, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool};
use uuid::Uuid;

use crate::{server_db::ServerDB, vault};
use crate::entropy;

#[derive(Deserialize, Debug)]
pub struct RegisterRequest {
    login: String,
    password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct LoginRequest{
    login: String,
    password: String,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub user_id: Uuid,
    pub message: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub session: Session,
    pub message: String,
}

#[derive(Serialize, Deserialize)]
pub struct Session {
    pub session_token: Uuid,
    pub session_id: i32,
    pub user_id: Uuid,
}

impl Session {
    #[inline]
    pub fn token_as_bytes(&self) -> &[u8; 16] {
        self.session_token.as_bytes()
    }

    #[inline]
    pub fn id_as_bytes(&self) -> [u8; 4] {
        self.session_id.to_le_bytes()
    }

    #[inline]
    pub fn uid_as_bytes(&self) -> &[u8; 16] {
        self.user_id.as_bytes()
    }
}
/* NIST SP 800-63B, необходима проверка по базам
pub async fn check_password(password: String) -> bool{
    password.len() > 8
}
*/
pub async fn register(
    State(ctx): State<ServerDB>,
    Json(payload): Json<RegisterRequest>
) -> Result<Json<RegisterResponse>, StatusCode> {
    
    if payload.login.len() < 3 || payload.password.len() < 8 {
        return Err(StatusCode::BAD_REQUEST);
    }
    
    if user_exists(&payload.login, payload.email.as_deref(), &ctx.db).await? {
        return Err(StatusCode::CONFLICT);
    }

    let salt = entropy::generate_random_bytes(64);
    let hash_result = vault::get_master_key(&payload.password, &salt, vault::SecurityProfile::Standard)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let hash = hash_result;

    let user_id = create_user(&payload.login, &hash, payload.email.as_deref(), salt, &ctx.db).await?;
    
    Ok(Json(RegisterResponse {
        user_id,
        message: "User created".to_string(),
    }))
}

pub async fn login_user(
    State(ctx): State<ServerDB>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, StatusCode> {
    let user: (Uuid,Vec<u8>,Vec<u8>) = sqlx::query_as(
        r#"
        SELECT id,salt,password_hash FROM users WHERE login = $1
        "#
    ).bind(&payload.login).fetch_one(&ctx.db).await.map_err(|e| {
        println!("error while logging in : {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let payload_password_hash = vault::get_master_key(
        &payload.password, 
        &user.1,
        vault::SecurityProfile::Standard
    ).map_err(|e| {
        eprintln!("KDF error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if payload_password_hash.as_slice() != user.2 {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let session = create_session(user.0, &ctx.db).await?;
    Ok(Json(LoginResponse { session, message: ("login complete").to_string() }))
}

pub async fn create_session(
    user_id: Uuid,
    pool: &PgPool,
) -> Result<Session,StatusCode>{
    println!("creating new session for: {}", user_id);
    
    let session_id = Uuid::new_v4();

    let session: (i32,) = sqlx::query_as(
        r#"
        INSERT INTO sessions (session_token, user_id) values ($1,$2)
        returning id
        "#
    )
    .bind(session_id)
    .bind(user_id)
    .fetch_one(pool)
    .await.map_err(|e|{
        println!("error while creating session : {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    println!("session was created for user : {}", user_id);
    Ok(Session { session_token: session_id, session_id: session.0, user_id: user_id})
}

async fn user_exists(login: &str, email: Option<&str>, pool: &PgPool) -> Result<bool, StatusCode> {
    println!("user_exists: login={} email={:?}", login, email);
    
    //TODO: СДЕЛАТЬ ВАРИАТИВНОСТЬ EMAIL 

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM users WHERE login = $1 OR email IS NOT DISTINCT FROM $2"
    )
    .bind(login)
    .bind(email)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        println!("user_exists DB ERROR: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    println!("user_exists COUNT = {}", count);
    Ok(count > 0)
}


async fn create_user(
    login: &str,
    hash: &[u8],
    email: Option<&str>,
    salt: Vec<u8>,
    pool: &PgPool
) -> Result<Uuid, StatusCode> {
    println!("create_user: login={} hash_len={} email={:?}", login, hash.len(), email);
    
    let row: (Uuid,) = sqlx::query_as(
        r#"
        INSERT INTO users (login, password_hash, email, salt) 
        VALUES ($1, $2, $3, $4) 
        RETURNING id
        "#
    )
    .bind(login)
    .bind(hash)
    .bind(email)
    .bind(salt)
    .fetch_one(pool)
    .await
    .map_err(|e: sqlx::Error| {
        println!("create_user ERROR: {:?}", e);
        if e.to_string().contains("duplicate key") {
            StatusCode::CONFLICT
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    })?;

    println!("create_user ID = {}", row.0);
    Ok(row.0)
}