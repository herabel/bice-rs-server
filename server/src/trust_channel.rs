use std::{fmt::Debug};

use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
use pqcrypto_traits::{
    self,
    kem::{Ciphertext, PublicKey, SharedSecret},
};

use axum::{extract::State};
use axum::{extract::Json, http::StatusCode};
use pqcrypto_kyber::{
    self,
    kyber1024::{self},
};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use serde_bytes;
use sqlx::{PgPool, types::chrono::{self, DateTime, Utc}};
use tiny_keccak::{Hasher, Shake, Xof};
use uuid::{Uuid};
use x25519_dalek::{self, EphemeralSecret};

use crate::{
    entropy::{self}, registration::{self, Session}, server_db::ServerDB, sessions
};

#[derive(Serialize, Deserialize)]
pub struct HandshakeRequest {
    session: registration::Session,
    #[serde(with = "serde_bytes")]
    kyber_pub: [u8; 1568],
    #[serde(with = "serde_bytes")]
    x25519_pub: [u8; 32],
}

#[derive(Serialize)]
pub struct HandshakeResponse {
    #[serde(with = "serde_bytes")]
    x25519_pub: [u8; 32],
    #[serde(with = "serde_bytes")]
    cipher_text: [u8; 1568],
    auth_tag: [u8; 16],
}

#[derive(Serialize, Deserialize)]
pub struct SyncRequest{
    session: Session,
    nonce: [u8;24],
    ciphertext: Vec<u8>,
    timestamp: u64
}

#[derive(Serialize)]
pub struct SyncResponse{
    nonce: [u8;24],
    ciphertext: Vec<u8>,
}

#[derive(Serialize)]
struct PushResponsePayload {
    status: String,
    version: i32,
    server_time: i64,
}

#[derive(Serialize,Deserialize)]
struct PullResponsePayload{
    status: String,
    file_bytes: Vec<u8>,
    server_time: i64
}

pub async fn generate_x25519_sec() -> EphemeralSecret {
    let mut pool = entropy::HardwareEntropyPool::new();
    x25519_dalek::EphemeralSecret::random_from_rng(&mut pool)
}

#[derive(Debug,Serialize,Deserialize)]
pub struct RedisInternal{
    #[serde(with="serde_bytes")]
    kdf: [u8;64],
    user_id: Uuid
}

#[axum::debug_handler]
pub async fn secure_channel(
    State(ctx): State<ServerDB>,
    Json(payload): Json<HandshakeRequest>,
) -> Result<Json<HandshakeResponse>, StatusCode> {
    let session = &payload.session;
    if !sessions::verify_session(&session, &ctx.db).await? {
        Err(StatusCode::UNAUTHORIZED)
    } else {
        let x25519_sec = generate_x25519_sec().await;
        let x25519_pub = x25519_dalek::PublicKey::from(&x25519_sec);
        let x25519_payload_pub: x25519_dalek::PublicKey =
            x25519_dalek::PublicKey::from(payload.x25519_pub);
        let x25519_shared_secret = x25519_sec.diffie_hellman(&x25519_payload_pub);
        let kyber_payload_pub: kyber1024::PublicKey =
            kyber1024::PublicKey::from_bytes(&payload.kyber_pub).map_err(|e| {
                println!("error while kyber_payload_pub : {}", e);
                StatusCode::BAD_REQUEST
            })?;
        let kyber_pk = kyber_payload_pub.try_into().map_err(|e| {
            println!("error while kyber_pk : {}", e);
            StatusCode::BAD_REQUEST
        })?;
        let kyber_shared_secret_pair = pqcrypto_kyber::kyber1024_encapsulate(&kyber_pk);

        let mut hasher = Shake::v256();

        hasher.update("BICE_v1_Handshake_SHAKE256".as_bytes());
        hasher.update(x25519_shared_secret.as_bytes());
        hasher.update(kyber_shared_secret_pair.0.as_bytes());
        hasher.update(payload.session.token_as_bytes());
        hasher.update(&payload.session.id_as_bytes());
        hasher.update(payload.session.uid_as_bytes());

        let mut kdf_buf = [0u8; 64];
        hasher.squeeze(&mut kdf_buf);
        let mut auth_tag = [0u8; 16];
        hasher.squeeze(&mut auth_tag);

        let cipher_text: [u8; 1568] =
            kyber_shared_secret_pair
                .1
                .as_bytes()
                .try_into()
                .map_err(|e| {
                    println!("[SECURE] {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;

        let output = HandshakeResponse {
            x25519_pub: *x25519_pub.as_bytes(),
            cipher_text: cipher_text,
            auth_tag: auth_tag,
        };



        let redis_key = format!("bice:hs:{}", payload.session.session_token);
        let internals = postcard::to_allocvec(&RedisInternal{kdf: kdf_buf, user_id: payload.session.user_id}).map_err(|e| {
            eprintln!("[SYNC] {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        let _: () = ctx
            .redis
            .clone()
            .set_ex(redis_key, internals, 60 * 10)
            .await
            .map_err(|e| {
                eprintln!("[REDIS] {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        Ok(Json(output))
    }
}

pub async fn sync(
    State(mut ctx): State<ServerDB>,
    Json(payload): Json<SyncRequest>,
) -> Result<Json<SyncResponse>, StatusCode> {
    let sync_session_key = format!("bice:hs:{}", payload.session.session_token);
    let raw_data: Option<Vec<u8>> = ctx.redis.get(sync_session_key).await.map_err(|e| {
        eprintln!("[SYNC] {}", e);
        StatusCode::UNAUTHORIZED
    })?;

    let session_data: RedisInternal = postcard::from_bytes(&raw_data.ok_or(StatusCode::UNAUTHORIZED)?).map_err(|e|{
        eprintln!("[SYNC] {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    #[derive(Serialize, Deserialize)]
    #[serde(tag = "type")]
    enum SyncCommand {
        Pull { version: i32 },
        Push { encrypted_blob: Vec<u8> },
        DeleteAccount,
        GetVersions
    }

    let key_vec = session_data.kdf;

    let key = Key::from_slice(&key_vec[..32]);
    let nonce = XNonce::from_slice(&payload.nonce);
    let cipher = XChaCha20Poly1305::new(key);

    let decrypted_data = XChaCha20Poly1305::decrypt(&cipher, nonce, payload.ciphertext.as_ref()).map_err(|e| {
        eprintln!("[SYNC] {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let command: SyncCommand = serde_json::from_slice(&decrypted_data).map_err(|_| StatusCode::BAD_REQUEST)?;

    match command {
        SyncCommand::Pull { version } => {
            let user_dir = format!("storage/{}", session_data.user_id);
            let _ = tokio::fs::read_dir(&user_dir).await.map_err(|_| StatusCode::NOT_FOUND)?;

            let file_path = format!("{}/{}.bin",user_dir,version);
            let raw_file = tokio::fs::read(file_path).await.map_err(|e| {
                eprintln!("[SYNC] Error while read in pull | {} | for {} session | user {}", e, payload.session.session_id, payload.session.user_id);
                StatusCode::NOT_FOUND
            })?;
            
            let raw_nonce = entropy::generate_random_bytes(24);
            let nonce: [u8;24] = raw_nonce.try_into().map_err(|_| {
                StatusCode::INTERNAL_SERVER_ERROR
            })?; 

            let response_cipher_nonce = XNonce::from_slice(&nonce);

            let raw_ciphertext = PullResponsePayload{status: "OK".to_string(), file_bytes: raw_file, server_time: chrono::DateTime::timestamp(&Utc::now())};
            let serialized_ciphertext = postcard::to_allocvec(&raw_ciphertext).map_err(|e| {
                eprintln!("[SYNC PULL] {e}");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            let encrypted_ciphertext = XChaCha20Poly1305::encrypt(&cipher, response_cipher_nonce, serialized_ciphertext.as_ref()).map_err(|e| {
                eprintln!("[SYNC PULL] {e}");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            Ok(Json(SyncResponse { nonce: (nonce), ciphertext: (encrypted_ciphertext) }))
        },
        SyncCommand::Push { encrypted_blob } => {
            let user_dir = format!("storage/{}", session_data.user_id);
            tokio::fs::create_dir_all(&user_dir).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            let file_path = format!("{}/upload_{}.bin", user_dir, payload.session.session_token);
            tokio::fs::write(&file_path, encrypted_blob).await.map_err(|e| {
                eprintln!("[SYNC] Error while file write | {} | for {} session | user {}", e, payload.session.session_id, payload.session.user_id);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            let new_version = register_new_version(&ctx.db, payload.session, &file_path).await?;
            tokio::fs::rename(&file_path, format!("{}/{}.bin", user_dir, new_version.version)).await.map_err(|e| {
                eprintln!("[SYNC] Error while file push | {e} | rename");
                let _ = tokio::fs::remove_file(file_path);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
            let file_version_response = new_version.version;
            let server_time_response: DateTime<Utc> = new_version.datetime;

            let raw_nonce = entropy::generate_random_bytes(24);
            let nonce: [u8;24] = raw_nonce.try_into().map_err(|_| {
                StatusCode::INTERNAL_SERVER_ERROR
            })?; 
            let raw_ciphertext = PushResponsePayload{status: "OK".to_string(), version: file_version_response, server_time: server_time_response.timestamp()};
            let response_ciphertext_serialized = postcard::to_allocvec(&raw_ciphertext).map_err(|e| {
                eprintln!("[SYNC] {e}");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            let response_cipher_nonce = XNonce::from_slice(&nonce);
            let response_ciphertext_encrypted = XChaCha20Poly1305::encrypt(&cipher, response_cipher_nonce, response_ciphertext_serialized.as_ref()).map_err(|e| {
                eprintln!("[SYNC] {e}");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            Ok(Json(SyncResponse{nonce: nonce, ciphertext: response_ciphertext_encrypted}))
        },
        SyncCommand::GetVersions{  } => {
            let versions = get_versions(&ctx.db, &payload.session).await?;
            let nonce = generate_nonce().await.map_err(|e| {
                eprintln!("[NONCE | SYNC (GV)] Error while generating nonce for SYNC {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            let ciphertext = postcard::to_allocvec(&versions).map_err(|_| {
                eprintln!("[SYNC(GV)] Error while ciphertext");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            let encrypted_cipher = XChaCha20Poly1305::encrypt(&cipher, &nonce, ciphertext.as_ref()).map_err(|e| {
                eprintln!("[encrypt | SYNC] {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            Ok(Json(SyncResponse { nonce: (nonce).into(), ciphertext: (encrypted_cipher) }))
        },
        _ => return Err(StatusCode::NOT_IMPLEMENTED),
    }
}

#[derive(sqlx::FromRow)]
struct NewVersionRow {
    version: i32,
    datetime: chrono::DateTime<chrono::Utc>,
}

async fn register_new_version(
    pool: &PgPool,
    session: Session,
    file_path: &str
) -> Result<NewVersionRow,StatusCode>{
    
    sqlx::query_as::<_, NewVersionRow>(
        r#"
        INSERT INTO files (user_id, file_path, version, datetime)
        VALUES (
            $1, 
            $2, 
            (SELECT COALESCE(MAX(version), 0) + 1 FROM files WHERE user_id = $1), 
            NOW()
        )
        RETURNING version, datetime;
        "#
    )
    .bind(session.user_id)
    .bind(file_path)
    .fetch_one(pool) 
    .await
    .map_err(|e| {
        eprintln!("[DB ERROR] {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })
}

async fn get_versions(
    pool: &PgPool,
    session: &Session,
) -> Result<Vec<i32>,StatusCode> {
    let versions: Vec<i32> = sqlx::query_scalar(
        r#"
        SELECT version 
        FROM files 
        WHERE user_id = $1
        ORDER BY version ASC
        "#
    )
    .bind(&session.user_id)
    .fetch_all(pool)
    .await
    .map_err(|e| {
        eprintln!("[DB] Error fetching versions: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(versions)
}

async fn generate_nonce() -> Result<XNonce, StatusCode> {
    let raw_nonce = entropy::generate_random_bytes(24);
    let nonce: [u8;24] = raw_nonce.try_into().map_err(|_| {
        StatusCode::INTERNAL_SERVER_ERROR
    })?; 
    Ok(*XNonce::from_slice(&nonce))
}