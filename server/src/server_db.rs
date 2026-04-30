use redis::aio::MultiplexedConnection;
use sqlx::PgPool;

#[derive(Clone)]
pub struct ServerDB{
    pub db: PgPool,
    pub redis: MultiplexedConnection,
}