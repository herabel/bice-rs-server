# bice-rs-server
A rust server for bice-rs project that implements:
- registration
- login
- pull/push
- versioning of users databases
- KyberX25519 handshake and channel protection via XChaCha20-poly1305

## Requirements
git & docker

## Launch
1. Clone git repository: `git clone https://github.com/herabel/bice-rs-server`<br/>
2. To run this server you *must* edit the `.env.example` and rename it to `.env`<br/>
3. Then you can run this server by using `docker compose up --build -d app` via terminal in your folder<br/>

then check the `docker ps` to ensure that server works fine. server works on 3000 port by default, but you can change it by modifying dockerfile or using reverse-proxy like nginx

## Data storage
Users databases stored using {version}.bin (e.g. 1.bin / 4.bin) in {user_id} folder
