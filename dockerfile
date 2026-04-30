FROM rust:bookworm AS builder
WORKDIR /build
COPY server/Cargo.lock server/Cargo.toml ./
COPY server/src/ ./src/
RUN cargo build --release

FROM debian:bookworm-slim AS runner
COPY --from=builder build/target/release/password-manager-server ./
EXPOSE 3000
CMD ["./password-manager-server"]