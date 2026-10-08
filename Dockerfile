# syntax=docker/dockerfile:1.7
FROM rust:1.94.1-slim-bookworm AS builder

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates git pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /source
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src

RUN cargo build --frozen --release \
    && strip /source/target/release/hiro-proxy

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 65532 --home-dir /nonexistent --shell /usr/sbin/nologin hiro

COPY --from=builder --chown=65532:65532 /source/target/release/hiro-proxy /usr/local/bin/hiro-proxy

USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/hiro-proxy"]

