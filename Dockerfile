# syntax=docker/dockerfile:1.7
FROM debian:bookworm-slim AS builder

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
       ca-certificates curl git build-essential pkg-config cmake perl python3 unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /source
COPY .bazelversion ./
COPY scripts/install-bazel ./scripts/install-bazel
RUN bash scripts/install-bazel /usr/local/bin

COPY MODULE.bazel MODULE.bazel.lock BUILD.bazel .bazelrc .bazelignore Cargo.toml Cargo.lock ./
COPY src ./src

RUN --mount=type=cache,target=/root/.cache/bazel,sharing=locked \
    bazel build --config=release --lockfile_mode=error //:hiro-proxy \
    && install -D -m 0755 bazel-bin/hiro-proxy /out/hiro-proxy

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 65532 --home-dir /nonexistent --shell /usr/sbin/nologin hiro

COPY --from=builder --chown=65532:65532 /out/hiro-proxy /usr/local/bin/hiro-proxy

USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/hiro-proxy"]
