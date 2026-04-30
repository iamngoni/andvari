# syntax=docker/dockerfile:1.7
# ----------------------------------------------------------------------------
# Andvari server image — multi-stage, distroless final.
#
# Stage 1 (chef): plan a recipe of crate dependencies for a fast cache layer.
# Stage 2 (builder): cook the recipe (build deps), then build the workspace.
# Stage 3 (runtime): copy the static binary into a distroless image.
# ----------------------------------------------------------------------------

ARG RUST_VERSION=1.93.1
ARG DEBIAN_VERSION=bookworm

# ----------------------------------------------------------------------------
# Stage 1 — chef: produce a recipe.json describing dependency layout
# ----------------------------------------------------------------------------
FROM rust:${RUST_VERSION}-${DEBIAN_VERSION} AS chef
RUN cargo install cargo-chef --locked --version ^0.1
WORKDIR /work

FROM chef AS planner
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/
RUN cargo chef prepare --recipe-path recipe.json

# ----------------------------------------------------------------------------
# Stage 2 — builder: cook deps, then build the binary
# ----------------------------------------------------------------------------
FROM chef AS builder
COPY --from=planner /work/recipe.json recipe.json

# Cook the dependency layer (cached unless deps change).
RUN cargo chef cook --release --recipe-path recipe.json --bin andvari-server

# Now bring in the actual sources and build.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/

ENV SQLX_OFFLINE=true
RUN cargo build --release --bin andvari-server \
 && strip target/release/andvari-server

# ----------------------------------------------------------------------------
# Stage 3 — runtime: distroless, non-root, single binary
# ----------------------------------------------------------------------------
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

COPY --from=builder /work/target/release/andvari-server /usr/local/bin/andvari-server

USER nonroot:nonroot
EXPOSE 8080
ENV ANDVARI_BIND=0.0.0.0:8080 \
    RUST_LOG=info

ENTRYPOINT ["/usr/local/bin/andvari-server"]
