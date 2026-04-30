# Andvari task runner. Run `just` to list tasks.
set shell := ["bash", "-cu"]
set dotenv-load

default:
    @just --list

# ---------- build & test ----------------------------------------------------

# Build everything in debug mode.
build:
    cargo build --workspace

# Build everything in release mode.
build-release:
    cargo build --workspace --release

# Run all tests.
test:
    cargo test --workspace --all-features

# Format the entire workspace.
fmt:
    cargo fmt --all

# Lint with clippy, deny warnings.
lint:
    cargo clippy --workspace --all-targets --all-features -- -D warnings

# Run rustfmt + clippy in check mode (CI-style).
check:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets --all-features -- -D warnings

# Run cargo-deny (advisories, licenses, bans, sources).
deny:
    cargo deny check

# ---------- run -------------------------------------------------------------

# Run the server locally (expects ANDVARI_DATABASE_URL + ANDVARI_ROOT_KEY).
server:
    cargo run -p andvari-server

# Run the CLI locally with passthrough args, e.g. `just cli config`.
cli *args:
    cargo run -p andvari-cli -- {{args}}

# ---------- docker ----------------------------------------------------------

# Start the full stack (postgres + andvari) in the foreground.
up:
    docker compose up --build

# Start the full stack in the background.
up-d:
    docker compose up -d --build

# Stop everything.
down:
    docker compose down

# Stop everything AND wipe the postgres volume. Destructive — confirm intent.
down-hard:
    docker compose down -v

# Tail server logs.
logs:
    docker compose logs -f andvari

# Open a psql shell against the running postgres container.
psql:
    docker compose exec postgres psql -U andvari -d andvari
