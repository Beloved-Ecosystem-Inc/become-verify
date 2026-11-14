#!/usr/bin/env bash
# Build the browser checker reproducibly: wasm/pkg/become_verify_wasm_bg.wasm and its JavaScript loader.
# The same source (this commit), Rust toolchain (../rust-toolchain.toml) and wasm-bindgen version give the same bytes;
# CI rebuilds it and compares with wasm/SHA256SUMS.
# Cargo mixes a path dependency's folder into symbol names, so the source is copied to one fixed folder
# (/tmp/become-verify-wasm-build/become-verify) and built there, and local paths are mapped away.
set -euo pipefail
cd "$(dirname "$0")/.."
WB=0.2.100
command -v wasm-bindgen >/dev/null && wasm-bindgen --version | grep -q " $WB\$" || {
  echo "needs wasm-bindgen-cli $WB: cargo install wasm-bindgen-cli --version $WB --locked" >&2; exit 2; }
B=/tmp/become-verify-wasm-build
rm -rf "$B" && mkdir -p "$B/become-verify"
tar --exclude=./target --exclude=./wasm/target --exclude=./wasm/pkg --exclude=./.git -cf - . | tar -C "$B/become-verify" -xf -
OLDPWD_WASM="$PWD/wasm"
cd "$B/become-verify/wasm"
rustup target add wasm32-unknown-unknown >/dev/null 2>&1 || true
CH="${CARGO_HOME:-$HOME/.cargo}"
export RUSTFLAGS="--remap-path-prefix=$CH=/cargo --remap-path-prefix=$B=/build"
export CARGO_TARGET_DIR="$B/target"
export SOURCE_DATE_EPOCH=0
cargo build --release --locked --target wasm32-unknown-unknown
cd "$OLDPWD_WASM"
rm -rf pkg
wasm-bindgen --target web --no-typescript --out-dir pkg "$B/target/wasm32-unknown-unknown/release/become_verify_wasm.wasm"
(cd pkg && sha256sum become_verify_wasm_bg.wasm become_verify_wasm.js)
