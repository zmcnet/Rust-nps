#!/usr/bin/env bash
# Cross-architecture release builder for Rust-nps (rnps + rnpc).
#
# Usage:
#   ./scripts/build-matrix.sh                       # build all default Linux targets
#   ./scripts/build-matrix.sh aarch64-unknown-linux-gnu mipsel-unknown-linux-musl
#   TARGETS="..." ./scripts/build-matrix.sh          # same, via env var
#
# Output layout:
#   dist/<triple>/rnps
#   dist/<triple>/rnpc
#
# Design notes:
#   * Linkers / strippers are passed as per-target environment variables
#     (CARGO_TARGET_<TRIPLE>_LINKER). We deliberately do NOT edit .cargo/config.toml,
#     so this script is safe to run from a clean checkout and never disturbs the
#     native Windows build config that the repository already ships.
#   * A failing target never aborts the whole run; results are summarised at the end.
#   * Release profile already enables `strip = true`, but we additionally run the
#     matching cross `strip`/`llvm-strip` to squeeze the binaries further.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

DIST="${DIST:-$ROOT/dist}"
STRIP_BIN="${STRIP:-strip}"

# All targets we attempt by default. Apple/Windows targets need their native
# runners (see .github/workflows/release.yml); on a Linux host only the Linux
# triples are buildable, so those are the default here.
DEFAULT_TARGETS=(
  x86_64-unknown-linux-gnu
  x86_64-unknown-linux-musl
  aarch64-unknown-linux-gnu
  aarch64-unknown-linux-musl
  i686-unknown-linux-gnu
  i686-unknown-linux-musl
  armv7-unknown-linux-gnueabihf
  armv7-unknown-linux-musleabihf
  arm-unknown-linux-gnueabihf
  arm-unknown-linux-musleabihf
  mips-unknown-linux-musl
  mipsel-unknown-linux-musl
  mips64-unknown-linux-muslabi64
)

if [ "$#" -gt 0 ]; then
  TARGETS=("$@")
elif [ -n "${TARGETS:-}" ]; then
  read -r -a TARGETS <<< "$TARGETS"
else
  TARGETS=("${DEFAULT_TARGETS[@]}")
fi

# Convert triple to the env-var fragment rustc expects:
#   x86_64-unknown-linux-gnu -> X86_64_UNKNOWN_LINUX_GNU
triple_env() {
  printf '%s' "$1" | tr '[:lower:]-' '[:upper:]_'
}

linker_for() {
  case "$1" in
    x86_64-unknown-linux-gnu)             echo "${LINKER_x86_64:-cc}" ;;
    x86_64-unknown-linux-musl)            echo "${LINKER_x86_64_MUSL:-musl-gcc}" ;;
    aarch64-unknown-linux-gnu)            echo "${LINKER_AARCH64:-aarch64-linux-gnu-gcc}" ;;
    aarch64-unknown-linux-musl)           echo "${LINKER_AARCH64_MUSL:-aarch64-linux-musl-gcc}" ;;
    i686-unknown-linux-gnu)               echo "${LINKER_I686:-i686-linux-gnu-gcc}" ;;
    i686-unknown-linux-musl)              echo "${LINKER_I686_MUSL:-i686-linux-musl-gcc}" ;;
    armv7-unknown-linux-gnueabihf)        echo "${LINKER_ARMV7:-arm-linux-gnueabihf-gcc}" ;;
    armv7-unknown-linux-musleabihf)       echo "${LINKER_ARMV7_MUSL:-arm-linux-musleabihf-gcc}" ;;
    arm-unknown-linux-gnueabihf)          echo "${LINKER_ARM:-arm-linux-gnueabihf-gcc}" ;;
    arm-unknown-linux-musleabihf)         echo "${LINKER_ARM_MUSL:-arm-linux-musleabihf-gcc}" ;;
    mips-unknown-linux-musl)              echo "${LINKER_MIPS:-mips-linux-musl-gcc}" ;;
    mipsel-unknown-linux-musl)            echo "${LINKER_MIPSEL:-mipsel-linux-musl-gcc}" ;;
    mips64-unknown-linux-musl|mips64-unknown-linux-muslabi64) \
                                          echo "${LINKER_MIPS64:-mips64-linux-muslabi64-gcc}" ;;
    *)                                    echo "" ;;
  esac
}

strip_for() {
  case "$1" in
    x86_64-unknown-linux-*)               echo "${STRIP_x86_64:-$STRIP_BIN}" ;;
    aarch64-unknown-linux-*)              echo "${STRIP_AARCH64:-aarch64-linux-gnu-strip}" ;;
    i686-unknown-linux-*)                 echo "${STRIP_I686:-i686-linux-gnu-strip}" ;;
    armv7-unknown-linux-*|arm-unknown-linux-*) \
                                          echo "${STRIP_ARM:-arm-linux-gnueabihf-strip}" ;;
    mips-unknown-linux-*)                 echo "${STRIP_MIPS:-mips-linux-gnu-strip}" ;;
    mipsel-unknown-linux-*)               echo "${STRIP_MIPSEL:-mipsel-linux-gnu-strip}" ;;
    mips64-unknown-linux-*)               echo "${STRIP_MIPS64:-mips64-linux-gnuabi64-strip}" ;;
    x86_64-pc-windows-msvc)               echo "${STRIP_X86_64_WIN:-x86_64-w64-mingw32-strip}" ;;
    i686-pc-windows-msvc)                 echo "${STRIP_I686_WIN:-i686-w64-mingw32-strip}" ;;
    x86_64-apple-darwin|aarch64-apple-darwin) echo "${STRIP_APPLE:-strip}" ;;
    *)                                    echo "$STRIP_BIN" ;;
  esac
}

human_size() {
  if [ -f "$1" ]; then
    du -h "$1" | cut -f1
  else
    echo "N/A"
  fi
}

SUCCESS=()
FAIL=()

echo "== Rust-nps release matrix =="
echo "workspace : $ROOT"
echo "dist dir  : $DIST"
echo "targets   : ${TARGETS[*]}"
echo

for TARGET in "${TARGETS[@]}"; do
  echo "------------------------------------------------------------------"
  echo ">>> $TARGET"
  OUT_DIR="$DIST/$TARGET"
  mkdir -p "$OUT_DIR"

  # Determine linker; fail early with a clear message if it is missing.
  LINKER="$(linker_for "$TARGET")"
  ENV_PREFIX="CARGO_TARGET_$(triple_env "$TARGET")"
  if [ -n "$LINKER" ]; then
    if ! command -v "$LINKER" >/dev/null 2>&1; then
      echo "    [SKIP/FAILED] linker not found: $LINKER (install the matching cross toolchain)"
      FAIL+=("$TARGET (missing linker: $LINKER)")
      continue
    fi
    export "${ENV_PREFIX}_LINKER=$LINKER"
    echo "    linker: $LINKER"
  fi

  BUILD_LOG="$OUT_DIR/build.log"
  if cargo build --release --target "$TARGET" \
        -p nps-app --bin rnps \
        -p nps-client --bin rnpc 2>&1 | tee "$BUILD_LOG"; then
    :
  else
    echo "    [FAILED] cargo build failed for $TARGET (see $BUILD_LOG)"
    FAIL+=("$TARGET (cargo build failed; see $OUT_DIR/build.log)")
    continue
  fi

  # Copy + strip artifacts. A missing artifact after a "successful" build is a failure.
  BIN_DIR="target/$TARGET/release"
  OK=1
  for BIN in rnps rnpc; do
    SRC="$BIN_DIR/$BIN"
    DST="$OUT_DIR/$BIN"
    if [ ! -f "$SRC" ]; then
      echo "    [FAILED] expected artifact not found: $SRC"
      OK=0
      continue
    fi
    cp -f "$SRC" "$DST" || OK=0
    STRIPPER="$(strip_for "$TARGET")"
    if command -v "$STRIPPER" >/dev/null 2>&1; then
      "$STRIPPER" "$DST" 2>/dev/null || echo "    (warn: strip failed with $STRIPPER)"
    else
      echo "    (warn: no strip tool '$STRIPPER', keeping unstripped copy)"
    fi
    echo "    $BIN -> $DST ($(human_size "$DST"))"
  done

  if [ "$OK" -eq 1 ]; then
    SUCCESS+=("$TARGET")
  else
    FAIL+=("$TARGET (artifact copy/strip failed)")
  fi
done

echo
echo "================== SUMMARY =================="
echo "Success: ${#SUCCESS[@]}"
for t in "${SUCCESS[@]}"; do echo "  OK   $t"; done
echo "Failed: ${#FAIL[@]}"
for t in "${FAIL[@]}"; do echo "  FAIL $t"; done

# Non-zero exit only when every target failed (partial success is still useful
# for CI artifact collection). Set STRICT=1 in CI to require all targets.
if [ "${#SUCCESS[@]}" -eq 0 ]; then
  exit 1
fi
if [ "${STRICT:-0}" = "1" ] && [ "${#FAIL[@]}" -gt 0 ]; then
  exit 1
fi
exit 0
