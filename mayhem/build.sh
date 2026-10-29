#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# Build dirs live under build/ (gitignored upstream, so `git clean -ffdX` removes them).
COMMON_OPTS=(-G Ninja -DCMAKE_C_COMPILER="$CC" -DBUILD_SHARED_LIBS=OFF -DBUILD_STATIC_LIBS=ON
             -DBUILD_EXAMPLES=OFF -DLIBSSH2_BUILD_DOCS=OFF -DCRYPTO_BACKEND=OpenSSL
             -DENABLE_ZLIB_COMPRESSION=ON -DCMAKE_BUILD_TYPE=)

# 1) Sanitized + SanCov-instrumented project (the fuzzed code). HMAC-SHA1 is enabled like upstream's
#    OSS-Fuzz build (tests/ossfuzz/ossfuzz.sh).
FUZZ_CFLAGS="-O1 $SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS -DLIBSSH2_HMAC_SHA1_ENABLE"
cmake -S . -B build/fuzz "${COMMON_OPTS[@]}" -DBUILD_TESTING=OFF -DCMAKE_C_FLAGS="$FUZZ_CFLAGS" >/dev/null
cmake --build build/fuzz -j"$MAYHEM_JOBS"
LIB=build/fuzz/src/libssh2.a
[ -f "$LIB" ]

# 2) Harness (upstream's own OSS-Fuzz harness) twice: libFuzzer + standalone reproducer.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o build/fuzz/lsan_off.o
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -x c -c "$STANDALONE_FUZZ_MAIN" -o build/fuzz/standalone_main.o
$CXX -O1 $SANITIZER_FLAGS $DEBUG_FLAGS -Iinclude -c tests/ossfuzz/ssh2_client_fuzzer.cc \
    -o build/fuzz/ssh2_client_fuzzer.o
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE build/fuzz/ssh2_client_fuzzer.o build/fuzz/lsan_off.o \
    "$LIB" -lssl -lcrypto -lz -o "$SRC/ssh2_client_fuzzer"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS build/fuzz/ssh2_client_fuzzer.o build/fuzz/standalone_main.o build/fuzz/lsan_off.o \
    "$LIB" -lssl -lcrypto -lz -o "$SRC/ssh2_client_fuzzer-standalone"

# 3) Test suite with the project's NORMAL flags (no sanitizers, no DWARF pin): upstream's network-free
#    unit tests plus a known-answer probe over the public API. The sshd/container tests need a server.
cmake -S . -B build/tests "${COMMON_OPTS[@]}" -DBUILD_TESTING=ON -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" >/dev/null
cmake --build build/tests -j"$MAYHEM_JOBS" --target test_simple test_auth_keyboard_info_request
$CC -O2 $COVERAGE_FLAGS -Iinclude mayhem/selftest.c build/tests/src/libssh2.a -lssl -lcrypto -lz \
    -o build/tests/selftest
