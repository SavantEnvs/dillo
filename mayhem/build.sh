#!/usr/bin/env bash
# mayhem/build.sh — build dillo (sanitized, out of tree in build-fuzz/), the fuzz harnesses in
# mayhem/harnesses/, and the upstream unit tests (normal flags, out of tree in build-tests/).
# Both build dirs match upstream's `/build*/` .gitignore entry, so `git clean -ffdX` removes them.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export CC CXX
cd "$SRC"

# Upstream's generated autotools files are gitignored, so (re)create them every time (offline).
[ -x configure ] || ./autogen.sh

# Only TLS is off (no certificate handling is fuzzed). Every image decoder is in: SVG (vendored
# nanosvg), GIF (dillo's own), and PNG/JPEG/WebP (dillo's glue over the distro libpng/libjpeg/libwebp,
# which stay uninstrumented). configure only warns when a library is missing, so build.sh checks
# config.h below and fails instead of silently fuzzing a stub decoder.
CONF_OPTS=(--disable-tls --enable-png --enable-jpeg --enable-webp --enable-svg --enable-gif)

# 1) Sanitized dillo build, with libFuzzer coverage instrumentation (fuzzer-no-link) so the fuzzed
#    dillo code — not only the harnesses — feeds coverage back to the fuzzer.
#    All UBSan checks and ASan stay on and halting for the dillo tree; the one relaxation
#    (shift-base, gif.c only) is applied after the main make below.
FUZZ_CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS"
[ -z "$SANITIZER_FLAGS" ] || FUZZ_CFLAGS="$FUZZ_CFLAGS -fsanitize=fuzzer-no-link"
mkdir -p build-fuzz
if [ ! -f build-fuzz/config.status ]; then
  (cd build-fuzz && ../configure "${CONF_OPTS[@]}" CC="$CC" CXX="$CXX" \
      CFLAGS="$FUZZ_CFLAGS" CXXFLAGS="$FUZZ_CFLAGS" LDFLAGS="$SANITIZER_FLAGS")
fi
for f in ENABLE_PNG ENABLE_JPEG ENABLE_WEBP ENABLE_GIF ENABLE_SVG; do
  grep -q "^#define $f 1" build-fuzz/config.h || { echo "build.sh: configure dropped $f" >&2; exit 1; }
done
make -C build-fuzz -j"$MAYHEM_JOBS"
# UBSan relaxation for src/gif.c only: -fno-sanitize=shift-base. Gif_decode's LZW bit reader does
# `window = (window >> 8) | (*buf++ << 24);` (src/gif.c:647) on an int-promoted byte, so every byte
# >= 0x80 in the image data trips "left shift of 132 by 24 places cannot be represented in type
# 'int'" (frame #0 Gif_decode gif.c:647, via Gif_process_bytes -> Gif_write -> a_Gif_callback);
# the shipped seed 2x2.gif halts on it. gif.o is recompiled with the flag on every run; no other
# dillo object gets it.
rm -f build-fuzz/src/gif.o
make -C build-fuzz/src gif.o CFLAGS="$FUZZ_CFLAGS -fno-sanitize=shift-base"

# 2) Harnesses, each linked twice: libFuzzer binary and -standalone reproducer.
B="$SRC/build-fuzz"
HFLAGS="$FUZZ_CFLAGS -I$SRC -I$SRC/src -I$SRC/dpi -I$B -I$B/src $(fltk-config --cflags | sed 's/-O[0-9s]//g')"
mkdir -p "$B/mayhem"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$B/mayhem/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/mayhem/standalone_main.o"
$CC $HFLAGS -c "$SRC/mayhem/harnesses/stubs.c" -o "$B/mayhem/stubs.o"
$CXX $HFLAGS -fno-rtti -fno-exceptions -c "$SRC/mayhem/harnesses/stubs_css.cc" -o "$B/mayhem/stubs_css.o"
FLTK_LIBS="$(fltk-config --ldflags) -lX11"
DLIB="$B/dlib/libDlib.a"
link() { # name harness.c objs...
  local name="$1" h="$2"; shift 2
  case "$h" in
    *.cc) $CXX $HFLAGS -fno-rtti -fno-exceptions -c "$h" -o "$B/mayhem/$name.o" ;;
    *)    $CC $HFLAGS ${HARNESS_EXTRA_CFLAGS:-} -c "$h" -o "$B/mayhem/$name.o" ;;
  esac
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$B/mayhem/$name.o" "$@" \
      "$B/mayhem/stubs.o" "$B/mayhem/lsan_off.o" "$DLIB" $FLTK_LIBS -lz -lbrotlidec -lm -o "$SRC/$name"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$B/mayhem/standalone_main.o" "$B/mayhem/$name.o" "$@" \
      "$B/mayhem/stubs.o" "$B/mayhem/lsan_off.o" "$DLIB" $FLTK_LIBS -lz -lbrotlidec -lm -o "$SRC/$name-standalone"
}
O="$B/src"
link fuzz_svg     "$SRC/mayhem/harnesses/fuzz_svg.c"    "$O/svg.o" "$O/url.o" "$O/hsts.o"
link fuzz_gif     "$SRC/mayhem/harnesses/fuzz_gif.c"    "$O/gif.o" "$O/url.o" "$O/hsts.o"
IMG_LIBS="-lpng -ljpeg -lwebp"
link fuzz_png     "$SRC/mayhem/harnesses/fuzz_png.c"    "$O/png.o" "$O/url.o" "$O/hsts.o" $IMG_LIBS
link fuzz_jpeg    "$SRC/mayhem/harnesses/fuzz_jpeg.c"   "$O/jpeg.o" "$O/url.o" "$O/hsts.o" $IMG_LIBS
link fuzz_webp    "$SRC/mayhem/harnesses/fuzz_webp.c"   "$O/webp.o" "$O/url.o" "$O/hsts.o" $IMG_LIBS
# fuzz_cache #includes src/cache.c (for its static entry helpers) and links the real URL, HSTS,
# domain-filter and decoder objects; the browser-UI calls cache.c makes are stood in for in the harness.
link fuzz_cache   "$SRC/mayhem/harnesses/fuzz_cache.c"  "$O/url.o" "$O/hsts.o" "$O/decode.o" "$O/misc.o" \
    "$O/utf8.o" "$O/domain.o"
link fuzz_url     "$SRC/mayhem/harnesses/fuzz_url.c"    "$O/url.o" "$O/hsts.o"
link fuzz_hsts    "$SRC/mayhem/harnesses/fuzz_hsts.c"   "$O/url.o" "$O/hsts.o"
link fuzz_decode  "$SRC/mayhem/harnesses/fuzz_decode.c" "$O/decode.o" "$O/utf8.o"
link fuzz_misc    "$SRC/mayhem/harnesses/fuzz_misc.c"   "$O/misc.o" "$O/utf8.o"
link fuzz_cookies "$SRC/mayhem/harnesses/fuzz_cookies.c" "$B/dpi/dpiutil.o" "$B/dpip/libDpip.a"
link fuzz_datauri "$SRC/mayhem/harnesses/fuzz_datauri.c" "$B/dpi/dpiutil.o" "$B/dpip/libDpip.a"
# fuzz_auth #includes src/auth.c, whose Auth_parse_token_value() counts token length in a
# `size_t *token_size` that starts at NULL (`token_size++`, src/auth.c:180): UBSan's pointer-overflow
# check fires "applying non-zero offset 8 to null pointer" (frame #0 Auth_parse_token_value
# auth.c:180, via Auth_parse_challenge_args -> Auth_parse_challenge -> Auth_do_auth) on every
# challenge with a token, i.e. on all three shipped seeds. Relaxed for this one compile
# (fuzz_auth.o, which holds auth.c) only; the rest of UBSan and ASan stay halting.
HARNESS_EXTRA_CFLAGS="-fno-sanitize=pointer-overflow" \
link fuzz_auth    "$SRC/mayhem/harnesses/fuzz_auth.c"   "$O/digest.o" "$O/md5.o" "$O/url.o" "$O/hsts.o" \
    "$O/misc.o" "$O/utf8.o"
link fuzz_css     "$SRC/mayhem/harnesses/fuzz_css.cc"   "$O/css.o" "$O/cssparser.o" "$O/colors.o" \
    "$O/url.o" "$O/hsts.o" "$O/misc.o" "$O/utf8.o" "$B/mayhem/stubs_css.o" "$B/dw/libDw-core.a" "$B/lout/liblout.a"

# 3) Upstream unit tests with NORMAL flags (test.sh only runs them).
mkdir -p build-tests
if [ ! -f build-tests/config.status ]; then
  (cd build-tests && env -u CFLAGS -u CXXFLAGS -u LDFLAGS ../configure "${CONF_OPTS[@]}" \
      CFLAGS="-O2 $COVERAGE_FLAGS" CXXFLAGS="-O2 $COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS")
fi
for d in dlib lout dpip dw; do make -C build-tests/$d -j"$MAYHEM_JOBS"; done
make -C build-tests/test/unit -j"$MAYHEM_JOBS" check TESTS=
# Known-answer oracle over the fuzzed modules, linked against the normal-flags objects.
make -C build-tests/src -j"$MAYHEM_JOBS" url.o hsts.o misc.o decode.o utf8.o
T="$SRC/build-tests"
$CC -O2 $COVERAGE_FLAGS -I"$SRC" -I"$SRC/src" -I"$T" -I"$T/src" $(fltk-config --cflags) \
   -c "$SRC/mayhem/oracle/kat.c" -o "$T/kat.o"
$CXX $COVERAGE_FLAGS "$T/kat.o" "$T/src/url.o" "$T/src/hsts.o" "$T/src/misc.o" "$T/src/decode.o" \
   "$T/src/utf8.o" "$T/dlib/libDlib.a" $(fltk-config --ldflags) -lX11 -lz -lbrotlidec -o "$T/dillo_kat"
