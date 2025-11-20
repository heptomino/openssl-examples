#!/usr/bin/env bash
set -euo pipefail

# tools/extract_and_build.sh
# Usage: tools/extract_and_build.sh [NOTES_DIR] [OUT_DIR] [COMPILE]
# NOTES_DIR - directory containing markdown articles (default: ./notes)
# OUT_DIR   - directory to write extracted .cpp files and build artifacts (default: ./examples)
# COMPILE   - 1 to attempt compilation (default: 1), 0 to skip compilation

WORKDIR="$(cd "$(dirname "$0")/.." && pwd)"
NOTES_DIR="${1:-$WORKDIR/notes}"
OUT_DIR="${2:-$WORKDIR/examples}"
COMPILE="${3:-1}"

# Keep compiler settings consistent with the Makefile; allow callers to override via env.
CXX="${CXX:-g++}"
CXXFLAGS="${CXXFLAGS:--std=c++17 -O2 -Wall -Wextra}"
LDFLAGS="${LDFLAGS:--lssl -lcrypto}"

mkdir -p "$OUT_DIR"
shopt -s nullglob

echo "Notes dir: $NOTES_DIR"
echo "Out dir: $OUT_DIR"
echo "Compile: $COMPILE"
echo "Compiler: $CXX $CXXFLAGS $LDFLAGS"

echo "Scanning Markdown files..."

count=0

for md in "$NOTES_DIR"/*.md; do
  # avoid ((count++)) because with set -e it may exit when expression evaluates to 0
  count=$((count+1))
  basename="$(basename "$md")"
  name="${basename%.*}"

  # Try to get first H1 title from markdown
  title="$(awk 'BEGIN{found=0} /^# / && found==0 {found=1; sub(/^# +/,"",$0); print; exit}' "$md" || true)"
  if [[ -n "$title" ]]; then
    # Sanitize title -> ascii, lowercase, replace non-alnum with '-', trim '-'
    # iconv used to transliterate where possible; fallback to basename if result empty
    sanitized="$(echo "$title" | iconv -c -t ASCII//TRANSLIT | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/-/g' | sed -E 's/^-+|-+$//g')"
    [[ -z "$sanitized" ]] && sanitized="$name"
    fname="$sanitized"
  else
    fname="$name"
  fi

  out="$OUT_DIR/$fname.cpp"

  # Check for a filename override immediately before the code block using an HTML comment:
  # <!-- filename: examples/your_name.cpp -->
  fname_override="$(awk '/<!--[[:space:]]*filename:/ { if(match($0,/<!--[[:space:]]*filename:[[:space:]]*([^ ]+)[[:space:]]*-->/,a)){print a[1]; exit} } /```cpp/ { exit }' "$md" || true)"
  if [[ -n "$fname_override" ]]; then
    # If override contains a directory (e.g. examples/foo.cpp) treat it as repo-relative path
    if [[ "$fname_override" == */* ]]; then
      out="$WORKDIR/$fname_override"
    else
      out="$OUT_DIR/$fname_override"
    fi
    # Ensure parent dir exists
    mkdir -p "$(dirname "$out")"
  fi

  # Extract first ```cpp block (the code block that follows the optional filename comment)
  awk 'BEGIN{inside=0} /^<!--[[:space:]]*filename:/ {next} /^```cpp/{if(inside==0){inside=1; next}} /^```/{if(inside==1){exit}} inside==1{print}' "$md" > "$out" || true

  if [[ ! -s "$out" ]]; then
    echo "[skip] No cpp code block found in $md"
    rm -f "$out" 2>/dev/null || true
    continue
  fi

  echo "[extract] $md -> $out"

  if [[ "$COMPILE" -ne 0 ]]; then
    bin_name="$(dirname "$out")/$(basename "$out" .cpp)"
    build_log="${bin_name}.build.log"
    echo "[build] Compiling $out -> $bin_name"
    if "$CXX" $CXXFLAGS "$out" -o "$bin_name" $LDFLAGS 2>"$build_log"; then
      echo "[ok] Compiled $bin_name"
    else
      echo "[fail] Compile failed for $out. See $build_log"
    fi
  fi

done

if [[ $count -eq 0 ]]; then
  echo "No markdown files found in $NOTES_DIR"
fi

echo "done"
