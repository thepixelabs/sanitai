#!/usr/bin/env bash
# scripts/install-hooks.sh — installs project git hooks from .githooks/
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
SOURCE_DIR="${REPO_ROOT}/.githooks"
DEST_DIR="${HOOKS_DIR:-${REPO_ROOT}/.git/hooks}"

if [ ! -d "$SOURCE_DIR" ]; then
  echo "ERROR: .githooks/ not found at $SOURCE_DIR" >&2
  exit 1
fi

mkdir -p "$DEST_DIR"
installed=0

for hook_src in "$SOURCE_DIR"/*; do
  hook_name="$(basename "$hook_src")"
  hook_dest="${DEST_DIR}/${hook_name}"
  if [ ! -f "$hook_src" ] || [[ "$hook_name" == .* ]]; then
    continue
  fi
  if [ -f "$hook_dest" ] && ! diff -q "$hook_src" "$hook_dest" &>/dev/null; then
    backup="${hook_dest}.bak.$(date +%s)"
    echo "Backing up existing $hook_name to $(basename "$backup")"
    mv "$hook_dest" "$backup"
  fi
  cp "$hook_src" "$hook_dest"
  chmod +x "$hook_dest"
  echo "Installed: $hook_name -> $hook_dest"
  ((installed++)) || true
done

if [ "$installed" -eq 0 ]; then
  echo "No hooks found in $SOURCE_DIR."
else
  echo ""
  echo "$installed hook(s) installed. Run 'make install-hooks' to reinstall."
fi
