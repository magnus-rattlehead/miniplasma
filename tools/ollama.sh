#!/usr/bin/env bash
# Local Ollama wrapper for this repo. macOS arm64 only.
# Subcommands: install | pull | status | chat | stop | help
# Override model with OLLAMA_MODEL.

set -euo pipefail

MODEL="${OLLAMA_MODEL:-qwen2.5-coder:32b}"
HOST_URL="http://127.0.0.1:11434"

die() { printf 'error: %s\n' "$*" >&2; exit 2; }

require_macos_arm64() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"
  if [[ "$os" != "Darwin" || "$arch" != "arm64" ]]; then
    die "macOS arm64 only (got $os/$arch). This script wraps Homebrew + Ollama on Apple Silicon."
  fi
}

usage() {
  cat <<EOF
Usage: tools/ollama.sh <subcommand>

Subcommands:
  install   Install Ollama via Homebrew (idempotent).
  pull      Pull the model ($MODEL). Idempotent.
  status    Print binary path, daemon state, model presence, disk footprint.
  chat      Open interactive chat. Auto-spawns the daemon if needed.
  stop      Kill any running 'ollama serve' daemon.
  help      Print this message.

Environment:
  OLLAMA_MODEL   Override the model tag (default: qwen2.5-coder:32b).

Example:
  tools/ollama.sh install && tools/ollama.sh pull && tools/ollama.sh chat
EOF
}

cmd_install() {
  require_macos_arm64
  if command -v ollama >/dev/null 2>&1; then
    printf 'ollama already installed: %s\n' "$(command -v ollama)"
  else
    command -v brew >/dev/null 2>&1 || die "Homebrew required. Install from https://brew.sh first."
    brew install ollama
  fi
  ollama --version
}

cmd_pull() {
  require_macos_arm64
  command -v ollama >/dev/null 2>&1 || die "ollama not installed. Run: tools/ollama.sh install"
  ollama pull "$MODEL"
}

daemon_up() {
  curl -fsS --max-time 2 "$HOST_URL/api/tags" >/dev/null 2>&1
}

cmd_status() {
  require_macos_arm64

  local bin
  if bin="$(command -v ollama 2>/dev/null)"; then
    printf 'binary:  %s\n' "$bin"
  else
    printf 'binary:  not installed (run: tools/ollama.sh install)\n'
    return 0
  fi

  if daemon_up; then
    printf 'daemon:  up at %s\n' "$HOST_URL"
  else
    printf 'daemon:  down (auto-spawns on chat)\n'
  fi

  # `ollama list` reads the local blob store; works whether daemon is up or not.
  local list_out
  if list_out="$(ollama list 2>/dev/null)"; then
    if printf '%s\n' "$list_out" | awk 'NR>1 {print $1}' | grep -Fxq "$MODEL"; then
      local size
      size="$(printf '%s\n' "$list_out" | awk -v m="$MODEL" 'NR>1 && $1==m {print $3" "$4; exit}')"
      printf 'model:   %s present (%s)\n' "$MODEL" "${size:-size unknown}"
    else
      printf 'model:   %s NOT pulled (run: tools/ollama.sh pull)\n' "$MODEL"
    fi
  else
    printf 'model:   %s status unknown (ollama list failed)\n' "$MODEL"
  fi
}

cmd_chat() {
  require_macos_arm64
  command -v ollama >/dev/null 2>&1 || die "ollama not installed. Run: tools/ollama.sh install"
  exec ollama run "$MODEL"
}

cmd_stop() {
  require_macos_arm64
  # Match argv0='ollama' + argv1='serve' — won't catch 'ollama run ...' in another shell.
  if pkill -f 'ollama serve' 2>/dev/null; then
    printf 'stopped ollama serve\n'
  else
    printf 'no ollama serve process running\n'
  fi
}

main() {
  local sub="${1:-help}"
  case "$sub" in
    install) cmd_install ;;
    pull)    cmd_pull ;;
    status)  cmd_status ;;
    chat)    cmd_chat ;;
    stop)    cmd_stop ;;
    help|-h|--help) usage ;;
    *)       printf 'error: unknown subcommand: %s\n\n' "$sub" >&2; usage >&2; exit 2 ;;
  esac
}

main "$@"
