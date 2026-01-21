#!/usr/bin/env bash
# Cursor command: stage -> AI commit message -> commit -> push
# Works as a single file for Bash OR PowerShell:
# - Bash:  .cursor/commands/commit
# - PowerShell:  pwsh -File .cursor/commands/commit

:; exec bash "$0" "$@"

set -euo pipefail

# ---------- BASH ----------
git add -A

if git diff --cached --quiet; then
  echo "No changes to commit."
  exit 0
fi

diff="$(git diff --cached)"

# Prefer Cursor CLI: `agent` (new) then `cursor-agent` (older). Fallback if missing.
ai_bin=""
if command -v agent >/dev/null 2>&1; then
  ai_bin="agent"
elif command -v cursor-agent >/dev/null 2>&1; then
  ai_bin="cursor-agent"
fi

msg="chore: sync"

if [ -n "${ai_bin}" ]; then
  prompt=$(
    cat <<'EOF'
Write ONE git commit subject line (no body) for these staged changes.
Rules:
- Conventional Commits style: feat|fix|chore|refactor|docs|test|perf|build|ci|style
- <= 72 chars
- present tense, no trailing period
- output ONLY the subject line, nothing else

PATCH:
EOF
  )
  # Ask LLM using Cursor CLI (print mode). Keep only first non-empty line.
  # Note: output-format "text" returns plain text suitable for scripting.
  ai_out="$("$ai_bin" -p --output-format text "$prompt$diff" 2>/dev/null || true)"
  ai_line="$(printf "%s\n" "$ai_out" | sed '/^[[:space:]]*$/d' | head -n 1 | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  if [ -n "${ai_line}" ]; then
    msg="$ai_line"
  fi
fi

echo "Commit: $msg"
git commit -m "$msg"
git push
exit 0

# ---------- POWERSHELL ----------
<# 
$ErrorActionPreference = "Stop"

git add -A

git diff --cached --quiet
if ($?) {
  Write-Host "No changes to commit."
  exit 0
}

$diff = git diff --cached

# Prefer Cursor CLI: agent (new) then cursor-agent (older). Fallback if missing.
$aiBin = $null
if (Get-Command agent -ErrorAction SilentlyContinue) { $aiBin = "agent" }
elseif (Get-Command cursor-agent -ErrorAction SilentlyContinue) { $aiBin = "cursor-agent" }

$msg = "chore: sync"

if ($aiBin) {
  $prompt = @"
Write ONE git commit subject line (no body) for these staged changes.
Rules:
- Conventional Commits style: feat|fix|chore|refactor|docs|test|perf|build|ci|style
- <= 72 chars
- present tense, no trailing period
- output ONLY the subject line, nothing else

PATCH:
"@

  try {
    $aiOut = & $aiBin -p --output-format text ($prompt + $diff) 2>$null
    $aiLine = ($aiOut | Where-Object { $_ -and $_.Trim() -ne "" } | Select-Object -First 1).Trim()
    if ($aiLine) { $msg = $aiLine }
  } catch { }
}

Write-Host "Commit: $msg"
git commit -m $msg
git push
exit 0
#>
