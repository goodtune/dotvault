#!/bin/sh
# PreToolUse hook that fires before any Bash invocation. When the
# command about to run is a `git push`, emit a reminder that
# /precommit-review must be the immediately-preceding action — the
# project's pre-push review contract (see CLAUDE.md, "Agent
# workflow: review before pushing").
#
# The hook does NOT block the push. Blocking would force a context
# round-trip every time a follow-up review-driven fix needs to go
# out; the reminder is enough for a Claude agent following the
# CLAUDE.md instruction. The user can always tell the agent to
# skip review explicitly.
#
# Input arrives on stdin as JSON; we only need .tool_input.command,
# which is the literal Bash command about to execute.

set -e

input=$(cat)

# Be defensive about jq not being installed (rare but possible on
# minimal images): fall back to grep on the raw payload. Either
# extraction yields the bash command string.
if command -v jq >/dev/null 2>&1; then
  cmd=$(printf '%s' "$input" | jq -r '.tool_input.command // empty' 2>/dev/null)
else
  cmd=$(printf '%s' "$input" | grep -o '"command":"[^"]*"' | head -n1 | sed 's/^"command":"//; s/"$//')
fi

# Only act on actual `git push` invocations. Match the literal
# token boundary so `git push-something` or `echo 'git push'`
# wouldn't false-trigger.
case "$cmd" in
  *"git push "*|*"git push")
    cat >&2 <<'EOF'
Reminder: this repo's CLAUDE.md requires a five-persona pre-push
review (security, architecture, cross-platform, test &
correctness, docs & DX) before `git push`. If you have not just
run `/precommit-review` against the unpushed changes, run it now
and address findings before pushing. Skip only with explicit
user opt-out or for an administrative push that changes no code.
EOF
    ;;
esac

exit 0
