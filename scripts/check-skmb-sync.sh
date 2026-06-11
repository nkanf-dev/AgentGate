#!/usr/bin/env bash
set -u

failures=0

fail() {
  printf 'skmb: %s\n' "$*" >&2
  failures=$((failures + 1))
}

trim() {
  sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
skmb_index="$repo_root/docs/isme/SKMB.md"
decision_dir="$repo_root/docs/isme/decisions"

if [ ! -e "$skmb_index" ] && [ ! -d "$decision_dir" ]; then
  exit 0
fi

if [ ! -f "$skmb_index" ]; then
  fail "docs/isme/decisions exists but docs/isme/SKMB.md is missing"
  exit 1
fi

if [ ! -d "$decision_dir" ]; then
  fail "docs/isme/SKMB.md exists but docs/isme/decisions is missing"
  exit 1
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

decision_index="$tmpdir/decision-index.tsv"
open_index="$tmpdir/open-index.tsv"

awk -F'|' '
function clean(value) {
  gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
  gsub(/`/, "", value)
  return value
}
/^## Decision Index[[:space:]]*$/ {
  section = "decision"
  next
}
/^## / {
  if (section == "decision") {
    section = ""
  }
}
section == "decision" && $2 ~ /^[[:space:]]*SKMB-[0-9][0-9][0-9][0-9]-/ {
  print clean($2) "\t" clean($3) "\t" clean($6) "\t" clean($7)
}
' "$skmb_index" >"$decision_index"

awk -F'|' '
function clean(value) {
  gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
  gsub(/`/, "", value)
  return value
}
/^## Open Decisions[[:space:]]*$/ {
  section = "open"
  next
}
/^## / {
  if (section == "open") {
    section = ""
  }
}
section == "open" && $2 ~ /^[[:space:]]*OPEN-/ {
  print clean($2) "\t" clean($6)
}
' "$skmb_index" >"$open_index"

duplicate_decisions="$(cut -f1 "$decision_index" | sort | uniq -d | tr '\n' ' ' | trim)"
if [ -n "$duplicate_decisions" ]; then
  fail "duplicate Decision Index IDs: $duplicate_decisions"
fi

duplicate_open="$(cut -f1 "$open_index" | sort | uniq -d | tr '\n' ' ' | trim)"
if [ -n "$duplicate_open" ]; then
  fail "duplicate Open Decisions IDs: $duplicate_open"
fi

field_value() {
  local file="$1"
  local key="$2"
  sed -n "s/^- ${key}:[[:space:]]*//p" "$file" | head -n 1
}

header_id() {
  sed -n '1s/^# \([^:]*\):.*/\1/p' "$1"
}

index_row_for() {
  local id="$1"
  local table="$2"
  awk -F'\t' -v id="$id" '$1 == id { print; found = 1; exit } END { if (!found) exit 1 }' "$table"
}

check_indexed_decision_file() {
  local id="$1"
  local status="$2"
  local rel_path="$3"
  local commit="$4"
  local file="$repo_root/docs/isme/$rel_path"

  if [ -z "$rel_path" ]; then
    fail "$id has no decision file path in SKMB.md"
    return
  fi

  if [ ! -f "$file" ]; then
    fail "$id references missing decision file: $rel_path"
    return
  fi

  local file_id
  file_id="$(header_id "$file")"
  if [ "$file_id" != "$id" ]; then
    fail "$rel_path header id is '$file_id', expected '$id'"
  fi

  local file_status
  file_status="$(field_value "$file" "status")"
  if [ "$file_status" != "$status" ]; then
    fail "$id status mismatch: SKMB.md has '$status', file has '$file_status'"
  fi

  local file_commit
  file_commit="$(field_value "$file" "commit")"
  if [ "$file_commit" != "$commit" ]; then
    fail "$id commit mismatch: SKMB.md has '$commit', file has '$file_commit'"
  fi

  if [ "$file_status" != "accepted" ]; then
    fail "$id is '$file_status'; concrete SKMB decisions must be accepted before commit"
  fi

  if [ "$file_status" = "accepted" ]; then
    local decided_by
    decided_by="$(field_value "$file" "decided_by")"
    if [ "$decided_by" != "designer" ]; then
      fail "$id is accepted but decided_by is '$decided_by', expected 'designer'"
    fi

    local approval_source
    approval_source="$(field_value "$file" "approval_source")"
    if [ -z "$approval_source" ] || printf '%s\n' "$approval_source" | grep -qi 'pending'; then
      fail "$id is accepted but approval_source is missing or pending"
    fi
  fi
}

while IFS="$(printf '\t')" read -r id status rel_path commit; do
  [ -n "$id" ] || continue
  check_indexed_decision_file "$id" "$status" "$rel_path" "$commit"
done <"$decision_index"

for file in "$decision_dir"/SKMB-*.md; do
  [ -e "$file" ] || continue
  id="$(header_id "$file")"
  if [ -z "$id" ]; then
    fail "$(basename "$file") has no '# SKMB-...:' header"
    continue
  fi

  row="$(index_row_for "$id" "$decision_index" || true)"
  if [ -z "$row" ]; then
    fail "$id exists in decisions/ but is missing from SKMB.md Decision Index"
  fi
done

while IFS="$(printf '\t')" read -r id rel_path; do
  [ -n "$id" ] || continue
  file="$repo_root/docs/isme/$rel_path"

  if [ -z "$rel_path" ]; then
    fail "$id has no open decision file path in SKMB.md"
    continue
  fi

  if [ ! -f "$file" ]; then
    fail "$id references missing open decision file: $rel_path"
    continue
  fi

  file_id="$(header_id "$file")"
  if [ "$file_id" != "$id" ]; then
    fail "$rel_path header id is '$file_id', expected '$id'"
  fi

  file_status="$(field_value "$file" "status")"
  if [ "$file_status" != "open" ]; then
    fail "$id is listed as open but file status is '$file_status'"
  fi
done <"$open_index"

for file in "$decision_dir"/OPEN-*.md; do
  [ -e "$file" ] || continue
  id="$(header_id "$file")"
  if [ -z "$id" ]; then
    fail "$(basename "$file") has no '# OPEN-...:' header"
    continue
  fi

  row="$(index_row_for "$id" "$open_index" || true)"
  if [ -z "$row" ]; then
    fail "$id exists in decisions/ but is missing from SKMB.md Open Decisions"
  fi
done

if [ "$failures" -gt 0 ]; then
  printf 'skmb: pre-commit check failed with %d issue(s)\n' "$failures" >&2
  exit 1
fi

exit 0
