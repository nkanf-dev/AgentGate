#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
skmb_root="${AGENTGATE_SKMB_ROOT:-$repo_root/docs/isme}"
archive_root="${AGENTGATE_SKMB_ARCHIVE_ROOT:-$skmb_root/archive}"
skmb_index="$skmb_root/SKMB.md"
decision_dir="$skmb_root/decisions"

if [ ! -e "$skmb_index" ] && [ ! -d "$decision_dir" ]; then
  exit 0
fi

if [ ! -f "$skmb_index" ]; then
  printf 'skmb: cannot archive; %s is missing\n' "$skmb_index" >&2
  exit 1
fi

if [ ! -d "$decision_dir" ]; then
  printf 'skmb: cannot archive; %s is missing\n' "$decision_dir" >&2
  exit 1
fi

if [ -x "$repo_root/scripts/check-skmb-sync.sh" ]; then
  "$repo_root/scripts/check-skmb-sync.sh"
fi

commit="$(git rev-parse HEAD)"
short_commit="$(git rev-parse --short HEAD)"
branch="$(git branch --show-current 2>/dev/null || true)"
if [ -z "$branch" ]; then
  branch="detached"
fi
created_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
archive_name="$(date -u '+%Y%m%dT%H%M%SZ')-$short_commit"
archive_dir="$archive_root/$archive_name"

suffix=1
while [ -e "$archive_dir" ]; do
  suffix=$((suffix + 1))
  archive_dir="$archive_root/$archive_name-$suffix"
done

mkdir -p "$archive_dir/decisions"
cp "$skmb_index" "$archive_dir/SKMB.md"

find "$decision_dir" -maxdepth 1 -type f -name '*.md' | sort | while IFS= read -r file; do
  cp "$file" "$archive_dir/decisions/$(basename "$file")"
done

{
  printf '# SKMB Archive\n\n'
  printf -- '- commit: %s\n' "$commit"
  printf -- '- branch: %s\n' "$branch"
  printf -- '- created_at: %s\n' "$created_at"
  printf -- '- source: %s\n' "$skmb_root"
  printf -- '- archive: %s\n\n' "$archive_dir"
  printf '## Files\n\n'
  find "$archive_dir" -type f | sort | sed "s#^$archive_dir/#- #"
} >"$archive_dir/MANIFEST.md"

printf 'skmb: archived current SKMB to %s\n' "$archive_dir"
