#!/usr/bin/env bash
# Prints the body of the "## <tag>" section of a changelog: every line after
# that exact heading, up to the next "## " heading. Fails when the section is
# missing or empty, so a release is never published without notes.
#
# Usage: extract-release-notes.sh <tag> <changelog>
set -euo pipefail

tag="${1:?usage: extract-release-notes.sh <tag> <changelog>}"
changelog="${2:?usage: extract-release-notes.sh <tag> <changelog>}"

notes="$(awk -v heading="## ${tag}" '
  $0 == heading { in_section = 1; next }
  in_section && /^## / { exit }
  in_section { print }
' "$changelog")"

# Trim leading and trailing blank lines.
notes="$(printf '%s\n' "$notes" | sed -e '/./,$!d' | sed -e ':a' -e '/^\n*$/{$d;N;ba' -e '}')"

if [ -z "$notes" ]; then
  echo "No '## ${tag}' section (or an empty one) in ${changelog}." >&2
  exit 1
fi

printf '%s\n' "$notes"
