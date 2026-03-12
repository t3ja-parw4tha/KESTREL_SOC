#!/usr/bin/env bash
# Remove sensitive or generated files from Git tracking (they remain on disk).
# Run from repo root. After this, commit the change. To remove from history, use
# git filter-repo or BFG Repo-Cleaner (see kestrel_review_plan.md).

set -e
cd "$(dirname "$0")/.."

for path in .env soc_platform.db repomix-output.xml; do
  if git ls-files --error-unmatch "$path" 2>/dev/null; then
    git rm --cached "$path" 2>/dev/null || true
    echo "Stopped tracking: $path"
  fi
done
if git ls-files --error-unmatch "frontend/dist" 2>/dev/null; then
  git rm -r --cached frontend/dist 2>/dev/null || true
  echo "Stopped tracking: frontend/dist"
fi
echo "Done. Commit the change. Ensure .gitignore contains .env, *.db, repomix-output.xml, frontend/dist/."
