#!/usr/bin/env bash
# Rewrite every commit authored by the environment's default identity
# ("Claude <noreply@anthropic.com>") to the project owner, so GitHub attributes
# them to you (GitHub keys attribution on the author EMAIL, which a .mailmap does
# NOT change — only a history rewrite does).
#
# WARNING — this rewrites history:
#   • every commit SHA changes
#   • already-merged PRs will point at old SHAs
#   • collaborators must re-clone afterwards
# Safe for a young/solo repo; think twice on a shared one.
#
# Usage:
#   scripts/reauthor.sh            # rewrite, then print the push command (dry by default)
#   scripts/reauthor.sh --push     # rewrite AND force-push all branches + tags
#
# Run it on a FRESH clone of the repo.
set -euo pipefail

NEW_NAME="novaai0401-ui"
NEW_EMAIL="novaai0401@gmail.com"
OLD_EMAIL="noreply@anthropic.com"

echo "Rewriting commits authored/committed by <$OLD_EMAIL> -> $NEW_NAME <$NEW_EMAIL>"

if command -v git-filter-repo >/dev/null 2>&1 || git filter-repo --version >/dev/null 2>&1; then
  # Preferred: git-filter-repo (pip install git-filter-repo)
  printf '%s\n' "Claude <$OLD_EMAIL> $NEW_NAME <$NEW_EMAIL>" > /tmp/aa-mailmap
  git filter-repo --mailmap /tmp/aa-mailmap --force
else
  echo "git-filter-repo not found; falling back to git filter-branch."
  FILTER_BRANCH_SQUELCH_WARNING=1 git filter-branch -f --env-filter "
    if [ \"\$GIT_AUTHOR_EMAIL\" = \"$OLD_EMAIL\" ]; then
      export GIT_AUTHOR_NAME='$NEW_NAME'; export GIT_AUTHOR_EMAIL='$NEW_EMAIL'
    fi
    if [ \"\$GIT_COMMITTER_EMAIL\" = \"$OLD_EMAIL\" ]; then
      export GIT_COMMITTER_NAME='$NEW_NAME'; export GIT_COMMITTER_EMAIL='$NEW_EMAIL'
    fi
  " --tag-name-filter cat -- --all
fi

echo
echo "Done. Verify with:  git shortlog -sne --all"
if [ "${1:-}" = "--push" ]; then
  # filter-repo drops 'origin' as a safety measure; re-add if needed.
  git remote get-url origin >/dev/null 2>&1 || \
    git remote add origin "https://github.com/novaai0401-ui/agent-authority.git"
  git push --force --all
  git push --force --tags
  echo "Force-pushed all branches and tags."
else
  echo "Review, then push with:"
  echo "  git push --force --all && git push --force --tags"
fi
