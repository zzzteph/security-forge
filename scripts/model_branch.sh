#!/usr/bin/env bash
# CI-only persistence: keep each target's durable model + findings on its own
# lean branch  model/<slug>  (containing just knowledge/<slug>/…), so a new PR
# never has to reanalyze the project. Never touches the TARGET repo — only this
# (security-forge) repo's branches. Committed by the CI bot, not by Claude.
#
#   scripts/model_branch.sh restore <slug>   # before analysis: pull persisted model into ./knowledge
#   scripts/model_branch.sh save    <slug>   # after analysis: commit+push ./knowledge to model/<slug>
#
# Requires: a checkout with push creds (actions/checkout persist-credentials) and
# `permissions: contents: write`.
set -uo pipefail

cmd="${1:?usage: restore|save <slug>}"
slug="${2:?missing slug}"
branch="model/${slug}"
wt=".model-branch"
bot_name="github-actions[bot]"
bot_email="41898282+github-actions[bot]@users.noreply.github.com"

cleanup() { git worktree remove "$wt" --force >/dev/null 2>&1 || rm -rf "$wt"; }
trap cleanup EXIT

case "$cmd" in
  restore)
    if git fetch origin "$branch" >/dev/null 2>&1; then
      rm -rf "$wt"
      git worktree add "$wt" "origin/$branch" >/dev/null 2>&1 || { echo "[model] worktree add failed; starting fresh"; exit 0; }
      mkdir -p knowledge
      cp -a "$wt/knowledge/." knowledge/ 2>/dev/null || true
      echo "[model] restored model for $slug from $branch"
    else
      echo "[model] no existing $branch — baseline run (will create it on save)"
    fi
    ;;

  save)
    rm -rf "$wt"
    if git ls-remote --exit-code origin "$branch" >/dev/null 2>&1; then
      git fetch origin "$branch" >/dev/null 2>&1
      git worktree add "$wt" "origin/$branch" >/dev/null 2>&1
    else
      # first time: an orphan branch holding only the model
      git worktree add --detach "$wt" >/dev/null 2>&1
      ( cd "$wt" && git checkout --orphan "$branch" >/dev/null 2>&1 && git rm -rf . >/dev/null 2>&1 || true )
    fi
    mkdir -p "$wt/knowledge"
    cp -a knowledge/. "$wt/knowledge/" 2>/dev/null || true
    (
      cd "$wt"
      git add -f -A knowledge   # -f: knowledge/ is gitignored on main; force it onto the model branch
      if git diff --cached --quiet; then
        echo "[model] no model changes to persist"
      else
        git -c user.name="$bot_name" -c user.email="$bot_email" \
            commit -m "model: update ${slug} [skip ci]" >/dev/null
        git push origin "HEAD:refs/heads/${branch}"
        echo "[model] pushed updated model to $branch"
      fi
    )
    ;;

  *)
    echo "unknown command: $cmd (use restore|save)"; exit 2 ;;
esac
