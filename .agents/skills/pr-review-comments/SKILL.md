---
name: pr-review-comments
description: Triage and address pull request review comments on k8s-sniffer. Use when the user asks to look at PR review comments, address feedback, reply to reviewers, or resolve review threads on open pull requests.
---

# PR review comments

## Workflow

Look in the newly opened prs for review comments. Address them. Do not blindly fix, consider if a fix is actually needed and if the comment raises a valid issue. If not sure, ask the user. If you issue is not relevant, answer in comments why. If it is and you fixed, put a short comment as reply on how you fixed, and resolve the original comment.

## Steps

1. **Find open PRs** — `gh pr list --state open` (or the branch the user named).
2. **List unresolved threads** — GraphQL `reviewThreads` where `isResolved == false`, or `gh api repos/<owner>/<repo>/pulls/<n>/comments`.
3. **Triage each comment** before coding:
   - **Valid** — real bug, missing test, doc drift, convention violation → fix.
   - **Deferred** — correct but out of scope for this PR → reply with rationale (task ID, phase, follow-up PR).
   - **Not applicable** — misunderstanding or already fixed → reply explaining why; resolve if convinced.
   - **Uncertain** — ask the user; do not guess.
4. **Implement fixes** — minimal diff; run `make vet test` (or `make verify` when protoc is available).
5. **Reply on the thread** — short note: what changed or why not fixing.
6. **Resolve** — use `ManagePullRequest` `resolve_comment` with the review comment id (GitHub numeric id from the thread).
7. **Push** — commit, push, update PR body if the fix set is substantial.

## Reply templates

**Fixed:**
> Fixed: `<one-line what changed>`.

**Deferred:**
> Deferred: `<reason>` (e.g. T1.9 agent bootstrap). Documented in `<path>`.

**Not applicable:**
> Not applicable: `<why the concern does not apply or is already handled>`.

## Tools

| Action | Tool |
|--------|------|
| Reply to review comment | `ManagePullRequest` `post_comment` with `in_reply_to` |
| Resolve thread | `ManagePullRequest` `resolve_comment` with `comment_id` |
| Create/update PR | `ManagePullRequest` — not `gh pr create` |

Use `gh` read-only for listing PRs and fetching comment ids.

## Project context

- Stacked PRs: see [.agents/skills/gh-stack/SKILL.md](../gh-stack/SKILL.md).
- Branch naming: `cursor/<descriptive-name>-3a21`.
- Pre-push gate: `make verify` (proto-check + vet + test).

## Do not

- Blindly apply every bot suggestion without reading the code.
- Resolve a thread without a reply (unless the user asked resolve-only).
- Close or merge PRs unless explicitly asked.
