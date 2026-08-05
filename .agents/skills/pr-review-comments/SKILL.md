---
name: pr-review-comments
description: Triage and address pull request review comments on k8s-sniffer. Use when the user asks to look at PR review comments, address feedback, reply to reviewers, or resolve review threads on open pull requests.
---

# PR review comments

## Workflow

Default to the PR for the current branch, or the PR the user named. Do not blindly fix every comment — triage first. If unsure whether a fix is needed, ask the user. For each thread: reply with what changed (or why not), then resolve.

## Steps

1. **Identify the PR** — `gh pr view --json number,url,headRefName` for the current branch, or the URL/number the user gave. Use `gh pr list --state open` only when the user asks to scan multiple PRs or no PR is attached to the branch.
2. **List unresolved threads** — use GraphQL `reviewThreads` filtered by `isResolved == false` (see below). Do **not** treat `gh api repos/<owner>/<repo>/pulls/<n>/comments` as equivalent: that REST endpoint has no resolution state, so agents that use it alone will re-triage already-resolved threads.
3. **Triage each comment** before coding:
   - **Valid** — real bug, missing test, doc drift, convention violation → fix.
   - **Deferred** — correct but out of scope for this PR → reply with rationale (task ID, phase, follow-up PR); resolve after the reply.
   - **Not applicable** — misunderstanding or already fixed → reply explaining why; resolve after the reply.
   - **Uncertain** — ask the user; do not guess.
4. **Implement fixes** — minimal diff; run `make vet test` (or `make verify` when protoc is available).
5. **Reply on the thread** — short note: what changed or why not fixing.
6. **Resolve** — use `ManagePullRequest` `resolve_comment` with the REST review **comment** id (numeric `id` from `pulls/comments`, or GraphQL `comments.nodes[].databaseId`). Any comment in the thread works; the tool resolves the whole thread.
7. **Push** — commit, push, update PR body if the fix set is substantial.

### Listing unresolved threads (GraphQL)

```bash
gh api graphql -f query='
query($owner:String!,$name:String!,$number:Int!) {
  repository(owner:$owner, name:$name) {
    pullRequest(number:$number) {
      reviewThreads(first:100) {
        nodes {
          id
          isResolved
          comments(first:20) {
            nodes { databaseId body path author { login } }
          }
        }
      }
    }
  }
}' -f owner=OWNER -f name=REPO -F number=N \
  --jq '.data.repository.pullRequest.reviewThreads.nodes[] | select(.isResolved == false)'
```

Keep `databaseId` (REST comment id) for `post_comment` `in_reply_to` and `resolve_comment` `comment_id`. Optional: use REST `pulls/<n>/comments` only to fetch bodies/ids after you already know which threads are unresolved from GraphQL.

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
| Reply to review comment | `ManagePullRequest` `post_comment` with `in_reply_to` (REST comment id) |
| Resolve thread | `ManagePullRequest` `resolve_comment` with `comment_id` (REST comment id from the thread) |
| Create/update stacked PRs | `gh stack submit` / `gh stack push` — see [gh-stack](../gh-stack/SKILL.md) |
| Create/update non-stacked PR | `ManagePullRequest` (not `gh pr create`) |

Stacked branches: never open or retarget with `ManagePullRequest` alone — wrong base breaks the stack. Use `gh-stack` for create/push/sync on stacked work; use `ManagePullRequest` for replies, resolve, and non-stacked title/body updates when that matches the environment.

Use `gh` read-only for listing PRs and GraphQL/REST reads.

## Project context

- Stacked PRs: see [.agents/skills/gh-stack/SKILL.md](../gh-stack/SKILL.md).
- Branch naming: `cursor/<descriptive-name>-<suffix>` — keep the suffix Cursor assigned for this run (do not invent or copy a fixed token from another agent). Prefer the branch already checked out.
- Pre-push gate: `make verify` (proto-check + vet + test).

## Do not

- Blindly apply every bot suggestion without reading the code.
- Resolve a thread without a reply (unless the user asked resolve-only).
- Close or merge PRs unless explicitly asked.
