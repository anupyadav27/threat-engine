---
paths:
  - ".claude/planning/stories/**/*.md"
  - ".claude/planning/SPRINT_*.md"
  - ".claude/planning/multi-csp/**/*.md"
---

# Planning File Lifecycle Rule

## Core Rule
**Never leave a completed sprint prompt or story file in place without asking.**

When a user confirms a task, sprint, or story is done:
1. Ask: *"Story {ID} is marked done — shall I delete the file?"*
2. On confirmation: `rm` the file immediately.
3. Update `stories/README.md` completed sprint table with one-line summary.
4. If it was the last story in a sprint, ask about the sprint prompt file too.

## What counts as "done"

A story is done when the user says any of:
- "done", "ship it", "merged", "deployed", "confirmed", "it's working"
- marks story `status: done`
- says the kubectl rollout was clean and findings look right

A sprint prompt is done when ALL its stories are done AND the image is deployed.

## File cleanup sequence

```
story done → delete .claude/planning/stories/{ID}_*.md
             ↓
all stories in sprint done → ask to delete SPRINT_{name}.md
             ↓
confirm → delete sprint prompt file
             ↓
update stories/README.md "Completed Sprints" table with one line:
| {Sprint name} | {Date} | {outcome} |
```

## What NOT to delete

- `stories/README.md` — the template and index, always keep
- `SPRINT_*.md` files while ANY story from that sprint is still in-progress
- Planning files the user says "keep for reference"

## Stale file detection

At the start of a session, if `.claude/planning/stories/` has files with `status: done`,
flag them: *"These story files are marked done — shall I delete them?"*

Similarly flag any `SPRINT_*.md` file if all its referenced stories are done.

## Why
Done planning files become noise. They get passed to agents by mistake, their
acceptance criteria get confused with current work, and they make it hard to see
what is actually still pending. A clean planning folder = one glance = current sprint only.
