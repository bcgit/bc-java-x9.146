---
name: copy-commit-message
description: When a discrete code-change task is finished and ready to be committed, craft ONE short imperative commit message and copy it to the system clipboard so the user can commit it themselves. Claude must NOT commit, stage, push, or otherwise change git state. Use this at the end of any self-contained change (a fixed TODO, a bug fix, a small feature) — especially while working through a list of items one by one — whenever the user expects to do the actual commit. Triggers include the user saying "copy the commit", "copy a commit message", "copy to clipboard", or finishing an item in an ongoing one-by-one task loop where the established rhythm is finish → copy message → user commits.
---

# Copy a commit message to the clipboard (never commit)

This skill captures a strict division of labour: **Claude writes the commit message and copies it to the clipboard; the human runs the commit.** It exists so that working through a backlog item-by-item never results in Claude creating commits on its own.

## Hard rules — do not violate

- **Never** run `git commit`, `git add`, `git push`, `git tag`, `git merge`, `git rebase`, `git reset`, or any other command that mutates git history, the index, or remotes.
- `git stash` is allowed **only** for the stash-the-fix verification discipline, and only when explicitly part of verifying a change — never as a way to "save" or "commit" work.
- Read-only git (`git status`, `git diff`, `git log`, `git show`) is fine.
- The clipboard is the **only** delivery mechanism. The user commits.
- If the user explicitly says "go ahead and commit" / "commit it yourself", that overrides this skill for that one request — but the default and the whole point of this skill is hands-off.

## What to produce

A **single-line imperative headline** following this repo's convention (see `docs/claude/conventions.md`, "Commit messages"):

- Short imperative sentence: *"Fix …"*, *"Add …"*, *"Remove …"*, *"Validate …"*.
- Self-contained — no multi-line body (multi-line bodies are unusual here).
- End with `relates to github #NNNN.` **only** when the work is tied to a tracked issue.
- Do **not** append the `Co-Authored-By: Claude …` trailer — the human is the author of their own commit. (That trailer is only for commits Claude itself makes, which this skill forbids.)
- Describe what the change *does*, not the process. Mention the verification only if it's the point of the change (e.g. a test rework).

Aim for ~60–100 characters; if a change genuinely spans two unrelated concerns, produce **two** messages and say which files belong to each, rather than one vague catch-all.

## How to copy

Copy with whatever clipboard tool the platform has — this machine has **`xclip`** (Wayland's `wl-copy` is *not* installed here, despite `WAYLAND_DISPLAY` being set, so don't rely on it). Use a fallback chain so the skill stays portable:

```bash
printf '%s' "Fix high-tag-number identifier encoding in the streaming BER/DER generators" \
  | (wl-copy 2>/dev/null || xclip -selection clipboard 2>/dev/null || pbcopy 2>/dev/null)
```

Then **confirm the copy landed** by reading it back (the trailing `echo "copied: …"` pattern is misleading — it prints regardless of whether the copy succeeded):

```bash
xclip -selection clipboard -o   # should echo the message back verbatim
```

If readback doesn't match, the clipboard write failed — tell the user and print the message in the chat so they can copy it manually.

## After copying

- Show the user the exact message you copied (in a quote block).
- List the files they should stage for it — and call out any files to **leave out** (working artifacts like `todo-audit.md`, `.todo-audit/`, scratch references).
- Stop there. Do not offer to commit; do not run the commit even if it seems convenient.

## Worked example

Finished fixing a defect in `BERGenerator`/`DERGenerator` plus a new test:

> Fix high-tag-number identifier encoding in the streaming BER/DER generators, verified tagged output against X.690 8.14.2/8.14.3 with new ASN1GeneratorTest

Copied via the `xclip` chain above, readback confirmed, then:

- Stage: `BERGenerator.java`, `DERGenerator.java`, `ASN1GeneratorTest.java`, `RegressionTest.java`, `docs/releasenotes.html`
- Leave out: `todo-audit.md`, `.todo-audit/`
