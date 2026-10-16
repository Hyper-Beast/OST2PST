# Instructions for AI-assisted development

Read this file explicitly before changing the project. Its filename is `agent.md`; tools that
only auto-load `AGENTS.md` need an explicit instruction to read it.

## First steps

1. Read [README.md](README.md) for supported input, CLI behavior and license status.
2. Read the relevant section of [DEVELOPMENT.md](DEVELOPMENT.md). It consolidates the original
   M1–M7 architecture, native GUI contracts and verification lessons; no Trellis installation is needed.
3. Inspect Git status and preserve uncommitted work. Identify the owning layer and smallest useful
   regression before editing. Keep a concrete checkpoint for long tasks: changes, evidence, next step.

## Runtime and architecture

- C++20, Windows x64, MSVC /W4, no Outlook/MAPI/account/network requirement for conversion.
- Keep dependency direction `cli → msg → ltp → ndb → util`; `msg → writer → ltp/ndb` is allowed.
  NDB stays format-only. Writer receives parsed values and never reads a source OST handle.
- Public interfaces live in `include/ost2pst`; internal helpers stay in their owning source layer.
- GUI view/process dependencies stay in `src/gui`; reuse the versioned CLI event protocol. Do not
  change format/writer/staging semantics to fix a UI issue. Success requires terminal, exit and report
  agreement. Preserve paths, run identity and results when changing language. Check all nine locales.
- Use existing `Status`/`Result<T>` and absolute field offsets for corrupt-input diagnostics.
  Propagate failures through library, caller, CLI and report. Output I/O failure is not a corrupt item.
- Transfer ownership with `Result<T>::take()`; `value()` is const and moving its members can copy.

## Format evidence

- Obtain/open the official reference before adding offsets or interpretations; do not guess.
  DEVELOPMENT lists authoritative links. Search headings and read relevant sections rather than
  loading an entire specification. Cite MS-PST sections or the exact libpff heading beside constants.
- A 4K input is not a 512-byte PST layout. Do not infer block counts from `bidNextB`, use a
  source field as proof of output compatibility or infer roles from folder display names.
- Before claiming a layout is undocumented, search both MS-PST and libpff format notes for its
  structure and field names. If both are silent, write “inferred from one sample, not in MS-PST
  or libpff notes”. A sample observation is never a universal format requirement.
- Stop and retain a small reproduction if a count only works after an invented shift/multiplier,
  a field exceeds its referent's bounds, or a heuristic is needed to choose a spec field's meaning.
  Suspect our decoder first. Do not add CRC-matching, interpretation guessing or relaxed checks.
- After three failed attempts on the same issue, document the blocker and escalate rather than
  patching around it. Unknown content stays unknown; green counts cannot justify data loss.

## Data, privacy and recovery

- Never commit OST/PST files, extracted mail, recipients, subjects, attachments, private logs,
  credentials or local mailbox paths. `.gitignore` is a convenience, not proof of privacy.
- Public fixtures are generated from synthetic patterns/public spec examples in the build tree.
  Add code-generated minimal reproductions, not excerpts from a real mailbox.
- For authorized private comparisons, use a frozen copy and record its SHA-256 locally. Outlook
  can change an OST without changing its size; compare revisions on the same snapshot.
- Preserve failed/accepted evidence locally. Outlook tests use a separate output copy; never
  open or repair the immutable comparison authority. Keep raw logs out of public commits.
- Resume binds source hash/size, converter hash, profile, options and destination. Do not weaken
  identity checks or delete unknown state. Retain existing output protection and item transactions.

## Build, check and finish

Run in a VS 2022 environment, using `scripts/dev.cmd` from Command Prompt:

```bat
scripts\dev.cmd cmake -S . -B build -A x64
scripts\dev.cmd cmake --build build --config Release --parallel 4
scripts\dev.cmd ctest --test-dir build -C Release --output-on-failure
```

Use `scripts/check_layers.sh` in Git Bash with ripgrep installed; format only changed C++ files
using `.clang-format`. Review `git diff --check`. Do not edit scripts while they are executing.

For a defect, first demonstrate the failing regression, fix it and run affected tests. At batch
completion run the full applicable suite. Production decoding/writing changes also require
the external content and Outlook checks specified in DEVELOPMENT. Do not count missing,
skipped or NOT VERIFIED checks as passed. Distinguish direct author review from independent review.

Keep logical commits, explicit validation commands and limitations. Update DEVELOPMENT when a
stable contract changes; do not accumulate contradictory historical todo lists. Do not invent an
open-source license or third-party attribution. Report what changed, why, what passed and what
still requires external evidence. Never push or publish without the owner's authorization.
