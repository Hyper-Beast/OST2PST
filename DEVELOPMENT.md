# Development guide

This guide consolidates the converter's M1–M7 plan and stable development contracts. It is
intended for maintainers and their AI assistants. Read [agent.md](agent.md) first; no Trellis
runtime, archived task history or private mailbox is required to build the public source.
The user-facing scope, benchmark and license status are in [README.md](README.md).

## 1. Goal and current scope

Build a new Unicode PST from an offline OST, using standalone C++20 code with no Outlook,
MAPI, account or network dependency. Outlook is an acceptance-test application, never a
conversion dependency. All planned CLI converter milestones are complete. The optional native
Windows conversion wizard is implemented as a separate frontend over the existing CLI worker.

Supported decoding covers unencoded Unicode 4K-profile input and Unicode 512-byte-page
structures; output uses the latter profile. ANSI, WIP and nonzero encoding are refused.
There is no source write-back, synchronization, incremental update of an existing PST,
protected-store decryption or recovery of data absent from the cache. Public API/ABI stability
is not promised. RTF/OLE interpretation is outside the reader scope: preserve available bytes.

## 2. Repository and build

| Path | Responsibility |
| --- | --- |
| `include/ost2pst/{util,ndb,ltp,msg,writer}` | Public C++ interfaces |
| `src/{util,ndb,ltp,msg,writer}` | Layer implementations and local internal helpers |
| `src/cli` | `ost2pst`, `ostinfo`, read-only modes and full orchestration |
| `src/gui` | Bounded protocol reducer, native process host, localization and wizard |
| `resources/gui` | Native manifest/icon and generated nine-language catalogs |
| `tests/unit` | C++/Python regressions and process/recovery tests |
| `tests/tools/generate_fixtures.py` | Synthetic NDB fixtures and public MS-PST examples |
| `tests/tools` | Optional independent reference/content/API/export comparison tools |
| `scripts` | Toolchain, layer checks and verification runners |

CMake 3.22+, Visual Studio 2022 C++ tools, Windows x64. Use `scripts/dev.cmd` to enter the
toolchain (discovered using `vswhere`, overridable with `VSCDEV_BAT`). Default tests require
Python 3.8+. Use `-DBUILD_TESTING=OFF` for application-only builds. Runtime uses the standard
C++/Microsoft runtime and Windows APIs, with no third-party format library. See README for commands.

Fixtures/golden JSON are generated in the CMake build tree at configuration. If fixture generator
code changes, rerun CMake configuration before building/testing. Test directories may be generated
outside the source checkout by setting `-B` to another directory. Public code contains no private
binary fixtures. Keep outputs, sidecars, exports and third-party checkouts ignored and local.

## 3. Architecture and data flow

```text
cli -> msg -> ltp -> ndb -> util
        |      ^
        +-> writer -> ndb
```

| Layer | Owns | Boundary |
| --- | --- | --- |
| util | Explicit byte I/O, status/errors, CRC32, SHA-256, inflate, file identity, budgets/spools | No PST semantics |
| ndb | Header/root, page/block trailers, allocation maps, BBT/NBT and data-block reads | No properties/folder/message semantics |
| ltp | HN/BTH, data trees, PC/TC, subnode trees, Name-to-ID and supported queues | Exposes parsed values, not output bytes |
| msg | Mailbox ownership/manifest, item extraction, recipients/attachments, coverage/outcomes | Produces content plans; does not allocate file bytes |
| writer | HN/PC/TC emission, allocation, references, IDs, fresh store, staging and publication | Receives parsed values, never opens the source OST |
| cli | Options, action selection, progress, orchestration, typed exits and reports | No duplicated format arithmetic |

LTP still contains diagnostic folder walking in `ltp_read.cpp`; Messaging uses it alongside
NBT `nidParent` attribution. This is known architectural debt, not permission for an unrelated
refactor. Reuse `ltp::open_node` instead of reimplementing node/block classification.
`scripts/check_layers.sh` enforces include direction and selected layout citations.

Full conversion proceeds through stable source identity, bounded indices/NameID, mailbox manifest,
destination ID reservation, per-item extraction/commit, folder/scaffold plans, streaming assembly,
candidate reread, reports and publication. Source indices/folder values are released before
assembly and candidate reread. No complete mailbox or PST-sized byte vector is retained.

## 4. Milestones M1–M7

M0 established explicit decoding primitives, CRC/signature/layout checks, CMake and small regressions.
The following completed milestones remain maintenance boundaries rather than an open todo list.

| Milestone | Implementation | Required evidence when changing it |
| --- | --- | --- |
| M1: NDB reader | Header/root policy, profile-specific pages/blocks, BBT/NBT traversal, block CRCs/signatures and allocation diagnostics | Synthetic normal/corrupt/truncated reads, truthful findings; compare enumeration with an independent reader on fixed private inputs |
| M2: LTP reader | HN/HID, BTH, multi-block data trees, subnode trees, property/table contexts, Name-to-ID and supported internal structures | Boundary and malformed-context regressions, source-value/schema availability and explicit unsupported findings |
| M3: Messaging inventory | Folder ownership, normal/FAI items, recipients, attachments, embedded/opaque content, source-gap/outcome accounting | Whole-tree inventory and ownership reconciliation; distinguish missing cache content from decoder failure |
| M4: Empty PST writer | Fresh header/maps/trees, required store/folder/queue/template structures, PC/three-TC folders, IDs and NameID | Self-reader plus independent libpff, comparison with an immutable Outlook-generated blank oracle and actual Outlook open/restart |
| M5: Content writer | Folder/message PCs and TCs, recipient/attachment schemas, HN/data emission, named identity remapping, EntryIDs and body bytes | Representative subset (historical target: at least 50 messages/5 attachments), full schema/value/payload checks and Outlook content/attachment observations |
| M6: Full conversion | Stable mailbox manifest, transaction staging, bounded values/workspace, block sharing, resume, per-item isolation, internal reread and reporting | Full mapped content/reference/API/export comparisons; process interruption/recovery, resource measurement and Outlook acceptance |
| M7: CLI robustness | Dry-run, verification, shared header refusal policy, strict numbers, Unicode paths, typed exits and deterministic truncation corpus | Exact diagnostics, side-effect protection, full CLI callers, corpus with timeouts/no crash/no false success and retained compatibility |

The accepted M6 writer fixed a root-opening failure by preserving fixed allocation maps during
growth. Reader/libpff success alone had missed this defect. M7 changed CLI policy rather than writer
bytes. The original M7 local acceptance had 53 tests and twelve strict gate steps; the
CLI-only public build had 52 default tests, with the external gate meta-test opt-in. Original acceptance and benchmark
are historical evidence, not automatic acceptance of future revisions. The M7 synthetic truncation
corpus ran 4,727 diagnostic invocations without crashes, timeouts or silent success. The GUI-enabled
public build passed 57 tests, covering event/result agreement, real stop/resume and close interactions,
failure propagation, nine languages at 100/150/200% DPI and live language switching. Default/event
worker conversions on the frozen sample produced PST bytes identical to the accepted writer output.
Native visual automation on one Windows host cannot establish compatibility with every theme or OS.

## Native GUI maintenance

Build with `OST2PST_BUILD_GUI=ON` on Windows. Use `OST2PST_STATIC_RUNTIME=ON` consistently across
all MSVC targets for the portable package. Generated resources are checked in; application-only
builds need neither Python nor a GUI framework. `scripts/package_gui.py` refuses existing outputs
and packages `OST2PST.exe`, `engine/ost2pst.exe`, notices, usage and SHA-256 manifest. Keep the
two executables together. Updating the worker changes recovery's binary identity.

`src/gui/protocol.*` owns dependency-free JSON parsing, locale matching, quoting and the typed
session reducer. `process_host.*` owns subprocesses/pipes and `wizard.*` renders snapshots.
`src/cli/gui_events.*` emits opt-in `--events-json` full-mode/resume events. No format or writer
layer imports Windows view types, and no format or durable staging schema changed for the GUI.

Event v1 uses flushed UTF-8 JSONL stdout; human diagnostics use stderr. Every event has schema 1.
Start declares protocol 1. Progress carries phase (identity/index/items/folders/assembly/verification/
publication/published), nullable total and terminal/normal/fai/skipped counters. Skipped includes
failed item outcomes. Only the items phase has a percentage. Typed error events carry input/operation
scope, kind, field, offset, value and detail. Complete/0 or incomplete/3 results embed the exact
published aggregate report. An input/verification failure with exit 3 is failed, not incomplete.
Completed resume must also emit a terminal result. Presentation flags do not enter durable options.

The parser rejects invalid UTF-8/JSON, duplicate keys, integer overflow and invalid surrogate pairs;
limits are 1 MiB per event/report and 32 nested containers. The reducer checks phase/count monotonicity,
count sums, denominator and exactly one start/terminal. A complete/incomplete GUI verdict requires
matching terminal event, actual worker exit and decoded on-disk report. A PST file alone, truncated
stream or stale/missing report never proves success. Avoid exposing mail subjects/body/names/payloads
in progress events. Original diagnostics remain available in a read-only Details dialog.

The native progress control initializes its range once and changes marquee style/timer only when
its mode changes. Item snapshots update the position only when it changes; language refreshes must
not restart the animation or reset the range. Unknown-length phases still use activity, not an
invented overall percentage, and terminal results stop the animation.

Launch uses explicit module-relative `engine/ost2pst.exe` (sibling fallback in build trees), explicit
CreateProcessW application path, tested Windows argv quoting and inherited-handle allowlisting.
Drain stdout/stderr concurrently. Retain only the newest 256 KiB diagnostic tail with a visible
truncation indication. At most one pending posted notification coalesces snapshots; errors/results
remain retained. Workers live in an owned kill-on-close job, with no shell/PATH lookup. Stop only
terminates the owned worker, retains recovery data and waits for exit plus both readers before
another run. A finished terminal success wins a late Stop. Close confirmation must drain the worker.

Nine embedded catalogs cover English, Simplified/Traditional Chinese, Japanese, French, Italian,
Spanish, German and Korean. At startup resolve ordered Windows preferred UI languages, not region
or date settings; explicit Chinese script wins over region, and unsupported/failed detection falls
back to English. The top combo displays the selected autonym. Switching immediately relocalizes
the current page and validation without resetting entered paths, the active run, counts or result.
Selection is process-local. Edit `resources/gui/catalogs.json`, run `scripts/generate_gui_strings.py`,
then `--check`. Preserve key/placeholder parity. Do not hand-edit generated `strings.h`.

The four native pages use Segoe UI, standard file dialogs, keyboard traversal, a per-monitor DPI
manifest, scaled fonts/reflow and Windows high-contrast colors. Result actions share one footer
baseline. Existing outputs/reports are protected and reserved destination filenames are rejected.
Keep implementation diagnostics behind Details; the main conversion flow uses formal short labels.

Run `ctest -R gui_ --output-on-failure` after GUI changes. Protocol tests cover adversarial parsing,
result reconciliation and real worker complete/incomplete/failure/resume paths. Native tests use
synthetic sources, actual dialogs/controls, stop/resume/close races, failure injection, spaced/Unicode
portable paths, unrelated CWD and all nine languages at 100/150/200% DPI. They save rendered captures
and verify bounds, localized button fit, language switching and aligned result actions. The palette
test seam exercises system-color code without changing the user's Windows theme. Review captures;
automated checks do not prove every OS theme or human usability preference.

When full-entry instrumentation changes, `scripts/verify_gui_equivalence.py` can run default and
event modes on an authorized immutable source and compare PST bytes/reports against a separate
accepted authority. Supply both identities explicitly. Keep private inputs and logs outside commits.
No new Outlook operation is required for catalog/layout-only changes. Direct author review is not
independent code review. Runtime imports/package sizes must be measured from the actual build.

## 5. Format and coding contracts

### Evidence and profile selection

Use Microsoft's [MS-PST] and libpff's format notes (links in THIRD_PARTY_NOTICES). Obtain the
documents locally before research, search a structure/field/heading and read its window. The
libpff 4K notes contain Unknown/TODO fields; do not convert them into confirmed constants.
Documented contracts, one-sample observations and hypotheses are distinct.

Select layout by validated profile: 512-byte pages/64-byte block allocation for output Unicode
PST; 4096-byte pages/512-byte allocation for supported 4K input. Do not transplant offsets or
infer block populations from `bidNextB`. Do not infer output requirements from OST behavior.
Actual Outlook output/oracle observations support writer compatibility policy, not universal
reader restrictions. Fixed-map placement beyond normative details retains its single-sample
inference provenance in `store.cpp` and the audit script.

Before claiming “not in MS-PST”, “OST-only” or a measured layout constant, search both references
by structure/field aliases and cite the section found. If silent, label it explicitly as inferred
from one sample. Stop on impossible references, invented count units, heuristics to choose a field
meaning or three failed attempts. Preserve a minimal case; suspect the decoder before the file.

### C++ and errors

- Decode every little-endian field explicitly through bounded byte helpers. Never overlay a file
  buffer with a C++ struct using `reinterpret_cast`; padding/endianness are not format contracts.
- Use fixed-width integers for format fields. Check lengths, addition/multiplication overflow,
  recursion, references and allocation capacity before indexing or allocating.
- Corrupt/unsupported data returns `Status`/`Result<T>` with absolute offset, record/field and
  actual value when known. Never turn a failed child into a clean parent or suppress a finding.
- Use `Result<T>::take()` for ownership transfer. `value()` returns const; `std::move` can copy.
- Types `PascalCase`, functions/variables `snake_case`, constants `kName`, files `snake_case`.
  `#pragma once`, explicit includes, no mutable globals or `using namespace std` in public headers.
- Comments explain reasons and reference opened sources. Format touched C++ with `.clang-format`.
  Build with `/W4 /permissive- /Zc:__cplusplus /utf-8`; keep changes within their owning layer.

### Content and identity

- Manifest creation requires complete indices and a validated NameID map; it does not inspect
  every payload. Source-NID order fixes folder/normal/FAI output IDs before extraction. Failed
  items leave reserved holes; later items must not be renumbered.
- Source root becomes `Imported OST` below the output IPM subtree. Actual parents are retained;
  missing owners/cycles/content beneath excluded searches fail planning. Never infer roles by name.
- Named properties are GUID + numeric/string identity, not source NPID numbers. Deduplicate/sort
  the immutable registry and register both PC values and TC schemas, including empty tables.
  Preserve ordinary types; remap named columns/cells together. Dynamic output range is inclusive
  `0x8000..0x8FFF` (4096 identities); ordinal starts at zero (MS-PST 2.4.2.2, 2.4.7).
- Numeric named properties do not require a String Stream lookup; string identities do. GUID
  availability is checked separately. NAMEID_GUID_NONE is the explicit no-GUID property set:
  its index is zero, bytes are empty, and guid_resolved remains false. Accept it consistently in
  manifest planning, PC values and TC schemas/cells; an unresolved nonzero GUID index still fails.
  Duplicate/unresolved source identities fail honestly.
- Regenerate PST object EntryIDs using the destination provider identity. Recipient address-book
  EntryIDs are provider-defined source values and must be preserved rather than synthesized from row IDs.
- Every source NBT entry gets a coverage record. Search exclusion, regenerated scaffold, unknown
  internal structures and content are explicit. Recognizing a template does not prove equivalence.
- CEB-set non-inline HNID zero is a present empty value; unset CEB is absence. Preserve that distinction.
- All multi-valued TC types use an HNID, including arrays of fixed-size numeric values
  (MS-PST 2.3.4.4.2). Apply the same rule in extraction, column layout and empty-cell emission.
  Present-empty Attachment PC property 0x3701 retains its type and HNID zero; it must not disappear
  merely because there are no payload bytes.
- A tolerant BTH walk is not proof of complete extraction: skipped records, trailing partial records
  or an early stop invalidate the owning PC/TC. Carry the reason into the item diagnostic and
  terminal outcome; resource ceilings remain unsupported, malformed content remains corrupt.
- PC writers split sorted records into leaves of at most 3580 bytes and index their first keys
  (MS-PST 2.3.2.2/2.3.2.3, 2.6.2.1.2). Property count alone must not force one oversized allocation.
- Terminal outcomes are unique and committed; source/committed/verified populations reconcile.
  Source omissions, unsupported content, corrupt data and deliberate exclusions stay separate.
  Available body/attachment/recursive object bytes are compared, not replaced by guessed content.
- A present Recipient/Attachment Table with bidData zero is unreadable, not absent. Attachment
  rows must name unique Attachment-type subnodes, and every enumerated Attachment object must
  have a readable row. Missing/short/unreadable tables cannot establish an empty attachment
  population. Retain object diagnostics and mark the item corrupt/incomplete rather than converting
  a message after silently dropping its attachments.
- Allocate and emit an Attachment Table whenever the content request supplies columns, even with
  zero rows/objects. Preserve named identities through emission, assembly and reread, including in
  embedded messages. Compare schemas, not just row/object counts.

Maintenance regressions for unreadable/missing Attachment Tables, valid no-GUID named properties
and zero-row Attachment Table schemas cover item preparation, embedded-message reread, and
default/event full conversion with a corrupt neighboring item. The historical M6 benchmark and
Outlook observation in README predate these fixes. The later large-mailbox run completed with
internal verification, but independent private-mailbox content comparison and renewed Outlook
acceptance remain unrecorded. Source review was by the implementing assistant.

### Bounded processing

Engineering ceilings are not format layout constants or allocator/RSS guarantees. Full conversion
uses an 8 GiB on-demand source/candidate index accounting ceiling, 512 MiB item/folder metadata,
32 MiB record metadata, 1 GiB aggregate encoded assembly metadata, 32 million physical output blocks
(including generated internal blocks), one million top-level output nodes and recursive depth 64.
The one-million-object/block ceiling still applies to each private record, independently of the
whole output. Read-only diagnostics retain their separate 256 MiB workspace ceiling. Consult the
owning headers for precise scopes. A resource limit must propagate as unsupported/incomplete,
not corruption or success. ValueSpool budgets payload separately; nested metadata shares reservation.
The manifest bounds its NBT copy/destination mapping to one million entries. It reuses the census
BBT, whose memory was already budgeted by the reader; it must not impose the former second 128 MiB
BBT ceiling. This does not remove the source/candidate index workspace limit.
The extraction ceiling is cumulative allocation accounting, including conservative construction,
copy and vector-growth multipliers, not live memory or RSS. It is charged on demand and resets
for each top-level item; embedded messages share the parent's budget. The former 64 MiB default
rejected valid recipient-heavy items. The 512 MiB default increases capacity without releasing
reservations prematurely, retrying partial extraction, or relaxing content checks. Explicit smaller
budgets still refuse with an unsupported outcome and no item plan. Budget diagnostics record used,
limit and requested bytes. The limit is finite and does not guarantee every possible item fits.
`writer_item_plan_test` generates nested messages with 3,000 recipients and 16 fixed-value columns,
and 300 recipients with 16 heap-backed 2 KiB columns. Both reproduce the old limit, succeed under
the new default, and stage the same content digest as unspooled reference extraction. Existing
tiny-budget, I/O-failure and neighboring-item isolation tests remain applicable.

Aggregate budgets target 100 GiB-class inputs: 100 GiB of full 8176-byte payload blocks needs about
13.2 million external blocks, with additional capacity for partial blocks, heaps, tables and generated
trees. File size alone cannot guarantee that block/node/metadata budgets fit. The ceilings do not
preallocate memory; large stores may require several GiB of RAM. Writer block descriptors are at most
40 bytes each and staged references use 24 bytes on x64, held in fixed 4096-entry chunks to avoid
whole-index reallocation. Only generated internal blocks own byte vectors. Payloads remain streamed.
This capacity model is not real-mailbox or Outlook acceptance at 100 GiB.

Assembly shares raw external blocks using CRC32 followed by exact bytes; CRC alone is insufficient.
The default sharing index holds up to 524,288 entries; saturation emits unshared copies without
data loss. Each logical reference remains represented; allocate another physical block before
uint16 reference capacity is exhausted. Deterministic ordering preserves recovery behavior.
Historical sample budget was <900 seconds and <1,000,000,000 bytes peak working set, measured for
the whole conversion. Passing it does not establish arbitrary large-store capacity.

`writer_staged_plan_test` exercises more than one million distinct physical blocks through both
unshared and saturated-sharing assembly. `writer_streaming_test --100gib` is an explicit, heavier
capacity check: it generates and checksums 100 GiB of synthetic payload through the real writer,
using a counting sink rather than allocating a 100 GiB disk file. It checks final 64-bit offsets,
trailer/CRC/EOF and flush, but does not reopen a complete PST or exercise Outlook. Record measured
time/peak memory separately from real-mailbox throughput; never advertise it as a conversion benchmark.
The 100 GiB counting-sink run for this capacity fix passed with 13,132,851 external blocks,
13,145,749 total blocks and a modeled EOF of 111,634,523,136 bytes: 192.375 seconds and
1,490,092,032 bytes peak working set on the local Windows x64 Release build. The public suite
passed 57/57. These numbers exclude source parsing, staging, disk payload I/O and complete-file
reread. A subsequent real-mailbox report confirmed successful conversion of 26,119,315,456 source
bytes into a 22,903,186,432-byte PST on an Intel Core Ultra 5 235U / 16 GB RAM / SSD machine:
18,145 items completed, no skipped/failed items, and internal verification passed. Source, committed
and output-verified counters agree. This successful run's elapsed time and peak memory were not
saved in the supplied reports; the GUI Details log is memory-only and was closed. Independent
content comparison and Outlook acceptance for this sample remain unrecorded. The earlier 2.635 GB
benchmark machine was identified by the user as AMD Ryzen 8845HS / 32 GB RAM / SSD. Do not
substitute failed-run or counting-sink timings for real conversion time. A later run on the same
235U machine used a different source snapshot of 26,252,746,752 bytes and produced a
22,983,689,216-byte PST. Its aggregate report records complete/0, internal verification passed,
18,188/18,188 converted items, zero skipped/failed items, and identical source/committed/output-
verified populations. The per-report timer was 1,532.2688041 seconds at 17,133,251.477647834
source bytes/s; the whole-invocation diagnostic timer was 1,895.122 seconds. Peak working set was
447,881,216 bytes. The two timers cover different scopes and the source snapshots are not identical.
Independent content comparison and Outlook acceptance for this later run remain unrecorded.

A subsequent Intel Core i5-1245U / 32 GB RAM / SSD report for a 6,421,520,384-byte input returned
incomplete/3: 9,226 converted items, two skipped unsupported, no failed items, and internal
verification passed for a 4,289,012,736-byte output. The skipped items hit `data_tree.workspace`
and `subset.cell_workspace` during extraction; increasing aggregate assembly/index capacity does
not change per-item budgets. Their source populations are unknown, so preserved attachment-byte
totals cannot establish full content preservation. Report time was 384.6360514 seconds before
publication; whole-invocation diagnostic time was 448.493 seconds, with peak working set
121,708,544 bytes in both records. The subsequent capacity fix is covered by synthetic regressions
above. The user reports a later run on this i5-1245U machine finished without errors in roughly the
same time. Its aggregate report has not yet been supplied, so do not assign the earlier partial
run's PST size, counts, exact timing or memory peak to that successful retest. Content comparison
and Outlook acceptance for the retest remain unrecorded.

## 6. Staging, recovery and publication

Aggregate report schema 1 adds an optional `performance` object. `wall_seconds` uses the steady
clock from full-conversion entry to report preparation after internal verification; it excludes
final report flush/publication/cleanup. `peak_working_set_bytes` samples Windows process peak
working set at the same boundary (null if unavailable). `throughput_bytes_per_second` is source
size / elapsed seconds for fresh runs, null for resumed runs or a zero interval. `resumed` records
the invocation mode and `scope` is `current_invocation_before_publication`. Numeric JSON uses the
classic locale. Measurements are captured before sealing, never patched into a published file;
ready/completed resume preserves original report bytes and metrics. Interrupted attempts are not
added to later durations. GUI event reports carry the same object as the disk report. Equivalence
checks omit performance when comparing separate invocations, but retain all content counters.

The full converter creates `<output>.work` using a completely initialized private temporary
directory and same-volume no-replace publication. Validate the original output leaf before Windows
normalization removes trailing dots/spaces. Resolve and pin the canonical existing parent.
Work-directory redirection, replaced files and inappropriate hard links are refused.

Identity binds stable source hash/size, profile, converter binary hash and normalized options plus
destination/file identities. Validate all identities before recovery truncation. Unknown additional
files and abandoned initialization directories remain untouched. Checksums detect damage, not
hostile authenticated state changes.

Journal data flush precedes record write/flush. Only a successful commit adds a terminal outcome.
Rollback removes the active uncommitted suffix; a failed I/O poisons the session and requires
recovery. Never roll back possibly committed data after a failed commit flush. Reads are bounded
to each committed record; assembly read errors propagate.

`OSTPLAN1` encodes explicit little-endian private plan metadata/local block slots and recursive
nodes; it is an application schema, not an OST/PST format. Only the scaffold supplies `rgnid`.
Repeatable TC row sources keep stable IDs across passes. Output assembly remaps logical references
and streams payloads from committed ranges. Publication keeps collision checks and reports/receipts
consistent across interruptions; completion resume must not duplicate items or accept foreign files.
Relevant interfaces: `staging_workspace.h`, `staging_journal.h`, `staged_plan.h`, `publication.h`.

## 7. CLI contract

Read-only preflight uses a stable handle: common header prefix/policy → CRC/EOF → NDB → LTP.
ANSI/WIP must be identified from the common prefix before reading Unicode-only fields. Physical
EOF must agree with the header. Diagnostic memory ceiling is 256 MiB for probe/index workspace.

Dry-run disables payload census and uses full-mode mailbox identity/coverage planning; output is
optional/display-only. It writes no reports, directories or spools and tests no destination access.
An uninitialized minimal blank NameID map can verify structurally but fail full-mode planning.
Verification reports supported structural/context checks, unsupported structures and findings;
it does not prove original content equivalence or Outlook acceptance.

Read-only modes reject conversion flags before opening inputs. Numeric options start with an
ASCII digit, parse fully, fit the destination range and obey option-specific zero rules. Preserve
Unicode path display. Usage/I/O/output/recovery failures exit 1; unsupported input/explicit limits
exit 2; corruption, findings and incomplete conversion exit 3. Source-phase provenance must reach
the CLI rather than guessing error classes from field names. An output's existence is not success.

<a id="verification"></a>
## 8. Verification

### Public regressions

Build/test commands are in README. Default CTest covers all application/layer/process tests and
the synthetic truncation corpus without private samples or libpff. Generate a minimal failing test
before a bug fix, run affected tests after it and run the full applicable batch at completion.
The corpus tests original header prefixes, structural boundaries and deterministic seeded cuts
with per-process timeouts and diagnostic exit codes. A repaired-header cut must actually remove
referenced data; removing only free tail cannot be required to fail a structure check.

Run layer checks with Git Bash/ripgrep, format changed code and use `git diff --check`. Never
edit scripts during a running verification. Freeze scripts before batch commands. Retain one
authoritative log per command/revision/input locally; avoid copied dumps and repeat full scans
only when changed code, failure or new evidence makes prior results insufficient.

### External automated acceptance (Gate 1)

Reader/writer changes require independent evidence on a frozen authorized private input:

1. Reconcile complete folder/item/FAI/recipient/attachment/embedded populations and coverage.
2. Verify headers, all page/block CRCs/signatures, EOF, maps and every stored reference.
3. Compare actual source/output PCs, TCs (including zero-row schemas), named identities and
   recursive original values/payloads. Counts alone do not prove preservation.
4. Read through independent libpff APIs and compare complete exported trees/bytes. Exporter
   diagnostics are not silently ignored. The retained optional upstream exporter patch addresses
   a specifically observed unfilled-member-buffer read; do not broadly allowlist errors.
5. Measure whole-process time/peak working set separately from external comparison time; compare
   old/new executables on the same snapshot if the live mailbox changed.

`scripts/verify.sh` runs legacy build/self/empty/subset/external gates. `STRICT=1` fails missing
prerequisites as NOT VERIFIED; default nonstrict mode may finish with missing evidence and must
not be called complete acceptance. Inputs are supplied using `OST2PST_SAMPLE`, `ORACLE`,
`LIBPFF`, `SUBSET_FOLDER`, `BUILD`, `CONFIG` and `LOGDIR`. `LIBPFF` expects separately built
Windows libraries/tools under `third_party/libpff/vs2022/Release/x64` by default; the API probe
compile uses upstream headers in that checkout. Blank oracle and mailbox stay read-only.

The Bash meta-test is opt-in via `OST2PST_EXTERNAL_GATE_TESTS=ON`, requires libpff/Git Bash and
uses a build directory under the source checkout. It creates logs/synthetic outputs under `build`.
It injects compile/early-exit/tree-count/prerequisite/collision faults into real gate runs.
Only those injected nested runs omit the repeated truncation corpus and explicitly record unit
scope NOT VERIFIED; the outer CTest and normal strict acceptance retain the full corpus.

`scripts/verify_full.py --help` lists the explicit full-gate input/tool options. Public standalone
tools are `tests/tools/verify_pst_refs.cpp`, `mapped_content_compare.cpp`,
`libpff_fai_compare.py` and `compare_export_trees.py`. Configure with
`-DOST2PST_BUILD_AUDIT_TOOLS=ON` to build `verify_pst_refs.exe` and `mapped_content_compare.exe`
against matching project libraries. The libpff API probe uses its own headers/libs.
The full gate also requires a source export baseline and its unmodified diagnostic log, created
with the same independently built exporter. No such private baseline or external binary is bundled.
Apply the optional exporter patch from the checkout root with
`git apply tests/tools/libpff-export-member-read.patch` after obtaining the matching upstream
source under `third_party/libpff`; upstream drift must be resolved rather than applying it blindly.
Some unchanged diagnostic literals name the original `docs/reference` extracts; obtain the
corresponding documents using THIRD_PARTY_NOTICES links instead of expecting bundled full texts.

### Outlook acceptance (Gate 2)

Test a separate copy of the verified candidate in Outlook and record pre-open hash, exact version,
folder tree/counts, representative sender/recipients/date/body, opening attachments, embedded/OLE
cases and restart/reopen. Outlook may rewrite the copy. Never open the immutable authority.
No repair prompt, duplicate/orphan content or root-opening failure is acceptable. SCANPST output
must be assessed rather than declared harmless without evidence. Local tests do not replace this
gate. Existing one-version acceptance does not automatically cover changed writer code.

### Writer trap checklist (Gate 3)

- Both header CRC ranges, `rgnid` seeds, NameID registration and TC named-column/cell remapping.
- Required store/folder/receive/outgoing/template/queue structures; each folder's PC + three TCs
  share nidIndex. Reconcile against an Outlook-generated blank, not a mutated template.
- Allocation growth preserves AMap/PMap/FMap/FPMap, including deprecated fixed maps; BBT/NBT
  traversal alone does not visit them (MS-PST 2.2.2.7.5/6, 2.6.1.1.2).
- EOF backs advertised free regions, every stored reference resolves and cRef matches all uses.
- Output blocks use 64-byte footprints; CRC excludes padding. Tested output HN policy keeps
  nonfinal leaves at 8176 raw bytes and validates even heap offsets without fabricating allocations.
- Separate object and recipient EntryIDs, presence vs absence, Row Matrix boundaries, named-table
  schemas even when empty, required summary counts and explicit no-password store state.
- Interruption/recovery boundaries, durable outcomes, foreign-output refusal and corrupt-neighbor
  isolation continue to pass at CLI level; output I/O failure aborts instead of becoming an item skip.

## 9. Development workflow and extension points

Scope each change, identify its layer and smallest reproduction, obtain references before format
changes, implement, run targeted checks, then full applicable gates. Review actual diff and failure
propagation. Record exact revision/tool/input identity in private evidence and report what was not
verified. Direct author review and independent code review are distinct; neither substitutes for
Outlook observations. Keep logical commits and update these contracts with proven stable findings.

For a GUI, reuse CLI/core behavior and structured outcomes; leave format decoding out of UI code.
For broader input support, add profile-specific source-backed decode/refusal regressions before
changing dispatch. For capacity increases, test budgets/overflow/recovery and measure real whole
runs; do not infer large-store support from a small sample. For writer changes, renew Gates 1–3.
Use a separate local evidence area and respect the project's currently unspecified license.
