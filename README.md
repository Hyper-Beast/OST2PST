# OST2PST

[English](#english) · [简体中文](#简体中文)

<a id="english"></a>
## English

An offline Windows C++20 converter from Outlook **OST to Unicode PST**. It reads the
source directly and builds a new PST, without Outlook, MAPI, a mail account or a network
connection. Includes `ostinfo` for read-only format diagnostics.

The M1–M7 converter milestones are complete. This source includes both the CLI and a native
Windows conversion wizard with source, destination, progress and result pages.

### Download and use the GUI

1. Download **`OST2PST-Windows-x64.zip`** from this repository's **Releases** page.
2. Extract the entire ZIP and double-click **`OST2PST.exe`**. Keep the `engine` folder beside it.
3. Select your OST, choose a new PST destination, and start conversion. The wizard shows progress
   and the final result; an incomplete result includes reports for inspection.

The portable package requires Windows 10 1607+ x64 and needs no installation or separate
.NET/VC++ runtime. Language follows Windows automatically (English fallback), with a selector
at the top. Stop preserves recovery data; use Resume with the same source and destination.
Close Outlook before copying the OST, or use an immutable copy.

### Features and scope

- Converts actual folders, normal messages, folder-associated items (FAI), recipients,
  attachments and embedded messages, preserving available property/body/attachment bytes.
- Streams large values through bounded storage; shares identical output blocks only after
  exact byte comparison; reports phase and item progress.
- Supports interrupted-run recovery with `--resume`, per-item outcomes and aggregate reports.
- Automatically budgets workspace from available RAM and spills large tables/metadata to temporary
  disk storage. Temporary disk use can grow; the workspace allowance is not a total process-memory cap.
- Provides `--dry-run`, `--verify`, empty-store generation and folder-subset conversion.
- Supports unencoded Unicode 4 KiB-page input and 512-byte-page PST structures; writes a
  512-byte-page Unicode PST. ANSI, WIP version 37 and nonzero `bCryptMethod` are refused.

The converter cannot recover content that an OST never downloaded. Search definitions are
excluded; output store identities/internal structures are regenerated. Opaque OLE and compressed
RTF values are preserved, not rendered. Unknown structures, source gaps and skipped items are
reported separately. Other Outlook versions and much larger stores need their own validation.

### Build from source and test

Use Windows x64, Visual Studio 2022 **Desktop development with C++**, CMake 3.22+ and Python
3.8+ for tests. `scripts/dev.cmd` discovers Community, Professional, Enterprise or Build Tools
through `vswhere`; set `VSCDEV_BAT` for a custom installation. Run in Command Prompt:

```bat
scripts\dev.cmd cmake -S . -B build -A x64
scripts\dev.cmd cmake --build build --config Release --parallel 4
scripts\dev.cmd ctest --test-dir build -C Release --output-on-failure
```

Executables: `build\Release\ost2pst.exe`, `build\Release\ostinfo.exe`.
To build only the applications, configure with `-DBUILD_TESTING=OFF`; Python is then unnecessary.
The converter does not require Python, Git Bash or libpff at runtime. Like other MSVC applications,
its default build uses the Microsoft C++ runtime; install the x64 Visual C++ Redistributable if needed.

Public tests generate synthetic fixtures inside the build directory. No private mailbox, real
mailbox fragment or reference PST is bundled. External gate fault-injection tests are opt-in:
`-DOST2PST_EXTERNAL_GATE_TESTS=ON` requires Git Bash and a separately built libpff installation.
See [DEVELOPMENT.md](DEVELOPMENT.md#verification) for the difference between public regression
tests, external content validation and Outlook acceptance.

### Build the GUI from source

For a portable native wizard, configure a separate static-runtime build:

```bat
scripts\dev.cmd cmake -S . -B build-gui -A x64 -DOST2PST_BUILD_GUI=ON -DOST2PST_STATIC_RUNTIME=ON
scripts\dev.cmd cmake --build build-gui --config Release --parallel 4
scripts\dev.cmd ctest --test-dir build-gui -C Release --output-on-failure
python scripts\package_gui.py --build-dir build-gui --output dist\OST2PST-Windows-x64
```

Run `OST2PST.exe` in the resulting folder; retain `engine/ost2pst.exe`. Windows UI language is
selected automatically, with English fallback. The top selector switches immediately between
English, Simplified/Traditional Chinese, Japanese, French, Italian, Spanish, German and Korean.
This package needs no separate .NET or VC++ runtime install. Windows 10 1607+ is required by
its DPI APIs; native testing was on Windows 11 x64. The wizard converts files and opens reports,
without a mail viewer. Item counts/progress are real; assembly/verification/publication show activity.
Stop retains recovery files, and Resume validates the original source and worker identities.
Packaging refuses an existing folder/ZIP. No signing or installer is included.

### CLI usage

Use an immutable OST copy, or close Outlook before copying it. The output parent directory must exist.
Quote paths containing spaces. A full conversion protects existing outputs:

```bat
build\Release\ost2pst.exe "C:\Mail\source.ost" "C:\Export\mailbox.pst"
build\Release\ost2pst.exe --resume "C:\Mail\source.ost" "C:\Export\mailbox.pst"
build\Release\ost2pst.exe --dry-run "C:\Mail\source.ost"
build\Release\ost2pst.exe --verify "C:\Export\mailbox.pst"
build\Release\ostinfo.exe --inventory "C:\Mail\source.ost"
```

Full conversion publishes the PST, `<output>.report.json` and `<output>.items.jsonl`. Check the
`performance` object in `.report.json` for persistent measurements:

| Field | Meaning |
| --- | --- |
| `wall_seconds` | Seconds in this invocation up to report preparation, after internal verification |
| `peak_working_set_bytes` | Peak resident memory of the converter process up to that point; `null` if measurement fails |
| `throughput_bytes_per_second` | Source OST bytes divided by `wall_seconds`; divide by 1,000,000 for MB/s |
| `resumed` | Whether this report was prepared during a resumed invocation |
| `scope` | `current_invocation_before_publication` |

Measurements include hashing, indexing, conversion, assembly and internal verification; final report
flush, publication and cleanup are excluded. Resume records only the invocation preparing the report,
so throughput is `null` for resumed runs. A previously sealed/published report retains its original
measurements on resume. GUI and CLI use the same report; closing the GUI does not remove these fields.

The report's `resources` object records `memory_limit_bytes`, `peak_managed_bytes` and
`scratch_spilled_bytes` for this invocation. These describe the managed workspace; use
`performance.peak_working_set_bytes` for measured process memory. Spilled bytes are cumulative scratch
growth, not peak disk usage, and may include multiple processing passes.

Check the exit code and report: a partial output may exist even when the run is incomplete. An interrupted
run keeps `<output>.work`; resume with the same source, binary, paths and options. A changed
source/binary is refused. Full conversion does not accept `--force`; choose a fresh destination.
Empty/subset modes and all options are listed by `--help`.

`--dry-run` checks structures and plans mailbox identities/coverage. It creates no files, does
not check every payload and does not test destination access. `--verify` checks supported
structures; it does not compare source content or prove Outlook compatibility.

| Exit | Meaning |
| --- | --- |
| 0 | Complete conversion, clean verification or successful planning |
| 1 | Invalid usage, OS/file I/O or output/staging/recovery operation failure |
| 2 | Unsupported input format/encoding or explicit processing limit |
| 3 | Corrupt/truncated input, verification findings or incomplete conversion |

### How it works

The reader is implemented in this project with reference to Microsoft's [MS-PST] specification
and [libyal/libpff](https://github.com/libyal/libpff), especially Joachim Metz's
[PFF format notes](https://github.com/libyal/libpff/blob/main/documentation/Personal%20Folder%20File%20(PFF)%20format.asciidoc)
for Unicode 4 KiB-page OST structures. Selected libpff/libfmapi source constants and behavior
were also consulted, with citations beside the relevant implementation. Thanks to Joachim Metz
and the libyal contributors for these references. Unknown fields in the notes remain unknown.

The reader decodes NDB pages/blocks and B-trees, then LTP heaps, property/table
contexts and named properties. The messaging layer constructs a mailbox manifest, assigns
stable destination identities and extracts each item. A transactional staging journal supports
recovery. The writer assembles a fresh PST, regenerates store-local references and allocation
maps, rereads the candidate and publishes outcomes. The dependency direction is
`CLI → Messaging → LTP → NDB → Utilities`, with Messaging also using the writer.

### Measured results

One immutable, unencoded Unicode OST was converted with the accepted M6 writer revision
`352157c` in a Windows x64 / MSVC 14.41 Release build. These are observations from one run,
not general performance or capacity guarantees. The user subsequently supplied the machine
configuration: AMD Ryzen 8845HS, 32 GB RAM, SSD. External verification time is excluded.

| Measurement | Result |
| --- | ---: |
| Machine | AMD Ryzen 8845HS · 32 GB RAM · SSD |
| Input OST | 2,635,407,360 bytes (2.635 GB / 2.454 GiB) |
| Output PST, before Outlook opened it | 2,042,045,440 bytes (2.042 GB / 1.902 GiB) |
| Output/input ratio | 77.485% (22.515% smaller) |
| Whole conversion process | 197.928 s (3 min 17.928 s) |
| Throughput, input size / elapsed time | 13.315 MB/s (12.698 MiB/s) |
| Peak process working set | 97,513,472 bytes (93.0 MiB) |
| Actual folders / normal messages / FAI | 65 / 11,259 / 145 |
| Embedded messages / recipients / attachment objects | 150 / 54,904 / 18,946 |
| Available attachment payload | 1,942,542,046 bytes |
| Skipped or failed items | 0 |

The timing includes identity hashing, indexing, conversion, assembly, internal verification,
report publication and cleanup. Available content matched in complete mapped comparisons and
independent libpff API/export checks: 70,284 exported files, 2,639,753,214 compared bytes,
zero byte differences. Private inputs, exports and raw logs are excluded from this repository.

A retest of the same immutable input with the adaptive-workspace build completed all 11,404
items with no skips or failures. Source, committed and internally reread output counts agree for
18,946 attachments, 150 embedded messages and 54,904 recipients; the PST size is unchanged.
The retest report does not record hardware configuration, so these results are not a controlled
performance comparison with the earlier build.

| Measurement | Adaptive-workspace retest |
| --- | ---: |
| Report time, before publication | 131.061 s |
| Report throughput | 20.108 MB/s |
| Whole invocation time | 158.614 s (2 min 38.614 s) |
| Whole invocation throughput | 16.615 MB/s |
| Peak process working set | 70,205,440 bytes (66.95 MiB) |
| Peak managed workspace | 45,877,776 bytes (43.75 MiB) |
| Scratch spilled bytes | 0 |

This retest passed internal verification but did not repeat the historical external content or
Outlook checks. It did not need disk spill; it does not establish performance for larger tables
that require spill. Report timing excludes final publication/cleanup, while invocation timing
includes those stages.

A later real-mailbox run on an Intel Core Ultra 5 235U / 16 GB RAM / SSD machine completed
without errors. Its source snapshot differs from an earlier run on this machine. The aggregate
report records `complete`, exit code `0` and internal verification `passed`.

| Measurement | Result |
| --- | ---: |
| Machine | Intel Core Ultra 5 235U · 16 GB RAM · SSD |
| Input OST | 26,252,746,752 bytes (26.253 GB / 24.450 GiB) |
| Output PST | 22,983,689,216 bytes (22.984 GB / 21.405 GiB) |
| Output/input ratio | 87.548% (12.452% smaller) |
| Actual folders / normal messages / FAI | 108 / 17,946 / 242 |
| Completed items | 18,188 / 18,188 |
| Embedded messages / recipients / attachment objects | 1,084 / 85,734 / 32,854 |
| Available attachment payload | 23,243,330,793 bytes |
| Skipped or failed items | 0 |
| Report time, before publication | 1,532.269 s (25 min 32.269 s) |
| Report throughput | 17.133 MB/s (16.340 MiB/s) |
| Whole invocation time | 1,895.122 s (31 min 35.122 s) |
| Whole invocation throughput | 13.853 MB/s (13.211 MiB/s) |
| Peak process working set | 447,881,216 bytes (427.13 MiB) |

Source, committed and output-verified object/attachment-byte counts agree in this report.
The report timer stops before final publication/cleanup; the invocation timer includes those stages.
Independent content comparison and Outlook acceptance for this sample have not been recorded.

On an Intel Core i5-1245U / 32 GB RAM / SSD machine, the user reports that a subsequent run
finished without errors and took roughly as long as the earlier run. The new aggregate report
has not yet been supplied, so its exact PST size, item counts, elapsed time and memory peak are
not included in the measured table.

One user observed correct-looking mail formatting, opening attachments and successful Outlook
restart/reopen on **Microsoft 365 Outlook MSO 2609, Build 16.0.20430.20032, 64-bit**. This is a
spot check on one sample/version. Other recorded SCANPST diagnostics remain unresolved; no
universal compatibility or exhaustive manual item inspection is claimed. The performance and
Outlook observations above apply to the builds used for those runs.

### Dependencies, references and license

OST2PST's own code and documentation are licensed under the [MIT License](LICENSE), allowing
use, modification and redistribution, including commercial use, with the copyright and permission
notice retained. Third-party materials retain their respective licenses; the optional libpff exporter
patch is LGPL-3.0-or-later and is not relicensed under MIT.

The core uses the C++ standard library and Windows APIs. It does not link libpff, libpst, pstsdk
or third-party zlib. Its CRC32, SHA-256 and RFC1950/1951 inflate implementations are in-tree.
[libpff](https://github.com/libyal/libpff) provided implementation references as described above
and was also used as a separately installed verification oracle. The inspected source headers
specify LGPL 3 or later. Its format notes are GNU FDL 1.3 or later.
Microsoft [MS-PST] and RFCs are format/algorithm references. Full upstream libraries and reference
documents are not bundled. The small optional exporter patch retains upstream license notices.

See [THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt) for exact sources, component notices and
license boundaries. For development, start with [agent.md](agent.md) and
[DEVELOPMENT.md](DEVELOPMENT.md). `agent.md` is intentionally named as supplied; point your AI
at it explicitly if it only auto-discovers `AGENTS.md`.

---

<a id="简体中文"></a>
## 简体中文

[切换到 English](#english)

OST2PST 是 Windows C++20 离线 **OST → Unicode PST** 转换器。直接解析源文件并生成新的
PST，转换过程不需要安装 Outlook、MAPI、邮箱账户或联网。附带 `ostinfo` 只读诊断工具。
M1–M7 转换器里程碑已完成；本版本包含 CLI 和原生 Windows 四步转换向导。

### 下载与图形界面使用

1. 在本项目的 **Releases** 页面下载 **`OST2PST-Windows-x64.zip`**。
2. **完整解压**后双击 **`OST2PST.exe`**，保留旁边的 `engine` 文件夹。
3. 选择 OST 文件和新的 PST 保存位置，开始转换。界面显示进度和最终结果；结果不完整时可查看报告。

便携包需要 Windows 10 1607+ x64，无需安装或另装 .NET/VC++ 运行库。界面默认跟随系统语言，
不支持时显示英文，也可在顶部切换。停止会保留恢复数据，使用相同源文件和目标位置可继续。
复制 OST 前请退出 Outlook，或使用不会再变化的副本。

### 功能与范围

- 转换实际文件夹、普通邮件、FAI 关联项、收件人、附件和嵌入邮件，保留源文件中可读取的属性及内容。
- 提供阶段与条目进度、断点恢复、逐项结果、汇总报告、只读预检和结构验证。
- 使用有界内存及磁盘暂存，逐项提交；相同输出块须经逐字节比较后才共享。
- 根据可用内存自动分配工作区，大型表和元数据超出额度后转存临时文件。临时磁盘占用可能增加；
  工作区额度并不等于整个进程的内存上限。
- 支持未编码 Unicode 4 KiB 页面输入及 512 字节页面 PST 结构；输出 Unicode 512 字节页面 PST。
  ANSI、WIP 版本 37 和非零 `bCryptMethod` 会明确拒绝。

无法恢复 OST 从未下载的内容。搜索定义不转换，输出内部结构及存储身份会重新生成。
压缩 RTF、OLE 等保留原始数据，不负责显示或解释。源数据缺失、无法读取、不支持及主动排除
分别记录。更大邮箱和其他 Outlook 版本需要重新验证。

### 从源码构建与 CLI 用法

安装 Windows x64、Visual Studio 2022「使用 C++ 的桌面开发」、CMake 3.22+；测试需要
Python 3.8+。`scripts/dev.cmd` 自动查找 VS 2022，特殊安装可设置 `VSCDEV_BAT`。
在项目根目录的命令提示符中运行：

```bat
scripts\dev.cmd cmake -S . -B build -A x64
scripts\dev.cmd cmake --build build --config Release --parallel 4
scripts\dev.cmd ctest --test-dir build -C Release --output-on-failure
build\Release\ost2pst.exe "C:\Mail\source.ost" "C:\Export\mailbox.pst"
```

自行构建图形界面时，使用上方英文区的 `build-gui` 构建和打包命令。运行包内 `OST2PST.exe`，
保留 `engine` 文件夹。界面默认跟随 Windows 界面语言，无法匹配时显示英文；顶部可立即切换
简体中文、繁體中文、English、日本語、Français、Italiano、Español、Deutsch、한국어。
静态运行库便携包无需另装 .NET/VC++ 运行库。需要 Windows 10 1607+；原生测试环境为 Windows 11 x64。
向导仅负责转换，显示实际条目进度及当前阶段；停止保留恢复数据，继续前校验身份。

仅编译程序可加 `-DBUILD_TESTING=OFF`，无需 Python。转换时不依赖 Python、Git Bash 或
libpff；默认 MSVC 构建使用微软 C++ 运行库，缺少时安装 x64 Visual C++ Redistributable。
公开测试由代码在构建目录生成合成数据，不附带任何真实邮箱文件或片段。

使用固定的 OST 副本，复制前退出 Outlook；输出父目录须存在。转换生成 PST、
`<output>.report.json` 和 `<output>.items.jsonl`。输出文件存在不等于转换完整，须检查退出码和报告。
中断后保留 `<output>.work`，以相同源文件、程序、路径和选项加 `--resume` 恢复。
源文件或程序发生变化会拒绝恢复。完整转换保护已有输出，不支持 `--force`。

新版 `.report.json` 的 `performance` 对象会持久保存性能数据，关闭 GUI 后仍可读取：

| 字段 | 含义 |
| --- | --- |
| `wall_seconds` | 本次启动至报告准备时的秒数，此时内部校验已完成 |
| `peak_working_set_bytes` | 截至该时刻转换器进程的峰值驻留内存，单位字节；测量失败为 `null` |
| `throughput_bytes_per_second` | OST 字节数除以耗时；除以 1,000,000 可换算为 MB/s |
| `resumed` | 是否在断点恢复运行中生成这份报告 |
| `scope` | 固定为 `current_invocation_before_publication` |

计时包含哈希、索引、转换、组装和内部校验，不包含最后的报告刷盘、文件发布及清理。
断点恢复只记录生成报告的那次启动，吞吐量为 `null`；若报告此前已封存或发布，则保留原统计。
GUI 与 CLI 使用同一份报告。

`resources` 对象记录本次启动的 `memory_limit_bytes`（工作区额度）、`peak_managed_bytes`
（受管理内存的核算峰值）及 `scratch_spilled_bytes`（累计转存字节数）。进程实际峰值仍看
`performance.peak_working_set_bytes`。累计转存量可能包含多遍处理，不代表磁盘占用峰值。

`--dry-run <input> [output]` 只做结构与邮箱清单预检，不写文件，也不检查所有内容或输出可写性。
`--verify <file>` 只验证支持的结构，不证明源内容完全一致或 Outlook 一定兼容。
其他选项见 `--help`。

| 退出码 | 含义 |
| --- | --- |
| 0 | 完整转换、结构检查通过或预检成功 |
| 1 | 参数错误、系统 I/O 或输出/暂存/恢复操作失败 |
| 2 | 不支持的格式/编码或明确处理上限 |
| 3 | 损坏/截断、结构检查发现问题或转换不完整 |

### 实现方式与实测结果

本项目的读取实现参考 Microsoft [MS-PST] 规范及
[libyal/libpff](https://github.com/libyal/libpff)，尤其是 Joachim Metz 编写的
[PFF 格式文档](https://github.com/libyal/libpff/blob/main/documentation/Personal%20Folder%20File%20(PFF)%20format.asciidoc)
中关于 Unicode 4 KiB 页面 OST 的说明。开发时还查阅了 libpff/libfmapi 的部分源码常量和行为，
相关实现旁保留来源引用。感谢 Joachim Metz 及 libyal 贡献者的工作；文档中的未知字段仍按未知处理。

NDB 解析页面、块和 B 树；LTP 解析堆、属性上下文、表上下文及命名属性；Messaging
建立邮箱清单并分配目标身份，逐项提取并写入事务暂存；Writer 重新构造 PST，生成身份及
分配映射，回读校验后发布。层次与开发契约见 [DEVELOPMENT.md](DEVELOPMENT.md)。

以下为接受的 M6 修订 `352157c` 在 Windows x64 / MSVC 14.41 Release 下的一次私有样本实测。
不代表所有邮箱的性能或容量。用户后续补充了机器配置：AMD Ryzen 8845HS、32 GB RAM、SSD。
外部比较用时不计入转换用时。

| 指标 | 结果 |
| --- | ---: |
| 机器配置 | AMD Ryzen 8845HS · 32 GB RAM · SSD |
| OST 大小 | 2,635,407,360 字节（2.635 GB / 2.454 GiB） |
| Outlook 打开前的 PST 大小 | 2,042,045,440 字节（2.042 GB / 1.902 GiB） |
| 大小比例 | 输出为输入的 77.485%，减少 22.515% |
| 完整转换用时 | 197.928 秒（3 分 17.928 秒） |
| 输入字节数/用时 | 13.315 MB/s（12.698 MiB/s） |
| 峰值工作集 | 97,513,472 字节（93.0 MiB） |
| 实际文件夹 / 普通邮件 / FAI | 65 / 11,259 / 145 |
| 嵌入邮件 / 收件人 / 附件对象 | 150 / 54,904 / 18,946 |
| 可读取附件内容 | 1,942,542,046 字节 |
| 跳过或失败条目 | 0 |

完整用时包含身份哈希、索引、转换、组装、内部验证、报告发布和清理。完整映射比较及独立
libpff API/导出比较通过：70,284 个导出文件、2,639,753,214 字节，逐字节差异为零。
原始邮箱、导出内容和详细日志均未放入本项目。

同一份固定输入在采用自适应工作区的版本中重测，11,404 项全部转换，跳过和失败均为零。
18,946 个附件、150 封嵌入邮件和 54,904 个收件人的源端、已提交及内部回读计数一致，PST 大小不变。
这次报告没有记录硬件配置，因此这些数据不作为与早期版本的受控性能比较。

| 指标 | 自适应工作区版本重测 |
| --- | ---: |
| 报告耗时，发布前截止 | 131.061 秒 |
| 报告吞吐量 | 20.108 MB/s |
| 整次进程耗时 | 158.614 秒（2 分 38.614 秒） |
| 整次进程吞吐量 | 16.615 MB/s |
| 进程峰值工作集 | 70,205,440 字节（66.95 MiB） |
| 受管工作区核算峰值 | 45,877,776 字节（43.75 MiB） |
| 累计磁盘转存量 | 0 |

本次内部校验通过，未重复此前的外部内容对照及 Outlook 检查。该样本不需要磁盘转存，
不能据此推断需要转存的大型表的性能。报告耗时不含最终发布和清理，整次进程耗时包含这些阶段。

Intel Core Ultra 5 235U、16 GB RAM、SSD 机器上的一次较新真实邮箱转换没有报错。
这次使用的 OST 快照与该机器先前的样本不同；汇总报告记录状态为 `complete`、
退出码为 `0`、内部校验为 `passed`。

| 指标 | 结果 |
| --- | ---: |
| 机器配置 | Intel Core Ultra 5 235U · 16 GB RAM · SSD |
| OST 大小 | 26,252,746,752 字节（26.253 GB / 24.450 GiB） |
| PST 大小 | 22,983,689,216 字节（22.984 GB / 21.405 GiB） |
| 大小比例 | 输出为输入的 87.548%，减少 12.452% |
| 实际文件夹 / 普通邮件 / FAI | 108 / 17,946 / 242 |
| 已完成条目 | 18,188 / 18,188 |
| 嵌入邮件 / 收件人 / 附件对象 | 1,084 / 85,734 / 32,854 |
| 可读取附件内容 | 23,243,330,793 字节 |
| 跳过或失败条目 | 0 |
| 报告耗时，发布前截止 | 1,532.269 秒（25 分 32.269 秒） |
| 报告吞吐量 | 17.133 MB/s（16.340 MiB/s） |
| 整次进程耗时 | 1,895.122 秒（31 分 35.122 秒） |
| 整次进程吞吐量 | 13.853 MB/s（13.211 MiB/s） |
| 峰值工作集 | 447,881,216 字节（427.13 MiB） |

报告中的源端、已提交和输出回读对象数及附件字节数一致。报告计时在最后发布和清理前
截止，整次进程计时包含这些阶段。这份样本尚未记录独立内容对照和 Outlook 验收。

另一台 Intel Core i5-1245U、32 GB RAM、SSD 机器上，用户反馈新版重跑没有错误，
耗时与先前大致相同。新版汇总报告尚未提供，因此这里不填写新版 PST 大小、条目数、
精确耗时或峰值内存。

用户在 Microsoft 365 Outlook MSO 2609、Build 16.0.20430.20032、64 位中确认邮件格式
显示正常、附件能打开、重启后能重新打开。这是单一样本和版本的抽查，并非逐条人工检查。
其他已记录的 SCANPST 诊断尚未全部解决，不宣称普遍兼容。上述性能和 Outlook 观察
适用于各自实测时使用的版本。

### 第三方与许可证

项目自身代码和文档采用 [MIT 许可证](LICENSE)，允许使用、修改、再分发及商业使用，
须保留版权和许可声明。第三方材料保留各自协议；可选 libpff 导出工具补丁仍为
LGPL-3.0-or-later，不因本项目采用 MIT 而变更。

核心使用 C++ 标准库和 Windows API，不链接 libpff、libpst、pstsdk 或第三方 zlib。
CRC32、SHA-256 和 RFC1950/1951 解压在项目内实现。libpff 除提供上述实现参考外，
还作为单独安装的外部对照验证工具；转换程序运行时不依赖它。
所检查的源码头声明 LGPL 3 或后续版本；其格式笔记是 GNU FDL 1.3 或后续版本。
Microsoft [MS-PST] 和 RFC 作为格式/算法参考，不附带完整参考全文或第三方库。
可选导出工具补丁保留上游许可说明。

来源和许可边界见 [THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt)。二次开发请先让 AI
读取 [agent.md](agent.md)，再按 [DEVELOPMENT.md](DEVELOPMENT.md) 选择相关模块。
此文件按要求命名为 `agent.md`；仅自动识别 `AGENTS.md` 的 AI 工具须显式指定它。
