"""Package a completed static Release build, refusing to overwrite any destination."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import zipfile

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--build-dir',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    build=a.build_dir.resolve()
    output=a.output.resolve()
    archive=Path(str(output)+'.zip')
    cache=(build/'CMakeCache.txt').read_text(encoding='utf-8')
    for key in ('OST2PST_STATIC_RUNTIME:BOOL=ON','OST2PST_BUILD_GUI:BOOL=ON'):
        if key not in cache:
            raise SystemExit('Required CMake option missing: '+key)
    if output.exists() or archive.exists():
        raise SystemExit('Refusing to overwrite package or archive: '+str(output))
    binaries={Path('OST2PST.exe'):build/'Release/ost2pst-gui.exe',Path('engine/ost2pst.exe'):build/'Release/ost2pst.exe'}
    for source in binaries.values():
        if not source.is_file(): raise SystemExit('Missing Release binary: '+str(source))
    license_source = Path(__file__).resolve().parent.parent / 'LICENSE'
    if not license_source.is_file(): raise SystemExit('Missing project LICENSE')
    (output/'engine').mkdir(parents=True)
    for relative,source in binaries.items(): shutil.copy2(source,output/relative)
    shutil.copyfile(license_source, output/'LICENSE')
    (output/'README.txt').write_text('''OST2PST — Windows x64 portable conversion wizard

Run OST2PST.exe. Select an OST source, then a new PST destination.
The interface follows your Windows UI language (English fallback).
Use the top language selector to switch immediately.
Supported: English, Simplified/Traditional Chinese, Japanese, French,
Italian, Spanish, German and Korean.

Keep engine/ost2pst.exe beside the application in the engine folder.
Outlook, MAPI, .NET and a separate VC++ runtime installation are not required.
Windows 10 version 1607 or newer is required by the DPI APIs; tested host: Windows 11 x64.

Progress percentages describe item processing only. Assembly, verification
and publication show activity with the current phase. An incomplete result
requires inspecting the aggregate/per-item reports next to the PST.
Stop preserves recovery files. Resume uses the same source and destination;
the engine validates their identities. Updating the engine changes its hash
and may prevent resuming older recovery data. Do not delete .work to retry.
Existing destinations and reports are never overwritten.

简体中文：运行 OST2PST.exe，依次选择 OST 和新的 PST 保存位置。
界面自动使用系统界面语言，也可在顶部切换。停止会保留恢复数据，继续时由引擎校验。
请保留 engine 文件夹；不要用新版本引擎替换尚未完成转换的旧引擎。
转换不完整时，请查看 PST 旁的报告。已有文件不会被覆盖。

This package does not change the source mailbox. Supported source profiles,
limitations and measured verification are documented in the source README.
No code-signing, installer or automatic updater is included.
''',encoding='utf-8')
    (output/'NOTICE.txt').write_text('''OST2PST
Project license: MIT; see LICENSE for the full copyright and permission notice.
The executables use the Windows platform APIs and the statically linked
Microsoft Visual C++ runtime supplied by the build toolchain. Microsoft runtime
components are subject to Microsoft's applicable redistribution terms.
No libpff, libpst, zlib, Qt, .NET or third-party format library is linked.
The application icon is original project artwork generated from source.
Protocol version 1; GUI version 1.0.0.
''',encoding='utf-8')
    manifest={str(path.relative_to(output)).replace('\\','/'):{'bytes':path.stat().st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()} for path in sorted(output.rglob('*')) if path.is_file()}
    (output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for path in sorted(output.rglob('*')):
            if path.is_file(): z.write(path,str(Path(output.name)/path.relative_to(output)))
    print(json.dumps({'folder':str(output),'files':len(manifest)+1,'uncompressed_bytes':sum(f.stat().st_size for f in output.rglob('*') if f.is_file()),'zip':str(archive),'zip_bytes':archive.stat().st_size,'sha256':hashlib.sha256(archive.read_bytes()).hexdigest()},ensure_ascii=False))

if __name__ == '__main__': main()
