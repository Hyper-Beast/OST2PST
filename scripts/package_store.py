"""Build the x64 Microsoft Store upload package from a static GUI Release build."""
import argparse
import hashlib
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import zipfile

from generate_gui_icon import png


ROOT = Path(__file__).resolve().parents[1]


def require_x64(exe):
    with exe.open('rb') as stream:
        if stream.read(2) != b'MZ':
            raise ValueError(f'Not an executable: {exe}')
        stream.seek(0x3c)
        stream.seek(struct.unpack('<I', stream.read(4))[0])
        if stream.read(6) != b'PE\0\0\x64\x86':
            raise ValueError(f'Not an AMD64 executable: {exe}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', required=True, type=Path)
    parser.add_argument('--output-dir', required=True, type=Path)
    parser.add_argument('--makeappx', default='makeappx.exe', help='Windows SDK MakeAppx executable')
    args = parser.parse_args()
    build = args.build_dir.resolve()
    config = (build / 'CMakeCache.txt').read_text(encoding='utf-8').splitlines()
    for key in ('OST2PST_STATIC_RUNTIME:BOOL=ON', 'OST2PST_BUILD_GUI:BOOL=ON'):
        if key not in config:
            parser.error(f'Missing CMake configuration: {key}')

    manifest = ROOT / 'store' / 'AppxManifest.xml'
    identity = ET.parse(manifest).getroot().find('{*}Identity').attrib
    filename = '{Name}_{Version}_{ProcessorArchitecture}.msix'.format(**identity)
    dest = args.output_dir.resolve() / filename
    if dest.exists():
        parser.error(f'Refusing to overwrite {dest}')
    dest.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        'AppxManifest.xml': manifest,
        'OST2PST.exe': build / 'Release' / 'ost2pst-gui.exe',
        'engine/ost2pst.exe': build / 'Release' / 'ost2pst.exe',
        'LICENSE': ROOT / 'LICENSE',
        'THIRD_PARTY_NOTICES.txt': ROOT / 'THIRD_PARTY_NOTICES.txt',
        'PRIVACY.md': ROOT / 'PRIVACY.md',
    }
    with tempfile.TemporaryDirectory(dir=dest.parent) as td:
        tmp = Path(td)
        layout = tmp / 'layout'
        for name, source in payload.items():
            if name.endswith('.exe'):
                require_x64(source)
            target = layout / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        assets = layout / 'Assets'
        assets.mkdir()
        for name, size in [('StoreLogo', 50), ('Square44', 44), ('Square150', 150)]:
            (assets / (name + '.png')).write_bytes(png(size))
        candidate = tmp / filename
        subprocess.run([args.makeappx, 'pack', '/d', layout, '/p', candidate, '/o'], check=True)
        # Store upload is unsigned; never install a signing certificate during packaging.
        with zipfile.ZipFile(candidate) as archive:
            expected = {f.relative_to(layout).as_posix() for f in layout.rglob('*') if f.is_file()}
            if set(archive.namelist()) != expected | {'AppxBlockMap.xml', '[Content_Types].xml'}:
                raise ValueError('Unexpected MSIX inventory')
            for name in expected:
                if archive.read(name) != (layout / name).read_bytes():
                    raise ValueError(f'Packaged file differs: {name}')
        candidate.rename(dest)
    print(f'{dest}\n{dest.stat().st_size:,} bytes; SHA256 {hashlib.sha256(dest.read_bytes()).hexdigest()}')


if __name__ == '__main__':
    main()
